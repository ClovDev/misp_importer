from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPTag
from datetime import datetime, timedelta
import numpy as np
import logging
import pytz
import pandas

class MISPHandler:

    def __init__(self, config: dict):
        self.url = config['misp_url']
        self.key = config['misp_auth_key']
        self.misp = PyMISP(self.url, self.key)
        self.tag_list = self.create_tag_list()

        self.logger = logging.getLogger('misp_handler')
        self.logger.debug("URLhausHandler init done")

    def create_tag_list(self) -> list:
        tags = []
        for item in self.misp.tags(pythonify=True):
            tags.append(item.name)
        return tags

    def make_sure_tag_exists(self, tag: str) -> bool:
        if tag in self.tag_list:
            return True
        else:
            self.misp.add_tag({"name": tag}, pythonify=True)
            self.tag_list = self.create_tag_list()
            if tag in self.tag_list:
                return True
            else:
                return False

    def add_tag_to_attribute(self, attr: MISPAttribute, tag: str) -> MISPAttribute:
        if self.make_sure_tag_exists(tag):
            attr.add_tag(tag)
        return attr

    def create_attr(self, raw_attr: dict) -> MISPAttribute:
        # Create attribute and assign simple values
        attr = MISPAttribute()
        attr.type = 'url'
        attr.value = raw_attr['url']
        attr.disable_correlation = False
        attr.__setattr__('first_seen', datetime.strptime(raw_attr['dateadded'], '%Y-%m-%d %H:%M:%S'))
        # Add URLhaus tag
        self.add_tag_to_attribute(attr, 'URLhaus')
        # Add other tags
        if raw_attr['tags']:
            for tag in raw_attr['tags'].split(','):
                self.add_tag_to_attribute(attr, tag.strip())

        # Add online/offline tag
        if not pandas.isna(raw_attr['url_status']):
            if raw_attr['url_status'] == 'online':
                attr.to_ids = True
            else:
                attr.to_ids = False
            self.add_tag_to_attribute(attr, raw_attr['url_status'])

        # Add reporter tag
        if not pandas.isna(raw_attr['reporter']):
            self.add_tag_to_attribute(attr, raw_attr['reporter'])

        attr.comment = raw_attr['urlhaus_link']
        return attr

    def create_attr_feodo(self, raw_attr: dict) -> MISPAttribute:
        attr = MISPAttribute()
        attr.type = 'ip-dst|port'
        attr.value = f"{raw_attr['DstIP']}|{raw_attr['DstPort']}"
        self.add_tag_to_attribute(attr, 'FeodoTracker')
        self.add_tag_to_attribute(attr, raw_attr['Malware'])
        attr.comment = 'Feodo tracker DST IP/port'
        attr.__setattr__('first_seen', datetime.strptime(raw_attr['Firstseen'], '%Y-%m-%d %H:%M:%S'))
        if not pandas.isna(raw_attr['LastOnline']):
            last_seen_time = datetime.strptime(str(raw_attr['LastOnline']), '%Y-%m-%d').replace(tzinfo=pytz.utc)
            first_seen_time = datetime.strptime(str(raw_attr["Firstseen"]), '%Y-%m-%d %H:%M:%S').replace(tzinfo=pytz.utc)
            if first_seen_time > last_seen_time:
                last_seen_time = first_seen_time + timedelta(seconds=1)
            attr.__setattr__('last_seen', last_seen_time)
        else:
            last_seen_time = datetime.strptime(str(raw_attr['Firstseen']), '%Y-%m-%d %H:%M:%S').replace(tzinfo=pytz.utc)
            attr.__setattr__('last_seen', last_seen_time)
        attr.to_ids = False
        attr.disable_correlation = False
        return attr

    def create_attr_azorult(self, raw_attr: dict) -> MISPAttribute:
        attr_list = []
        for type in [{'json': 'domain', 'misp': 'domain'},
                     {'json': 'ip', 'misp': 'ip-dst'},
                     {'json': 'panel_index', 'misp': 'url'}]:
            if type['json'] in raw_attr:
                attr = MISPAttribute()
                self.add_tag_to_attribute(attr, 'AzorultTracker')
                self.add_tag_to_attribute(attr, raw_attr['panel_version'])
                self.add_tag_to_attribute(attr, raw_attr['feeder'])
                self.add_tag_to_attribute(attr, raw_attr['status'])
                attr.comment = f'Azorult panel {type["misp"]}'
                attr.__setattr__('first_seen', datetime.fromtimestamp(raw_attr['first_seen']))
                attr.to_ids = False
                attr.disable_correlation = False
                attr.type = type['misp']
                attr.value = f"{raw_attr[type['json']]}"
                attr_list.append(attr)
        return attr_list

    @staticmethod
    def get_attribute_tag_list(self, tag_list: list) -> list:
        tags = []
        for item in tag_list:
            tags.append(item['name'])
        return tags

    @staticmethod
    def create_event(title: str, date_added: datetime) -> MISPEvent:
        misp_event = MISPEvent()
        misp_event.info = title
        if date_added != '':
            misp_event.date = date_added
        return misp_event

    def get_event(self, event_id):
        return self.misp.get_event(event_id, pythonify=True)

    def add_attr_to_event(self, event: MISPEvent, attribute: MISPAttribute):
        event.attributes.append(attribute)
        return event

    def update_event(self, event: MISPEvent):
        return self.misp.update_event(event, pythonify=True)

    def get_day_event(self, day: str, source: str, date: str):
        if source in ['URLHaus', 'FeodoTracker']:
            misp_event = self.misp.search('events', 'json', org=1, eventinfo=f'{source} import day {day}',
                                          pythonify=True)
        elif source in ['AzorultTracker']:
            misp_event = self.misp.search('events', 'json', org=1, eventinfo=f'{source} import panel {day}',
                                          pythonify=True)
        if len(misp_event) >= 1:
            return misp_event[0]
        else:
            if source in ['URLHaus', 'FeodoTracker']:
                misp_event = self.create_event(f"{source} import day {day}",
                                               date_added=datetime.timestamp(
                                                   datetime.strptime(date, '%Y-%m-%d %H:%M:%S')))
            elif source in ['AzorultTracker']:
                misp_event = self.create_event(f"{source} import panel {day}",
                                               date_added=datetime.fromtimestamp(date))
            event_id = self.misp.add_event(misp_event)
            self.misp.publish(event_id)
            return self.get_event(event_id)

    @staticmethod
    def delete_attribute_by_value(search_value: str, event: MISPEvent):
        found = False
        for a in event.attributes:
            if (hasattr(a, 'value') and a.value == search_value):
                a.deleted = True
        return event
