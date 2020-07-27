from datetime import datetime, date, timedelta
from io import StringIO
import pathlib
import pandas
import MISPHandler
import requests
import logging
import pytz
import json

class AzorultHandler:
    # Get header and download link
    def __init__(self, config: dict):
        self.download_filename = ""
        self.url = config["azorult_url"]
        self.download_path = f"{config['download_path_azorult']}"

        self.logger = logging.getLogger('azorult_importer')
        self.logger.debug("AzorultHandler init done")

    def download_azorult_file(self):
        try:
            now = datetime.now()
            filename = f"{self.download_path}{now.year}/" \
                       f"azorult.json.{now.year}{now.month}{now.day}-{now.hour}"
            pathlib.Path(f"{self.download_path}{now.year}/").mkdir(parents=True, exist_ok=True)
            # filename = "Downloads/Azorult/2020/azorult.json.202069-16"
            response = requests.get(self.url, stream=True)
            with open(filename, "wb") as f_write:
                for chunk in response.iter_content(chunk_size=512):
                    if chunk:
                        f_write.write(chunk)
                f_write.close()
            # testing only
            # filename = f"{self.download_path}{now.year}/azorult.json.2020616-9"
            return filename
        except Exception as e:
            self.logger.exception(f"Error downloading file \n {e}")
            exit(0)

    # Create a list of URL out of list containing attr dicts
    @staticmethod
    def create_matchlist(attribute_list: list):
        match_list = []
        for attr in attribute_list:
            match_list.append(attr['value'])
        return match_list

    def daily_azorult_update(self, mh: MISPHandler):
        if self.download_filename == "":
            self.download_filename = self.download_azorult_file()

        with open(self.download_filename, 'r') as f_json:
            data = json.load(f_json)

        attributes = dict()
        events = dict()
        datetime.min.time()
        existing_domains = self.create_matchlist(mh.misp.search('attributes', 'json',
                                             tags=mh.misp.build_complex_query(and_parameters=['AzorultTracker']),
                                             pythonify=True))
        online_domains = self.create_matchlist(
                                mh.misp.search('attributes', 'json',
                                    tags=mh.misp.build_complex_query(and_parameters=['AzorultTracker','online']),
                                    pythonify=True))
        for json_item in data:
            domain = json_item['panel_index']
            if json_item['panel_index'] in existing_domains:
                if json_item['panel_index'] in online_domains and json_item['status'] == 'offline':
                    # Change tag
                    event = mh.get_day_event(domain, source='AzorultTracker', date=json_item["first_seen"])
                    for attr in event.attributes:
                        event = mh.delete_attribute_by_value(attr.value, event)
                        #event = mh.add_attr_to_event(event, new_attr)
                    new_attr = mh.create_attr_azorult(json_item)
                    for attr in new_attr:
                        event = mh.add_attr_to_event(event, attr)
                    try:
                        send_event = mh.update_event(event)
                        if send_event:
                            mh.misp.publish(send_event.id, alert=False)
                    except Exception as e:
                        self.logger.exception(f"Error updating event {event}"
                                              f"\n {e}")
                    continue
                else:
                    continue
            else:
                events[domain] = mh.get_day_event(domain, 'AzorultTracker', date=json_item["first_seen"])
                attributes[domain] = mh.create_attr_azorult(json_item)

        for key, event in events.items():
            for attr in attributes[key]:
                event = mh.add_attr_to_event(event, attr)
            try:
                send_event = mh.update_event(event)
                if send_event:
                    mh.misp.publish(send_event.id, alert=False)
            except Exception as e:
                self.logger.exception(f"Error updating event {event}"
                                  f"with attrs: {attributes[key]}"
                                  f"\n {e}")