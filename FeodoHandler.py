from datetime import datetime, date, timedelta
from io import StringIO
import pathlib
import pandas
import MISPHandler
import requests
import logging
import pytz


class FeodoHandler:
    # Get header and download link
    def __init__(self, config: dict):
        self.header = ["Firstseen","DstIP","DstPort","LastOnline","Malware"]
        self.download_filename = ""
        self.url = config["feodo_url"]
        self.download_path = f"{config['download_path_feodo']}"

        self.logger = logging.getLogger('feodo_importer')
        self.logger.debug("URLhausHandler init done")

    def download_feodo_file(self):
        try:
            now = datetime.now()
            filename = f"{self.download_path}{now.year}/" \
                       f"feodo.csv.{now.year}{now.month}{now.day}-{now.hour}"
            # filename = "Downloads/URLHaus/2020/feodo.csv.2020515-11"
            response = requests.get(self.url, stream=True)
            pathlib.Path(f"{self.download_path}{now.year}/").mkdir(parents=True, exist_ok=True)
            with open(filename, "wb") as f_write:
                for chunk in response.iter_content(chunk_size=512):
                    if chunk:
                        f_write.write(chunk)
                f_write.close()
            return filename
        except Exception as e:
            self.logger.exception(f"Error downloading file \n {e}")
            exit(0)

    def create_panda_dataframe(self, f_csv: StringIO) -> pandas.core.frame.DataFrame:
        try:
            return pandas.read_csv(f_csv, comment="#", names=self.header)
        except Exception as e:
            self.logger.exception(f"Could not read CSV file: {self.download_filename}")
            exit(0)

    def initial_import(self, mh: MISPHandler):
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv"
        self.download_filename = self.download_urlhaus_file()
        events = dict()
        attributes = dict()
        with open(self.download_filename, 'r') as f:
            df = self.create_panda_dataframe(f)
            for index, row in df.iterrows():
                day = str(row["Firstseen"].strip().split(' ')[0])
                if day not in events:
                    events[day] = mh.create_event(f"FeodoTracker import day {day}", date_added=row["Firstseen"])
                # If current day is known in attributes just append to list of day attributes
                # Else create list for day and append.
                if day in attributes:
                    attributes[day].append(mh.create_attr_feodo(row))
                else:
                    attributes[day] = []
                    attributes[day].append(mh.create_attr_feodo(row))

                    # With dict of events and attributes, add them to MISP

            for day in attributes:
                for attr in attributes[day]:
                    events[day] = mh.add_attr_to_event(events[day], attr)
                self.logger.info(f'{day} attr changes {len(attributes[day])}')
                try:
                    mh.misp.add_event(events[day])
                except Exception as e:
                    self.logger.exception(f"Error updating event {events[day]}"
                                          f"with attrs: {attributes[day]}"
                                          f"\n {e}")

    def daily_update(self, mh: MISPHandler):
        if self.download_filename == "":
            self.download_filename = self.download_feodo_file()

        # Open downloaded Feodo csv and convert to panda frame
        with open(self.download_filename) as f:
            dataset = self.create_panda_dataframe(f)
            self.logger.debug(f"Loaded CSV file: {self.download_filename}")

        # Dict to load changed attributes and needed events
        attributes = dict()
        events = dict()
        # Use initial logic here instead of per line. Break for loop when known URL has been found
        for index, row in dataset.iterrows():
            # Get the day in YYYY-MM-DD format
            day = str(row["Firstseen"].strip().split(' ')[0])
            # Query if the attribute exists with FeodoTracker tag
            to_update_attribute = mh.misp.search('attributes', 'json', value=row['DstIP'],
                                                  tags=mh.misp.build_complex_query(and_parameters=['FeodoTracker']),
                                                 pythonify=True)
            # Set updated is false to track if change is needed
            updated = False
            # If attribute found, verify if it needs changes
            if len(to_update_attribute) == 1:
                # If the MISP Attr has last_seen already check if newer then change
                # else add last_seen to attr
                if hasattr(to_update_attribute[0], 'last_seen'):
                    attr_date = to_update_attribute[0].last_seen
                    if not pandas.isna(row['LastOnline']):
                        new_date = datetime.strptime(row['LastOnline'], '%Y-%m-%d').replace(tzinfo=pytz.utc)
                    else:
                        t=datetime.now(tz=pytz.utc)
                        new_date = datetime(t.year, t.month, t.day, tzinfo=pytz.utc)
                    if new_date > attr_date:
                        to_update_attribute[0].__setattr__('last_seen',new_date)
                        updated = True
                else:
                    if not pandas.isna(row['LastOnline']):
                        last_seen_time = datetime.strptime(str(row['LastOnline']), '%Y-%m-%d').replace(tzinfo=pytz.utc)
                        first_seen_time = datetime.strptime(str(row["Firstseen"]), '%Y-%m-%d %H:%M:%S').replace(tzinfo=pytz.utc)
                        if first_seen_time > last_seen_time:
                                last_seen_time = first_seen_time + timedelta(seconds=1)
                        to_update_attribute[0].__setattr__('last_seen',last_seen_time)
                        updated = True
                    else:
                        to_update_attribute[0].__setattr__('last_seen',datetime.now())
                        updated = True

                # if updated retreive full event and update attribute
                if updated:
                    events[day] = mh.get_day_event(day, 'FeodoTracker', date=row["Firstseen"])
                    if day in attributes:
                        attributes[day].append(to_update_attribute[0])
                    else:
                        attributes[day] = []
                        attributes[day].append(to_update_attribute[0])
            else:
                events[day] = mh.get_day_event(day, 'FeodoTracker', date=row["Firstseen"])
                if day in attributes:
                    attributes[day].append(mh.create_attr_feodo(row))
                else:
                    attributes[day] = []
                    attributes[day].append(mh.create_attr_feodo(row))

        # Loop over to be change attrs and change the value in the event
        for day in attributes:
            for attr in attributes[day]:
                for a in events[day].attributes:
                    if hasattr(a, 'value') and a.value == attr.value:
                        a.last_seen = attr.last_seen
                        break
                else:
                    events[day] = mh.add_attr_to_event(events[day], attr)
            self.logger.info(f'{day} attr changes {len(attributes[day])}')
            # update event with new attr changes
            try:
                event = mh.update_event(events[day])
                if(event):
                    mh.misp.publish(event.id, alert=False)
            except Exception as e:
                self.logger.exception(f"Error updating event {events[day]}"
                                  f"with attrs: {attributes[day]}"
                                  f"\n {e}")

        pathlib.Path(self.download_filename).unlink()