from datetime import datetime, date, timedelta
from io import StringIO
import pathlib
import zipfile
import pandas
import MISPHandler
import requests
import logging

class URLhausHandler:
    # Get header and download link
    def __init__(self, config: dict):
        self.header = ["id", "dateadded", "url", "url_status", "threat", "tags", "urlhaus_link", "reporter"]
        self.download_filename = ""
        self.url = config["urlhaus_url"]
        self.download_path = f"{config['download_path_urlhaus']}"

        self.logger = logging.getLogger('urlhaus_importer')
        self.logger.debug("URLhausHandler init done")

    # Get and save urlhaus zip file
    def download_urlhaus_file(self) -> str:
        try:
            response = requests.get(self.url, stream=True)
            with open("urlhaus_full.csv.zip", "wb") as f_write_zip:
                for chunk in response.iter_content(chunk_size=512):
                    if chunk:
                        f_write_zip.write(chunk)
                f_write_zip.close()
        except Exception as e:
            self.logger.exception(f"Error downloading file \n {e}")
            exit(0)
        self.logger.debug("File downloaded")
        now = datetime.now()
        pathlib.Path(f"{self.download_path}{now.year}/").mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile('urlhaus_full.csv.zip', 'r') as f_zip:
                for zipinfo in f_zip.infolist():
                    new_filename = f"{self.download_path}{now.year}/" \
                                   f"{zipinfo.filename}.{now.year}{now.month}{now.day}-{now.hour}"
                    zipinfo.filename = new_filename
                    f_zip.extract(zipinfo)
            f_zip.close()
            self.logger.debug("File unzipped")
            return new_filename
        except Exception as e:
            self.logger.exception(f"Error unzipping file \n {e}")
            exit(0)

    def create_panda_dataframe(self, f_csv: StringIO) -> pandas.core.frame.DataFrame:
        try:
            return pandas.read_csv(f_csv, comment="#", names=self.header)
        except Exception as e:
            self.logger.exception(f"Could not read CSV file: {self.download_filename}")
            exit(0)

    @staticmethod
    def check_url_in_event(attributes: list, url: str):
        for attr in attributes:
            if attr['value'] == url:
                return True
        return False

    # Create a list of URL out of list containing attr dicts
    @staticmethod
    def create_matchlist(attribute_list: list):
        match_list = []
        for attr in attribute_list:
            match_list.append(attr['value'])
        return match_list

    def initial_urlhaus_import(self, mh: MISPHandler):

        if self.download_filename == "":
            self.download_filename = self.download_urlhaus_file()

        # Creates dicts to keep track of which attributes/events are part of what day
        # Both will be filled to create an MISP event and add those days attribute
        events = dict()
        attributes = dict()
        # Open the URLhaus CSV list
        with open(self.download_filename) as f:
            # Create a panda dataframe from CSV and iterate per row
            dataset = self.create_panda_dataframe(f)
            for index, row in dataset.iterrows():
                # Get the day in YYYY-MM-DD format
                day = str(row["dateadded"].strip().split(' ')[0])
                # If the current day does not exists in dict Event, create it
                if day not in events:
                    events[day] = mh.create_event(f"URLHaus import day {day}", date_added=row["dateadded"])
                # If current day is known in attributes just append to list of day attributes
                # Else create list for day and append.
                if day in attributes:
                    attributes[day].append(mh.create_attr(row))
                else:
                    attributes[day] = []
                    attributes[day].append(mh.create_attr(row))

            # With dict of events and attributes, add them to MISP
            for key in events:
                # Check if event already exists to be sure
                misp_event = mh.misp.search('events', 'json', org=1, eventinfo=f'URLHaus import day {key}')
                if len(misp_event) == 1:
                    event_id = misp_event[0]['Event']['id']
                else:
                    event_id = mh.misp.add_event(events[key])
                # Add relevant attributes to event, doubles are handled
                mh.misp.add_attribute(event_id, attributes[key])
                # Publish event when everything is imported
                mh.misp.publish(event_id, alert=False)

    def daily_urlhaus_update(self, mh: MISPHandler):

        if self.download_filename == "":
            self.download_filename = self.download_urlhaus_file()

        # Open downloaded URLhaus csv update
        with open(self.download_filename) as f:
            dataset = self.create_panda_dataframe(f)
            self.logger.debug(f"Loaded CSV file: {self.download_filename}")

        # create dicts for storing to update events
        attributes = dict()
        matchlist = dict()
        events = dict()
        days_backwards = str((date.today() - timedelta(days=10)).isoformat())
        self.logger.debug(f"Days looking back to import: {days_backwards}")
        # Use initial logic here instead of per line. Break for loop when known URL has been found
        for index, row in dataset.iterrows():

            # Get the day in YYYY-MM-DD format
            day = str(row["dateadded"].strip().split(' ')[0])
            if day == days_backwards:
                break
            #Get the relevant MISP event
            if day not in events:
                events[day] = mh.get_day_event(day, source='URLHaus', date=row["dateadded"])

            # Create a list of url per day if it does not exists
            if day not in matchlist:
                matchlist[day] = self.create_matchlist(events[day]['Attribute'])
            # Check if url is already known in misp for the event day
            if row['url'] in matchlist[day]:
                continue
            else:
                if day in attributes:
                    attributes[day].append(mh.create_attr(row))
                else:
                    attributes[day] = []
                    attributes[day].append(mh.create_attr(row))
        self.logger.debug(f"Changes in events loaded in memory")

        # add events to misp event
        for day in attributes:
            # If the current day does not exists in dict Event, create it
            for attr in attributes[day]:
                events[day] = mh.add_attr_to_event(events[day], attr)
            self.logger.info(f'{day} attr added {len(attributes[day])}')
            # update new event
            try:
                mh.update_event(events[day])
            except Exception as e:
                self.logger.exception(f"Error importing event {events[day]}"
                                  f"with attrs: {attributes[day]}"
                                  f"\n {e}")
            self.logger.debug(f"Added attr to {events[day]}")

        # For 'online' attributes in MISP check if still offline in current download
        startTime = datetime.now()
        events = dict()
        attributes = dict()
        # Get current attributes which are from KPN KSRT and have tag 'online' and 'urlhaus'
        to_update_attributes = mh.misp.search('attributes', 'json',
                                              tags=mh.misp.build_complex_query(and_parameters=['online', 'URLhaus']))

        for item in to_update_attributes['Attribute']:
            # Get all items where offline/online differ
            row = dataset.loc[
                (dataset["url"] == item['value']) &
                (dataset["url_status"] == "offline")
                ]
            # if differs remove attr and recreate with new data, then publish
            # For now MISP API does not allow easy attributes tag removal/adding. So removing an adding
            if len(row) == 1:
                    for index, r in row.iterrows():
                        day = str(r['dateadded'].strip().split(' ')[0])
                        if day not in events:
                            events[day] = mh.get_day_event(day, source='URLHaus', date=r["dateadded"])
                        if day in attributes:
                            attributes[day].append(mh.create_attr(r))
                        else:
                            attributes[day] = []
                            attributes[day].append(mh.create_attr(r))

        for day in attributes:
            for attr in attributes[day]:
                events[day] = mh.delete_attribute_by_value(attr.value, events[day])
                events[day] = mh.add_attr_to_event(events[day], attr)
            self.logger.info(f'{day} attr changes {len(attributes[day])}')
            try:
                mh.update_event(events[day])
            except Exception as e:
                self.logger.exception(f"Error updating event {events[day]}"
                                  f"with attrs: {attributes[day]}"
                                  f"\n {e}")

        pathlib.Path(self.download_filename).unlink()
