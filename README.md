# MISP importer

Some open source threat feeds have a lot of context added beside the IOCs. We wanted to have that context in MISP including tags and online/offline status. These script parse the feeds below and add the IOCs with extra context to MISP in a quick and dirty way. Not for use in production systems without some better coding.

## Feeds

The following feeds are parsed:

- URLhaus
  - URL
  - tags (Including submitter and malware family)
  - online/offline
- Feodotracker
  - IP:port
  - Last seen time
- Azorult
  - URL/IP
  - Online/offline status
  - Tags (including source and version)

## Install

Note these are guidelines, proper user setup etc are not handled.

1. Clone the directory

    ``` bash
    mkdir /software
    cd /software
    git clone https://github.com/KPN-SRT/misp_importer.git
    ```

2. Set config file

    ``` bash
    cd etc
    cp config.yaml.template config.yaml
    # edit the file to add MISP information
    ```

3. Create a virtual env for python

    ``` bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

4. crontab -e

    ``` bash
    0 */3 * * * cd /software/misp_importer/ && /software/misp_importer/venv/bin/python3 /software/misp_importer/main.py
    ```

5. Done
