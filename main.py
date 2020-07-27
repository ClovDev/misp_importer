import URLhausHandler
import MISPHandler
import FeodoHandler
import AzorultHandler
import logging
import pathlib
import yaml


def set_logger(log_file: str):
    logger = logging.getLogger()
    logger.setLevel(level=(logging.INFO))
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s - %(message)s')

    # Set CLI handler
    cli_handler = logging.StreamHandler()
    cli_handler.setFormatter(formatter)
    logger.addHandler(cli_handler)

    # Set log file handler
    pathlib.Path(log_file).parents[0].mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(log_file, 'a')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logger.debug("Logger creation complete.")
    return logger


def parse_config_file():
    try:
        with open('etc/config.yml', 'r', encoding='utf-8', errors='ignore') as configFile:
            config = yaml.load(configFile, Loader=yaml.FullLoader)
    except IOError as e:
        logger.error(
            f"Config file etc/config.yml is not accessible. Error details: {e}")
        exit(1)
    return config


if __name__ == "__main__":
    config = parse_config_file()
    logger = set_logger(config["log_file"])
    logger.info(f"Starting misp_import")
    mh = MISPHandler.MISPHandler(config)
    uh = URLhausHandler.URLhausHandler(config)
    uh.daily_urlhaus_update(mh)
    fh = FeodoHandler.FeodoHandler(config)
    fh.daily_update(mh)
    ah = AzorultHandler.AzorultHandler(config)
    ah.daily_azorult_update(mh)
    logger.info(f"Finished misp_import")