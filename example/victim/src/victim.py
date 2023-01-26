import os
import time
import logging

import coloredlogs
import requests

URL = "http://class.diverge.dev:1200/login"
PING_INTERVAL = 5.0


# noinspection PyBroadException
def main():
    coloredlogs.install(level="INFO")

    username = os.environ.get("USERNAME")
    if username is None:
        username = "root"
    password = os.environ.get("PASSWORD")
    if password is None:
        password = "supersecure"
    data = dict(username=username, password=password)

    while True:
        try:
            logging.info(f"contacting {URL}")
            response = requests.post(URL, data=data)
            response_data = response.json()
            secret = response_data["secret"]
            logging.info(f"received secret {{{secret}}}")
        except Exception as e:
            logging.exception(e)

        time.sleep(PING_INTERVAL)


if __name__ == "__main__":
    main()
