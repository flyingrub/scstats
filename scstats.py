#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

"""y2mp3 download all playlist of an user

Usage:
    y2mp3
    y2mp3 <link>
    y2mp3 -h | --help


Options:
    -h --help          Show this screen
"""

import logging
import os
import signal
import sys
import time
import warnings
import math
import shutil
import requests
import re
import tempfile
import subprocess
import getpass
from docopt import docopt
from datetime import datetime
import sqlite3
import pickle


logging.basicConfig(level=logging.DEBUG, format='%(message)s')
logging.getLogger('requests').setLevel(logging.WARNING)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.newline = print

arguments = None
client_id = "cKf4vDOFJQhksTD5LHptv0uG9P0gHZA0"
invalid_chars = '\/:*?|<>"'

connect_endpoint = 'https://api-auth.soundcloud.com/web-auth/sign-in/password?client_id=cKf4vDOFJQhksTD5LHptv0uG9P0gHZA0'
me = r"""https://api-v2.soundcloud.com/me?client_id=cKf4vDOFJQhksTD5LHptv0uG9P0gHZA0"""
playhistory = r"""https://api-v2.soundcloud.com/me/play-history/tracks?client_id=cKf4vDOFJQhksTD5LHptv0uG9P0gHZA0&limit=500"""
s = requests.Session()
database = sqlite3.connect('stats.db')
cursor = database.cursor()

def main():
    """
    Main function, call parse_url
    """
    signal.signal(signal.SIGINT, signal_handler)
    global offset
    global arguments
    global s

    # Parse argument
    arguments = docopt(__doc__, version='v0.0.1')

    # user = input("Username:")
    # pswd = getpass.getpass('Password:')

    restore_session()
    connect()
    history = get_collection(playhistory)
    write_stats(history)
    show_last_date(history)
    save_session()

def save_session():
    save_token()
    with open('cookies', 'wb') as f:
        pickle.dump(s.cookies, f)

def restore_session():
    restore_token()
    if not os.path.exists("cookies"):
        return
    with open('cookies', 'rb') as f:
        s.cookies.update(pickle.load(f))

def is_authorized():
    r = s.get(playhistory)
    # r.raise_for_status()
    return r.status_code == 200

def save_token():
    with open('token', 'w') as f:
        f.write(s.headers["Authorization"])

def restore_token():
    with open('token', 'r') as f:
        token = f.read()
        logger.debug(token)
        headers = {'Authorization': token}
        s.headers.update(headers)

def connect():
    global s
    if is_authorized():
        logger.debug("Connection restored")
        return
    else:
        s = requests.Session()

    logger.debug("Connecting")
    r = s.post(connect_endpoint, login_data)
    logger.debug(r.text)

    token = r.json()["session"]["access_token"]
    logger.debug(token)
    headers = {'Authorization': "OAuth {0}".format(token)}
    s.headers.update(headers)

def stat_day():
    global s
    now = datetime.now()
    timestamp = datetime.timestamp(now)
    logger.debug(int(timestamp))
    r = s.get(playhistory)
    logger.debug(r.text)

def is_this_month(timestamp, offset):
    if timestamp is None:
        return True

    timestamp -= offset
    date = datetime.fromtimestamp(timestamp / 1000.0)
    return date.month is datetime.now().month

def until_2020(timestamp, offset):
    if timestamp is None:
            return True

    timestamp -= offset
    date = datetime.fromtimestamp(timestamp / 1000.0)
    logger.debug(date)
    return date.year >= 2020

def get_timestamp(url):
    query = requests.utils.urlparse(url).query
    params = dict(x.split('=') for x in query.split('&'))
    return int(params["from"])

def get_offset(url):
    query = requests.utils.urlparse(url).query
    params = dict(x.split('=') for x in query.split('&'))
    return int(params["offset"])

def show_last_date(history):
    listen = history[-1]
    played_at = listen["played_at"]
    date = datetime.fromtimestamp(played_at / 1000.0)
    logger.debug("Last date :")
    logger.debug(date)

def get_collection(url):
    global s
    resources = list()
    timestamp = None
    offset = None
    while until_2020(timestamp, offset):
        response = s.get(url)
        logger.debug(response.text)
        response.raise_for_status()
        json_data = response.json()
        if 'collection' in json_data:
            resources.extend(json_data['collection'])
        else:
            resources.extend(json_data)
        if 'next_href' in json_data:
            url = json_data['next_href']
            logger.debug(url)
            if url is "null" or url is None:
                break
        
            timestamp = get_timestamp(url)
            offset = get_offset(url)
        else:
            break
    return resources

def write_stats(history):
    global cursor
    for listen in history:
        played_at = listen["played_at"]
        track_id = listen["track_id"]
        title = listen["track"]["title"]
        user_id = listen["track"]["user_id"]
        user = listen["track"]["user"]["username"]
        # logger.debug("{0} - {1} - {2} - {3} - {4}".format(user, title, track_id, user_id, played_at))
        cursor.execute("INSERT OR IGNORE INTO history (artist_id, artist_name, title_id, title_name, played_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, user, track_id, title, played_at))

    database.commit()

def signal_handler(signal, frame):
    """
    Handle Keyboardinterrupt
    """
    save_session()
    logger.newline()
    logger.info('Good bye!')
    sys.exit(0)

if __name__ == '__main__':
    main()
