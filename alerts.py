#!/usr/bin/env python3

import json
import time
import datetime
import logging
import traceback
import sys
import argparse
import os
import requests
import urllib.parse
import hashlib

try:
    from systemd.journal import JournalHandler
    logger = logging.getLogger('abraracourcix-alerts')
    logger.addHandler(JournalHandler())
except ImportError:
    logger = logging.getLogger('abraracourcix-alerts')
    stdout = logging.StreamHandler(sys.stdout)
    logger.addHandler(stdout)
finally:
    logger.setLevel(logging.DEBUG)

global dir_path, args

def ESquery(query):
    url = "https://%s:%s@gra3.logs.ovh.com:9200/%s/_search"%(
      urllib.parse.quote_plus(args.ESuser), urllib.parse.quote_plus(args.ESpassword), urllib.parse.quote_plus(args.ESindex))

    logger.debug(query)
    r = requests.post(url, json = query)
    requestsList = []
    if r.status_code == 200:
        value = r.json()['hits']['total']
    else:
        r.raise_for_status()

    return value

def getESData(queryFile):
    global dir_path

    with open('%s/ESqueries/%s.json'%(dir_path, queryFile)) as f:
        query = json.load(f)
        value = ESquery(query)

    return value

def generateAlert(value, alertConfig):
    if alertConfig["direction"] == "below":
        if value < alertConfig["threshold"]:
            eventAction = "trigger"
        else:
            eventAction = "resolve"
    else:
        if value > alertConfig["threshold"]:
            eventAction = "trigger"
        else:
            eventAction = "resolve"
    now = datetime.datetime.now().isoformat()
    dedupKey = hashlib.sha224(json.dumps(alertConfig, separators=(',', ':')).encode()).hexdigest()
    payload = {
      "payload": {
        "summary": "Alert %d/%d (%s)"%(value, alertConfig["threshold"], alertConfig["direction"]),
        "timestamp": now,
        "source": "abraracourcix-alerts",
        "severity": "critical",
        "component": alertConfig["component"],
        "custom_details": {
          "description": alertConfig["description"]
        }
      },
      "routing_key": args.PDintegration,
      "dedup_key": dedupKey,
      "event_action": eventAction
    }

    url = "https://events.pagerduty.com/v2/enqueue"

    logger.debug(payload)
    #r = requests.post(url, data = json.dumps(payload))
    r = requests.get("https://cloud.parois.net")
    if r.status_code == 200:
        logger.info("Alert sent to pagerduty")
    else:
        logger.critical("Failed to send alert to pagerduty")
        r.raise_for_status()

    return value


def main():
    global dir_path, args

    parser = argparse.ArgumentParser(description='Send alerts to pagerduty by looking at ElasticSearch')
    parser.add_argument('--ESuser', metavar='ESUSER', required=True,
                        help='ElasticSearch user')
    parser.add_argument('--ESpassword', metavar='ESPASSWORD', required=True,
                        help='ElasticSearch password')
    parser.add_argument('--ESindex', metavar='ESINDEX', required=True,
                        help='ElasticSearch index')
    parser.add_argument('--PDintegration', metavar='PDINTEGRATION', required=True,
                        help='PagerDuty integration key')
    args = parser.parse_args()

    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open('%s/alert-config.json'%dir_path) as f:
        alertConfigList = json.load(f)

    for alertConfig in alertConfigList:
        value = getESData(alertConfig["queryFile"])
        generateAlert(value, alertConfig)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logger.exception('An unexpected error occurred')
        logger.exception("".join(traceback.format_exception(None,e, e.__traceback__)))
        sys.exit(2)
