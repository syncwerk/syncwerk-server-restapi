import logging
import threading
import time

from django.core.management.base import BaseCommand

from restapi.api3.syncwevent.syncwevent_async_client import startEventListening

from restapi.api3.utils.licenseInfo import parse_license_to_json

logger = logging.getLogger(__name__)

def is_traffic_tracking_available():
    license_info = parse_license_to_json()
    available_features_arr = license_info['available_features']
    if license_info['edition'] == 'freeware':
        return True
    else:
        return True if 'trafficTracking' in available_features_arr else False,

class SyncwerkEventClientThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        if not is_traffic_tracking_available():
            logger.info('Syncwerk event is not available')
            while True:
                time.sleep(3600)
        else:
            startEventListening()

class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        syncwevent_client_thread = SyncwerkEventClientThread()
        syncwevent_client_thread.start()