import logging
import time
import threading

from django.core.management.base import BaseCommand

from restapi.api3.virus_scanning import start_virus_scanning

from restapi import settings

from restapi.api3.utils.licenseInfo import parse_license_to_json

from restapi.settings import ENABLE_VIRUS_SCANNING

logger = logging.getLogger(__name__)

def is_virus_scanning_available():
    license_info = parse_license_to_json()
    available_features_arr = license_info['available_features']
    if license_info['edition'] == 'freeware':
        return True
    else:
        return True if 'virusScanning' in available_features_arr and ENABLE_VIRUS_SCANNING else False

class VirusScanningBackgroundThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        while True:
            if is_virus_scanning_available():
                time.sleep(settings.VIRUS_SCAN_INTERVAL*60)
                logger.info('Virus scanning is running...')
                start_virus_scanning()
            else:
                logger.info('Virus scanning is disabled')
                time.sleep(settings.VIRUS_SCAN_INTERVAL*60)

class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        print "virus scanning thread starting"
        virus_scanning_thread = VirusScanningBackgroundThread()
        virus_scanning_thread.start()