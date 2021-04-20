import logging
import time

from django.core.management.base import BaseCommand

from restapi.api3.virus_scanning import start_virus_scanning

from restapi.api3.utils.licenseInfo import parse_license_to_json

from restapi.settings import ENABLE_VIRUS_SCANNING

from restapi import settings

logger = logging.getLogger(__name__)
            
def is_virus_scanning_available():
    license_info = parse_license_to_json()
    available_features_arr = license_info['available_features']
    if license_info['edition'] == 'freeware':
        return True
    else:
        return True if 'virusScanning'in available_features_arr and ENABLE_VIRUS_SCANNING else False

class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        if is_virus_scanning_available():
            logger.info('Virus scanning started')
            start_virus_scanning(log_to_console=True)
        else:
            logger.info('Virus scanning is disabled')