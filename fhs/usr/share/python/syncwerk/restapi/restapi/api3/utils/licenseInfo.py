# Copyright (c) 2012-2016 Seafile Ltd.
import logging
import os
import commands
import ConfigParser

from django.conf import settings

from synserv import ccnet_api
from restapi.settings import SYNCWERK_SERVER_EXEC, LICENSE_PATH

logger = logging.getLogger(__name__)


def parse_license_to_json():
    if os.path.isfile(LICENSE_PATH):
        # Parse the license file & get the number of allowed users
        config = ConfigParser.ConfigParser()
        config.read(LICENSE_PATH)
        license_json = {
            'auth_signature': config.get('SYNCWERK-SERVER', 'auth_signature'),
            'owner_name': config.get('SYNCWERK-SERVER', 'owner_name'),
            'owner_email': config.get('SYNCWERK-SERVER', 'owner_email'),
            'allowed_users': config.getint('SYNCWERK-SERVER', 'allowed_users'),
            'edition': config.get('SYNCWERK-SERVER', 'edition'),
        }
        if config.has_option('SYNCWERK-SERVER', 'from_date'):
            license_json['from_date'] = config.get(
                'SYNCWERK-SERVER', 'from_date')
        else:
            license_json['from_date'] = ''
        if config.has_option('SYNCWERK-SERVER', 'to_date'):
            license_json['to_date'] = config.get(
                'SYNCWERK-SERVER', 'to_date')
        else:
            license_json['to_date'] = ''
        if config.has_option('SYNCWERK-SERVER', 'from_sw_version'):
            license_json['from_sw_version'] = config.get(
                'SYNCWERK-SERVER', 'from_sw_version')
        else:
            license_json['from_sw_version'] = ''
        if config.has_option('SYNCWERK-SERVER', 'to_sw_version'):
            license_json['to_sw_version'] = config.get(
                'SYNCWERK-SERVER', 'to_sw_version')
        else:
            license_json['to_sw_version'] = ''

        available_features = config.get('SYNCWERK-SERVER', 'features')
        available_features_arr = available_features.split(',')
        license_json['available_features'] = available_features_arr
    else:
        license_json = {
            'auth_signature': None,
            'owner_name': None,
            'owner_email': None,
            'allowed_users': 3,
            'edition': "freeware",
            'from_date': None,
            'to_date': None,
            'from_sw_version': None,
            'to_sw_version': None,
            'available_features': ['folders','fileComments','groups','wiki','filePreview','internalShare','publicShare','adminArea','multiTenancy','webdav','trafficTracking','virusScanning','auditLog'],
        }
    return license_json


def is_pro_version():
    if os.path.isfile(SYNCWERK_SERVER_EXEC):
        lic_file_validate_result = os.system(
            SYNCWERK_SERVER_EXEC+' check-authorization-key '+LICENSE_PATH)
        if lic_file_validate_result != 0:
            return False
        else:
            return True
    else:
        return False

def get_machine_id():
    if os.path.isfile(SYNCWERK_SERVER_EXEC):
        status, output = commands.getstatusoutput(SYNCWERK_SERVER_EXEC + " show-id")
        if status == 0:
            return output
        else:
            return ''
    else:
        return ''
