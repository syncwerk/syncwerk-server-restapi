# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from synserv import syncwerk_api, ccnet_api
from pyrpcsyncwerk import RpcsyncwerkError

# from restapi.utils import is_pro_version
# from restapi.utils.licenseparse import parse_license, parse_license_to_json

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.models import TokenV2
from restapi.api3.utils import api_response, api_error
from restapi.api3.permissions import IsSystemAdminOrTenantAdmin


from restapi.api3.utils.licenseInfo import parse_license_to_json, is_pro_version, get_machine_id

from restapi import settings
from restapi.utils import HAS_OFFICE_CONVERTER, HAS_FILE_SEARCH
from constance import config

try:
    from restapi.settings import MULTI_TENANCY
except ImportError:
    MULTI_TENANCY = False

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema


def is_syncwerk_pro():
    return any(['restapi_extra' in app for app in settings.INSTALLED_APPS])


class SysInfo(APIView):
    """ Show system info.
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsSystemAdminOrTenantAdmin,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get system info',
        operation_description='''Get system info''',
        tags=['admin-system'],
        responses={
            200: openapi.Response(
                description='System info retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "current_connected_devices_count": 0,
                            "total_devices_count": 1,
                            "total_files_count": 25,
                            "groups_count": 4,
                            "license_json": {
                                "auth_signature": "license auth signature",
                                "available_features": [
                                    "folders",
                                    "fileComments",
                                    "groups",
                                    "wiki",
                                    "filePreview",
                                    "internalShare",
                                    "publicShare",
                                    "adminArea",
                                    "multiTenancy",
                                    "webdav"
                                ],
                                "owner_email": "owner@email.com",
                                "edition": "perpetual",
                                "from_date": "",
                                "owner_name": "Owner name",
                                "allowed_users": 1000,
                                "to_date": "",
                                "from_sw_version": "20170101",
                                "machine_id": "",
                                "to_sw_version": "20200130"
                            },
                            "users_count": 105,
                            "total_storage": 182133615,
                            "active_users_count": 105,
                            "server_version": "SYNCWERKVERSION",
                            "multi_tenancy_enabled": False,
                            "repos_count": 24,
                            "is_pro": True,
                            "org_count": 0
                        }
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": 'Token invalid'
                    }
                }
            ),
            403: openapi.Response(
                description='Operation not permitted',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            500: openapi.Response(
                description='Internal server error',
                examples={
                    'application/json': {
                        "message": "Internal server error",
                        "data": None
                    }
                }
            ),
        }
    )
    def get(self, request, format=None):
        # count repos
        try:
            repos_count = syncwerk_api.count_repos()
        except RpcsyncwerkError as e:
            logger.error(e)
            repos_count = 0

        # count groups
        try:
            groups_count = len(ccnet_api.get_all_groups(-1, -1))
        except Exception as e:
            logger.error(e)
            groups_count = 0

        # count orgs
        if MULTI_TENANCY:
            multi_tenancy_enabled = True
            try:
                org_count = ccnet_api.count_orgs()
            except Exception as e:
                logger.error(e)
                org_count = 0
        else:
            multi_tenancy_enabled = False
            org_count = 0

        # count users
        try:
            active_db_users = ccnet_api.count_emailusers('DB')
        except Exception as e:
            logger.error(e)
            active_db_users = 0

        try:
            active_ldap_users = ccnet_api.count_emailusers('LDAP')
        except Exception as e:
            logger.error(e)
            active_ldap_users = 0

        try:
            inactive_db_users = ccnet_api.count_inactive_emailusers('DB')
        except Exception as e:
            logger.error(e)
            inactive_db_users = 0

        try:
            inactive_ldap_users = ccnet_api.count_inactive_emailusers('LDAP')
        except Exception as e:
            logger.error(e)
            inactive_ldap_users = 0

        active_users = active_db_users + active_ldap_users if active_ldap_users > 0 \
            else active_db_users

        inactive_users = inactive_db_users + inactive_ldap_users if inactive_ldap_users > 0 \
            else inactive_db_users

        # get license info
        is_pro = is_pro_version()
        if is_pro:
            # pro version
            license_json = parse_license_to_json()
        else:
            # freeware
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
                'available_features': ['folders']
            }
        license_json['machine_id'] = get_machine_id()
        # get license info
        # is_pro = is_pro_version()
        # if is_pro:
        #     license_json = parse_license_to_json()
        #     license_json['is_pro'] = True
        # else:
        #     license_json = {
        #         'is_pro': False,
        #         'allowed_users': 3,
        #         'to_date': '',
        #         'owner_name': '',
        #     }

        # if license_json:
        #     with_license = True
        #     try:
        #         max_users = int(license_json['allowed_users'])
        #     except ValueError as e:
        #         logger.error(e)
        #         max_users = 0
        # else:
        #     with_license = False
        #     max_users = 0

        # count total file number
        try:
            total_files_count = syncwerk_api.get_total_file_number()
        except Exception as e:
            logger.error(e)
            total_files_count = 0

        # count total storage
        try:
            total_storage = syncwerk_api.get_total_storage()
        except Exception as e:
            logger.error(e)
            total_storage = 0

        # Fix table name for counting devices
        # TokenV2.objects.model._meta.db_table = 'api2_tokenv2'
        # count devices number
        try:
            total_devices_count = TokenV2.objects.get_total_devices_count()
        except Exception as e:
            logger.error(e)
            total_devices_count = 0

        # count current connected devices
        try:
            current_connected_devices_count = TokenV2.objects.get_current_connected_devices_count()
        except Exception as e:
            logger.error(e)
            current_connected_devices_count = 0

        info = {
            'users_count': active_users + inactive_users,
            'active_users_count': active_users,
            'repos_count': repos_count,
            'total_files_count': total_files_count,
            'groups_count': groups_count,
            'org_count': org_count,
            'multi_tenancy_enabled': multi_tenancy_enabled,
            'is_pro': is_pro,
            'license_json': license_json,
            'total_storage': total_storage,
            'total_devices_count': total_devices_count,
            'current_connected_devices_count': current_connected_devices_count,
            'server_version': settings.SYNCWERK_VERSION,
        }

        # return Response(info)
        return api_response(data=info)


class SysVersion(APIView):
    """ API for exposing system version.
    """
    throttle_classes = (UserRateThrottle,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='Get system version',
        operation_description='''Get system version''',
        tags=['other'],
        responses={
            200: openapi.Response(
                description='System version retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "version": "SYNCWERKVERSION",
                            "features": [
                                "syncwerk-basic"
                            ]
                        }
                    }
                },
            ),
        }
    )
    def get(self, request, format=None):
        info = {
            'version': settings.SYNCWERK_VERSION,
        }
        features = ['syncwerk-basic']

        if is_syncwerk_pro():
            features.append('syncwerk-pro')

        if HAS_OFFICE_CONVERTER:
            features.append('office-preview')

        if HAS_FILE_SEARCH:
            features.append('file-search')

        if config.DISABLE_SYNC_WITH_ANY_FOLDER:
            features.append('disable-sync-with-any-folder')

        if hasattr(settings, 'DESKTOP_CUSTOM_LOGO'):
            info['desktop-custom-logo'] = settings.MEDIA_URL + \
                getattr(settings, 'DESKTOP_CUSTOM_LOGO')

        if hasattr(settings, 'DESKTOP_CUSTOM_BRAND'):
            info['desktop-custom-brand'] = getattr(
                settings, 'DESKTOP_CUSTOM_BRAND')

        info['features'] = features

        return api_response(data=info)
