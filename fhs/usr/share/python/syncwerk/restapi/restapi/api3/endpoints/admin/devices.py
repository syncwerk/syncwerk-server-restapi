# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from django.utils.translation import ugettext as _

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.views import APIView
from rest_framework import status

from pyrpcsyncwerk import RpcsyncwerkError

from restapi.utils.devices import do_unlink_device
from restapi.utils.timeutils import datetime_to_isoformat_timestr
from restapi.views import is_registered_user

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response
from restapi.api3.models import TokenV2, DESKTOP_PLATFORMS

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class AdminDevices(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get device list',
        operation_description='''Get device list''',
        tags=['admin-devices'],
        manual_parameters=[
            openapi.Parameter(
                name='page',
                in_='query',
                type='string',
                description='page. Default to 1',
            ),
            openapi.Parameter(
                name='per_page',
                in_='query',
                type='string',
                description='device entries per page. Default to 50',
            ),
            openapi.Parameter(
                name='platform',
                in_='query',
                type='string',
                description='"desktop" or "mobile". If no provided, then retrieve all',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Device list retrived successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "page_info": {
                                "current_page": 1,
                                "has_next_page": False
                            },
                            "devices": [
                                {
                                    "is_desktop_client": True,
                                    "last_accessed": "2019-02-01T11:14:30+00:00",
                                    "last_login_ip": "::ffff:192.168.1.250",
                                    "platform": "windows",
                                    "user": "test10@grr.la",
                                    "client_version": "6.2.9",
                                    "device_name": "DESKTOP-3HE3P2O",
                                    "device_id": "db8ba925d61ca58cdbf6dcfa1acdc986be1fe6db"
                                }
                            ]
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
        }
    )
    def get(self, request, format=None):
        # Fix table name for counting devices
        # TokenV2.objects.model._meta.db_table = 'api2_tokenv2'

        try:
            current_page = int(request.GET.get('page', '1'))
            per_page = int(request.GET.get('per_page', '50'))
        except ValueError:
            current_page = 1
            per_page = 50

        total_device_count = TokenV2.objects.get_total_devices_count()

        platform = request.GET.get('platform', None)

        start = (current_page - 1) * per_page
        end = current_page * per_page + 1
        if per_page < 0:
            start = 0
            end = total_device_count
        devices = TokenV2.objects.get_devices(platform, start, end)
        if per_page < 0:
            has_next_page = False
        elif len(devices) == end - start:
            devices = devices[:per_page]
            has_next_page = True
        else:
            has_next_page = False

        return_results = []
        for device in devices:
            result = {}
            result['client_version'] = device.client_version
            result['device_id'] = device.device_id
            result['device_name'] = device.device_name
            result['last_accessed'] = datetime_to_isoformat_timestr(device.last_accessed)
            result['last_login_ip'] = device.last_login_ip
            result['user'] = device.user
            result['platform'] = device.platform

            result['is_desktop_client'] = False
            if result['platform'] in DESKTOP_PLATFORMS:
                result['is_desktop_client'] = True

            return_results.append(result)

        page_info = {
            'has_next_page': has_next_page,
            'current_page': current_page,
            'total_result': total_device_count,
        }
        resp = {"page_info": page_info, "devices": return_results}
        return api_response(data=resp)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Unlink device',
        operation_description='''Unlink device''',
        tags=['admin-devices'],
        manual_parameters=[
            openapi.Parameter(
                name='device_id',
                in_='query',
                type='string',
                description='device id',
                required=True,
            ),
            openapi.Parameter(
                name='wipe_device',
                in_='query',
                type='boolean',
                description='device will wipped if this params is true',
            ),
            openapi.Parameter(
                name='user',
                in_='query',
                type='boolean',
                description='email of the device owner',
                required=True,
            ),
            openapi.Parameter(
                name='platform',
                in_='query',
                type='string',
                description='"desktop" or "mobile"',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Device unlinked successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                },
            ),
            400: openapi.Response(
                description='Bad request',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": 'Token invalid'
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
    def delete(self, request, format=None):
        
        # print request.GET.get('platform')
        platform = request.GET.get('platform', '')
        device_id = request.GET.get('device_id', '')
        remote_wipe = request.GET.get('wipe_device', '')
        user = request.GET.get('user', '')

        if not platform:
            error_msg = 'platform invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if not device_id:
            error_msg = 'device_id invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if not user:
            error_msg = 'user invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        remote_wipe = True if remote_wipe == 'true' else False

        try:
            do_unlink_device(user, platform, device_id, remote_wipe=remote_wipe)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return api_response(msg=_('The device has been removed successfully'))
