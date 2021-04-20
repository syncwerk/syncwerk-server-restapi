import datetime
import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import status

from restapi.api3.utils import api_error, api_response
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle

from restapi.api2.models import TokenV2, DESKTOP_PLATFORMS
from restapi.utils.devices import do_unlink_device
from restapi.utils.timeutils import datetime_to_isoformat_timestr

from pyrpcsyncwerk import RpcsyncwerkError

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

logger = logging.getLogger(__name__)


class DevicesView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication, )
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get user devices',
        operation_description='''Get all the connected devices of the user''',
        tags=['devices'],
        responses={
            200: openapi.Response(
                description='User device retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            {
                                "is_desktop_client": False,
                                "last_accessed": "2019-01-28T03:59:19+00:00",
                                "device_name": "Redmi Note 5",
                                "platform_version": "8.1.0",
                                "platform": "android",
                                "user": "admin@alpha.syncwerk.com",
                                "key": "c2d2f9b5a47b1aa7e8f0c13c6fd8b52e338bab12",
                                "wiped_at": None,
                                "client_version": "2.2.11",
                                "last_login_ip": "::ffff:192.168.1.250",
                                "device_id": "c9dcfce418a189d1"
                            }
                        ]
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid"
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
        username = request.user.username
        devices = TokenV2.objects.get_user_devices(username)

        for device in devices:
            device['last_accessed'] = datetime_to_isoformat_timestr(device['last_accessed'])
            device['is_desktop_client'] = False
            if device['platform'] in DESKTOP_PLATFORMS:
                device['is_desktop_client'] = True

        return api_response(data=devices)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Unlink user device',
        operation_description='''Unlink specific user device''',
        tags=['devices'],
        manual_parameters=[
            openapi.Parameter(
                name='platform',
                in_="query",
                type='string',
                description='device platform',
            ),
            openapi.Parameter(
                name='device_id',
                in_="query",
                type='string',
                description='device id to be deleted',
            ),
            openapi.Parameter(
                name='wipe_device',
                in_="query",
                type='string',
                description='is device to be wiped or not',
            ),
        ],
        responses={
            200: openapi.Response(
                description='User device unlinked successfully.',
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
                        "detail": "Token invalid"
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
        
        platform = request.GET.get('platform', '')
        device_id = request.GET.get('device_id', '')
        remote_wipe = request.GET.get('wipe_device', '')

        if not platform:
            error_msg = 'platform invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if not device_id:
            error_msg = 'device_id invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        remote_wipe = True if remote_wipe == 'true' else False

        try:
            do_unlink_device(request.user.username,
                             platform,
                             device_id,
                             remote_wipe=remote_wipe)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return api_response()
