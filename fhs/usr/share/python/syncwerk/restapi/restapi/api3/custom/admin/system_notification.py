import logging
import json
import os

from django.utils.translation import ugettext as _

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.views import APIView

from restapi.notifications.models import Notification, NotificationForm, \
    UserNotification
from restapi.notifications.utils import refresh_cache

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema


class SystemNotifications(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get list notification',
        operation_description='''Get list notification''',
        tags=['admin-notifications'],
        responses={
            200: openapi.Response(
                description='Notification list retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            {
                                "is_default": False,
                                "notificationMessage": "ddddd",
                                "id": 1
                            }
                        ]
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid",
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
        notes = Notification.objects.all().order_by('-id')
        resp_data = []
        for notification in notes:
            resp_data.append({
                'id': notification.id,
                'notificationMessage': notification.message,
                'is_default': notification.primary
            })
        return api_response(data=resp_data)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Add system notification',
        operation_description='''Add system notification''',
        tags=['admin-notifications'],
        manual_parameters=[
            openapi.Parameter(
                name='message',
                in_="formData",
                type='string',
                description='Notification message',
                required=True,
            ),
            openapi.Parameter(
                name='primary',
                in_="formData",
                type='boolean',
                description='set to "true" and the newly created notification will be the default one.',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Added new system notification successfully',
                examples={
                    'application/json': {
                        "message": "Added new system notification successfully",
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
                        "detail": "Token invalid",
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
    def post(self, request):
        message = request.POST.get('message', None)
        is_primary = request.POST.get('primary', False)

        print request.POST

        if message is None or message.strip() == '':
            return api_error(code=400, msg=_("Notification message is required."))
        f = NotificationForm({'message': message, 'primary': is_primary})
        f.save()
        return api_response(msg=_('Added new system notification successfully.'))


class SystemNotification(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Update notification',
        operation_description='''Update system notification''',
        tags=['admin-notifications'],
        manual_parameters=[
            openapi.Parameter(
                name='notification_id',
                in_="path",
                type='string',
                description='id of the notification to be updated',
                required=True,
            ),
            openapi.Parameter(
                name='message',
                in_="formData",
                type='string',
                description='new message',
                required=True,
            ),
            openapi.Parameter(
                name='primary',
                in_="formData",
                type='number',
                description='set to "1" and the updated notification will be the default one.',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Update notification successfully',
                examples={
                    'application/json': {
                        "message": "Update notification successfully",
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
                        "detail": "Token invalid",
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
    def put(self, request, notification_id):
        message = request.data.get('message')
        primary = int(request.data.get('primary'))
        if primary == 1:
            Notification.objects.filter(primary=1).update(primary=0)

        Notification.objects.filter(id=notification_id).update(
            primary=primary, message=message)
        refresh_cache()
        return api_response(msg=_('Set default notification successfully'))

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Remove notification',
        operation_description='''Remove system notification''',
        tags=['admin-notifications'],
        manual_parameters=[
            openapi.Parameter(
                name='notification_id',
                in_="path",
                type='string',
                description='id of the notification to be updated',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Remove notification successfully',
                examples={
                    'application/json': {
                        "message": "Remove notification successfully",
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
                        "detail": "Token invalid",
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
    def delete(self, request, notification_id):
        Notification.objects.filter(id=notification_id).delete()
        refresh_cache()
        return api_response(msg=_('Delete notification successfully'))


class CurrentNotification(APIView):

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='Get current (default) notification',
        operation_description='''Get current (default) notification''',
        tags=['other'],
        responses={
            200: openapi.Response(
                description='Current notification retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "message": "",
                            "id": "",
                            "primary": True,
                        }
                    }
                },
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
    def get(self, request):
        current_notification = Notification.objects.filter(primary=1)
        if len(current_notification) <= 0:
            data = None
        else:
            data = {
                'message': current_notification[0].message,
                'id': current_notification[0].id,
                'primary': current_notification[0].primary
            }
        return api_response(data=data)
