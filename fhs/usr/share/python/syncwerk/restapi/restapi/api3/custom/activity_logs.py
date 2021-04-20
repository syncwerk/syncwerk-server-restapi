import logging
import json
import csv

from django.utils.translation import ugettext as _
from django.http import HttpResponse

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated

from restapi.admin_log.models import AdminLog
from restapi.notifications.models import UserNotification

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response
from restapi.api3.base import APIView
from restapi.api3.utils import get_user_common_info
from restapi.api3.endpoints.notifications import get_notice_info

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class ActivitiesLog(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get activity logs',
        operation_description='''Get activity logs''',
        tags=['other'],
        responses={
            200: openapi.Response(
                description='Activity logs retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            {
                                "log_source": "admin-logs",
                                "detail": {
                                    "owner": {
                                        "login_id": "",
                                        "avatar_size": 80,
                                        "name": "admin",
                                        "nick_name": None,
                                        "is_default_avatar": False,
                                        "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                                        "email": "admin@alpha.syncwerk.com"
                                    },
                                    "id": "2efda003-51a7-4258-a51f-edf6e53a7a0e",
                                    "name": "enc2"
                                },
                                "datetime": "2019-02-19T03:56:42",
                                "user_info": {
                                    "login_id": "",
                                    "avatar_size": 80,
                                    "name": "admin",
                                    "nick_name": None,
                                    "is_default_avatar": False,
                                    "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                                    "email": "admin@alpha.syncwerk.com"
                                },
                                "email": "admin@alpha.syncwerk.com",
                                "type": "repo_create",
                                "id": 113
                            }
                        ]
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
        """ List all logs

        Permission checking:
        1. Admin user;
        """
        email = request.user.email
        activity_log_entries = []
        # Get logs from admin logs
        activities_from_admin = AdminLog.objects.all()
        for activity in activities_from_admin:
            activity_detail = json.loads(activity.detail)
            if 'owner' in activity_detail and activity_detail['owner']==email:
                activity_log_entries.append({
                    'id': activity.id,
                    'email': activity.email,
                    'user_info': get_user_common_info(activity.email),
                    'type': activity.operation,
                    'detail': activity_detail,
                    'datetime': activity.datetime,
                    'log_source': 'admin-logs'
                })
            elif 'from' in activity_detail and activity_detail['from']==email:
                activity_log_entries.append({
                    'id': activity.id,
                    'email': activity.email,
                    'user_info': get_user_common_info(activity.email),
                    'type': activity.operation,
                    'detail': activity_detail,
                    'datetime': activity.datetime,
                    'log_source': 'admin-logs'
                })
            elif 'to' in activity_detail and activity_detail['to']==email:
                activity_log_entries.append({
                    'id': activity.id,
                    'email': activity.email,
                    'user_info': get_user_common_info(activity.email),
                    'type': activity.operation,
                    'detail': activity_detail,
                    'datetime': activity.datetime,
                    'log_source': 'admin-logs'
                })
        # Get info of all the email field of the activity
        for activity in activity_log_entries:
            if 'owner' in activity['detail']:
                activity['detail']['owner']=get_user_common_info(activity['detail']['owner'])
            if 'from' in activity['detail']:
                activity['detail']['from']=get_user_common_info(activity['detail']['from'])
            if 'to' in activity['detail']:
                activity['detail']['to']=get_user_common_info(activity['detail']['to'])

        # Get logs from user notifications
        activities_from_user_notifications = UserNotification.objects.get_user_notifications(
            email)
        for activity in activities_from_user_notifications:
            print activity.detail
            notice_info = get_notice_info(activity)
            if notice_info != None:
                activity_log_entries.append({
                    'id': activity.id,
                    'email': activity.to_user,
                    'user_info': get_user_common_info(activity.to_user),
                    'type': activity.msg_type,
                    'detail': notice_info,
                    'datetime': activity.timestamp,
                    'log_source': 'user-notifications'
                })
            else:
                continue 
        return api_response(code=200, data=activity_log_entries)


class ActivitiesLogCSV(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Export activity log to CSV',
        operation_description='''Export activity log to CSV''',
        tags=['other'],
        responses={
            200: openapi.Response(
                description='Export activity log to CSV successfully.',
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
    def get(self, request):
        """ Export logs to csv

        Permission checking:
        1. Admin user;
        """
        email = request.user.email
        activity_log_entries = []
        # Get logs from admin logs
        activities_from_admin = AdminLog.objects.all()
        for activity in activities_from_admin:
            activity_detail = json.loads(activity.detail)
            if 'owner' in activity_detail and activity_detail['owner']==email:
                activity_log_entries.append({
                    'id': activity.id,
                    'email': activity.email,
                    'type': activity.operation,
                    'detail': activity_detail,
                    'datetime': activity.datetime,
                    'log_source': 'admin-logs'
                })
            elif 'from' in activity_detail and activity_detail['from']==email:
                activity_log_entries.append({
                    'id': activity.id,
                    'email': activity.email,
                    'type': activity.operation,
                    'detail': activity_detail,
                    'datetime': activity.datetime,
                    'log_source': 'admin-logs'
                })
            elif 'to' in activity_detail and activity_detail['to']==email:
                activity_log_entries.append({
                    'id': activity.id,
                    'email': activity.email,
                    'type': activity.operation,
                    'detail': activity_detail,
                    'datetime': activity.datetime,
                    'log_source': 'admin-logs'
                })
        # Get info of all the email field of the activity
        for activity in activity_log_entries:
            if 'owner' in activity['detail']:
                activity['detail']['owner']=get_user_common_info(activity['detail']['owner'])
            if 'from' in activity['detail']:
                activity['detail']['from']=get_user_common_info(activity['detail']['from'])
            if 'to' in activity['detail']:
                activity['detail']['to']=get_user_common_info(activity['detail']['to'])

        # Get logs from user notifications
        activities_from_user_notifications = UserNotification.objects.get_user_notifications(
            email)
        for activity in activities_from_user_notifications:
            print activity.detail
            activity_log_entries.append({
                'id': activity.id,
                'email': activity.to_user,
                'type': activity.msg_type,
                'detail': get_notice_info(activity),
                'datetime': activity.timestamp,
                'log_source': 'user-notifications'
            })
        response = HttpResponse(content_type='text/csv')
        writer = csv.writer(response, lineterminator='\n')
        for val in activity_log_entries:
            writer.writerow([val['email'], val['log_source'], val['type'], val['datetime'], val['detail']])
        response['Content-Disposition'] = 'attachment; filename=activity_logs.csv'
        return response
