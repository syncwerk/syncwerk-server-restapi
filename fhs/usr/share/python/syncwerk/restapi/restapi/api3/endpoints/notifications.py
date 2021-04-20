import json
import logging
import os

from constance import config

from django.core.cache import cache
from django.utils.translation import ugettext as _

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response, get_user_common_info

from restapi.avatar.util import get_default_avatar_url
from restapi.notifications.models import UserNotification
from restapi.notifications.models import get_cache_key_of_unseen_notifications
from restapi.notifications.views import add_notice_from_info
from restapi.base.templatetags.restapi_tags import email2nickname, \
    translate_restapi_time

from synserv import syncwerk_api, ccnet_api

logger = logging.getLogger(__name__)

from drf_yasg.utils import swagger_auto_schema, no_body
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema
from rest_framework import parsers


def get_notice_info(notice):
    avatar_url = get_default_avatar_url()
    default_avatar_url = '%s%s' % (config.SERVICE_URL, avatar_url)
    result = {}
    result['id'] = notice.id
    result['seen'] = notice.seen
    result['to_user'] = notice.to_user
    result['msg_type'] = notice.msg_type
    result['timestamp'] = notice.timestamp
    result['mtime_relative'] = notice.timestamp
    result['default_avatar_url'] = default_avatar_url

    if notice.is_user_message():
        d = notice.user_message_detail_to_dict()
        if d.get('msg_from') is not None:
            result['msg_from'] = get_user_common_info(d.get('msg_from'))
        result['detail'] = d

    elif notice.is_group_msg():
        d = notice.group_message_detail_to_dict()
        if d.get('msg_from') is not None:
            result['msg_from'] = get_user_common_info(d.get('msg_from'))

        group_id = d['group_id']

        try:
            group = ccnet_api.get_group(group_id)
        except Exception as e:
            logger.error(e)
            return None

        result['detail'] = d
        if group is None:
            notice.delete()
            return None
        result['detail']['group_name'] = group.group_name

    elif notice.is_file_uploaded_msg():
        try:
            d = json.loads(notice.detail)
        except Exception as e:
            logger.error(e)
            return None

        result['detail'] = d
        repo_id = d['repo_id']
        repo = syncwerk_api.get_repo(repo_id)
        if repo:
            if d['uploaded_to'] == '/':
                name = repo.name
            else:
                name = os.path.basename(d['uploaded_to'])
            result['detail']['name'] = name
        else:
            return None

    elif notice.is_repo_share_msg():
        try:
            d = json.loads(notice.detail)
        except Exception as e:
            logger.error(e)
            return None

        repo_id = d['repo_id']

        repo = syncwerk_api.get_repo(repo_id)
        if repo is None:
            notice.delete()
            return None

        result['msg_from'] = get_user_common_info(d['share_from'])
        result['detail'] = d
        result['detail']['repo_name'] = repo.name

    elif notice.is_repo_share_to_group_msg():
        try:
            d = json.loads(notice.detail)
        except Exception as e:
            logger.error(e)
            return None

        repo_id = d['repo_id']
        group_id = d['group_id']

        try:
            repo = syncwerk_api.get_repo(repo_id)
            group = ccnet_api.get_group(group_id)
        except Exception as e:
            logger.error(e)
            return None

        if not repo or not group:
            notice.delete()
            return None

        result['msg_from'] = get_user_common_info(d['share_from'])
        result['detail'] = d
        result['detail']['repo_name'] = repo.name
        result['detail']['group_name'] = group.group_name

    elif notice.is_group_join_request():
        try:
            d = json.loads(notice.detail)
        except Exception as e:
            logger.error(e)
            return None

        group_id = d['group_id']
        group = ccnet_api.get_group(group_id)
        if group is None:
            notice.delete()
            return None

        result['msg_from'] = get_user_common_info(d['username'])
        result['detail'] = d
        result['detail']['group_name'] = group.group_name

    elif notice.is_add_user_to_group():
        try:
            d = json.loads(notice.detail)
        except Exception as e:
            logger.error(e)
            return None

        group_id = d['group_id']
        group = ccnet_api.get_group(group_id)
        if group is None:
            notice.delete()
            return None

        result['msg_from'] = get_user_common_info(d['group_staff'])
        result['detail'] = d
        result['detail']['group_name'] = group.group_name

    elif notice.is_file_comment_msg():
        try:
            d = json.loads(notice.detail)
        except Exception as e:
            logger.error(e)
            return None

        repo_id = d['repo_id']
        file_path = d['file_path']

        repo = syncwerk_api.get_repo(repo_id)
        if repo is None or not syncwerk_api.get_file_id_by_path(repo.id,
                                                            file_path):
            notice.delete()
            return None

        result['msg_from'] = get_user_common_info(d['author'])
        result['detail'] = d
        result['detail']['file_name'] = os.path.basename(file_path)

    else:
        pass

    return result


class NotificationCountView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get unread notification count',
        operation_description='Get the number of unread notifications',
        tags=['notification'],
        responses={
            200: openapi.Response(
                description='Successfully retrieve result.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "unseen_count": 5,
                        }
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
                        "detail": "Internal server error"
                    }
                }
            ),
        }
    )
    def get(self, request):
        result = {}

        username = request.user.username
        cache_key = get_cache_key_of_unseen_notifications(username)

        count_from_cache = cache.get(cache_key, None)

        # for case of count value is `0`
        if count_from_cache is not None:
            result['unseen_count'] = count_from_cache
        else:
            count_from_db = UserNotification.objects.count_unseen_user_notifications(username)
            result['unseen_count'] = count_from_db

            # set cache
            cache.set(cache_key, count_from_db)

        # return Response(result)
        return api_response(data=result)

class NotificationTopView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get top notifications',
        operation_description='''Get top notifications following the below logics: \n
- If unseen notices > 5, return all unseen notices.
- If unseen notices = 0, return last 5 notices.
- Otherwise return all unseen notices, plus some seen notices to make the sum equal to 5.
        ''',
        tags=['notification'],
        responses={
            200: openapi.Response(
                description='Successfully retrieve result.',
                examples={
                    'application/json': {
                    "message": "",
                    "data": {
                        "notifications": [
                            {
                                "msg_from": {
                                    "login_id": "",
                                    "avatar_size": 80,
                                    "name": "test10@grr.la",
                                    "nick_name": "test10@grr.la",
                                    "is_default_avatar": True,
                                    "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                                    "email": "test10@grr.la"
                                },
                                "msg_type": "repo_share_to_group",
                                "timestamp": "2019-02-12T09:24:04",
                                "detail": {
                                    "repo_id": "de138e58-9e0e-4e79-907c-f2a8ad003f5e",
                                    "share_from": "test10@grr.la",
                                    "org_id": None,
                                    "group_name": "1",
                                    "path": "/",
                                    "group_id": 1,
                                    "repo_name": "share to group admin"
                                },
                                "mtime_relative": "<time datetime=\"2019-02-12T09:24:04\" is=\"relative-time\" title=\"Tue, 12 Feb 2019 09:24:04 +0000\" >2 days ago</time>",
                                "to_user": "admin@alpha.syncwerk.com",
                                "default_avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                                "seen": True,
                                "id": 8
                            },
                            {
                                "msg_from": {
                                    "login_id": "",
                                    "avatar_size": 80,
                                    "name": "test10@grr.la",
                                    "nick_name": "test10@grr.la",
                                    "is_default_avatar": True,
                                    "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                                    "email": "test10@grr.la"
                                },
                                "msg_type": "repo_share",
                                "timestamp": "2019-02-11T10:26:53",
                                "detail": {
                                    "path": "/",
                                    "repo_id": "b50d8399-dafb-4682-950f-a35142ed9169",
                                    "org_id": None,
                                    "share_from": "test10@grr.la",
                                    "repo_name": "this folder will be corrupted"
                                },
                                "mtime_relative": "<time datetime=\"2019-02-11T10:26:53\" is=\"relative-time\" title=\"Mon, 11 Feb 2019 10:26:53 +0000\" >3 days ago</time>",
                                "to_user": "admin@alpha.syncwerk.com",
                                "default_avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                                "seen": True,
                                "id": 7
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
                        "detail": "Token invalid"
                    }
                }
            ),
            500: openapi.Response(
                description='Internal server error',
                examples={
                    'application/json': {
                        "detail": "Internal server error"
                    }
                }
            ),
        }
    )
    def get(self, request):

        username = request.user.username

        result_notices = []
        unseen_notices = []
        seen_notices = []

        list_num = 5
        unseen_num = UserNotification.objects.count_unseen_user_notifications(username)
        if unseen_num == 0:
            seen_notices = UserNotification.objects.get_user_notifications(
                username)[:list_num]
        elif unseen_num > list_num:
            unseen_notices = UserNotification.objects.get_user_notifications(
                username, seen=False)
        else:
            unseen_notices = UserNotification.objects.get_user_notifications(
                username, seen=False)
            seen_notices = UserNotification.objects.get_user_notifications(
                username, seen=True)[:list_num - unseen_num]

        result_notices += unseen_notices
        result_notices += seen_notices

        # Add 'msg_from' or 'default_avatar_url' to notice.
        # result_notices = add_notice_from_info(result_notices)
        res = []
        for notice in result_notices:
            info = get_notice_info(notice)
            if info is not None:
                res.append(get_notice_info(notice))
            # res.append({
            #     'to_user': notice.to_user,
            #     'msg_type': notice.msg_type,
            #     'detail': notice.detail
            # })
        result = { "notifications": res }

        # return Response(result)
        return api_response(data=result)


class NotificationsView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get user notifications',
        operation_description='Get all user notification with pagination support',
        tags=['notification'],
        manual_parameters=[
            openapi.Parameter(
                name='offset',
                in_="query",
                type='string',
                description='offset. Will be 0 by default.',
            ),
            openapi.Parameter(
                name='limit',
                in_="query",
                type='string',
                description='limit. Will be 0 by default',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Notifications retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "notifications": [
                                {
                                    "msg_from": {
                                        "login_id": "",
                                        "avatar_size": 80,
                                        "name": "test10@grr.la",
                                        "nick_name": "test10@grr.la",
                                        "is_default_avatar": True,
                                        "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                                        "email": "test10@grr.la"
                                    },
                                    "msg_type": "repo_share_to_group",
                                    "timestamp": "2019-02-12T09:24:04",
                                    "detail": {
                                        "repo_id": "de138e58-9e0e-4e79-907c-f2a8ad003f5e",
                                        "share_from": "test10@grr.la",
                                        "org_id": None,
                                        "group_name": "1",
                                        "path": "/",
                                        "group_id": 1,
                                        "repo_name": "share to group admin"
                                    },
                                    "mtime_relative": "<time datetime=\"2019-02-12T09:24:04\" is=\"relative-time\" title=\"Tue, 12 Feb 2019 09:24:04 +0000\" >2 days ago</time>",
                                    "to_user": "admin@alpha.syncwerk.com",
                                    "default_avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                                    "seen": True,
                                    "id": 8
                                },
                                {
                                    "msg_from": {
                                        "login_id": "",
                                        "avatar_size": 80,
                                        "name": "test10@grr.la",
                                        "nick_name": "test10@grr.la",
                                        "is_default_avatar": True,
                                        "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                                        "email": "test10@grr.la"
                                    },
                                    "msg_type": "repo_share",
                                    "timestamp": "2019-02-11T10:26:53",
                                    "detail": {
                                        "path": "/",
                                        "repo_id": "b50d8399-dafb-4682-950f-a35142ed9169",
                                        "org_id": None,
                                        "share_from": "test10@grr.la",
                                        "repo_name": "this folder will be corrupted"
                                    },
                                    "mtime_relative": "<time datetime=\"2019-02-11T10:26:53\" is=\"relative-time\" title=\"Mon, 11 Feb 2019 10:26:53 +0000\" >3 days ago</time>",
                                    "to_user": "admin@alpha.syncwerk.com",
                                    "default_avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                                    "seen": True,
                                    "id": 7
                                }
                            ],
                            "total": 2
                        }
                    }
                },
            ),
            401: openapi.Response(
                description='Token invalid.',
                examples={
                    'application/json': {
                        "detail": "Token invalid"
                    }
                }
            ),
        }
    )
    def get(self, request):

        username = request.user.username
        offset = int(request.GET.get('offset', 0))
        limit = int(request.GET.get('limit', 25))

        all_notices = UserNotification.objects.get_user_notifications(username)
        notices = all_notices[offset : offset+limit-1]

        # Add 'msg_from' or 'default_avatar_url' to notice.
        res = []
        for notice in notices:
            info = get_notice_info(notice)
            if info is not None:
                res.append(get_notice_info(notice))

        resp = {
            'notifications': res,
            'total': len(all_notices),
        }
        return api_response(data=resp)


    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Mark all notifications as read',
        operation_description='Mark all notifications as read',
        tags=['notification'],
        responses={
            200: openapi.Response(
                description='All notification marked as read.',
                examples={
                    'application/json': {
                        "message": "All notifications marked read.",
                        "data": None
                    }
                },
            ),
            401: openapi.Response(
                description='Token invalid.',
                examples={
                    'application/json': {
                        "detail": "Token invalid"
                    }
                }
            ),
        }
    )
    def put(self, request):
        username = request.user.username
        unseen_notices = UserNotification.objects.get_user_notifications(username,
                                                                         seen=False)
        for notice in unseen_notices:
            notice.seen = True
            notice.save()

        cache_key = get_cache_key_of_unseen_notifications(username)
        cache.delete(cache_key)

        # return Response({'success': True})
        return api_response(msg=_("All notifications marked read."))

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Remove all notifications',
        operation_description='Remove all notifications',
        tags=['notification'],
        responses={
            200: openapi.Response(
                description='All notifications are removed.',
                examples={
                    'application/json': {
                        "message": "Remove all notification successfully.",
                        "data": None
                    }
                },
            ),
            401: openapi.Response(
                description='Token invalid.',
                examples={
                    'application/json': {
                        "detail": "Token invalid"
                    }
                }
            ),
        }
    )
    def delete(self, request):
        UserNotification.objects.remove_user_notifications(request.user.username)
        return api_response(msg=_("Successfully cleaned all notifications."))


class NotificationView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Mark a notification as read',
        operation_description='Mark a specific notification as read',
        tags=['notification'],
        manual_parameters=[
            openapi.Parameter(
                name="notification_id",
                in_="formData",
                type='string',
                description='id of the notification which will be marked as read.'
            )
        ],
        responses={
            200: openapi.Response(
                description='Notification marked as read.',
                examples={
                    'application/json': {
                        "message": "Notification marked as read.",
                        "data": None
                    }
                },
            ),
            401: openapi.Response(
                description='Token invalid.',
                examples={
                    'application/json': {
                        "detail": "Token invalid"
                    }
                }
            ),
            401: openapi.Response(
                description='Notification not found.',
                examples={
                    'application/json': {
                        "message": "Notification not found",
                        "data": "",
                    }
                }
            ),
        }
    )
    def put(self, request):
        notice_id = request.data.get('notification_id')

        try:
            notice = UserNotification.objects.get(id=notice_id)
        except UserNotification.DoesNotExist as e:
            logger.error(e)
            return api_error(status.HTTP_404_NOT_FOUND, 'Notification not found.')

        if not notice.seen:
            notice.seen = True
            notice.save()

        username = request.user.username
        cache_key = get_cache_key_of_unseen_notifications(username)
        cache.delete(cache_key)

        # return Response({'success': True})
        return api_response()
