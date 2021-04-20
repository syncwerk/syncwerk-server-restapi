# Copyright (c) 2012-2016 Seafile Ltd.
import json

from django.core.paginator import EmptyPage, InvalidPage
from django.http import HttpResponse

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.permissions import IsGroupMember
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response, get_user_common_info
from restapi.group.models import GroupMessage
from restapi.group.signals import grpmsg_added 
from restapi.utils.paginator import Paginator
from restapi.utils.timeutils import datetime_to_isoformat_timestr
from restapi.avatar.settings import AVATAR_DEFAULT_SIZE
from .utils import api_check_group

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

json_content_type = 'application/json; charset=utf-8'

class GroupDiscussions(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, IsGroupMember)
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get group discussions',
        operation_description='''List all group discussions''',
        tags=['groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='group id',
            ),
            openapi.Parameter(
                name='avatar_size',
                in_="query",
                type='string',
                description='avatar size',
            ),
            openapi.Parameter(
                name='page',
                in_="query",
                type='string',
                description='page. Default to 0',
            ),
            openapi.Parameter(
                name='per_page',
                in_="query",
                type='string',
                description='number of items per page, default to 20',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Discussion list retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "current_page": 1,
                            "page_num": 1,
                            "msgs": [
                                {
                                    "content": "dddd",
                                    "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                                    "user_login_id": "",
                                    "created_at": "2019-02-19T08:33:25+00:00",
                                    "group_id": 3,
                                    "user_name": "admin",
                                    "id": 1,
                                    "user_email": "admin@alpha.syncwerk.com"
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
                        "detail": "Token invalid",
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
    @api_check_group
    def get(self, request, group_id, format=None):
        
        # 1 <= page, defaults to 1
        try:
            page = int(request.GET.get('page', '1'))
        except ValueError:
            page = 1
        if page < 0:
            page = 1

        # 1 <= per_page <= 100, defaults to 20
        try:
            per_page = int(request.GET.get('per_page', '20'))
        except ValueError:
            per_page = 20
        if per_page < 1 or per_page > 100:
            per_page = 20

        paginator = Paginator(GroupMessage.objects.filter(
            group_id=group_id).order_by('-timestamp'), per_page)

        try:
            group_msgs = paginator.page(page)
        except (EmptyPage, InvalidPage):
            group_msgs = paginator.page(paginator.num_pages)

        try:
            avatar_size = int(request.GET.get('avatar_size',
                    AVATAR_DEFAULT_SIZE))
        except ValueError:
            avatar_size = AVATAR_DEFAULT_SIZE

        msgs = []
        for msg in group_msgs:
            info = get_user_common_info(msg.from_email, avatar_size)
            isoformat_timestr = datetime_to_isoformat_timestr(msg.timestamp)
            msgs.append({
                "id": msg.pk,
                "group_id": group_id,
                "user_name": info["name"],
                "user_email": info["email"],
                "user_login_id": info["login_id"],
                "avatar_url": request.build_absolute_uri(info["avatar_url"]),
                "content": msg.message,
                "created_at": isoformat_timestr
            })

        # return HttpResponse(json.dumps({
        #     "msgs": msgs,
        #     "current_page": page,
        #     "page_num": paginator.num_pages,
        #     }), status=200, content_type=json_content_type)
        resp = {
            "msgs": msgs,
            "current_page": page,
            "page_num": paginator.num_pages,
        }
        return api_response(data=resp)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Post a group discussion',
        operation_description='''Post a group discussion. Only group members can do this.''',
        tags=['groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='group id',
            ),
            openapi.Parameter(
                name='avatar_size',
                in_="formData",
                type='string',
                description='avatar size',
            ),
            openapi.Parameter(
                name='content',
                in_="query",
                type='string',
                description='content to post',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Discussion posted successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "content": "dddd",
                            "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                            "user_login_id": "",
                            "created_at": "2019-02-19T08:33:25+00:00",
                            "group_id": 3,
                            "user_name": "admin",
                            "id": 1,
                            "user_email": "admin@alpha.syncwerk.com"
                        }
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
    @api_check_group
    def post(self, request, group_id, format=None):
        
        content = request.data.get('content', '')
        if not content:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Content can not be empty.')

        try:
            avatar_size = int(request.data.get('avatar_size',
                            AVATAR_DEFAULT_SIZE))
        except ValueError:
            avatar_size = AVATAR_DEFAULT_SIZE

        username = request.user.username
        msg = GroupMessage.objects.create(group_id=group_id,
                                              from_email=username,
                                              message=content)
        # send signal
        grpmsg_added.send(sender=GroupMessage, group_id=group_id,
                from_email=username, message=content)

        info = get_user_common_info(username, avatar_size)

        isoformat_timestr = datetime_to_isoformat_timestr(msg.timestamp)
        # return Response({
        #     "id": msg.pk,
        #     "group_id": group_id,
        #     "user_name": info["name"],
        #     "user_email": info["email"],
        #     "user_login_id": info["login_id"],
        #     "avatar_url": request.build_absolute_uri(info["avatar_url"]),
        #     "content": msg.message,
        #     "created_at": isoformat_timestr
        # }, status=201)
        resp = {
            "id": msg.pk,
            "group_id": group_id,
            "user_name": info["name"],
            "user_email": info["email"],
            "user_login_id": info["login_id"],
            "avatar_url": request.build_absolute_uri(info["avatar_url"]),
            "content": msg.message,
            "created_at": isoformat_timestr
        }
        return api_response(code=status.HTTP_201_CREATED, data=resp)
