# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from synserv import syncwerk_api, ccnet_api

from restapi.group.utils import get_group_member_info, is_group_member
from restapi.avatar.settings import AVATAR_DEFAULT_SIZE
from restapi.base.accounts import User

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class AdminGroupMembers(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - List group members',
        operation_description='''List group members''',
        tags=['admin-groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='id of the group',
            ),
            openapi.Parameter(
                name='avatar_size',
                in_="query",
                type='string',
                description='size of user avatar thumbnail',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Group members list retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "group_id": 1,
                            "members": [
                                {
                                    "login_id": "",
                                    "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                                    "contact_email": "test10@grr.la",
                                    "name": "test10@grr.la",
                                    "is_admin": False,
                                    "role": "Member",
                                    "group_id": 1,
                                    "email": "test10@grr.la",
                                    "is_default_avatar": True
                                },
                                {
                                    "login_id": "",
                                    "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                                    "contact_email": "admin@alpha.syncwerk.com",
                                    "name": "admin",
                                    "is_admin": True,
                                    "role": "Owner",
                                    "group_id": 1,
                                    "email": "admin@alpha.syncwerk.com",
                                    "is_default_avatar": False
                                }
                            ],
                            "group_name": "1"
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
            404: openapi.Response(
                description='Group not found',
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
    def get(self, request, group_id, format=None):
        group_id = int(group_id)
        group = ccnet_api.get_group(group_id)
        if not group:
            error_msg = 'Group %d not found.' % group_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        try:
            avatar_size = int(request.GET.get('avatar_size',
                AVATAR_DEFAULT_SIZE))
        except ValueError:
            avatar_size = AVATAR_DEFAULT_SIZE

        try:
            members = ccnet_api.get_group_members(group_id)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        group_members_info = []
        for m in members:
            member_info = get_group_member_info(request, group_id, m.user_name, avatar_size)
            group_members_info.append(member_info)

        group_members = {
            'group_id': group_id,
            'group_name': group.group_name,
            'members': group_members_info
        }

        # return Response(group_members)
        return api_response(data=group_members)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Add group members',
        operation_description='''Add group members''',
        tags=['admin-groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='id of the group',
            ),
            openapi.Parameter(
                name='email',
                in_="formData",
                type='string',
                description='email of the user to be added to the group. Provide multiple of this parameter for adding multiple users to the group at once.',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Group members added successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "failed": [],
                            "success": [
                                {
                                    "login_id": "",
                                    "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                                    "contact_email": "mtamlett16@github.io",
                                    "name": "Myra Tamlett",
                                    "is_admin": False,
                                    "role": "Member",
                                    "group_id": 1,
                                    "email": "mtamlett16@github.io",
                                    "is_default_avatar": True
                                }
                            ]
                        }
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
            404: openapi.Response(
                description='Group / user not found',
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
    def post(self, request, group_id):
        # argument check
        group_id = int(group_id)
        group = ccnet_api.get_group(group_id)
        if not group:
            error_msg = 'Group %d not found.' % group_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        emails = request.POST.getlist('email', '')
        if not emails:
            error_msg = 'Email invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        result = {}
        result['failed'] = []
        result['success'] = []
        emails_need_add = []

        for email in emails:
            try:
                User.objects.get(email=email)
            except User.DoesNotExist:
                result['failed'].append({
                    'email': email,
                    'error_msg': 'User %s not found.' % email
                    })
                continue

            if ccnet_api.is_group_user(group_id, email):
                result['failed'].append({
                    'email': email,
                    'error_msg': 'User %s is already a group member.' % email
                    })
                continue

            emails_need_add.append(email)

        # Add user to group.
        for email in emails_need_add:
            try:
                ccnet_api.group_add_member(group_id, group.creator_name, email)
                member_info = get_group_member_info(request, group_id, email)
                result['success'].append(member_info)
            except Exception as e:
                logger.error(e)
                result['failed'].append({
                    'email': email,
                    'error_msg': 'Internal Server Error'
                    })

        # return Response(result)
        return api_response(data=result)


class AdminGroupMember(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Update group member role',
        operation_description='''Update group member role''',
        tags=['admin-groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='id of the group',
            ),
            openapi.Parameter(
                name='email',
                in_="path",
                type='string',
                description='email of the user.',
                required=True,
            ),
            openapi.Parameter(
                name='is_admin',
                in_="formData",
                type='string',
                description='"true" or "false". "true" will set the user as group admin, "false" will revoke the user group admin role',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Group member role updated successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "login_id": "",
                            "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                            "contact_email": "mtamlett16@github.io",
                            "name": "Myra Tamlett",
                            "is_admin": True,
                            "role": "Admin",
                            "group_id": 1,
                            "email": "mtamlett16@github.io",
                            "is_default_avatar": True
                        }
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
            404: openapi.Response(
                description='Group / user not found',
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
    def put(self, request, group_id, email, format=None):
        
        # argument check
        group_id = int(group_id)
        group = ccnet_api.get_group(group_id)
        if not group:
            error_msg = 'Group %d not found.' % group_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        try:
            User.objects.get(email=email)
        except User.DoesNotExist:
            error_msg = 'User %s not found.' % email
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        try:
            if not is_group_member(group_id, email):
                error_msg = 'Email %s invalid.' % email
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        is_admin = request.data.get('is_admin', '')
        try:
            # set/unset a specific group member as admin
            if is_admin.lower() == 'true':
                ccnet_api.group_set_admin(group_id, email)
            elif is_admin.lower() == 'false':
                ccnet_api.group_unset_admin(group_id, email)
            else:
                error_msg = 'is_admin invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        member_info = get_group_member_info(request, group_id, email)
        # return Response(member_info)
        return api_response(data=member_info)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Remove member from group',
        operation_description='''Remove member from group''',
        tags=['admin-groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='id of the group',
            ),
            openapi.Parameter(
                name='email',
                in_="path",
                type='string',
                description='email of the user.',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='Group member removed successfully',
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
            404: openapi.Response(
                description='Group / user not found',
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
    def delete(self, request, group_id, email, format=None):
        # argument check
        group_id = int(group_id)
        group = ccnet_api.get_group(group_id)
        if not group:
            error_msg = 'Group %d not found.' % group_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        try:
            User.objects.get(email=email)
        except User.DoesNotExist:
            error_msg = 'User %s not found.' % email
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # delete member from group
        try:
            if not is_group_member(group_id, email):
                # return Response({'success': True})
                return api_response()
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if group.creator_name == email:
            error_msg = '%s is group owner, can not be removed.' % email
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        try:
            ccnet_api.group_remove_member(group_id, group.creator_name, email)
            # remove repo-group share info of all 'email' owned repos
            syncwerk_api.remove_group_repos_by_owner(group_id, email)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # return Response({'success': True})
        return api_response()
