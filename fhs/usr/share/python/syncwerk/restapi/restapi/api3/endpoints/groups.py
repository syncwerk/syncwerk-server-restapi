# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from django.utils.translation import ugettext as _
from django.template.defaultfilters import filesizeformat

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from datetime import datetime
from constance import config

import synserv
from synserv import syncwerk_api, ccnet_api
from pyrpcsyncwerk import RpcsyncwerkError

from restapi.api3.utils import api_error, api_response, get_user_common_info
from restapi.api3.utils.group import get_group_member_info
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.avatar.settings import GROUP_AVATAR_DEFAULT_SIZE
from restapi.avatar.templatetags.group_avatar_tags import api_grp_avatar_url, \
    get_default_group_avatar_url
from restapi.utils import is_org_context, is_valid_username
from restapi.utils.timeutils import timestamp_to_isoformat_timestr
from restapi.group.utils import validate_group_name, check_group_name_conflict, \
    is_group_member, is_group_admin, is_group_owner, is_group_admin_or_owner
from restapi.group.views import remove_group_common
from restapi.base.templatetags.restapi_tags import email2nickname, \
    translate_restapi_time
from restapi.views.modules import is_wiki_mod_enabled_for_group, \
    enable_mod_for_group, disable_mod_for_group, MOD_GROUP_WIKI

from .utils import api_check_group

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema
from restapi.api3.models import BBBPrivateSetting, MeetingRoomShare

def get_group_admins(group_id):
    members = synserv.get_group_members(group_id)
    admin_members = filter(lambda m: m.is_staff, members)

    admins = []
    for u in admin_members:
        admins.append(u.user_name)

    return admins

def get_group_info(request, group_id, avatar_size=GROUP_AVATAR_DEFAULT_SIZE):

    org_id = None
    if is_org_context(request):
        org_id = request.user.org.org_id

    group = synserv.get_group(group_id)

    logger.debug("Group info = %s" % group.__dict__)

    try:
        with_repos = int(request.GET.get('with_repos', 0))
    except ValueError:
        with_repos = 0

    if with_repos not in (0, 1):
        error_msg = 'with_repos invalid.'
        return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

    try:
        avatar_url, is_default, date_uploaded = api_grp_avatar_url(group.id, avatar_size)
    except Exception as e:
        logger.error(e)
        avatar_url = get_default_group_avatar_url()

    isoformat_timestr = timestamp_to_isoformat_timestr(group.timestamp)
    try:
        members = ccnet_api.get_group_members(group_id)
    except RpcsyncwerkError as e:
        return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Internal Server Error')

    group_info = {
        "id": group.id,
        "name": group.group_name,
        "owner": get_user_common_info(group.creator_name),
        "created_at": isoformat_timestr,
        "avatar_url": request.build_absolute_uri(avatar_url),
        "admins": get_group_admins(group.id),
        "wiki_enabled": is_wiki_mod_enabled_for_group(group_id),
        "members_count": len(members)
    }

    if org_id:
        group_repos = syncwerk_api.get_org_group_repos(org_id, group_id)
    else:
        group_repos = syncwerk_api.get_repos_by_group(group_id)

    repos = []
    for r in group_repos:
        repo = {
            "id": r.id,
            "name": r.name,
            "size": r.size,
            "size_formatted": filesizeformat(r.size),
            "mtime": r.last_modified,
            "mtime_relative": translate_restapi_time(r.last_modified),
            "encrypted": r.encrypted,
            "permission": r.permission,
            "owner": r.user,
            "owner_name": email2nickname(r.user),
        }
        repos.append(repo)

    if with_repos:
        group_info['repos'] = repos

    group_info['repos_count'] = len(group_repos)

    group_info['members'] = []
    for m in members[:4]:
        member_info = get_group_member_info(
            request, group_id, m.user_name, avatar_size)
        group_info['members'].append(member_info)

    return group_info


class Groups(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser,)

    def _can_add_group(self, request):
        return request.user.permissions.can_add_group()

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='List groups',
        operation_description='''List all groups that the current user is in''',
        tags=['groups'],
        manual_parameters=[
            openapi.Parameter(
                name='avatar_size',
                in_="query",
                type='string',
                description='avatar size',
            ),
        ],
        responses={
            200: openapi.Response(
                description='List retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            {
                                "admins": [
                                    "admin@alpha.syncwerk.com"
                                ],
                                "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/groups/default.png",
                                "members_count": 1,
                                "name": "Group 3",
                                "members": [
                                    {
                                        "login_id": "",
                                        "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/48/af6635893c2728a0841c74cd0672d93a.png",
                                        "contact_email": "admin@alpha.syncwerk.com",
                                        "name": "admin",
                                        "is_admin": True,
                                        "role": "Owner",
                                        "group_id": 4,
                                        "email": "admin@alpha.syncwerk.com",
                                        "is_default_avatar": False
                                    }
                                ],
                                "owner": {
                                    "login_id": "",
                                    "avatar_size": 80,
                                    "name": "admin",
                                    "nick_name": None,
                                    "is_default_avatar": False,
                                    "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                                    "email": "admin@alpha.syncwerk.com"
                                },
                                "repos_count": 0,
                                "created_at": "2019-02-15T08:17:22+00:00",
                                "wiki_enabled": False,
                                "id": 4
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

        org_id = None
        username = request.user.username
        if is_org_context(request):
            org_id = request.user.org.org_id
            user_groups = synserv.get_org_groups_by_user(org_id, username)
        else:
            user_groups = synserv.get_personal_groups_by_user(username)

        try:
            avatar_size = int(request.GET.get('avatar_size', GROUP_AVATAR_DEFAULT_SIZE))
        except ValueError:
            avatar_size = GROUP_AVATAR_DEFAULT_SIZE

        groups = []
        for g in user_groups:
            group_info = get_group_info(request, g.id , avatar_size)
            groups.append(group_info)

        # return Response(groups)
        return api_response(data=groups)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Create group',
        operation_description='''Create a new group''',
        tags=['groups'],
        manual_parameters=[
            openapi.Parameter(
                name='name',
                in_='formData',
                type='string',
                description='name of the new group',
                required=True,
            ),
        ],
        responses={
            201: openapi.Response(
                description='New group created successfully.',
                examples={
                    'application/json': {
                        "message": "A group was created successfully",
                        "data": {
                            "admins": [
                                "admin@alpha.syncwerk.com"
                            ],
                            "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/groups/default.png",
                            "members_count": 1,
                            "name": "dddd",
                            "members": [
                                {
                                    "login_id": "",
                                    "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/48/af6635893c2728a0841c74cd0672d93a.png",
                                    "contact_email": "admin@alpha.syncwerk.com",
                                    "name": "admin",
                                    "is_admin": True,
                                    "role": "Owner",
                                    "group_id": 5,
                                    "email": "admin@alpha.syncwerk.com",
                                    "is_default_avatar": False
                                }
                            ],
                            "owner": {
                                "login_id": "",
                                "avatar_size": 80,
                                "name": "admin",
                                "nick_name": None,
                                "is_default_avatar": False,
                                "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                                "email": "admin@alpha.syncwerk.com"
                            },
                            "repos_count": 0,
                            "created_at": "2019-02-19T07:55:33+00:00",
                            "wiki_enabled": False,
                            "id": 5
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
        
        if not self._can_add_group(request):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        username = request.user.username
        group_name = request.data.get('name', '')
        group_name = group_name.strip()

        # Check whether group name is validate.
        if not validate_group_name(group_name):
            error_msg = _(u'Group name can only contain letters, numbers, blank, hyphen or underscore')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # Check whether group name is duplicated.
        if check_group_name_conflict(request, group_name):
            error_msg = _(u'There is already a group with that name.')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # create group.
        try:
            if is_org_context(request):
                org_id = request.user.org.org_id
                group_id = synserv.ccnet_threaded_rpc.create_org_group(org_id,
                                                                       group_name,
                                                                       username)
            else:
                group_id = synserv.ccnet_threaded_rpc.create_group(group_name,
                                                                   username)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # get info of new group
        group_info = get_group_info(request, group_id)

        # return Response(group_info, status=status.HTTP_201_CREATED)
        return api_response(code=status.HTTP_201_CREATED, msg=_('A group was created successfully'), data=group_info)


class Group(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser,)
    
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get group info',
        operation_description='''Get info of a group''',
        tags=['groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='id of the group',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Info retrieved successfully.',
                examples={
                    'application/json': {
                    "message": "",
                    "data": {
                        "admins": [
                            "admin@alpha.syncwerk.com"
                        ],
                        "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/groups/default.png",
                        "members_count": 2,
                        "name": "3",
                        "members": [
                            {
                                "login_id": "",
                                "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                                "contact_email": "test1@grr.la",
                                "name": "test1@grr.la",
                                "is_admin": False,
                                "role": "Member",
                                "group_id": 3,
                                "email": "test1@grr.la",
                                "is_default_avatar": True
                            },
                            {
                                "login_id": "",
                                "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/48/af6635893c2728a0841c74cd0672d93a.png",
                                "contact_email": "admin@alpha.syncwerk.com",
                                "name": "admin",
                                "is_admin": True,
                                "role": "Owner",
                                "group_id": 3,
                                "email": "admin@alpha.syncwerk.com",
                                "is_default_avatar": False
                            }
                        ],
                        "owner": {
                            "login_id": "",
                            "avatar_size": 80,
                            "name": "admin",
                            "nick_name": None,
                            "is_default_avatar": False,
                            "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/80/af6635893c2728a0841c74cd0672d93a.png",
                            "email": "admin@alpha.syncwerk.com"
                        },
                        "repos_count": 1,
                        "created_at": "2019-01-24T03:41:48+00:00",
                        "wiki_enabled": False,
                        "id": 3
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
    def get(self, request, group_id):

        try:
            # only group member can get info of a group
            if not is_group_member(group_id, request.user.username):
                error_msg = 'Permission denied.'
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        try:
            avatar_size = int(request.GET.get('avatar_size', GROUP_AVATAR_DEFAULT_SIZE))
        except ValueError:
            avatar_size = GROUP_AVATAR_DEFAULT_SIZE

        group_info = get_group_info(request, group_id, avatar_size)

        # check permission
        permissions = {
            "edit_bbb_config": True if request.user.email == group_info["owner"]["email"] and config.BBB_ALLOW_GROUPS_PRIVATE_SERVER == 1 else False
        }

        group_info["permissions"] = permissions

        # return Response(group_info)
        return api_response(data=group_info)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Rename / transfer group',
        operation_description='''Rename or transfer a specific group''',
        tags=['groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='id of the group',
            ),
            openapi.Parameter(
                name='name',
                in_="formData",
                type='string',
                description='if you want to rename the group, set the new name and do not provide anything else',
            ),
            openapi.Parameter(
                name='owner',
                in_="formData",
                type='string',
                description='if you want to transfer the group, set the email of the new owner here and do not provide anything else',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Group rename / transfer successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "admins": [
                                "mtamlett16@github.io"
                            ],
                            "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/groups/default.png",
                            "members_count": 2,
                            "name": "ddddddd",
                            "members": [
                                {
                                    "login_id": "",
                                    "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                                    "contact_email": "mtamlett16@github.io",
                                    "name": "Myra Tamlett",
                                    "is_admin": True,
                                    "role": "Owner",
                                    "group_id": 5,
                                    "email": "mtamlett16@github.io",
                                    "is_default_avatar": True
                                },
                                {
                                    "login_id": "",
                                    "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/0/1/58c19b1111725570594169b44c26c1/resized/48/af6635893c2728a0841c74cd0672d93a.png",
                                    "contact_email": "admin@alpha.syncwerk.com",
                                    "name": "admin",
                                    "is_admin": False,
                                    "role": "Member",
                                    "group_id": 5,
                                    "email": "admin@alpha.syncwerk.com",
                                    "is_default_avatar": False
                                }
                            ],
                            "owner": {
                                "login_id": "",
                                "avatar_size": 80,
                                "name": "Myra Tamlett",
                                "nick_name": "Myra Tamlett",
                                "is_default_avatar": True,
                                "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                                "email": "mtamlett16@github.io"
                            },
                            "repos_count": 0,
                            "created_at": "2019-02-19T07:55:33+00:00",
                            "wiki_enabled": False,
                            "id": 5
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
    @api_check_group
    def put(self, request, group_id):

        username = request.user.username
        new_group_name = request.data.get('name', None)
        # rename a group
        if new_group_name:
            try:
                # only group owner/admin can rename a group
                if not is_group_admin_or_owner(group_id, username):
                    error_msg = 'Permission denied.'
                    return api_error(status.HTTP_403_FORBIDDEN, error_msg)

                # Check whether group name is validate.
                if not validate_group_name(new_group_name):
                    error_msg = _(u'Group name can only contain letters, numbers, blank, hyphen or underscore')
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

                # Check whether group name is duplicated.
                if check_group_name_conflict(request, new_group_name):
                    error_msg = _(u'There is already a group with that name.')
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

                synserv.ccnet_threaded_rpc.set_group_name(group_id, new_group_name)

            except RpcsyncwerkError as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        new_owner = request.data.get('owner', None)
        # transfer a group
        if new_owner:
            try:
                # only group owner can transfer a group
                if not is_group_owner(group_id, username):
                    error_msg = 'Permission denied.'
                    return api_error(status.HTTP_403_FORBIDDEN, error_msg)

                # augument check
                if not is_valid_username(new_owner):
                    error_msg = 'Email %s invalid.' % new_owner
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

                if is_group_owner(group_id, new_owner):
                    error_msg = _(u'User %s is already group owner.') % new_owner
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

                # transfer a group
                if not is_group_member(group_id, new_owner):
                    ccnet_api.group_add_member(group_id, username, new_owner)

                if not is_group_admin(group_id, new_owner):
                    ccnet_api.group_set_admin(group_id, new_owner)

                ccnet_api.set_group_creator(group_id, new_owner)
                ccnet_api.group_unset_admin(group_id, username)

            except RpcsyncwerkError as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        wiki_enabled = request.data.get('wiki_enabled', None)
        # turn on/off group wiki
        if wiki_enabled:
            try:
                # only group owner/admin can turn on a group wiki
                if not is_group_admin_or_owner(group_id, username):
                    error_msg = 'Permission denied.'
                    return api_error(status.HTTP_403_FORBIDDEN, error_msg)

                # augument check
                if wiki_enabled != 'true' and wiki_enabled != 'false':
                    error_msg = 'wiki_enabled invalid.'
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

                # turn on/off group wiki
                if wiki_enabled == 'true':
                    enable_mod_for_group(group_id, MOD_GROUP_WIKI)
                else:
                    disable_mod_for_group(group_id, MOD_GROUP_WIKI)

            except RpcsyncwerkError as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        group_info = get_group_info(request, group_id)

        # return Response(group_info)
        return api_response(data=group_info)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Dismiss group',
        operation_description='''Dismiss a specific group''',
        tags=['groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='id of the group',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Dismiss group successfully.',
                examples={
                    'application/json': {
                        "message": "Dismiss group successfully",
                        "data": None
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
    @api_check_group
    def delete(self, request, group_id):
        org_id = None
        if is_org_context(request):
            org_id = request.user.org.org_id

        username = request.user.username
        try:
            # only group owner can dismiss a group
            if not is_group_owner(group_id, username):
                error_msg = 'Permission denied.'
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)
            
            MeetingRoomShare.objects.filter(group_id=group_id, share_type="SHARED_TO_GROUP").delete()

            remove_group_common(group_id, username, org_id=org_id)

        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # return Response({'success': True})
        return api_response(msg=_('Dismiss group successfully'))

class GroupBBB(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser,)

    def get(self, request, group_id):
        is_owner = False;
        try:
            # only group owner can edit group BBB setting
            if is_group_owner(group_id, request.user.username):
                is_owner = True;

        except RpcsyncwerkError as e:
            is_owner = False;

        if is_owner == False:
            return api_error(code=400, msg=_('You are not the group owner.'))
        
        try:
            existing_bbb_config = BBBPrivateSetting.objects.get(
                group_id=group_id
            )
        except BBBPrivateSetting.DoesNotExist:
            # not found => create one
            existing_bbb_config = None
        
        return_result = {}

        if existing_bbb_config is None:
            return_result = {
                "bbb_server": '',
                "bbb_secret": '',
                "is_active": False,
                "id": None,
            }
        else:
            # found - update existing
            return_result = {
                "bbb_server": existing_bbb_config.bbb_server,
                "bbb_secret": existing_bbb_config.bbb_secret,
                "is_active": existing_bbb_config.is_active,
                "id": existing_bbb_config.id, # this is return only for test connection only
            }
            
        return api_response(code=200, data=return_result, msg=_('BBB configuration retrieved successfully.'))

    def post(self, request, group_id):
        bbb_server_url = request.POST.get('bbb_server_url', '')
        bbb_server_secret = request.POST.get('bbb_server_secret', '')
        is_active = request.POST.get('bbb_is_active', 'false')

        is_owner = False;
        try:
            # only group owner can edit group BBB setting
            if is_group_owner(group_id, request.user.username):
                is_owner = True;

        except RpcsyncwerkError as e:
            is_owner = False;

        if is_owner == False:
            return api_error(code=400, msg=_('Only group owner can change the group BBB setting.'))

        try:
            existing_bbb_config = BBBPrivateSetting.objects.get(
                group_id=group_id
            )
        except BBBPrivateSetting.DoesNotExist:
            # not found => create one
            existing_bbb_config = None
        
        if existing_bbb_config is None:
            new_bbb_config = BBBPrivateSetting()

            new_bbb_config.bbb_server = bbb_server_url
            new_bbb_config.bbb_secret = bbb_server_secret
            new_bbb_config.is_active = True if is_active == 'true' else False
            new_bbb_config.group_id = group_id

            new_bbb_config.save()
        else:
            # found - update existing
            existing_bbb_config.bbb_server = bbb_server_url
            existing_bbb_config.bbb_secret = bbb_server_secret
            existing_bbb_config.is_active = True if is_active == 'true' else False
            existing_bbb_config.updated_at = datetime.now()

            existing_bbb_config.save()

        return api_response(code=200, msg=_('BBB configuration updated.'))
        