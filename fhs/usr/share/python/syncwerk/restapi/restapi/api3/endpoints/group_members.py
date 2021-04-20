# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from django.utils.translation import ugettext as _

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

import synserv
from synserv import syncwerk_api, ccnet_api
from pyrpcsyncwerk import RpcsyncwerkError

from restapi.api3.utils import api_error, api_response
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.avatar.settings import AVATAR_DEFAULT_SIZE
from restapi.utils import string2list, is_org_context
from restapi.base.accounts import User
from restapi.group.signals import add_user_to_group
from restapi.group.utils import is_group_member, is_group_admin, \
    is_group_owner, is_group_admin_or_owner
from restapi.api3.utils.group import get_group_member_info

from .utils import api_check_group

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema


logger = logging.getLogger(__name__)


class GroupMembers(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get group memebers',
        operation_description='''List all group memebers''',
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
                name='is_admin',
                in_="query",
                type='string',
                description='true or false. If true, then only retrieve list of group admins',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Member list retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {}
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

        try:
            avatar_size = int(request.GET.get('avatar_size',
                                              AVATAR_DEFAULT_SIZE))
        except ValueError:
            avatar_size = AVATAR_DEFAULT_SIZE

        try:
            # only group member can get info of all group members
            if not is_group_member(group_id, request.user.username):
                error_msg = 'Permission denied.'
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)

            members = ccnet_api.get_group_members(group_id)

        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        group_members = []
        is_admin = request.GET.get('is_admin', 'false')
        for m in members:
            # only return group admins
            if is_admin == 'true' and not m.is_staff:
                continue

            member_info = get_group_member_info(
                request, group_id, m.user_name, avatar_size)
            group_members.append(member_info)

        # return Response(group_members)
        return api_response(data=group_members)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Add group member',
        operation_description='''Add a new group member''',
        tags=['groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='group id',
            ),
            openapi.Parameter(
                name='email',
                in_="formData",
                type='string',
                description='email of the new user',
                required=True,
            ),
        ],
        responses={
            201: openapi.Response(
                description='Member added successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {}
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
    def post(self, request, group_id):
        
        username = request.user.username

        # only group owner/admin can add a group member
        if not is_group_admin_or_owner(group_id, username):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        email = request.data.get('email', None)
        try:
            User.objects.get(email=email)
        except User.DoesNotExist:
            error_msg = 'User %s not found.' % email
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        try:
            if is_group_member(group_id, email):
                error_msg = _(u'User %s is already a group member.') % email
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            if is_org_context(request):
                org_id = request.user.org.org_id
                if not ccnet_api.org_user_exists(org_id, email):
                    error_msg = _(
                        u'User %s not found in organization.') % email
                    return api_error(status.HTTP_404_NOT_FOUND, error_msg)

            ccnet_api.group_add_member(group_id, username, email)
            add_user_to_group.send(sender=None,
                                   group_staff=username,
                                   group_id=group_id,
                                   added_user=email)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        member_info = get_group_member_info(request, group_id, email)

        # return Response(member_info, status=status.HTTP_201_CREATED)
        return api_response(code=status.HTTP_201_CREATED, data=member_info)


class GroupMember(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get group member info',
        operation_description='''Get info a the specific group member''',
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
                name='email',
                in_="path",
                type='string',
                description='email of the user to retrieve information',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Member info retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {}
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
            404: openapi.Response(
                description='Not found',
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
    def get(self, request, group_id, email):
        
        try:
            # only group member can get info of a specific group member
            if not is_group_member(group_id, request.user.username):
                error_msg = 'Permission denied.'
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)

            if not is_group_member(group_id, email):
                error_msg = 'Email %s invalid.' % email
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        try:
            avatar_size = int(request.GET.get('avatar_size',
                                              AVATAR_DEFAULT_SIZE))
        except ValueError:
            avatar_size = AVATAR_DEFAULT_SIZE

        member_info = get_group_member_info(
            request, group_id, email, avatar_size)

        # return Response(member_info)
        return api_response(data=member_info)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Group admin manipulation',
        operation_description='''Set / unset a specific group member as group admin''',
        tags=['groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='group id',
            ),
            openapi.Parameter(
                name='is_admin',
                in_="query",
                type='string',
                description='"true" for setting the user to group admin, "false" for remove the user from group admin list',
            ),
            openapi.Parameter(
                name='email',
                in_="path",
                type='string',
                description='email of the user to set / unset admin status',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Set / unset user as admin successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {}
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
            404: openapi.Response(
                description='Not found',
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
    def put(self, request, group_id, email):
        username = request.user.username
        is_admin = request.data.get('is_admin', '')
        try:
            # only group owner + admin can set/unset a specific group member as admin
            if not is_group_admin_or_owner(group_id, username):
                error_msg = 'Permission denied.'
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)

            if not is_group_member(group_id, email):
                error_msg = 'Email %s invalid.' % email
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            # set/unset a specific group member as admin
            if is_admin.lower() == 'true':
                ccnet_api.group_set_admin(group_id, email)
            elif is_admin.lower() == 'false':
                ccnet_api.group_unset_admin(group_id, email)
            else:
                error_msg = 'is_admin invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        member_info = get_group_member_info(request, group_id, email)

        # return Response(member_info)
        return api_response(data=member_info, msg=_('Role updated.'))

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Remove group member',
        operation_description='''Admin / owner remove member or member leave group''',
        tags=['groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='group id',
            ),
            openapi.Parameter(
                name='email',
                in_="path",
                type='string',
                description='email of the user',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Removed user from group successfully / User left group successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {}
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
            404: openapi.Response(
                description='Not found',
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
    def delete(self, request, group_id, email):
        
        try:
            if not is_group_member(group_id, email):
                error_msg = 'Email %s invalid.' % email
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = _('Internal Server Error')
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        username = request.user.username
        # user leave group
        if username == email:
            try:
                if is_group_admin(group_id, username):
                    group = synserv.get_group(group_id)
                    if group:
                        ccnet_api.group_remove_member(
                            group_id, group.creator_name, email)
                else:
                    ccnet_api.quit_group(group_id, username)
                # remove repo-group share info of all 'email' owned repos
                syncwerk_api.remove_group_repos_by_owner(group_id, email)
                # return Response({'success': True})
                return api_response(msg=_('Successfully left group.'))
            except RpcsyncwerkError as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # group owner/admin delete a group member
        try:
            if is_group_owner(group_id, username):
                # group owner can delete all group member
                ccnet_api.group_remove_member(group_id, username, email)
                syncwerk_api.remove_group_repos_by_owner(group_id, email)
                # return Response({'success': True})
                return api_response(msg=_('Successfully removed member from group.'))
            elif is_group_admin(group_id, username):
                # group admin can NOT delete group owner
                if not is_group_owner(group_id, email):
                    ccnet_api.group_remove_member(group_id, username, email)
                    syncwerk_api.remove_group_repos_by_owner(group_id, email)
                    # return Response({'success': True})
                    return api_response(msg=_('Successfully removed member from group.'))
                else:
                    error_msg = _('Permission denied.')
                    return api_error(status.HTTP_403_FORBIDDEN, error_msg)

            else:
                error_msg = _('Permission denied.')
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = _('Internal Server Error')
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)


class GroupMembersBulk(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Bulk add group members.',
        operation_description='''Bulk add group members.''',
        tags=['groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='group id',
            ),
            openapi.Parameter(
                name='emails',
                in_="formData",
                type='string',
                description='string contains list email of the new members to add to the group. Separated by comma',
                required=True,
            ),
        ],
        responses={
            201: openapi.Response(
                description='Members added successfully.',
                examples={
                    'application/json': {
                        "message": "All members are imported successfully.",
                        "data": {
                            "failed": [],
                            "success": [
                                {
                                    "login_id": "",
                                    "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                                    "contact_email": "bbelbind@state.tx.us",
                                    "name": "Bale Belbin",
                                    "is_admin": False,
                                    "role": "Member",
                                    "group_id": 3,
                                    "email": "bbelbind@state.tx.us",
                                    "is_default_avatar": True
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
    def post(self, request, group_id):
        
        username = request.user.username
        try:
            if not is_group_admin_or_owner(group_id, username):
                error_msg = 'Permission denied.'
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        emails_str = request.data.get('emails', '')
        emails_list = string2list(emails_str)
        emails_list = [x.lower() for x in emails_list]

        result = {}
        result['failed'] = []
        result['success'] = []
        emails_need_add = []

        org_id = None
        if is_org_context(request):
            org_id = request.user.org.org_id

        for email in emails_list:
            try:
                User.objects.get(email=email)
            except User.DoesNotExist:
                result['failed'].append({
                    'email': email,
                    'error_msg': 'User %s not found.' % email
                })
                continue

            if synserv.is_group_user(group_id, email):
                result['failed'].append({
                    'email': email,
                    'error_msg': _(u'User %s is already a group member.') % email
                })
                continue

            # Can only invite organization users to group
            if org_id and not \
                    synserv.ccnet_threaded_rpc.org_user_exists(org_id, email):
                result['failed'].append({
                    'email': email,
                    'error_msg': _(u'User %s not found in organization.') % email
                })
                continue

            emails_need_add.append(email)

        # Add user to group.
        for email in emails_need_add:
            try:
                synserv.ccnet_threaded_rpc.group_add_member(group_id,
                                                            username, email)
                member_info = get_group_member_info(request, group_id, email)
                result['success'].append(member_info)
            except RpcsyncwerkError as e:
                logger.error(e)
                result['failed'].append({
                    'email': email,
                    'error_msg': 'Internal Server Error'
                })
        # Generate message
        number_of_success = len(result['success'])
        number_of_failed = len(result['failed'])
        msg = ''
        if number_of_success <= 0:
            msg = _(u'Couldn\'t import {number_of_failed} members because they are not registered users on this server or already in this group'.format(
                number_of_failed=number_of_failed))
        else:
            if (number_of_failed <= 0):
                msg = _(u'All members are imported successfully.')
            else:
                msg = _(u'Successfully imported %(number_of_success)d members. Couldn\'t import %(number_of_failed)d members because they are not registered users on this server or already in this group' % {
                    'number_of_success' : number_of_success, 'number_of_failed' : number_of_failed})
            # return Response(result)
        return api_response(data=result, msg=msg)
