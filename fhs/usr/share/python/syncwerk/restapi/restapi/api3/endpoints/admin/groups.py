import logging

from datetime import datetime

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from django.utils.translation import ugettext as _
from django.http import HttpResponse, Http404, HttpResponseRedirect, HttpResponseNotAllowed

import synserv
from synserv import syncwerk_api, ccnet_api
from restapi.base.templatetags.restapi_tags import tsstr_sec, email2nickname

from pyrpcsyncwerk import RpcsyncwerkError

from restapi.base.accounts import User
from restapi.utils import is_valid_username
from restapi.utils.timeutils import timestamp_to_isoformat_timestr
from restapi.group.utils import is_group_member, is_group_admin, \
        validate_group_name, check_group_name_conflict
from restapi.admin_log.signals import admin_operation
from restapi.admin_log.models import GROUP_CREATE, GROUP_DELETE, GROUP_TRANSFER
from restapi.settings import SITE_ROOT
from restapi.utils.ms_excel import write_xls
from restapi.api3.utils import api_error, api_response, get_user_common_info
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.endpoints.utils import api_check_group
from restapi.api3.models import BBBPrivateSetting

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

def get_group_info(group_id):
    group = ccnet_api.get_group(group_id)
    isoformat_timestr = timestamp_to_isoformat_timestr(group.timestamp)
    members = ccnet_api.get_group_members(group_id)
    group_repos = syncwerk_api.get_repos_by_group(group_id)
    group_info = {
        "id": group.id,
        "name": group.group_name,
        "owner": get_user_common_info(group.creator_name),
        "created_at": isoformat_timestr,
        "members_count": len(members),
        "repos_count": len(group_repos),
    }

    return group_info

class AdminGroups(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - List all groups / search groups',
        operation_description='''List all / search groups by name''',
        tags=['admin-groups'],
        manual_parameters=[
            openapi.Parameter(
                name='name',
                in_="query",
                type='string',
                description='search query',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Group list retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "page_info": {
                                "current_page": 1,
                                "has_next_page": False
                            },
                            "groups": [
                                {
                                    "members_count": 2,
                                    "name": "1",
                                    "created_at": "2019-01-23T10:50:47+00:00",
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
                                    "id": 1
                                },
                                {
                                    "members_count": 1,
                                    "name": "ddddddd",
                                    "created_at": "2019-02-19T07:55:33+00:00",
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
                                    "id": 5
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
    def get(self, request):
        # search groups by name
        group_name = request.GET.get('name', '')
        group_name = group_name.strip()
        return_results = []
        if group_name:
            # search by name(keyword in name)
            groups_all = ccnet_api.search_groups(group_name, -1, -1)
            for group in groups_all:
                group_info = get_group_info(group.id)
                return_results.append(group_info)

            # return Response({"name": group_name, "groups": return_results})
            resp = {"name": group_name, "groups": return_results}
            return api_response(data=resp)

        try:
            current_page = int(request.GET.get('page', '1'))
            per_page = int(request.GET.get('per_page', '100'))
        except ValueError:
            current_page = 1
            per_page = 100

        start = (current_page - 1) * per_page
        limit = per_page + 1


        # groups = ccnet_api.get_all_groups(start, limit)

        # if len(groups) > per_page:
        #     groups = groups[:per_page]
        #     has_next_page = True
        # else:
        #     has_next_page = False

        # Ignore the limit and return all the groups
        groups = ccnet_api.search_groups('', -1, -1)
        has_next_page = False

        return_results = []

        for group in groups:
            if hasattr(ccnet_api, 'is_org_group') and \
                    ccnet_api.is_org_group(group.id):
                continue

            group_info = get_group_info(group.id)
            return_results.append(group_info)

        page_info = {
            'has_next_page': has_next_page,
            'current_page': current_page
        }

        # return Response({"page_info": page_info, "groups": return_results})
        resp = {"page_info": page_info, "groups": return_results}
        return api_response(data=resp)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Create a new group',
        operation_description='''Create a new group''',
        tags=['admin-groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_name',
                in_="formData",
                type='string',
                description='name of the new group',
                required=True,
            ),
            openapi.Parameter(
                name='group_owner',
                in_="formData",
                type='string',
                description='name of the new group owner. If not provided, then the current logging in admin will be the owner',
            ),
        ],
        responses={
            201: openapi.Response(
                description='Group created successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "members_count": 1,
                            "name": "\u0111w",
                            "created_at": "2019-02-21T03:05:52+00:00",
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
                            "id": 6
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
                description='User not found',
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
        # argument check
        group_name = request.data.get('group_name', '')
        if not group_name:
            error_msg = 'group_name %s invalid.' % group_name
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        group_name = group_name.strip()
        # Check whether group name is validate.
        if not validate_group_name(group_name):
            error_msg = _(u'Group name can only contain letters, numbers, blank, hyphen or underscore')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # Check whether group name is duplicated.
        if check_group_name_conflict(request, group_name):
            error_msg = _(u'There is already a group with that name.')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        group_owner = request.data.get('group_owner', '')
        if group_owner:
            try:
                User.objects.get(email=group_owner)
            except User.DoesNotExist:
                error_msg = 'User %s not found.' % group_owner
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        username = request.user.username
        new_owner = group_owner or username

        # create group.
        try:
            group_id = ccnet_api.create_group(group_name, new_owner)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # send admin operation log signal
        admin_op_detail = {
            "id": group_id,
            "name": group_name,
            "owner": new_owner,
        }
        admin_operation.send(sender=None, admin_name=username,
                operation=GROUP_CREATE, detail=admin_op_detail)

        # get info of new group
        group_info = get_group_info(group_id)

        # return Response(group_info, status=status.HTTP_201_CREATED)
        return api_response(code=status.HTTP_201_CREATED, data=group_info)

class AdminGroupsExport(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Export group to excel file',
        operation_description='''Export group to excel file''',
        tags=['admin-groups'],
        responses={
            200: openapi.Response(
                description='Group exported successfully',
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
        next = request.META.get('HTTP_REFERER', None)
        if not next:
            next = SITE_ROOT

        try:
            groups = synserv.ccnet_threaded_rpc.get_all_groups(-1, -1)
        except Exception as e:
            logger.error(e)
            return api_response(code=500, msg=_('Failed to export to excel'))

        head = [_("Name"), _("Creator"), _("Create At")]
        data_list = []
        for grp in groups:
            create_at = tsstr_sec(grp.timestamp) if grp.timestamp else ''
            row = [grp.group_name, grp.creator_name, create_at]
            data_list.append(row)

        wb = write_xls('groups', head, data_list)
        if not wb:
            return api_response(code=500, msg=_('Failed to export to excel'))

        response = HttpResponse(content_type='application/ms-excel')
        response['Content-Disposition'] = 'attachment; filename=groups.xlsx'
        wb.save(response)
        return response

class AdminGroup(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Transfer / rename group',
        operation_description='''Transfer / rename group''',
        tags=['admin-groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='id of the group to take operation',
            ),
            openapi.Parameter(
                name='name',
                in_="formData",
                type='string',
                description='provide the new name here if you want to rename the group',
            ),
            openapi.Parameter(
                name='new_owner',
                in_="formData",
                type='string',
                description='provide the email of the new owner here if you want to transfer the group',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Transfer / rename group successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "members_count": 1,
                            "name": "dwddd",
                            "created_at": "2019-02-21T03:05:52+00:00",
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
                            "id": 6
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
    @api_check_group
    def put(self, request, group_id):
        # argument check
        new_group_name = request.data.get('name', None)
        if new_group_name:
            try:
                # Check whether group name is validate.
                if not validate_group_name(new_group_name):
                    error_msg = _(u'Group name can only contain letters, numbers, blank, hyphen or underscore')
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

                # Check whether group name is duplicated.
                if check_group_name_conflict(request, new_group_name):
                    error_msg = _(u'There is already a group with that name.')
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
                print 'RREEENNNAAAMMMEEE GGGRRROOOUUUpPPPP'
                print group_id
                print new_group_name
                synserv.ccnet_threaded_rpc.set_group_name(group_id, new_group_name)

            except RpcsyncwerkError as e:
                logger.error(e)
                print e
                error_msg = _(u'Internal Server Error')
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        new_owner = request.data.get('new_owner', None)
        if new_owner:
            if not new_owner or not is_valid_username(new_owner):
                error_msg = _('new_owner %s invalid.') % new_owner
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
            # recourse check
            group_id = int(group_id) # Checked by URL Conf
            group = ccnet_api.get_group(group_id)
            if not group:
                error_msg = _('Group %d not found.') % group_id
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

            # check if new_owner exists,
            # NOT need to check old_owner for old_owner may has been deleted.
            try:
                User.objects.get(email=new_owner)
            except User.DoesNotExist:
                error_msg = _(u'User %s not found.') % new_owner
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

            old_owner = group.creator_name
            if new_owner == old_owner:
                error_msg = _(u'User %s is already group owner.') % new_owner
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            # transfer a group
            try:
                if not is_group_member(group_id, new_owner):
                    ccnet_api.group_add_member(group_id, old_owner, new_owner)

                if not is_group_admin(group_id, new_owner):
                    ccnet_api.group_set_admin(group_id, new_owner)

                ccnet_api.set_group_creator(group_id, new_owner)
                ccnet_api.group_unset_admin(group_id, old_owner)
            except RpcsyncwerkError as e:
                logger.error(e)
                error_msg = _('Internal Server Error')
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            # send admin operation log signal
            admin_op_detail = {
                "id": group_id,
                "name": group.group_name,
                "from": old_owner,
                "to": new_owner,
            }
            admin_operation.send(sender=None, admin_name=request.user.username,
                    operation=GROUP_TRANSFER, detail=admin_op_detail)

        group_info = get_group_info(group_id)
        # return Response(group_info)
        return api_response(data=group_info)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Dismiss a group',
        operation_description='''Dismiss a group''',
        tags=['admin-groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='id of the group to dismiss',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Transfer / rename group successfully',
                examples={
                    'application/json': {
                        "message": "",
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
    def delete(self, request, group_id):
        group_id = int(group_id)
        group = ccnet_api.get_group(group_id)
        if not group:
            # return Response({'success': True})
            return api_response()

        group_owner = group.creator_name
        group_name = group.group_name

        try:
            BBBPrivateSetting.objects.filter(group_id=group_id).delete()
            ccnet_api.remove_group(group_id)
            syncwerk_api.remove_group_repos(group_id)
            
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # send admin operation log signal
        admin_op_detail = {
            "id": group_id,
            "name": group_name,
            "owner": group_owner,
        }
        admin_operation.send(sender=None, admin_name=request.user.username,
                operation=GROUP_DELETE, detail=admin_op_detail)

        # return Response({'success': True})
        return api_response()

class AdminGroupBBB(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser,)

    def get(self, request, group_id):
        
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