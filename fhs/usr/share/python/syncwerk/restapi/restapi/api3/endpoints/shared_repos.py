import logging

from django.utils.translation import ugettext as _

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

import synserv
from synserv import syncwerk_api, ccnet_api

from restapi.api3.utils import api_error, api_response, send_perm_audit_signal
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.profile.models import Profile
from restapi.utils import is_org_context, is_valid_username, send_perm_audit_msg
from restapi.base.templatetags.restapi_tags import email2nickname

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class SharedRepos(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get all shared folders',
        operation_description='''Get all shared folders the current user''',
        tags=['shares'],
        responses={
            200: openapi.Response(
                description='List retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            {
                                "share_permission": "rw",
                                "repo_id": "5162d1dd-428d-4a6f-9d44-c60ad57abebb",
                                "share_type": "group",
                                "encrypted": False,
                                "group_name": "3",
                                "group_id": 3,
                                "repo_name": "tgregr"
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
    def get(self, request, format=None):
        shared_repos = []
        username = request.user.username
        try:
            if is_org_context(request):
                org_id = request.user.org.org_id
                shared_repos += syncwerk_api.get_org_share_out_repo_list(
                    org_id, username, -1, -1)
                shared_repos += synserv.syncwserv_threaded_rpc.get_org_group_repos_by_owner(
                    org_id, username)
                shared_repos += synserv.syncwserv_threaded_rpc.list_org_inner_pub_repos_by_owner(
                    org_id, username)
            else:
                shared_repos += syncwerk_api.get_share_out_repo_list(
                    username, -1, -1)
                shared_repos += syncwerk_api.get_group_repos_by_owner(username)
                if not request.cloud_mode:
                    shared_repos += syncwerk_api.list_inner_pub_repos_by_owner(
                        username)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        returned_result = []
        shared_repos.sort(lambda x, y: cmp(x.repo_name, y.repo_name))
        for repo in shared_repos:
            if repo.is_virtual:
                continue

            result = {}
            result['repo_id'] = repo.repo_id
            result['repo_name'] = repo.repo_name
            result['share_type'] = repo.share_type
            result['share_permission'] = repo.permission
            result['encrypted'] = repo.encrypted

            if repo.share_type == 'personal':
                result['user_name'] = email2nickname(repo.user)
                result['user_email'] = repo.user
                result['contact_email'] = Profile.objects.get_contact_email_by_user(
                    repo.user)

            if repo.share_type == 'group':
                group = ccnet_api.get_group(repo.group_id)
                result['group_id'] = repo.group_id
                result['group_name'] = group.group_name

            returned_result.append(result)

        # return Response(returned_result)
        return api_response(data=returned_result)


class SharedRepo(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Update / create a shared folder',
        operation_description='''Update or create a share of a folder''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='permission',
                in_="formData",
                type='string',
                description='permission of the share',
                required=True,
                enum=['r', 'rw']
            ),
            openapi.Parameter(
                name='share_type',
                in_="formData",
                type='string',
                description='type of the share',
                required=True,
                enum=['personal','group','public']
            ),
        ],
        responses={
            200: openapi.Response(
                description='Create/update shared folder successfully.',
                examples={
                    'application/json': {
                        "message": "Create/update shared folder successfully.",
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
                description='Folder not found',
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
    def put(self, request, repo_id, format=None):

        # argument check
        permission = request.data.get('permission', None)
        if permission not in ['r', 'rw']:
            error_msg = 'permission invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        share_type = request.data.get('share_type', None)
        if not share_type:
            error_msg = 'share_type invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if share_type not in ('personal', 'group', 'public'):
            error_msg = "share_type can only be 'personal' or 'group' or 'public'."
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # recourse check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        username = request.user.username
        if is_org_context(request):
            repo_owner = syncwerk_api.get_org_repo_owner(repo_id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo_id)

        if username != repo_owner:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # update share permission
        if share_type == 'personal':
            shared_to = request.data.get('user', None)
            if not shared_to or not is_valid_username(shared_to):
                error_msg = 'user invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            try:
                if is_org_context(request):
                    org_id = request.user.org.org_id
                    synserv.syncwserv_threaded_rpc.org_set_share_permission(
                        org_id, repo_id, username, shared_to, permission)
                else:
                    syncwerk_api.set_share_permission(repo_id,
                                                     username, shared_to, permission)
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            send_perm_audit_msg('modify-repo-perm', username,
                                shared_to, repo_id, '/', permission)
            send_perm_audit_signal(request, 'modify-repo-perm', repo_id, '/', permission, shared_to, 'user_email')
        if share_type == 'group':
            group_id = request.data.get('group_id', None)
            if not group_id:
                error_msg = 'group_id invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            try:
                group_id = int(group_id)
            except ValueError:
                error_msg = 'group_id must be integer.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            group = ccnet_api.get_group(group_id)
            if not group:
                error_msg = 'Group %s not found.' % group_id
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

            try:
                if is_org_context(request):
                    org_id = request.user.org.org_id
                    synserv.syncwserv_threaded_rpc.set_org_group_repo_permission(
                        org_id, group_id, repo_id, permission)
                else:
                    syncwerk_api.set_group_repo_permission(
                        group_id, repo_id, permission)
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            send_perm_audit_msg('modify-repo-perm', username,
                                group_id, repo_id, '/', permission)
            send_perm_audit_signal(request, 'modify-repo-perm', repo_id, '/', permission, group_id, 'group')
        if share_type == 'public':
            try:
                if is_org_context(request):
                    org_id = request.user.org.org_id
                    synserv.syncwserv_threaded_rpc.set_org_inner_pub_repo(
                        org_id, repo_id, permission)
                else:
                    syncwerk_api.add_inner_pub_repo(repo_id, permission)
                    synserv.syncwserv_threaded_rpc.set_inner_pub_repo(
                        repo_id, permission)
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            send_perm_audit_msg('modify-repo-perm', username,
                                'all', repo_id, '/', permission)
            send_perm_audit_signal(request, 'modify-repo-perm', repo_id, '/', permission, 'all', 'all')
        # return Response({'success': True})
        return api_response(msg=_('Create/update shared folder successfully.'))

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Unshare a folder',
        operation_description='''Unshare a specific folder''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='share_type',
                in_='query',
                type='string',
                description='type of the share',
                required=True,
                enum=['personal','group','public']
            ),
        ],
        responses={
            200: openapi.Response(
                description='Unshared folder successfully',
                examples={
                    'application/json': {
                        "message": "Repo unshared successfully",
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
                description='Folder not found',
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
    def delete(self, request, repo_id, format=None):
        # argument check
        share_type = request.GET.get('share_type', None)
        if not share_type:
            error_msg = 'share_type invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if share_type not in ('personal', 'group', 'public'):
            error_msg = "share_type can only be 'personal' or 'group' or 'public'."
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            return api_error(status.HTTP_404_NOT_FOUND, 'Library %s not found.' % repo_id)

        # permission check
        username = request.user.username
        if is_org_context(request):
            repo_owner = syncwerk_api.get_org_repo_owner(repo_id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo_id)

        if username != repo_owner:
            error_msg = 'You don\'t have permission to unshare this library.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # delete share
        org_id = None
        if is_org_context(request):
            org_id = request.user.org.org_id

        if share_type == 'personal':
            user = request.GET.get('user', None)
            if not user or not is_valid_username(user):
                error_msg = 'user invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            # if user not found, permission will be None
            permission = syncwerk_api.check_permission_by_path(
                repo_id, '/', user)

            try:
                if org_id:
                    syncwerk_api.org_remove_share(org_id, repo_id,
                                                 username, user)
                else:
                    syncwerk_api.remove_share(repo_id, username, user)
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            send_perm_audit_msg('delete-repo-perm', username, user,
                                repo_id, '/', permission)
            send_perm_audit_signal(request, 'delete-repo-perm', repo_id, '/', permission, user, 'user_email')
        if share_type == 'group':
            group_id = request.GET.get('group_id', None)
            if not group_id:
                error_msg = 'group_id invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            try:
                group_id = int(group_id)
            except ValueError:
                error_msg = 'group_id must be integer.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            # hacky way to get group repo permission
            permission = ''
            if org_id:
                for e in syncwerk_api.list_org_repo_shared_group(
                        org_id, username, repo_id):
                    if e.group_id == group_id:
                        permission = e.perm
                        break
            else:
                for e in syncwerk_api.list_repo_shared_group_by_user(username, repo_id):
                    if e.group_id == group_id:
                        permission = e.perm
                        break

            try:
                if org_id:
                    synserv.del_org_group_repo(repo_id, org_id, group_id)
                else:
                    syncwerk_api.unset_group_repo(repo_id, group_id, username)
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            send_perm_audit_msg('delete-repo-perm', username, group_id,
                                repo_id, '/', permission)
            send_perm_audit_signal(request, 'delete-repo-perm', repo_id, '/', permission, group_id, 'group')
        if share_type == 'public':
            pub_repos = []
            if org_id:
                pub_repos = synserv.list_org_inner_pub_repos(org_id, username)

            if not request.cloud_mode:
                pub_repos = synserv.list_inner_pub_repos(username)

            try:
                if org_id:
                    synserv.syncwserv_threaded_rpc.unset_org_inner_pub_repo(
                        org_id, repo_id)
                else:
                    syncwerk_api.remove_inner_pub_repo(repo_id)
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            permission = ''
            for repo in pub_repos:
                if repo.repo_id == repo_id:
                    permission = repo.permission
                    break

            if permission:
                send_perm_audit_msg('delete-repo-perm',
                                    username, 'all', repo_id, '/', permission)
                send_perm_audit_signal(request, 'delete-repo-perm', repo_id, '/', permission, user, 'all', 'all')
        # return Response({'success': True})
        return api_response(msg=_('Repo unshared successfully.'))
