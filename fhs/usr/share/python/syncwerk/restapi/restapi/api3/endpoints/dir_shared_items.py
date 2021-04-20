import logging
import json

from django.http import HttpResponse
from pyrpcsyncwerk import RpcsyncwerkError
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from django.utils.translation import ugettext as _

import synserv
from synserv import syncwerk_api, ccnet_api

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.permissions import IsRepoAccessible
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response, send_perm_audit_signal
from restapi.api3.models import SharedRepo
from restapi.api2.endpoints.utils import is_org_user

from restapi.base.templatetags.restapi_tags import email2nickname
from restapi.base.accounts import User
from restapi.share.signals import share_repo_to_user_successful, \
    share_repo_to_group_successful
from restapi.utils import (is_org_context, is_valid_username,
                          send_perm_audit_msg)

from restapi.group.utils import is_group_member, is_group_admin, \
    is_group_owner, is_group_admin_or_owner

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

logger = logging.getLogger(__name__)
json_content_type = 'application/json; charset=utf-8'

def search_group_id_by_exact_name(search_query, username):
    groups = synserv.get_personal_groups_by_user(username)
    result = -1
    for group in groups:
        group_name = group.group_name
        if not group_name:
            continue
        # if is_group_owner(group.id, request.user.email) is False:
        #     continue
        if search_query == group_name:
            result = group.id
            break
    return result

class DirSharedItemsEndpoint(APIView):
    """Support uniform interface(list, share, unshare, modify) for sharing
    library/folder to users/groups.
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, IsRepoAccessible)
    throttle_classes = (UserRateThrottle,)
    parser_classes=(parsers.FormParser, parsers.MultiPartParser)

    def list_user_shared_items(self, request, repo_id, path):
        username = request.user.username

        if is_org_context(request):
            org_id = request.user.org.org_id
            if path == '/':
                share_items = syncwerk_api.list_org_repo_shared_to(org_id,
                        username, repo_id)
            else:
                share_items = syncwerk_api.get_org_shared_users_for_subdir(org_id,
                        repo_id, path, username)
        else:
            if path == '/':
                share_items = syncwerk_api.list_repo_shared_to(username, repo_id)
            else:
                share_items = syncwerk_api.get_shared_users_for_subdir(repo_id,
                                                                      path, username)
        ret = []
        for item in share_items:
            print item
            allow_view_history = True
            allow_view_snapshot = False
            allow_restore_snapshot = False
            try:
                shared_item = SharedRepo.objects.using('syncwerk-server').get(repo_id=repo_id, from_email=username, to_email=item.user)
                allow_view_history = shared_item.allow_view_history
                allow_view_snapshot = shared_item.allow_view_snapshot
                allow_restore_snapshot = shared_item.allow_restore_snapshot
            except Exception as e:
                pass
            ret.append({
                "share_type": "user",
                "user_info": {
                    "name": item.user,
                    "nickname": email2nickname(item.user),
                },
                "permission": item.perm,
                "allow_view_history": allow_view_history,
                "allow_view_snapshot": allow_view_snapshot,
                "allow_restore_snapshot": allow_restore_snapshot,
            })
        return ret

    def list_group_shared_items(self, request, repo_id, path):
        username = request.user.username
        if is_org_context(request):
            org_id = request.user.org.org_id
            if path == '/':
                share_items = syncwerk_api.list_org_repo_shared_group(org_id,
                        username, repo_id)
            else:
                share_items = syncwerk_api.get_org_shared_groups_for_subdir(org_id,
                        repo_id, path, username)
        else:
            if path == '/':
                share_items = syncwerk_api.list_repo_shared_group_by_user(username, repo_id)
            else:
                share_items = syncwerk_api.get_shared_groups_for_subdir(repo_id,
                                                                       path, username)
        ret = []
        for item in share_items:
            ret.append({
                "share_type": "group",
                "group_info": {
                    "id": item.group_id,
                    "name": synserv.get_group(item.group_id).group_name,
                },
                "permission": item.perm,
            })
        return ret

    def handle_shared_to_args(self, request):
        share_type = request.GET.get('share_type', None)
        shared_to_user = False
        shared_to_group = False
        if share_type:
            for e in share_type.split(','):
                e = e.strip()
                if e not in ['user', 'group']:
                    continue
                if e == 'user':
                    shared_to_user = True
                if e == 'group':
                    shared_to_group = True
        else:
            shared_to_user = True
            shared_to_group = True

        return (shared_to_user, shared_to_group)

    def get_repo_owner(self, request, repo_id):
        if is_org_context(request):
            return syncwerk_api.get_org_repo_owner(repo_id)
        else:
            return syncwerk_api.get_repo_owner(repo_id)

    def has_shared_to_user(self, request, repo_id, path, username):
        items = self.list_user_shared_items(request, repo_id, path)

        has_shared = False
        for item in items:
            if username == item['user_info']['name']:
                has_shared = True
                break

        return has_shared

    def has_shared_to_group(self, request, repo_id, path, group_id):
        items = self.list_group_shared_items(request, repo_id, path)

        has_shared = False
        for item in items:
            if group_id == item['group_info']['id']:
                has_shared = True
                break

        return has_shared

    def share_repo_to_user(self, repo_id, path, from_email, to_email, permission, allow_view_history, allow_view_snapshot, allow_restore_snapshot):
        if path == '/':
            syncwerk_api.share_repo(repo_id, from_email, to_email, permission)
            ## Update share permission
            newly_share = SharedRepo.objects.using('syncwerk-server').get(repo_id=repo_id, from_email=from_email, to_email=to_email)
            newly_share.allow_view_history=allow_view_history
            newly_share.allow_view_snapshot=allow_view_snapshot
            newly_share.allow_restore_snapshot=allow_restore_snapshot
            newly_share.save(using='syncwerk-server')
            return None
        else:
            sub_repo_id = syncwerk_api.share_subdir_to_user(repo_id, path, from_email, to_email, permission)
            newly_share = SharedRepo.objects.using('syncwerk-server').get(repo_id=sub_repo_id, from_email=from_email, to_email=to_email)
            newly_share.allow_view_history=allow_view_history
            newly_share.allow_view_snapshot=allow_view_snapshot
            newly_share.allow_restore_snapshot=allow_restore_snapshot
            newly_share.save(using='syncwerk-server')
            return sub_repo_id

    # if path == '/':
    #     syncwerk_api.share_repo(
    #             repo_id, username, to_user, permission)
    # else:
    #     sub_repo_id = syncwerk_api.share_subdir_to_user(
    #             repo_id, path, username, to_user, permission)
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Folder share list',
        operation_description='''List all shared items (share to users/groups) for a folder library''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='folder id for retriving the share',
            ),
            openapi.Parameter(
                name='p',
                in_="query",
                type='string',
                description='path of the folder for retrieving the share.',
            ),
            openapi.Parameter(
                name='share_type',
                in_="query",
                type='string',
                description='Type of the share to retrieve. "user" or "group". Will retrieve both by default',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Share list retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            {
                                "share_type": "user",
                                "permission": "rw",
                                "allow_view_snapshot": True,
                                "user_info": {
                                    "nickname": "Jamaal Goscar",
                                    "name": "jgoscare@networksolutions.com"
                                },
                                "allow_view_history": True,
                                "allow_restore_snapshot": False
                            }
                        ]
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
            403: openapi.Response(
                description='You don\'t have permission to perform this operation.',
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
    def get(self, request, repo_id, format=None):
        
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            return api_error(status.HTTP_404_NOT_FOUND, 'Library %s not found.' % repo_id)

        shared_to_user, shared_to_group = self.handle_shared_to_args(request)

        path = request.GET.get('p', '/')
        if syncwerk_api.get_dir_id_by_path(repo.id, path) is None:
            return api_error(status.HTTP_404_NOT_FOUND, 'Folder %s not found.' % path)

        ret = []
        if shared_to_user:
            ret += self.list_user_shared_items(request, repo_id, path)

        if shared_to_group:
            ret += self.list_group_shared_items(request, repo_id, path)

        # return HttpResponse(json.dumps(ret), status=200,
        #                     content_type=json_content_type)
        return api_response(data=ret)

    @swagger_auto_schema(
        auto_schema=None
    )
    def post(self, request, repo_id, format=None):
        username = request.user.username
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            return api_error(status.HTTP_404_NOT_FOUND, 'Library %s not found.' % repo_id)

        path = request.GET.get('p', '/')
        if syncwerk_api.get_dir_id_by_path(repo.id, path) is None:
            return api_error(status.HTTP_404_NOT_FOUND, 'Folder %s not found.' % path)

        if username != self.get_repo_owner(request, repo_id):
            return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')

        permission = request.data.get('permission', 'r')
        if permission not in ['r', 'rw']:
            return api_error(status.HTTP_400_BAD_REQUEST, 'permission invalid.')

        shared_to_user, shared_to_group = self.handle_shared_to_args(request)
        if shared_to_user:
            shared_to = request.GET.get('username')
            if shared_to is None or not is_valid_username(shared_to):
                return api_error(status.HTTP_400_BAD_REQUEST, 'Email %s invalid.' % shared_to)

            try:
                User.objects.get(email=shared_to)
            except User.DoesNotExist:
                return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid user, should be registered')

            if is_org_context(request):
                org_id = request.user.org.org_id
                if path == '/':
                    syncwerk_api.org_set_share_permission(
                            org_id, repo_id, username, shared_to, permission)
                else:
                    syncwerk_api.org_update_share_subdir_perm_for_user(
                            org_id, repo_id, path, username, shared_to, permission)
            else:
                if path == '/':
                    syncwerk_api.set_share_permission(
                            repo_id, username, shared_to, permission)
                else:
                    syncwerk_api.update_share_subdir_perm_for_user(
                            repo_id, path, username, shared_to, permission)

            send_perm_audit_msg('modify-repo-perm', username, shared_to,
                                repo_id, path, permission)
            send_perm_audit_signal(request, 'modify-repo-perm', repo_id, path, permission, shared_to, 'user_email')

        if shared_to_group:
            gid = request.GET.get('group_id')
            try:
                gid = int(gid)
            except ValueError:
                return api_error(status.HTTP_400_BAD_REQUEST, 'group_id %s invalid.' % gid)
            group = synserv.get_group(gid)
            if not group:
                return api_error(status.HTTP_404_NOT_FOUND, 'Group %s not found.' % gid)

            if is_org_context(request):
                org_id = request.user.org.org_id
                if path == '/':
                    synserv.syncwserv_threaded_rpc.set_org_group_repo_permission(
                            org_id, gid, repo.id, permission)
                else:
                    syncwerk_api.org_update_share_subdir_perm_for_group(
                            org_id, repo_id, path, username, gid, permission)
            else:
                if path == '/':
                    syncwerk_api.set_group_repo_permission(gid, repo.id, permission)
                else:
                    syncwerk_api.update_share_subdir_perm_for_group(
                            repo_id, path, username, gid, permission)

            send_perm_audit_msg('modify-repo-perm', username, gid,
                                repo_id, path, permission)
            send_perm_audit_signal(request, 'modify-repo-perm', repo_id, path, permission, gid, 'group')

        # return HttpResponse(json.dumps({'success': True}), status=200,
        #                     content_type=json_content_type)
        return api_response(msg='Update shared item permission successfully.')

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Create a share',
        operation_description='''Create a user / group share''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='folder id for sharing',
            ),
            openapi.Parameter(
                name='p',
                in_="query",
                type='string',
                description='path of the folder for sharing.',
            ),
            openapi.Parameter(
                name='share_type',
                in_="formData",
                type='string',
                description='Type of the share to create. "user" or "group"',
                required=True
            ),
            openapi.Parameter(
                name='username',
                in_="formData",
                type='string',
                description='If share type is "user", this will be the email of the user to share to',
            ),
            openapi.Parameter(
                name='allow_view_history',
                in_="formData",
                type='string',
                description='If share type is "user", this will decided if the user can view folder history or not',
            ),
            openapi.Parameter(
                name='allow_view_snapshot',
                in_="formData",
                type='string',
                description='"true" or "false". If share type is "user", this will decided if the user can restore folder history snapshot or not',
            ),
            openapi.Parameter(
                name='allow_restore_snapshot',
                in_="formData",
                type='string',
                description='"true" or "false". If share type is "user", this will decided if the user can restore folder history snapshot or not',
            ),
            openapi.Parameter(
                name='group_name',
                in_="formData",
                type='string',
                description='If share type is "group", this will be the name of the group to share to.',
            ),
            openapi.Parameter(
                name='permission',
                in_="formData",
                type='string',
                description='Permission of the share. "r","w" or "rw".',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Share list retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "Shared to groups successfully.",
                        "data": {
                            "failed": [],
                            "success": [
                                {
                                    "group_info": {
                                        "id": 1,
                                        "name": "1"
                                    },
                                    "share_type": "group",
                                    "permission": "rw"
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
                        "detail": "Token invalid"
                    }
                }
            ),
            403: openapi.Response(
                description='You don\'t have permission to perform this operation.',
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
        """ Update shared item permission.
        ---
        # YAML

        type:
          Authorization:
            required: true
            type: string
          repo_id:
            required: true
            type: string
          p:
            required: false
            type: string
          share_type:
            required: false
            type: string
          permission:
            required: false
            type: string
          username:
            required: false
            type: string
          group_id:
            required: false
            type: string

        parameters:
            - name: Authorization
              required: true
              type: string
              paramType: header
            - name: repo_id
              required: true
              type: string
              paramType: path
            - name: p
              description: / means the root folder, which is equivalent to the library.
              required: false
              type: string
              paramType: query
            - name: share_type
              description: user or group
              required: false
              type: string
              paramType: form
            - name: permission
              description: r or rw, default r
              required: false
              type: string
              paramType: form
            - name: username
              description: a email string or a list contains multi emails, necessary if share_type is user
              required: false
              type: string
              paramType: form
            - name: group_id
              description: an integer or a list contains multi integers, necessary if share_type is group
              required: false
              type: string
              paramType: form
            - name: allow_view_history
              description: allowed the shared user to view the history of the share or not. Default to true
              required: false
              paramType: form
            - name: allow_view_snapshot
              description: allowed the shared user to view the snapshot of the share or not. Default to false
              required: false
              paramType: form
            - name: allow_restore_snapshot
              description: allowed the shared user to view the history of the share or not. Default to false
              required: false
              paramType: form

        responseMessages:
            - code: 400
              message: BAD_REQUEST
            - code: 401
              message: UNAUTHORIZED
            - code: 403
              message: FORBIDDEN
            - code: 404
              message: NOT_FOUND
            - code: 500
              message: INTERNAL_SERVER_ERROR

        consumes:
            - application/json
        produces:
            - application/json
        """
        username = request.user.username
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            return api_error(status.HTTP_404_NOT_FOUND, 'Library %s not found.' % repo_id)

        path = request.GET.get('p', '/')
        if syncwerk_api.get_dir_id_by_path(repo.id, path) is None:
            return api_error(status.HTTP_404_NOT_FOUND, 'Folder %s not found.' % path)

        if username != self.get_repo_owner(request, repo_id):
            return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')

        share_type = request.data.get('share_type')
        if share_type != 'user' and share_type != 'group':
            return api_error(status.HTTP_400_BAD_REQUEST, 'share_type invalid.')

        permission = request.data.get('permission', 'r')
        if permission not in ['r', 'rw']:
            return api_error(status.HTTP_400_BAD_REQUEST, 'permission invalid.')

        result = {}
        result['failed'] = []
        result['success'] = []

        if share_type == 'user':
            share_to_users = request.data.getlist('username')
            for to_user in share_to_users:
                if not is_valid_username(to_user):
                    result['failed'].append({
                        'email': to_user,
                        'error_msg': _(u'username invalid.')
                        })
                    continue

                try:
                    User.objects.get(email=to_user)
                except User.DoesNotExist:
                    result['failed'].append({
                        'email': to_user,
                        'error_msg': _(u'User %s not found.') % to_user
                        })
                    continue

                if self.has_shared_to_user(request, repo_id, path, to_user):
                    result['failed'].append({
                        'email': to_user,
                        'error_msg': _(u'This item has been shared to %s.') % to_user
                        })
                    continue

                try:
                    if is_org_context(request):
                        org_id = request.user.org.org_id

                        if not is_org_user(to_user, int(org_id)):
                            org_name = request.user.org.org_name
                            error_msg = 'User %s is not member of organization %s.' \
                                    % (to_user, org_name)

                            result['failed'].append({
                                'email': to_user,
                                'error_msg': error_msg
                            })
                            continue

                        if path == '/':
                            synserv.syncwserv_threaded_rpc.org_add_share(
                                    org_id, repo_id, username, to_user,
                                    permission)
                        else:
                            sub_repo_id = syncwerk_api.org_share_subdir_to_user(org_id,
                                    repo_id, path, username, to_user, permission)
                    else:

                        if is_org_user(to_user):
                            error_msg = 'User %s is a member of organization.' % to_user
                            result['failed'].append({
                                'email': to_user,
                                'error_msg': error_msg
                            })
                            continue
                        allow_view_history = request.POST.get('allow_view_history', 'true')
                        allow_view_snapshot= request.POST.get('allow_view_snapshot', 'false')
                        allow_restore_snapshot = request.POST.get('allow_restore_snapshot', 'false')
                        if allow_view_history == 'true':
                            allow_view_history = True
                        else:
                            allow_view_history = False
                        if allow_view_snapshot == 'true':
                            allow_view_snapshot = True
                        else:
                            allow_view_snapshot = False
                        if allow_restore_snapshot == 'true':
                            allow_restore_snapshot = True
                        else:
                            allow_restore_snapshot = False
                        
                        sub_repo_id = self.share_repo_to_user(repo_id, path, username, to_user, permission, allow_view_history, allow_view_snapshot, allow_restore_snapshot)
                    # send a signal when sharing repo successful
                    if path == '/':
                        share_repo_to_user_successful.send(sender=None,
                                from_user=username, to_user=to_user, repo=repo, path="/")
                    else:
                        sub_repo = syncwerk_api.get_repo(sub_repo_id)
                        share_repo_to_user_successful.send(sender=None,
                                from_user=username, to_user=to_user, repo=sub_repo, path="/")

                    result['success'].append({
                        "share_type": "user",
                        "user_info": {
                            "name": to_user,
                            "nickname": email2nickname(to_user),
                        },
                        "permission": permission,
                        "allow_view_history": allow_view_history,
                        "allow_view_snapshot": allow_view_snapshot,
                        "allow_restore_snapshot": allow_restore_snapshot,
                    })

                    send_perm_audit_msg('add-repo-perm', username, to_user,
                                        repo_id, path, permission)
                    send_perm_audit_signal(request, 'add-repo-perm', repo_id, path, permission, to_user, 'user_email')
                except RpcsyncwerkError as e:
                    logger.error(e)
                    result['failed'].append({
                        'email': to_user,
                        'error_msg': 'Internal Server Error'
                        })
                    continue

        if share_type == 'group':

            group_names = request.data.getlist('group_name')
            group_ids = []
            for name in group_names:
                searchResult = search_group_id_by_exact_name(name, username);
                if searchResult == -1:
                    return api_error(status.HTTP_404_NOT_FOUND, 'Group %s not found' % name)
                else:
                    group_ids.append(searchResult)

            # group_ids = request.data.getlist('group_id')
            for gid in group_ids:
                # try:
                #     gid = int(gid)
                # except ValueError:
                #     return api_error(status.HTTP_400_BAD_REQUEST, 'group_id %s invalid.' % gid)

                group = synserv.get_group(gid)
                if not group:
                    return api_error(status.HTTP_404_NOT_FOUND, 'Group %s not found' % gid)

                if self.has_shared_to_group(request, repo_id, path, gid):
                    result['failed'].append({
                        'group_name': group.group_name,
                        'error_msg': _(u'This item has been shared to %s.') % group.group_name
                        })
                    continue

                try:
                    if is_org_context(request):
                        org_id = request.user.org.org_id
                        if path == '/':
                            syncwerk_api.add_org_group_repo(
                                    repo_id, org_id, gid, username, permission)
                        else:
                            sub_repo_id = syncwerk_api.org_share_subdir_to_group(org_id,
                                    repo_id, path, username, gid, permission)
                    else:
                        if path == '/':
                            syncwerk_api.set_group_repo(
                                    repo_id, gid, username, permission)
                        else:
                            sub_repo_id = syncwerk_api.share_subdir_to_group(
                                    repo_id, path, username, gid, permission)

                    if path == '/':
                        share_repo_to_group_successful.send(sender=None,
                                from_user=username, group_id=gid, repo=repo, path="/" )
                    else:
                        sub_repo = syncwerk_api.get_repo(sub_repo_id)
                        share_repo_to_group_successful.send(sender=None,
                                from_user=username, group_id=gid, repo=sub_repo, path="/")

                    result['success'].append({
                        "share_type": "group",
                        "group_info": {
                            "id": gid,
                            "name": group.group_name,
                        },
                        "permission": permission
                    })

                    send_perm_audit_msg('add-repo-perm', username, gid,
                                        repo_id, path, permission)
                    send_perm_audit_signal(request, 'add-repo-perm', repo_id, path, permission, gid, 'group')
                except RpcsyncwerkError as e:
                    logger.error(e)
                    result['failed'].append({
                        'group_name': group.group_name,
                        'error_msg': 'Internal Server Error'
                        })
                    continue

        # return HttpResponse(json.dumps(result),
        #     status=200, content_type=json_content_type)
        if share_type == 'user':
            responseMessage = _('Shared to users successfully.')
        elif share_type == 'group':
            responseMessage = _('Shared to groups successfully.')
        else:
            responseMessage == _('Update shared item permission successfully.')
        return api_response(data=result, msg=responseMessage)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Delete a share',
        operation_description='''Delete a user / group share entry''',
        tags=['shares'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='folder id for sharing',
            ),
            openapi.Parameter(
                name='p',
                in_="query",
                type='string',
                description='path of the folder for sharing.',
            ),
            openapi.Parameter(
                name='share_type',
                in_="query",
                type='string',
                description='Type of the share to delete. "user" or "group"',
                required=True
            ),
            openapi.Parameter(
                name='username',
                in_="query",
                type='string',
                description='If share type is "user", this will be the email of the user which share entry to be deleted',
            ),
            openapi.Parameter(
                name='group_id',
                in_="query",
                type='string',
                description='If share type is "group", this will be the id of the group which share entry to be deleted',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Share list retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "Delete shared item successfully.",
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
            403: openapi.Response(
                description='You don\'t have permission to perform this operation.',
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
        
        username = request.user.username
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            return api_error(status.HTTP_404_NOT_FOUND, 'Library %s not found.' % repo_id)

        path = request.GET.get('p', '/')
        if syncwerk_api.get_dir_id_by_path(repo.id, path) is None:
            return api_error(status.HTTP_404_NOT_FOUND, 'Folder %s not found.' % path)

        if username != self.get_repo_owner(request, repo_id):
            return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')

        shared_to_user, shared_to_group = self.handle_shared_to_args(request)
        if shared_to_user:
            shared_to = request.GET.get('username')
            if shared_to is None or not is_valid_username(shared_to):
                return api_error(status.HTTP_400_BAD_REQUEST, 'Email %s invalid.' % shared_to)

            # if user not found, permission will be None
            permission = syncwerk_api.check_permission_by_path(
                    repo_id, '/', shared_to)

            if is_org_context(request):
                org_id = request.user.org.org_id
                if path == '/':
                    synserv.syncwserv_threaded_rpc.org_remove_share(
                            org_id, repo_id, username, shared_to)
                else:
                    syncwerk_api.org_unshare_subdir_for_user(
                            org_id, repo_id, path, username, shared_to)

            else:
                if path == '/':
                    synserv.remove_share(repo_id, username, shared_to)
                else:
                    syncwerk_api.unshare_subdir_for_user(
                            repo_id, path, username, shared_to)

            send_perm_audit_msg('delete-repo-perm', username, shared_to,
                                repo_id, path, permission)
            send_perm_audit_signal(request, 'delete-repo-perm', repo_id, path, permission, shared_to, 'user_email')    

        if shared_to_group:
            group_id = request.GET.get('group_id')
            try:
                group_id = int(group_id)
            except ValueError:
                return api_error(status.HTTP_400_BAD_REQUEST, 'group_id %s invalid' % group_id)
            
            if is_group_member(group_id, request.user.email) is False:
                return api_error(status.HTTP_403_BAD_REQUEST, 'Current user is not a member of the group')

            # hacky way to get group repo permission
            permission = ''
            if is_org_context(request):
                org_id = request.user.org.org_id
                shared_groups = syncwerk_api.list_org_repo_shared_group(
                        org_id, username, repo_id)
            else:
                shared_groups = syncwerk_api.list_repo_shared_group(
                        username, repo_id)

            for e in shared_groups:
                if e.group_id == group_id:
                    permission = e.perm
                    break

            if is_org_context(request):
                org_id = request.user.org.org_id
                if path == '/':
                    synserv.del_org_group_repo(repo_id, org_id, group_id)
                else:
                    syncwerk_api.org_unshare_subdir_for_group(
                            org_id, repo_id, path, username, group_id)
            else:
                if path == '/':
                    syncwerk_api.unset_group_repo(repo_id, group_id, username)
                else:
                    syncwerk_api.unshare_subdir_for_group(
                            repo_id, path, username, group_id)

            send_perm_audit_msg('delete-repo-perm', username, group_id,
                                repo_id, path, permission)
            send_perm_audit_signal(request, 'delete-repo-perm', repo_id, path, permission, group_id, 'group')

        # return HttpResponse(json.dumps({'success': True}), status=200,
        #                     content_type=json_content_type)
        return api_response(msg=_('Delete shared item successfully.'))
