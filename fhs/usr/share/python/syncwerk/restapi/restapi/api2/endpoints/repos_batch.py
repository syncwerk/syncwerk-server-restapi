# Copyright (c) 2012-2016 Seafile Ltd.
import os
import logging

from pyrpcsyncwerk import RpcsyncwerkError
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils.translation import ugettext as _

import synserv
from synserv import syncwerk_api, ccnet_api

from restapi.api2.authentication import TokenAuthentication
from restapi.api2.throttling import UserRateThrottle
from restapi.api2.utils import api_error
from restapi.api2.views import HTTP_443_ABOVE_QUOTA

from restapi.group.utils import is_group_member
from restapi.base.accounts import User
from restapi.share.utils import is_repo_admin, \
        check_user_share_out_permission, check_group_share_out_permission
from restapi.share.models import ExtraSharePermission, ExtraGroupsSharePermission
from restapi.share.signals import share_repo_to_user_successful, \
        share_repo_to_group_successful
from restapi.utils import is_org_context, send_perm_audit_msg, \
        normalize_dir_path, get_folder_permission_recursively, \
        normalize_file_path, check_filename_with_rename
from restapi.utils.repo import get_repo_owner

from restapi.views import check_folder_permission
from restapi.settings import MAX_PATH
from restapi.constants import PERMISSION_READ, PERMISSION_READ_WRITE, \
        PERMISSION_ADMIN

logger = logging.getLogger(__name__)


class ReposBatchView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get_repo_shared_to_users(self, request, repo_id):
        username = request.user.username

        if is_org_context(request):
            org_id = request.user.org.org_id
            share_items = syncwerk_api.list_org_repo_shared_to(org_id, username, repo_id)
        else:
            share_items = syncwerk_api.list_repo_shared_to(username, repo_id)

        ret = []
        for item in share_items:
            ret.append(item.user)

        return ret

    def has_shared_to_user(self, request, repo_id, username):
        users = self.get_repo_shared_to_users(request, repo_id)

        has_shared = False
        if username in users:
            has_shared = True

        return has_shared

    def get_repo_shared_to_groups(self, request, repo_id):
        username = request.user.username
        if is_org_context(request):
            org_id = request.user.org.org_id
            share_items = syncwerk_api.list_org_repo_shared_group(org_id,
                    username, repo_id)
        else:
            share_items = syncwerk_api.list_repo_shared_group_by_user(
                    username, repo_id)

        ret = []
        for item in share_items:
            ret.append(item.group_id)

        return ret

    def has_shared_to_group(self, request, repo_id, group_id):
        group_ids = self.get_repo_shared_to_groups(request, repo_id)

        has_shared = False
        if group_id in group_ids:
            has_shared = True

        return has_shared

    def post(self, request):

        # argument check
        operation = request.data.get('operation', None)
        if not operation:
            error_msg = 'operation invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # operation could be `share`, `unshare`, `delete`, `transfer`
        # we now only use `share`, `unshare`
        if operation not in ('share', 'unshare'):
            error_msg = 'operation can only be "share", "unshare".'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        result = {}
        result['failed'] = []
        result['success'] = []

        username = request.user.username
        repo_id_list = request.data.getlist('repo_id')
        valid_repo_id_list = []

        # filter out invalid repo id
        for repo_id in repo_id_list:

            if not syncwerk_api.get_repo(repo_id):
                result['failed'].append({
                    'repo_id': repo_id,
                    'error_msg': 'Library %s not found.' % repo_id
                })
                continue

            repo_owner = get_repo_owner(request, repo_id)
            if repo_owner != username and not is_repo_admin(username, repo_id):
                result['failed'].append({
                    'repo_id': repo_id,
                    'error_msg': 'Permission denied.'
                })
                continue

            valid_repo_id_list.append(repo_id)

        # share repo
        if operation == 'share':

            share_type = request.data.get('share_type', None)
            if not share_type:
                error_msg = 'share_type invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            if share_type not in ('user', 'group'):
                error_msg = 'share_type can only be "user", "group".'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            permission = request.data.get('permission', 'rw')
            if permission not in [PERMISSION_READ, PERMISSION_READ_WRITE, PERMISSION_ADMIN]:
                error_msg = 'permission invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            # share repo to user
            if share_type == 'user':
                to_username = request.data.get('username', None)
                if not to_username:
                    error_msg = 'username invalid.'
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

                try:
                    User.objects.get(email=to_username)
                except User.DoesNotExist:
                    error_msg = 'User %s not found.' % to_username
                    return api_error(status.HTTP_404_NOT_FOUND, error_msg)

                # check if to_user is an org user
                try:
                    org_of_to_user = ccnet_api.get_orgs_by_user(to_username)
                except Exception as e:
                    logger.error(e)
                    org_of_to_user = []

                if is_org_context(request):
                    org_id = request.user.org.org_id
                    org_name = request.user.org.org_name
                    if len(org_of_to_user) == 0 or org_id != org_of_to_user[0].org_id:
                        error_msg = 'User %s is not member of organization %s.' \
                                % (to_username, org_name)
                        return api_error(status.HTTP_403_FORBIDDEN, error_msg)
                else:
                    if len(org_of_to_user) >= 1:
                        error_msg = 'User %s is member of organization %s.' \
                                % (to_username, org_of_to_user[0].org_name)
                        return api_error(status.HTTP_403_FORBIDDEN, error_msg)

                for repo_id in valid_repo_id_list:
                    if self.has_shared_to_user(request, repo_id, to_username):
                        result['failed'].append({
                            'repo_id': repo_id,
                            'error_msg': 'This item has been shared to %s.' % to_username
                            })
                        continue

                    try:
                        org_id = None
                        if is_org_context(request):
                            org_id = request.user.org.org_id
                            synserv.syncwserv_threaded_rpc.org_add_share(org_id,
                                    repo_id, username, to_username, permission)
                        else:
                            syncwerk_api.share_repo(
                                    repo_id, username, to_username, permission)

                        # send a signal when sharing repo successful
                        repo = syncwerk_api.get_repo(repo_id)
                        share_repo_to_user_successful.send(sender=None,
                                                           from_user=username,
                                                           to_user=to_username,
                                                           repo=repo, path='/',
                                                           org_id=org_id)

                        result['success'].append({
                            "repo_id": repo_id,
                            "username": to_username,
                            "permission": permission
                        })

                        send_perm_audit_msg('add-repo-perm', username, to_username,
                                            repo_id, '/', permission)
                    except Exception as e:
                        logger.error(e)
                        result['failed'].append({
                            'repo_id': repo_id,
                            'error_msg': 'Internal Server Error'
                            })

            # share repo to group
            if share_type == 'group':
                to_group_id = request.data.get('group_id', None)
                if not to_group_id:
                    error_msg = 'group_id invalid.'
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

                try:
                    to_group_id = int(to_group_id)
                except ValueError:
                    error_msg = 'group_id invalid.'
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

                group = ccnet_api.get_group(to_group_id)
                if not group:
                    error_msg = 'Group %s not found.' % to_group_id
                    return api_error(status.HTTP_404_NOT_FOUND, error_msg)

                group_name = group.group_name
                if not is_group_member(to_group_id, username):
                    error_msg = 'User %s is not member of group %s.' % (username, group_name)
                    return api_error(status.HTTP_403_FORBIDDEN, error_msg)

                for repo_id in valid_repo_id_list:
                    if self.has_shared_to_group(request, repo_id, to_group_id):
                        result['failed'].append({
                            'repo_id': repo_id,
                            'error_msg': 'This item has been shared to %s.' % group_name
                            })
                        continue

                    try:
                        org_id = None
                        if is_org_context(request):
                            org_id = request.user.org.org_id
                            syncwerk_api.add_org_group_repo(
                                    repo_id, org_id, to_group_id, username, permission)
                        else:
                            syncwerk_api.set_group_repo(
                                    repo_id, to_group_id, username, permission)

                        # send a signal when sharing repo successful
                        repo = syncwerk_api.get_repo(repo_id)
                        share_repo_to_group_successful.send(sender=None,
                                                            from_user=username,
                                                            group_id=to_group_id,
                                                            repo=repo, path='/',
                                                            org_id=org_id)

                        result['success'].append({
                            "repo_id": repo_id,
                            "group_id": to_group_id,
                            "group_name": group_name,
                            "permission": permission
                        })

                        send_perm_audit_msg('add-repo-perm', username, to_group_id,
                                            repo_id, '/', permission)

                    except RpcsyncwerkError as e:
                        logger.error(e)
                        result['failed'].append({
                            'repo_id': repo_id,
                            'error_msg': 'Internal Server Error'
                            })

        # unshare repo
        if operation == 'unshare':

            share_type = request.data.get('share_type', None)
            if not share_type:
                error_msg = 'share_type invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            if share_type not in ('user', 'group'):
                error_msg = 'share_type can only be "user", "group".'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            # unshare repo from user
            if share_type == 'user':
                to_username = request.data.get('username', None)
                if not to_username:
                    error_msg = 'username invalid.'
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

                for repo_id in valid_repo_id_list:

                    if not self.has_shared_to_user(request, repo_id, to_username):
                        result['failed'].append({
                            'repo_id': repo_id,
                            'error_msg': 'This item has not been shared to %s.' % to_username
                            })
                        continue

                    repo_owner = get_repo_owner(request, repo_id)
                    try:
                        # get share permission before unshare operation
                        permission = check_user_share_out_permission(repo_id,
                                '/', to_username, is_org_context(request))

                        if is_org_context(request):
                            # when calling syncwerk API to share authority related functions, change the uesrname to repo owner.
                            org_id = request.user.org.org_id
                            syncwerk_api.org_remove_share(org_id, repo_id, repo_owner, to_username)
                        else:
                            syncwerk_api.remove_share(repo_id, repo_owner, to_username)

                        # Delete share permission at ExtraSharePermission table.
                        ExtraSharePermission.objects.delete_share_permission(repo_id,
                                to_username)

                        # send message
                        send_perm_audit_msg('delete-repo-perm', username,
                                to_username, repo_id, '/', permission)

                        result['success'].append({
                            "repo_id": repo_id,
                            "username": to_username,
                        })
                    except Exception as e:
                        logger.error(e)
                        result['failed'].append({
                            'repo_id': repo_id,
                            'error_msg': 'Internal Server Error'
                        })

            # unshare repo from group
            if share_type == 'group':
                to_group_id = request.data.get('group_id', None)
                if not to_group_id:
                    error_msg = 'group_id invalid.'
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

                try:
                    to_group_id = int(to_group_id)
                except ValueError:
                    error_msg = 'group_id invalid.'
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

                group = ccnet_api.get_group(to_group_id)
                group_name = group.group_name if group else ''

                for repo_id in valid_repo_id_list:
                    if not self.has_shared_to_group(request, repo_id, to_group_id):
                        result['failed'].append({
                            'repo_id': repo_id,
                            'error_msg': 'This item has not been shared to %s.' % group_name
                        })
                        continue

                    try:
                        # get share permission before unshare operation
                        permission = check_group_share_out_permission(repo_id,
                                '/', to_group_id, is_org_context(request))

                        org_id = None
                        if is_org_context(request):
                            org_id = request.user.org.org_id
                            syncwerk_api.del_org_group_repo(repo_id, org_id, to_group_id)
                        else:
                            syncwerk_api.unset_group_repo(
                                    repo_id, to_group_id, username)

                        # Delete share permission at ExtraSharePermission table.
                        ExtraGroupsSharePermission.objects.delete_share_permission(repo_id,
                                to_group_id)

                        # send message
                        send_perm_audit_msg('delete-repo-perm', username,
                                to_group_id, repo_id, '/', permission)

                        result['success'].append({
                            "repo_id": repo_id,
                            "group_id": to_group_id,
                            "group_name": group_name,
                        })
                    except RpcsyncwerkError as e:
                        logger.error(e)
                        result['failed'].append({
                            'repo_id': repo_id,
                            'error_msg': 'Internal Server Error'
                        })

        return Response(result)


class ReposBatchCopyDirView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def post(self, request):
        """ Multi copy folders.

        Permission checking:
        1. User must has `r/rw` permission for src folder.
        2. User must has `rw` permission for dst folder.

        Parameter:
        {
            "src_repo_id":"7460f7ac-a0ff-4585-8906-bb5a57d2e118",
            "dst_repo_id":"a3fa768d-0f00-4343-8b8d-07b4077881db",
            "paths":[
                {"src_path":"/1/2/3/","dst_path":"/4/5/6/"},
                {"src_path":"/a/b/c/","dst_path":"/d/e/f/"},
            ]
        }
        """

        # argument check
        path_list = request.data.get('paths', None)
        if not path_list:
            error_msg = 'paths invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        src_repo_id = request.data.get('src_repo_id', None)
        if not src_repo_id:
            error_msg = 'src_repo_id invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        dst_repo_id = request.data.get('dst_repo_id', None)
        if not dst_repo_id:
            error_msg = 'dst_repo_id invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # permission check, user must has `r/rw` permission for src repo.
        if check_folder_permission(request, src_repo_id, '/') is None:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # permission check, user must has `rw` permission for dst repo.
        if check_folder_permission(request, dst_repo_id, '/') != 'rw':
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # resource check
        src_repo = syncwerk_api.get_repo(src_repo_id)
        if not src_repo:
            error_msg = 'Library %s not found.' % src_repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        dst_repo = syncwerk_api.get_repo(dst_repo_id)
        if not dst_repo:
            error_msg = 'Library %s not found.' % dst_repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # get total size of file/dir to be copied
        total_size = 0
        for path_item in path_list:
            src_path = path_item['src_path']
            src_path = normalize_dir_path(src_path)

            current_size = 0
            current_dir_id = syncwerk_api.get_dir_id_by_path(src_repo_id,
                    src_path)
            current_size = syncwerk_api.get_dir_size(src_repo.store_id,
                    src_repo.version, current_dir_id)

            total_size += current_size

        # check if above quota for dst repo
        if syncwerk_api.check_quota(dst_repo_id, total_size) < 0:
            return api_error(HTTP_443_ABOVE_QUOTA,  _(u"Out of quota."))

        result = {}
        result['failed'] = []
        result['success'] = []
        username = request.user.username

        for path_item in path_list:

            src_path = path_item['src_path']
            src_path = normalize_dir_path(src_path)
            src_parent_dir = os.path.dirname(src_path.rstrip('/'))
            src_parent_dir = normalize_dir_path(src_parent_dir)
            src_obj_name = os.path.basename(src_path.rstrip('/'))

            dst_path = path_item['dst_path']
            dst_path = normalize_dir_path(dst_path)
            dst_parent_dir = dst_path
            dst_obj_name = src_obj_name

            common_dict = {
                'src_repo_id': src_repo_id,
                'src_path': src_path,
                'dst_repo_id': dst_repo_id,
                'dst_path': dst_path,
            }

            # src/dst parameter check
            if src_repo_id == dst_repo_id and \
                    dst_path.startswith(src_path):
                error_dict = {
                    'error_msg': "The destination directory is the same as the source, or is it's subfolder."
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            if src_path == '/':
                error_dict = {
                    'error_msg': "The source path can not be '/'."
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            if len(dst_parent_dir + dst_obj_name) > MAX_PATH:
                error_dict = {
                    'error_msg': "'Destination path is too long."
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            # src resource check
            if not syncwerk_api.get_dir_id_by_path(src_repo_id, src_path):
                error_dict = {
                    'error_msg': 'Folder %s not found.' % src_path
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            # dst resource check
            if not syncwerk_api.get_dir_id_by_path(dst_repo_id, dst_path):
                error_dict = {
                    'error_msg': 'Folder %s not found.' % dst_path
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            # src path permission check, user must has `r/rw` permission for src folder.
            if check_folder_permission(request, src_repo_id, src_parent_dir) is None:
                error_dict = {
                    'error_msg': 'Permission denied.'
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            # dst path permission check, user must has `rw` permission for dst folder.
            if check_folder_permission(request, dst_repo_id, dst_path) != 'rw':
                error_dict = {
                    'error_msg': 'Permission denied.'
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            try:
                # need_progress=0, synchronous=1
                syncwerk_api.copy_file(src_repo_id, src_parent_dir, src_obj_name,
                        dst_repo_id, dst_parent_dir, dst_obj_name, username, 0, 1)
            except Exception as e:
                logger.error(e)
                error_dict = {
                    'error_msg': 'Internal Server Error'
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            result['success'].append(common_dict)

        return Response(result)


class ReposBatchCreateDirView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def post(self, request):
        """ Multi create folders.

        Permission checking:
        1. user with `rw` permission for every layer of subdirectories.

        Parameter:
        {
            "repo_id": "4dfdf5b6-806f-4a35-b2b7-604051d2114e",
            "paths": ["/1/2/", "/3/4/", "/5/6"]
        }
        """

        # argument check
        path_list = request.data.get('paths', None)
        if not path_list:
            error_msg = 'paths invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        repo_id = request.data.get('repo_id', None)
        if not repo_id:
            error_msg = 'repo_id invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if check_folder_permission(request, repo_id, '/') != 'rw':
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        result = {}
        result['failed'] = []
        result['success'] = []
        username = request.user.username

        for path in path_list:

            common_dict = {
                'repo_id': repo_id,
                'path': path,
            }

            path = normalize_dir_path(path)
            obj_name_list = path.strip('/').split('/')

            for obj_name in obj_name_list:
                try:
                    # check if path is valid
                    is_valid_name = syncwerk_api.is_valid_filename(
                            'fake_repo_id', obj_name)
                except Exception as e:
                    logger.error(e)
                    error_dict = {
                        'error_msg': 'Internal Server Error'
                    }
                    common_dict.update(error_dict)
                    result['failed'].append(common_dict)
                    continue

                if not is_valid_name:
                    error_dict = {
                        'error_msg': 'path invalid.'
                    }
                    common_dict.update(error_dict)
                    result['failed'].append(common_dict)
                    continue

            if syncwerk_api.get_dir_id_by_path(repo_id, path):
                error_dict = {
                    'error_msg': 'Folder already exists.'
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            # check parent directory's permission
            parent_dir = os.path.dirname(path.rstrip('/'))
            try:
                permission = get_folder_permission_recursively(
                        username, repo_id, parent_dir)
            except Exception as e:
                logger.error(e)
                error_dict = {
                    'error_msg': 'Internal Server Error'
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            if permission != 'rw':
                error_dict = {
                    'error_msg': 'Permission denied.'
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            try:
                # rename obj name if name is existed
                syncwerk_api.mkdir_with_parents(repo_id, '/', path.strip('/'), username)
            except Exception as e:
                logger.error(e)
                error_dict = {
                    'error_msg': 'Internal Server Error'
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            result['success'].append(common_dict)

        return Response(result)


class ReposBatchCopyItemView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def post(self, request):
        """ Multi copy files/folders.
        Permission checking:
        1. User must has `r/rw` permission for src folder.
        2. User must has `rw` permission for dst folder.
        Parameter:
        {
            "src_repo_id":"7460f7ac-a0ff-4585-8906-bb5a57d2e118",
            "dst_repo_id":"a3fa768d-0f00-4343-8b8d-07b4077881db",
            "paths":[
                {"src_path":"/1/2/3/","dst_path":"/4/5/6/"},
                {"src_path":"/a/b/c/","dst_path":"/d/e/f/"},
            ]
        }
        """

        # argument check
        path_list = request.data.get('paths', None)
        if not path_list:
            error_msg = 'paths invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        src_repo_id = request.data.get('src_repo_id', None)
        if not src_repo_id:
            error_msg = 'src_repo_id invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        dst_repo_id = request.data.get('dst_repo_id', None)
        if not dst_repo_id:
            error_msg = 'dst_repo_id invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        src_repo = syncwerk_api.get_repo(src_repo_id)
        if not src_repo:
            error_msg = 'Library %s not found.' % src_repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        dst_repo = syncwerk_api.get_repo(dst_repo_id)
        if not dst_repo:
            error_msg = 'Library %s not found.' % dst_repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if check_folder_permission(request, src_repo_id, '/') is None:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        if check_folder_permission(request, dst_repo_id, '/') is None:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        result = {}
        result['failed'] = []
        result['success'] = []
        username = request.user.username

        for path_item in path_list:

            src_path = path_item['src_path']
            src_path = normalize_dir_path(src_path)
            src_parent_dir = os.path.dirname(src_path.rstrip('/'))
            src_parent_dir = normalize_dir_path(src_parent_dir)
            src_obj_name = os.path.basename(src_path.rstrip('/'))

            dst_path = path_item['dst_path']
            dst_path = normalize_dir_path(dst_path)
            dst_parent_dir = dst_path
            dst_obj_name = src_obj_name

            common_dict = {
                'src_repo_id': src_repo_id,
                'src_path': src_path,
                'dst_repo_id': dst_repo_id,
                'dst_path': dst_path,
            }

            # src/dst parameter check
            if src_repo_id == dst_repo_id and \
                    dst_path.startswith(src_path):
                error_dict = {
                    'error_msg': "The destination directory is the same as the source, or is it's subfolder."
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            if src_path == '/':
                error_dict = {
                    'error_msg': "The source path can not be '/'."
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            if len(dst_parent_dir + dst_obj_name) > MAX_PATH:
                error_dict = {
                    'error_msg': "'Destination path is too long."
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            # src resource check
            ## as we don't know if `src_path` stands for a file or a folder,
            ## so we check both
            src_dir_id = syncwerk_api.get_dir_id_by_path(src_repo_id, src_path)
            src_file_id = syncwerk_api.get_file_id_by_path(src_repo_id,
                    normalize_file_path(src_path))

            if not src_dir_id and not src_file_id:
                error_dict = {
                    'error_msg': '%s not found.' % src_path
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            # dst resource check
            if not syncwerk_api.get_dir_id_by_path(dst_repo_id, dst_path):
                error_dict = {
                    'error_msg': 'Folder %s not found.' % dst_path
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            # src path permission check, user must has `r/rw` permission for src folder.
            if check_folder_permission(request, src_repo_id, src_parent_dir) is None:
                error_dict = {
                    'error_msg': 'Permission denied.'
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            # dst path permission check, user must has `rw` permission for dst folder.
            if check_folder_permission(request, dst_repo_id, dst_path) != 'rw':
                error_dict = {
                    'error_msg': 'Permission denied.'
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            try:
                dst_obj_name = check_filename_with_rename(dst_repo_id,
                        dst_parent_dir, dst_obj_name)
                # need_progress=0, synchronous=1
                syncwerk_api.copy_file(src_repo_id, src_parent_dir, src_obj_name,
                        dst_repo_id, dst_parent_dir, dst_obj_name, username, 0, 1)
            except Exception as e:
                logger.error(e)
                error_dict = {
                    'error_msg': 'Internal Server Error'
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            common_dict['dst_obj_name'] = dst_obj_name
            result['success'].append(common_dict)

        return Response(result)


class ReposBatchMoveItemView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def post(self, request):
        """ Multi move files/folders.
        Permission checking:
        1. User must has `rw` permission for src folder.
        2. User must has `rw` permission for dst folder.
        Parameter:
        {
            "src_repo_id":"7460f7ac-a0ff-4585-8906-bb5a57d2e118",
            "dst_repo_id":"a3fa768d-0f00-4343-8b8d-07b4077881db",
            "paths":[
                {"src_path":"/1/2/3/","dst_path":"/4/5/6/"},
                {"src_path":"/a/b/c/","dst_path":"/d/e/f/"},
            ]
        }
        """

        # argument check
        path_list = request.data.get('paths', None)
        if not path_list:
            error_msg = 'paths invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        src_repo_id = request.data.get('src_repo_id', None)
        if not src_repo_id:
            error_msg = 'src_repo_id invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        dst_repo_id = request.data.get('dst_repo_id', None)
        if not dst_repo_id:
            error_msg = 'dst_repo_id invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        src_repo = syncwerk_api.get_repo(src_repo_id)
        if not src_repo:
            error_msg = 'Library %s not found.' % src_repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        dst_repo = syncwerk_api.get_repo(dst_repo_id)
        if not dst_repo:
            error_msg = 'Library %s not found.' % dst_repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if check_folder_permission(request, src_repo_id, '/') is None:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        if check_folder_permission(request, dst_repo_id, '/') is None:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        result = {}
        result['failed'] = []
        result['success'] = []
        username = request.user.username

        for path_item in path_list:

            src_path = path_item['src_path']
            src_path = normalize_dir_path(src_path)
            src_parent_dir = os.path.dirname(src_path.rstrip('/'))
            src_parent_dir = normalize_dir_path(src_parent_dir)
            src_obj_name = os.path.basename(src_path.rstrip('/'))

            dst_path = path_item['dst_path']
            dst_path = normalize_dir_path(dst_path)
            dst_parent_dir = dst_path
            dst_obj_name = src_obj_name

            common_dict = {
                'src_repo_id': src_repo_id,
                'src_path': src_path,
                'dst_repo_id': dst_repo_id,
                'dst_path': dst_path,
            }

            # src/dst parameter check
            if src_repo_id == dst_repo_id and \
                    dst_path.startswith(src_path):
                error_dict = {
                    'error_msg': "The destination directory is the same as the source, or is it's subfolder."
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            if src_path == '/':
                error_dict = {
                    'error_msg': "The source path can not be '/'."
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            if len(dst_parent_dir + dst_obj_name) > MAX_PATH:
                error_dict = {
                    'error_msg': "'Destination path is too long."
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            # src resource check
            ## as we don't know if `src_path` stands for a file or a folder,
            ## so we check both
            src_dir_id = syncwerk_api.get_dir_id_by_path(src_repo_id, src_path)
            src_file_id = syncwerk_api.get_file_id_by_path(src_repo_id,
                    normalize_file_path(src_path))

            if not src_dir_id and not src_file_id:
                error_dict = {
                    'error_msg': '%s not found.' % src_path
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            # dst resource check
            if not syncwerk_api.get_dir_id_by_path(dst_repo_id, dst_path):
                error_dict = {
                    'error_msg': 'Folder %s not found.' % dst_path
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            # src path permission check, user must has `rw` permission for src folder.
            if check_folder_permission(request, src_repo_id, src_parent_dir) != 'rw':
                error_dict = {
                    'error_msg': 'Permission denied.'
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            # dst path permission check, user must has `rw` permission for dst folder.
            if check_folder_permission(request, dst_repo_id, dst_path) != 'rw':
                error_dict = {
                    'error_msg': 'Permission denied.'
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            try:
                dst_obj_name = check_filename_with_rename(dst_repo_id,
                        dst_parent_dir, dst_obj_name)
                # replace=False, username=username, need_progress=0, synchronous=1
                syncwerk_api.move_file(src_repo_id, src_parent_dir, src_obj_name,
                        dst_repo_id, dst_parent_dir, dst_obj_name,
                        False, username, 0, 1)
            except Exception as e:
                logger.error(e)
                error_dict = {
                    'error_msg': 'Internal Server Error'
                }
                common_dict.update(error_dict)
                result['failed'].append(common_dict)
                continue

            common_dict['dst_obj_name'] = dst_obj_name
            result['success'].append(common_dict)

        return Response(result)
