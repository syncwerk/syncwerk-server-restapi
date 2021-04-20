# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from functools import wraps

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from django.utils.translation import ugettext as _

from synserv import syncwerk_api, ccnet_api

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response

from restapi.base.accounts import User
from restapi.base.templatetags.restapi_tags import email2nickname
from restapi.utils import is_valid_username

logger = logging.getLogger(__name__)

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


def check_parameter(func):
    """
    Decorator for check parameter
    """
    @wraps(func)
    def _decorated(view, request, *args, **kwargs):
        # argument check
        if request.method == 'GET' or request.method == 'DELETE':
            repo_id = request.GET.get('repo_id', None)
            path = request.GET.get('path', '/')
            share_type = request.GET.get('share_type', None)
        else:
            repo_id = request.data.get('repo_id', None)
            path = request.data.get('path', '/')
            share_type = request.data.get('share_type', None)

        if not repo_id:
            error_msg = 'repo_id invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if not share_type or share_type not in ('user', 'group'):
            error_msg = 'share_type invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if not syncwerk_api.get_dir_id_by_path(repo_id, path):
            error_msg = 'Folder %s not found.' % path
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        return func(view, request, repo_id, path, share_type, *args, **kwargs)

    return _decorated

class AdminShares(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)

    @check_parameter
    def get(self, request, repo_id, path, share_type):
        """ List user/group shares

        Permission checking:
        1. admin user.

        ---
        # YAML

        type:
          Authorization:
            required: true
            type: string
          repo_id:
            required: true
            type: string
          path:
            required: false
            type: string
          share_type:
            required: true
            type: string

        parameters:
            - name: Authorization
              required: true
              type: string
              paramType: header
            - name: repo_id
              required: true
              type: string
              paramType: query
            - name: path
              description: Path, default is "/"
              required: true
              type: string
              paramType: query
            - name: share_type
              description: user or group
              required: true
              type: string
              paramType: query

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

        result = []

        # current `request.user.username` is admin user,
        # so need to identify the repo owner specifically.
        repo_owner = syncwerk_api.get_repo_owner(repo_id)
        if share_type == 'user':
            try:
                if path == '/':
                    share_items = syncwerk_api.list_repo_shared_to(
                            repo_owner, repo_id)
                else:
                    share_items = syncwerk_api.get_shared_users_for_subdir(
                            repo_id, path, repo_owner)
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            for share_item in share_items:

                user_email = share_item.user
                user_name = email2nickname(user_email) if user_email else '--'

                share_info = {}
                share_info['repo_id'] = repo_id
                share_info['path'] = path
                share_info['share_type'] = share_type
                share_info['user_email'] = user_email
                share_info['user_name'] = user_name
                share_info['permission'] = share_item.perm

                result.append(share_info)

        if share_type == 'group':
            try:
                if path == '/':
                    share_items = syncwerk_api.list_repo_shared_group_by_user(
                            repo_owner, repo_id)
                else:
                    share_items = syncwerk_api.get_shared_groups_for_subdir(
                            repo_id, path, repo_owner)
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            for share_item in share_items:

                group_id = share_item.group_id
                group = ccnet_api.get_group(group_id)
                group_name = group.group_name if group else '--'

                share_info = {}
                share_info['repo_id'] = repo_id
                share_info['path'] = path
                share_info['share_type'] = share_type
                share_info['group_id'] = group_id
                share_info['group_name'] = group_name
                share_info['permission'] = share_item.perm

                result.append(share_info)

        # return Response(result)
        return api_response(data=result)

    @check_parameter
    def post(self, request, repo_id, path, share_type):
        """ Admin share a library to user/group.

        Permission checking:
        1. admin user.

        ---
        # YAML

        type:
          Authorization:
            required: true
            type: string
          repo_id:
            required: true
            type: string
          path:
            required: false
            type: string
          share_type:
            required: true
            type: string
          share_to:
            required: true
            type: string
          permission:
            required: true
            type: string

        parameters:
            - name: Authorization
              required: true
              type: string
              paramType: header
            - name: repo_id
              required: true
              type: string
              paramType: query
            - name: path
              description: Path, default is "/"
              required: true
              type: string
              paramType: query
            - name: share_type
              description: user or group
              required: true
              type: string
              paramType: query
            - name: share_to
              description: list of email
              required: true
              type: string
              paramType: query
            - name: permission
              description: r or rw
              required: true
              type: string
              paramType: query

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

        # argument check
        permission = request.data.get('permission', None)
        if not permission or permission not in ('r', 'rw'):
            error_msg = 'permission invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        result = {}
        result['failed'] = []
        result['success'] = []
        group_names_to_share = request.data.getlist('share_to')
        share_to = request.data.getlist('share_to')

        # current `request.user.username` is admin user,
        # so need to identify the repo owner specifically.
        repo_owner = syncwerk_api.get_repo_owner(repo_id)

        if share_type == 'user':
            for email in share_to:
                if repo_owner == email:
                    result['failed'].append({
                        'user_email': email,
                        'error_msg': _(u'User %s is already library owner.') % email
                        })

                    continue

                if not is_valid_username(email):
                    result['failed'].append({
                        'user_email': email,
                        'error_msg': _('Email %s invalid.') % email
                        })

                    continue

                try:
                    User.objects.get(email=email)
                except User.DoesNotExist:
                    result['failed'].append({
                        'user_email': email,
                        'error_msg': 'User %s not found.' % email
                        })

                    continue

                try:
                    if path == '/':
                        syncwerk_api.share_repo(
                                repo_id, repo_owner, email, permission)
                    else:
                        syncwerk_api.share_subdir_to_user(
                                repo_id, path, repo_owner, email, permission)

                except Exception as e:
                    logger.error(e)
                    result['failed'].append({
                        'user_email': email,
                        'error_msg': 'Internal Server Error'
                        })

                    continue

                new_perm = syncwerk_api.check_permission_by_path(repo_id, path, email)
                result['success'].append({
                    "repo_id": repo_id,
                    "path": path,
                    "share_type": share_type,
                    "user_email": email,
                    "user_name": email2nickname(email),
                    "permission": new_perm
                })

        if share_type == 'group':
            share_to = []
            all_groups = ccnet_api.get_all_groups(-1, -1)
            group_found = -1
            for name in group_names_to_share:
                group_found = -1
                for group in all_groups:
                    group_name = group.group_name
                    if not group_name:
                        continue
                    # if is_group_owner(group.id, request.user.email) is False:
                    #     continue
                    if name == group_name:
                        share_to.append(group.id)
                        group_found = 0
                        break
                if group_found == -1:
                    result['failed'].append({
                        'group_name': name,
                        'error_msg': 'Group %s not found' % name
                    })
            for group_id in share_to:
                # try:
                #     group_id = int(group_id)
                # except ValueError as e:
                #     logger.error(e)
                #     result['failed'].append({
                #         'group_id': group_id,
                #         'error_msg': 'group_id %s invalid.' % group_id
                #         })

                #     continue

                # group = ccnet_api.get_group(group_id)
                # if not group:
                #     result['failed'].append({
                #         'group_id': group_id,
                #         'error_msg': 'Group %s not found' % group_id
                #         })

                #     continue

                try:
                    if path == '/':
                        syncwerk_api.set_group_repo(
                                repo_id, group_id, repo_owner, permission)
                    else:
                        syncwerk_api.share_subdir_to_group(
                                repo_id, path, repo_owner, group_id, permission)
                except Exception as e:
                    logger.error(e)
                    result['failed'].append({
                        "group_id": group_id,
                        'error_msg': 'Internal Server Error'
                        })

                    continue

                result['success'].append({
                    "repo_id": repo_id,
                    "path": path,
                    "share_type": share_type,
                    "group_id": group_id,
                    "group_name": group.group_name,
                    "permission": permission
                })

        # return Response(result)
        return api_response(data=result, msg=_('Added users/groups to share successfully'))

    @check_parameter
    def put(self, request, repo_id, path, share_type):
        """ Update user/group share permission.

        Permission checking:
        1. admin user.

        ---
        # YAML

        type:
          Authorization:
            required: true
            type: string
          repo_id:
            required: true
            type: string
          path:
            required: false
            type: string
          share_type:
            required: true
            type: string
          share_to:
            required: true
            type: string
          permission:
            required: true
            type: string

        parameters:
            - name: Authorization
              required: true
              type: string
              paramType: header
            - name: repo_id
              required: true
              type: string
              paramType: query
            - name: path
              description: Path, default is "/"
              required: true
              type: string
              paramType: query
            - name: share_type
              description: user or group
              required: true
              type: string
              paramType: query
            - name: share_to
              description: list of email
              required: true
              type: string
              paramType: query
            - name: permission
              description: r or rw
              required: true
              type: string
              paramType: query

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

        # argument check
        permission = request.data.get('permission', None)
        if not permission or permission not in ('r', 'rw'):
            error_msg = 'permission invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        share_info = {}
        share_info['repo_id'] = repo_id
        share_info['path'] = path
        share_info['share_type'] = share_type

        # current `request.user.username` is admin user,
        # so need to identify the repo owner specifically.
        repo_owner = syncwerk_api.get_repo_owner(repo_id)

        share_to = request.data.get('share_to', None)
        if share_type == 'user':
            email = share_to
            if not email or not is_valid_username(email):
                error_msg = 'email %s invalid.' % email
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            try:
                User.objects.get(email=email)
            except User.DoesNotExist:
                error_msg = 'User %s not found.' % email
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

            try:
                if path == '/':
                    syncwerk_api.set_share_permission(
                            repo_id, repo_owner, email, permission)
                else:
                    syncwerk_api.update_share_subdir_perm_for_user(
                            repo_id, path, repo_owner, email, permission)
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            new_perm = syncwerk_api.check_permission_by_path(repo_id, path, email)
            share_info['user_email'] = email
            share_info['user_name'] = email2nickname(email)
            share_info['permission'] = new_perm

        if share_type == 'group':
            group_id = share_to
            try:
                group_id = int(group_id)
            except ValueError:
                error_msg = 'group_id %s invalid.' % group_id
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            group = ccnet_api.get_group(group_id)
            if not group:
                error_msg = 'Group %s not found' % group_id
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

            try:
                if path == '/':
                    syncwerk_api.set_group_repo_permission(group_id,
                            repo_id, permission)
                else:
                    syncwerk_api.update_share_subdir_perm_for_group(
                            repo_id, path, repo_owner, group_id, permission)
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            share_info['group_id'] = group_id
            share_info['group_name'] = group.group_name
            share_info['permission'] = permission

        # return Response(share_info)
        return api_response(data=share_info, msg='Share permission updated successfully')

    @check_parameter
    def delete(self, request, repo_id, path, share_type):
        """ Delete user/group share permission.

        Permission checking:
        1. admin user.

        ---
        # YAML

        type:
          Authorization:
            required: true
            type: string
          repo_id:
            required: true
            type: string
          path:
            required: false
            type: string
          share_type:
            required: true
            type: string
          share_to:
            required: true
            type: string

        parameters:
            - name: Authorization
              required: true
              type: string
              paramType: header
            - name: repo_id
              required: true
              type: string
              paramType: query
            - name: path
              description: Path, default is "/"
              required: true
              type: string
              paramType: query
            - name: share_type
              description: user or group
              required: true
              type: string
              paramType: query
            - name: share_to
              description: list of email
              required: true
              type: string
              paramType: query

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

        # current `request.user.username` is admin user,
        # so need to identify the repo owner specifically.
        repo_owner = syncwerk_api.get_repo_owner(repo_id)

        share_to = request.GET.get('share_to', None)

        if share_type == 'user':
            email = share_to
            if not email or not is_valid_username(email):
                error_msg = 'email %s invalid.' % email
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            try:
                if path == '/':
                    syncwerk_api.remove_share(repo_id, repo_owner, email)
                else:
                    syncwerk_api.unshare_subdir_for_user(
                            repo_id, path, repo_owner, email)
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if share_type == 'group':
            group_id = share_to
            try:
                group_id = int(group_id)
            except ValueError:
                error_msg = 'group_id %s invalid' % group_id
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            try:
                if path == '/':
                    syncwerk_api.unset_group_repo(repo_id, group_id, repo_owner)
                else:
                    syncwerk_api.unshare_subdir_for_group(
                            repo_id, path, repo_owner, group_id)
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # return Response({'success': True})
        return api_response(msg=_('Removed from share successfully'))
