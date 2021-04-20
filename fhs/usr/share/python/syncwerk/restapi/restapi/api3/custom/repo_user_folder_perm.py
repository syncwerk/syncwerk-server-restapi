import os
import logging

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated

from restapi.api3.base import APIView
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response, send_perm_audit_signal

from restapi.base.accounts import User
from restapi.utils import is_org_context, is_pro_version, is_valid_username, send_perm_audit_msg
from restapi.base.templatetags.restapi_tags import email2nickname
from restapi.settings import ENABLE_FOLDER_PERM

import synserv
from synserv import syncwerk_api

from pyrpcsyncwerk import RpcsyncwerkError

logger = logging.getLogger(__name__)

class RepoUserFolderPerm(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)
    swagger_schema = None

    def _get_user_folder_perm_info(self, email, repo_id, path, perm):
        result = {}
        if email and repo_id and path and perm:
            result['repo_id'] = repo_id
            result['user_email'] = email
            result['user_name'] = email2nickname(email)
            result['folder_path'] = path
            result['folder_name'] = path if path == '/' else os.path.basename(path.rstrip('/'))
            result['permission'] = perm

        return result

    def get(self, request, repo_id, format=None):
        """ List repo user folder perms (by folder_path).

        Permission checking:
        1. repo owner & pro edition.

        ---
        # YAML

        type:
          Authorization:
            required: true
            type: string
          repo_id:
            required: true
            type: string
          folder_path:
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
            - name: folder_path
              required: false
              type: string
              paramType: query

        responseMessages:
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

        # resource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if is_org_context(request):
            repo_owner = syncwerk_api.get_org_repo_owner(repo_id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo_id)

        username = request.user.username
        if not (is_pro_version() and ENABLE_FOLDER_PERM and username == repo_owner):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # get perm list
        results = []
        path = request.GET.get('folder_path', None)
        folder_perms = syncwerk_api.list_folder_user_perm_by_repo(repo_id)
        for perm in folder_perms:
            result = {}
            if path:
                if path == perm.path:
                    result = self._get_user_folder_perm_info(
                            perm.user, perm.repo_id, perm.path, perm.permission)
            else:
                result = self._get_user_folder_perm_info(
                        perm.user, perm.repo_id, perm.path, perm.permission)

            if result:
                results.append(result)

        # return Response(results)
        return api_response(data=results)

    def post(self, request, repo_id, format=None):
        """ Add repo user folder perm.

        Permission checking:
        1. repo owner & pro edition & enable folder perm.

        ---
        # YAML

        type:
          Authorization:
            required: true
            type: string
          repo_id:
            required: true
            type: string
          folder_path:
            required: false
            type: string
          permission:
            required: false
            type: string
          user_email:
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
            - name: folder_path
              required: false
              type: string
              paramType: form
            - name: permission
              required: false
              type: string
              paramType: form
            - name: user_email
              required: false
              type: string
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

        # argument check
        path = request.data.get('folder_path', None)
        if not path:
            error_msg = 'folder_path invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        perm = request.data.get('permission', None)
        if not perm or perm not in ('r', 'rw'):
            error_msg = 'permission invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        path = path.rstrip('/') if path != '/' else path
        if not syncwerk_api.get_dir_id_by_path(repo_id, path):
            error_msg = 'Folder %s not found.' % path
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if is_org_context(request):
            repo_owner = syncwerk_api.get_org_repo_owner(repo_id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo_id)

        username = request.user.username
        if not (is_pro_version() and ENABLE_FOLDER_PERM and username == repo_owner):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # add repo user folder perm
        result = {}
        result['failed'] = []
        result['success'] = []

        users = request.data.getlist('user_email')
        for user in users:
            if not is_valid_username(user):
                result['failed'].append({
                    'user_email': user,
                    'error_msg': 'user_email invalid.'
                })
                continue

            try:
                User.objects.get(email=user)
            except User.DoesNotExist:
                result['failed'].append({
                    'user_email': user,
                    'error_msg': 'User %s not found.' % user
                })
                continue

            permission = syncwerk_api.get_folder_user_perm(repo_id, path, user)
            if permission:
                result['failed'].append({
                    'user_email': user,
                    'error_msg': 'Permission already exists.'
                })
                continue

            try:
                syncwerk_api.add_folder_user_perm(repo_id, path, perm, user)
                send_perm_audit_msg('add-repo-perm', username, user, repo_id, path, perm)
                send_perm_audit_signal(request, 'add-repo-perm', repo_id, path, perm, user, 'user_email')
            except RpcsyncwerkError as e:
                logger.error(e)
                result['failed'].append({
                    'user_email': user,
                    'error_msg': 'Internal Server Error'
                })

            new_perm = syncwerk_api.get_folder_user_perm(repo_id, path, user)
            new_perm_info = self._get_user_folder_perm_info(
                    user, repo_id, path, new_perm)
            result['success'].append(new_perm_info)

        # return Response(result)
        return api_response(data=result)

    def put(self, request, repo_id, format=None):
        """ Modify repo user folder perm.

        Permission checking:
        1. repo owner & pro edition & enable folder perm.

        ---
        # YAML

        type:
          Authorization:
            required: true
            type: string
          repo_id:
            required: true
            type: string
          folder_path:
            required: false
            type: string
          permission:
            required: false
            type: string
          user_email:
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
            - name: folder_path
              required: false
              type: string
              paramType: form
            - name: permission
              required: false
              type: string
              paramType: form
            - name: user_email
              required: false
              type: string
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

        # argument check
        path = request.data.get('folder_path', None)
        if not path:
            error_msg = 'folder_path invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        perm = request.data.get('permission', None)
        if not perm or perm not in ('r', 'rw'):
            error_msg = 'permission invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        user = request.data.get('user_email', None)
        if not user:
            error_msg = 'user_email invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        path = path.rstrip('/') if path != '/' else path
        if not syncwerk_api.get_dir_id_by_path(repo_id, path):
            error_msg = 'Folder %s not found.' % path
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        try:
            User.objects.get(email=user)
        except User.DoesNotExist:
            error_msg = 'User %s not found.' % user
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if is_org_context(request):
            repo_owner = syncwerk_api.get_org_repo_owner(repo_id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo_id)

        username = request.user.username
        if not (is_pro_version() and ENABLE_FOLDER_PERM and username == repo_owner):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        permission = syncwerk_api.get_folder_user_perm(repo_id, path, user)
        if not permission:
            error_msg = 'Folder permission not found.'
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # modify permission
        try:
            syncwerk_api.set_folder_user_perm(repo_id, path, perm, user)
            send_perm_audit_msg('modify-repo-perm', username, user, repo_id, path, perm)
            send_perm_audit_signal(request, 'modify-repo-perm', repo_id, path, perm, user, 'user_email')
            new_perm = syncwerk_api.get_folder_user_perm(repo_id, path, user)
            result = self._get_user_folder_perm_info(user, repo_id, path, new_perm)
            # return Response(result)
            return api_response(data=result)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

    def delete(self, request, repo_id, format=None):
        """ Remove repo user folder perm.

        Permission checking:
        1. repo owner & pro edition & enable folder perm.

        ---
        # YAML

        type:
          Authorization:
            required: true
            type: string
          repo_id:
            required: true
            type: string
          user_email:
            required: false
            type: string
          folder_path:
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
            - name: user_email
              required: false
              type: string
              paramType: form
            - name: folder_path
              required: false
              type: string
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
        
        # argument check
        user = request.data.get('user_email', None)
        path = request.data.get('folder_path', None)

        if not user:
            error_msg = 'user_email invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if not path:
            error_msg = 'folder_path invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        try:
            User.objects.get(email=user)
        except User.DoesNotExist:
            error_msg = 'User %s not found.' % user
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if is_org_context(request):
            repo_owner = syncwerk_api.get_org_repo_owner(repo_id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo_id)

        username = request.user.username
        if not (is_pro_version() and ENABLE_FOLDER_PERM) or \
                repo.is_virtual or username != repo_owner:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # delete permission
        path = path.rstrip('/') if path != '/' else path
        permission = syncwerk_api.get_folder_user_perm(repo_id, path, user)
        if not permission:
            # return Response({'success': True})
            return api_response()

        try:
            syncwerk_api.rm_folder_user_perm(repo_id, path, user)
            send_perm_audit_msg('delete-repo-perm', username,
                    user, repo_id, path, permission)
            send_perm_audit_signal(request, 'delete-repo-perm', repo_id, path, permission, user, 'user_email')
            # return Response({'success': True})
            return api_response()
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)
