import os
import logging
import posixpath

from django.utils.translation import ugettext as _

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework import parsers

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response
from restapi.api3.views import get_dir_recursively, \
    get_dir_entrys_by_id

from restapi.views import check_folder_permission
from restapi.utils import check_filename_with_rename, is_valid_dirent_name, \
    normalize_dir_path
from restapi.utils.timeutils import timestamp_to_isoformat_timestr
from restapi.base.templatetags.restapi_tags import translate_restapi_time
from restapi.share.models import FileShare, UploadLinkShare

from synserv import syncwerk_api, check_permission
from pyrpcsyncwerk import RpcsyncwerkError

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

logger = logging.getLogger(__name__)


class DirView(APIView):
    """
    Support uniform interface for directory operations, including
    create/delete/rename/list, etc.
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    def get_dir_info(self, repo_id, dir_path):

        dir_obj = syncwerk_api.get_dirent_by_path(repo_id, dir_path)
        dir_info = {
            'type': 'dir',
            'repo_id': repo_id,
            'parent_dir': os.path.dirname(dir_path.rstrip('/')),
            'name': dir_obj.obj_name,
            'id': dir_obj.obj_id,
            'mtime': timestamp_to_isoformat_timestr(dir_obj.mtime),
            'last_update': translate_restapi_time(dir_obj.mtime),
            'permission': 'rw'
        }

        return dir_info

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get sub folder details',
        operation_description='''Get details and folder/file list of a sub-folder''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name="repo_id",
                in_="path",
                type='string',
                description='id of the folder to get details'
            ),
            openapi.Parameter(
                name="p",
                in_="query",
                type='string',
                description='path to the subfolder in the folder. Default to "/"'
            ),
            openapi.Parameter(
                name="oid",
                in_="query",
                type='string',
                description='object id of the folder. The object id is the checksum of the directory contents'
            ),
            openapi.Parameter(
                name="t",
                in_="query",
                type='string',
                description='''- "f" : only return files \n
- "d": only return sub folders \n
- not provided: return all files and subfolders.'''
            ),
            openapi.Parameter(
                name="recursive",
                in_="query",
                type='string',
                description='if set t argument as "d" AND this recursive argument as 1, return all dir entries recursively'
            ),
        ],
        responses={
            200: openapi.Response(
                description='Successfully retrieve result.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "repo_id": "bc90a682-dcc5-4bf2-b5a5-e575934c69e8",
                            "permission": "rw",
                            "encrypted": False,
                            "dir_perm": "rw",
                            "oid": "ddc397013c0c2b99c9b224801e36bdb03754efc0",
                            "dirent_list": [
                                {
                                    "name": "111",
                                    "permission": "rw",
                                    "last_update": "<time datetime=\"2019-02-11T10:25:08\" is=\"relative-time\" title=\"Mon, 11 Feb 2019 10:25:08 +0000\" >6 days ago</time>",
                                    "mtime": 1549880708,
                                    "type": "dir",
                                    "id": "0000000000000000000000000000000000000000"
                                },
                                {
                                    "lock_time": 0,
                                    "last_update": "<time datetime=\"2019-02-01T02:21:40\" is=\"relative-time\" title=\"Fri, 1 Feb 2019 02:21:40 +0000\" >2019-02-01</time>",
                                    "modifier_email": "admin@alpha.syncwerk.com",
                                    "name": "home.md",
                                    "permission": "rw",
                                    "is_locked": False,
                                    "lock_owner": "",
                                    "mtime": 1548987700,
                                    "modifier_contact_email": "admin@alpha.syncwerk.com",
                                    "starred": False,
                                    "locked_by_me": False,
                                    "type": "file",
                                    "id": "0000000000000000000000000000000000000000",
                                    "modifier_name": "admin",
                                    "size": 0
                                }
                            ],
                            "allow_view_snapshot": True,
                            "allow_view_history": True,
                            "owner": "admin@alpha.syncwerk.com",
                            "allow_restore_snapshot": True,
                            "repo_name": "test wiki 4"
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
            404: openapi.Response(
                description='Sub folder not found',
                examples={
                    'application/json': {
                        "message": "Folder not found",
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
        path = request.GET.get('p', '/')
        if path[-1] != '/':
            path = path + '/'

        # recource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        try:
            dir_id = syncwerk_api.get_dir_id_by_path(repo_id, path)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # permission check
        if not check_folder_permission(request, repo_id, path):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        username = request.user.username
        if repo.encrypted \
                and not syncwerk_api.is_password_set(repo.id, username):
            err_msg = _(u'Library is encrypted.')
            return api_response(data={'lib_need_decrypt': True, 'repo_name' : repo.name}, msg=err_msg)

        if not dir_id:
            error_msg = 'Folder %s not found.' % path
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        old_oid = request.GET.get('oid', None)
        if old_oid and old_oid == dir_id:
            # resp = Response({'success': True})
            resp = {'success': True}
            resp["oid"] = dir_id
            # return resp
            return api_response(status.HTTP_200_OK, '', resp)
        else:
            request_type = request.GET.get('t', None)
            if request_type and request_type not in ('f', 'd'):
                error_msg = "'t'(type) should be 'f' or 'd'."
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            if request_type == 'd':
                recursive = request.GET.get('recursive', '0')
                if recursive not in ('1', '0'):
                    error_msg = "If you want to get recursive dir entries, you should set 'recursive' argument as '1'."
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

                if recursive == '1':
                    username = request.user.username
                    dir_list = get_dir_recursively(username, repo_id, path, [])
                    dir_list.sort(lambda x, y: cmp(
                        x['name'].lower(), y['name'].lower()))

                    # resp = Response(dir_list)
                    resp = {'dirent_list': dir_list}
                    resp['repo_id'] = repo.repo_id
                    resp['repo_name'] = repo.name
                    resp['oid'] = dir_id
                    resp['dir_perm'] = syncwerk_api.check_permission_by_path(
                        repo_id, path, username)
                    resp['permission'] = check_permission(
                        repo.id, request.user.username)
                    resp['encrypted'] = r.encrypted
                    # return resp
                    return api_response(data=resp)

            # return get_dir_entrys_by_id(request, repo, path, dir_id, request_type)
            resp = get_dir_entrys_by_id(
                request, repo, path, dir_id, request_type)
            
            resp["user_permission"] = {
                'can_generate_share_link': request.user.permissions.can_generate_share_link(),
                'can_generate_upload_link': request.user.permissions.can_generate_upload_link(),
                # 'can_generate_share_link': False,
                # 'can_generate_upload_link': False
            }
            return api_response(data=resp)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Subfolder operation',
        operation_description='''Perform create items / rename items or revert operations on sub folders''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name="repo_id",
                in_="path",
                type='string',
                description='id of the folder to perform operations on'
            ),
            openapi.Parameter(
                name="p",
                in_="query",
                type='string',
                description='path to the subfolder in the folder to perform operations on. Default to "/"'
            ),
        ],
        request_body=openapi.Schema(
            type='object',
            properties={
                "operation": openapi.Schema(
                    description='''- "rename": rename file / subfolder
- "mkdir": create new subfolder. Name of the sub folder will be the "p" query parameter
- "revert": revert folder to a commit with commit_id''',
                    required=['rename','mkdir','revert'],
                    type='string'
                ),
                "newname": openapi.Schema(
                    description='If operation is "rename", this will be the new name of the subfolder',
                    type='string'
                ),
                "commit_id": openapi.Schema(
                    description='If operation is "revert", the subfolder defined in "p" query parameter in this commit id will be reverted',
                    type='string'
                ),
            }
        ),
        responses={
            200: openapi.Response(
                description='Operation performed successfully.',
                examples={
                    'application/json - rename / mkdir sucess': {
                        "message": "Folder renamed successfully / Create subfolder successfully.",
                        "data": {
                            "repo_id": "bc90a682-dcc5-4bf2-b5a5-e575934c69e8",
                            "name": "fffff",
                            "mtime": "2019-02-11T10:25:08+00:00",
                            "permission": "rw",
                            "type": "dir",
                            "id": "0000000000000000000000000000000000000000",
                            "parent_dir": "/",
                            "last_update": "<time datetime=\"2019-02-11T10:25:08\" is=\"relative-time\" title=\"Mon, 11 Feb 2019 10:25:08 +0000\" >6 days ago</time>"
                        }
                    },
                    'application/json - revert success': {
                        "message": "Folder reverted successfully.",
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
            404: openapi.Response(
                description='Sub folder not found',
                examples={
                    'application/json': {
                        "message": "Folder not found",
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
    def post(self, request, repo_id, format=None):

        # argument check
        path = request.GET.get('p', None)
        if not path or path[0] != '/':
            error_msg = 'p invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if path == '/':
            error_msg = 'Can not operate root dir.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        operation = request.data.get('operation', None)
        if not operation:
            error_msg = 'operation invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        operation = operation.lower()
        if operation not in ('mkdir', 'rename', 'revert'):
            error_msg = "operation can only be 'mkdir', 'rename' or 'revert'."
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        path = path.rstrip('/')
        username = request.user.username
        parent_dir = os.path.dirname(path)
        if operation == 'mkdir':
            # resource check
            parent_dir_id = syncwerk_api.get_dir_id_by_path(
                repo_id, parent_dir)
            if not parent_dir_id:
                error_msg = 'Folder %s not found.' % parent_dir
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

            # permission check
            if check_folder_permission(request, repo_id, parent_dir) != 'rw':
                error_msg = 'Permission denied.'
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)

            new_dir_name = os.path.basename(path)

            if not is_valid_dirent_name(new_dir_name):
                return api_error(status.HTTP_400_BAD_REQUEST,
                                 'name invalid.')

            new_dir_name = check_filename_with_rename(
                repo_id, parent_dir, new_dir_name)
            try:
                syncwerk_api.post_dir(
                    repo_id, parent_dir, new_dir_name, username)
            except RpcsyncwerkError as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            new_dir_path = posixpath.join(parent_dir, new_dir_name)
            dir_info = self.get_dir_info(repo_id, new_dir_path)
            # resp = Response(dir_info)
            # return resp
            return api_response(data=dir_info, msg='Folder created successfully.')

        if operation == 'rename':
            # resource check
            dir_id = syncwerk_api.get_dir_id_by_path(repo_id, path)
            if not dir_id:
                error_msg = 'Folder %s not found.' % path
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

            # permission check
            if check_folder_permission(request, repo_id, path) != 'rw':
                error_msg = 'Permission denied.'
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)

            old_dir_name = os.path.basename(path)
            new_dir_name = request.data.get('newname', None)

            if not new_dir_name:
                error_msg = 'newname invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            if not is_valid_dirent_name(new_dir_name):
                return api_error(status.HTTP_400_BAD_REQUEST,
                                 'name invalid.')

            if new_dir_name == old_dir_name:
                dir_info = self.get_dir_info(repo_id, path)
                # resp = Response(dir_info)
                # return resp
                return api_response(status.HTTP_200_OK, '', dir_info)

            try:
                # rename duplicate name
                new_dir_name = check_filename_with_rename(
                    repo_id, parent_dir, new_dir_name)
                # rename dir
                syncwerk_api.rename_file(repo_id, parent_dir, old_dir_name,
                                         new_dir_name, username)

                new_dir_path = posixpath.join(parent_dir, new_dir_name)
                dir_info = self.get_dir_info(repo_id, new_dir_path)
                # resp = Response(dir_info)
                # return resp
                return api_response(data=dir_info, msg='Folder renamed successfully.')
            except RpcsyncwerkError, e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if operation == 'revert':
            commit_id = request.data.get('commit_id', None)
            if not commit_id:
                error_msg = 'commit_id invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            if syncwerk_api.get_dir_id_by_path(repo_id, path):
                # dir exists in repo
                if check_folder_permission(request, repo_id, path) != 'rw':
                    error_msg = 'Permission denied.'
                    return api_error(status.HTTP_403_FORBIDDEN, error_msg)
            else:
                # dir NOT exists in repo
                if check_folder_permission(request, repo_id, '/') != 'rw':
                    error_msg = 'Permission denied.'
                    return api_error(status.HTTP_403_FORBIDDEN, error_msg)

            try:
                syncwerk_api.revert_dir(repo_id, commit_id, path, username)
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            # return Response({'success': True})
            return api_response(msg=_('Folder reverted successfully.'))

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Delete subfolder',
        operation_description='''Delete a specific subfolder''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name="repo_id",
                in_="path",
                type='string',
                description='id of the folder contains the sub folder to be deleted'
            ),
            openapi.Parameter(
                name="p",
                in_="query",
                type='string',
                description='path to the subfolder to be deleted.',
                required=True
            ),
        ],
        responses={
            200: openapi.Response(
                description='Successfully delete folder.',
                examples={
                    'application/json': {
                        "message": "Delete folder successfully.",
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
            404: openapi.Response(
                description='Sub folder not found',
                examples={
                    'application/json': {
                        "message": "Folder not found",
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
        path = request.GET.get('p', None)
        if not path:
            error_msg = _('p invalid.')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if path == '/':
            error_msg = _('Can not delete root path.')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        dir_id = syncwerk_api.get_dir_id_by_path(repo_id, path)
        if not dir_id:
            error_msg = _('Folder %s not found.') % path
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = _('Folder %s not found.') % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if check_folder_permission(request, repo_id, path) != 'rw':
            error_msg = _('Permission denied.')
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        if path[-1] == '/':
            path = path[:-1]

        path = path.rstrip('/')
        username = request.user.username
        parent_dir = os.path.dirname(path)
        dir_name = os.path.basename(path)

        logger.debug('Deleting path: %s', path)
        try:
            syncwerk_api.del_file(repo_id, parent_dir, dir_name, username)

            try:
                # remove download link / upload link if exists
                fileshare = FileShare.objects.get(
                    username=username, repo_id=repo_id, path=path + '/')
                if (fileshare):
                    fileshare.delete()
            except FileShare.DoesNotExist as e:
                logger.debug(
                    'Can not found the folder %s in repo %', path, repo_id)
            try:
                uploadshare = UploadLinkShare.objects.get(
                    username=username, repo_id=repo_id, path=path + '/')
                if uploadshare:
                    uploadshare.delete()
            except UploadLinkShare.DoesNotExist as e:
                logger.debug(
                    'Can not found the folder %s in repo %', path, repo_id)

        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = _('Internal Server Error')
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # return Response({'success': True})
        return api_response(msg=_('Delete folder successfully.'))


class DirDetailView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Subfolder info',
        operation_description='''Get subfolder information''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name="repo_id",
                in_="path",
                type='string',
                description='id of the folder contains the sub folder'
            ),
            openapi.Parameter(
                name="p",
                in_="query",
                type='string',
                description='path to the subfolder',
                required=True
            ),
        ],
        responses={
            200: openapi.Response(
                description='Successfully retrieve information.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "repo_id": "bc90a682-dcc5-4bf2-b5a5-e575934c69e8",
                            "name": "fffff",
                            "file_count": 0,
                            "dir_count": 0,
                            "mtime": "2019-02-11T10:25:08+00:00",
                            "path": "/fffff/",
                            "size": 0
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
            404: openapi.Response(
                description='Sub folder not found',
                examples={
                    'application/json': {
                        "message": "Folder not found",
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
    def get(self, request, repo_id):

        # parameter check
        path = request.GET.get('path', None)
        if not path:
            error_msg = 'path invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        path = normalize_dir_path(path)
        if path == '/':
            error_msg = 'path invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        dir_id = syncwerk_api.get_dir_id_by_path(repo_id, path)
        if not dir_id:
            error_msg = 'Folder %s not found.' % path
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if not check_folder_permission(request, repo_id, path):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        try:
            dir_obj = syncwerk_api.get_dirent_by_path(repo_id, path)
            count_info = syncwerk_api.get_file_count_info_by_path(
                repo_id, path)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        dir_info = {
            'repo_id': repo_id,
            'path': path,
            'name': dir_obj.obj_name,
            'file_count': count_info.file_count,
            'dir_count': count_info.dir_count,
            'size': count_info.size,
            'mtime': timestamp_to_isoformat_timestr(dir_obj.mtime),
        }

        # return Response(dir_info)
        return api_response(data=dir_info)
