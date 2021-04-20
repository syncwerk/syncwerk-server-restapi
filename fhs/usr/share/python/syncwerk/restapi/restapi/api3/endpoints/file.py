import os
import logging
import posixpath
import requests

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import status

from django.utils.translation import ugettext as _

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response, get_file_size
from restapi.api3.utils.file import lock_file, check_file_lock, unlock_file, get_file_lock_info

from restapi.utils import check_filename_with_rename, is_pro_version, \
    gen_file_upload_url, is_valid_dirent_name
from restapi.utils.timeutils import timestamp_to_isoformat_timestr
from restapi.views import check_folder_permission
from restapi.base.templatetags.restapi_tags import translate_restapi_time
from restapi.share.models import FileShare

from restapi.settings import MAX_UPLOAD_FILE_NAME_LEN, \
    FILE_LOCK_EXPIRATION_DAYS, OFFICE_TEMPLATE_ROOT

from synserv import syncwerk_api, syncwserv_threaded_rpc
from pyrpcsyncwerk import RpcsyncwerkError

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

logger = logging.getLogger(__name__)


class FileView(APIView):
    """
    Support uniform interface for file related operations,
    including create/delete/rename/view, etc.
    """

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    parser_classes=(parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser)

    def get_file_info(self, username, repo_id, file_path):

        file_obj = syncwerk_api.get_dirent_by_path(repo_id, file_path)
        is_locked, locked_by_me = check_file_lock(repo_id, file_path, username)
        file_info = {
            'type': 'file',
            'repo_id': repo_id,
            'parent_dir': os.path.dirname(file_path),
            'name': file_obj.obj_name,
            'id': file_obj.obj_id,
            'size': file_obj.size,
            'mtime': timestamp_to_isoformat_timestr(file_obj.mtime),
            'is_locked': is_locked,
            'last_update': translate_restapi_time(file_obj.mtime),
            'permission': 'rw'
        }

        return file_info

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get file details',
        operation_description='''Get details of a specific file''',
        tags=['files'],
        manual_parameters=[
            openapi.Parameter(
                name="repo_id",
                in_="path",
                type='string',
                description='id of the folder contains the file to get details'
            ),
            openapi.Parameter(
                name="p",
                in_="query",
                type='string',
                description='path to the file',
                required=True
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
                            "name": "home.md",
                            "mtime": "2019-02-01T02:21:40+00:00",
                            "is_locked": False,
                            "permission": "rw",
                            "last_update": "<time datetime=\"2019-02-01T02:21:40\" is=\"relative-time\" title=\"Fri, 1 Feb 2019 02:21:40 +0000\" >2019-02-01</time>",
                            "type": "file",
                            "id": "0000000000000000000000000000000000000000",
                            "parent_dir": "/",
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
    def get(self, request, repo_id, format=None):
    
        # argument check
        path = request.GET.get('p', None)
        if not path:
            error_msg = 'p invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        try:
            file_id = syncwerk_api.get_file_id_by_path(repo_id, path)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if not file_id:
            error_msg = 'File %s not found.' % path
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        parent_dir = os.path.dirname(path)
        if check_folder_permission(request, repo_id, parent_dir) is None:
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        file_info = self.get_file_info(request.user.username, repo_id, path)
        # return Response(file_info)
        return api_response(data=file_info)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='File operations',
        operation_description='''Perform specific operation on a specific files''',
        tags=['files'],
        manual_parameters=[
            openapi.Parameter(
                name="repo_id",
                in_="path",
                type='string',
                description='id of the folder contains the file'
            ),
            openapi.Parameter(
                name="p",
                in_="query",
                type='string',
                description='path to the file',
                required=True
            ),
        ],
        request_body=openapi.Schema(
            type='object',
            properties={
                "operation": openapi.Schema(
                    description='''- "create": create a new file specified in "p" query parameter
- "rename": rename file
- "move": move file
- "copy": copy file
- "revert": revert file''',
                    required=['create','rename','move','copy','revert'],
                    type='string'
                ),
                "newname": openapi.Schema(
                    description='if operation is "rename", this will be the new name of the file',
                    type='string'
                ),
                "dst_repo": openapi.Schema(
                    description='if operation is "move" or "copy", this will be the id of the destination folder',
                    type='string'
                ),
                "dst_dir": openapi.Schema(
                    description='if operation is "move" or "copy", this will be the destination path in the destination folder',
                    type='string'
                ),
                "commit_id": openapi.Schema(
                    description='if operation is "revert", the file specified in "path" will be reverted to this commit',
                    type='string'
                ),
            }
        ),
        responses={
            200: openapi.Response(
                description='Operation success.',
                examples={
                    'application/json': {
                        "message": "File renamed successfully.",
                        "data": {
                            "repo_id": "bc90a682-dcc5-4bf2-b5a5-e575934c69e8",
                            "name": "dddd.md",
                            "mtime": "2019-02-01T02:21:40+00:00",
                            "is_locked": False,
                            "permission": "rw",
                            "last_update": "<time datetime=\"2019-02-01T02:21:40\" is=\"relative-time\" title=\"Fri, 1 Feb 2019 02:21:40 +0000\" >2019-02-01</time>",
                            "type": "file",
                            "id": "0000000000000000000000000000000000000000",
                            "parent_dir": "/",
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
    def post(self, request, repo_id, format=None):
       # argument check
        path = request.GET.get('p', None)
        if not path or path[0] != '/':
            error_msg = 'p invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        operation = request.data.get('operation', None)
        if not operation:
            error_msg = 'operation invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        operation = operation.lower()
        if operation not in ('create', 'rename', 'move', 'copy', 'revert'):
            error_msg = "operation can only be 'create', 'rename', 'move', 'copy' or 'revert'."
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        username = request.user.username
        parent_dir = os.path.dirname(path)

        if operation == 'create':
            # resource check
            try:
                parent_dir_id = syncwerk_api.get_dir_id_by_path(repo_id, parent_dir)
            except RpcsyncwerkError as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            if not parent_dir_id:
                error_msg = 'Folder %s not found.' % parent_dir
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

            # permission check
            if check_folder_permission(request, repo_id, parent_dir) != 'rw':
                error_msg = 'Permission denied.'
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)

            # create new empty file
            new_file_name = os.path.basename(path)

            if not is_valid_dirent_name(new_file_name):
                return api_error(status.HTTP_400_BAD_REQUEST,
                                 'name invalid.')

            new_file_name = check_filename_with_rename(repo_id, parent_dir, new_file_name)

            try:
                syncwerk_api.post_empty_file(repo_id, parent_dir, new_file_name, username)
            except RpcsyncwerkError, e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            # update office file by template
            if new_file_name.endswith('.xlsx'):
                empty_file_path = os.path.join(OFFICE_TEMPLATE_ROOT, 'empty.xlsx')
            elif new_file_name.endswith('.pptx'):
                empty_file_path = os.path.join(OFFICE_TEMPLATE_ROOT, 'empty.pptx')
            elif new_file_name.endswith('.docx'):
                empty_file_path = os.path.join(OFFICE_TEMPLATE_ROOT, 'empty.docx')
            else:
                empty_file_path = ''

            if empty_file_path:
                # get file server update url
                update_token = syncwerk_api.get_fileserver_access_token(
                        repo_id, 'dummy', 'update', username)

                if not update_token:
                    error_msg = 'Internal Server Error'
                    return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

                update_url = gen_file_upload_url(update_token, 'update-api')

                # update file
                try:
                    requests.post(
                        update_url,
                        data={'filename': new_file_name, 'target_file': path},
                        files={'file': open(empty_file_path, 'rb')}
                    )
                except Exception as e:
                    logger.error(e)

            new_file_path = posixpath.join(parent_dir, new_file_name)
            file_info = self.get_file_info(username, repo_id, new_file_path)
            # return Response(file_info)
            return api_response(data=file_info, msg='File created successfully.')

        if operation == 'rename':
            # argument check
            new_file_name = request.data.get('newname', None)
            if not new_file_name:
                error_msg = 'newname invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            if not is_valid_dirent_name(new_file_name):
                return api_error(status.HTTP_400_BAD_REQUEST,
                                 'name invalid.')

            if len(new_file_name) > MAX_UPLOAD_FILE_NAME_LEN:
                error_msg = 'newname is too long.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            oldname = os.path.basename(path)
            if oldname == new_file_name:
                error_msg = 'The new name is the same to the old'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            # resource check
            try:
                file_id = syncwerk_api.get_file_id_by_path(repo_id, path)
            except RpcsyncwerkError as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            if not file_id:
                error_msg = 'File %s not found.' % path
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

            # permission check
            if check_folder_permission(request, repo_id, parent_dir) != 'rw':
                error_msg = 'Permission denied.'
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)

            # rename file
            new_file_name = check_filename_with_rename(repo_id, parent_dir,
                    new_file_name)
            try:
                syncwerk_api.rename_file(repo_id, parent_dir, oldname,
                        new_file_name, username)
            except RpcsyncwerkError as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            new_file_path = posixpath.join(parent_dir, new_file_name)
            file_info = self.get_file_info(username, repo_id, new_file_path)
            # return Response(file_info)
            return api_response(data=file_info, msg='File renamed successfully.')

        if operation == 'move':
            # argument check
            dst_repo_id = request.data.get('dst_repo', None)
            dst_dir = request.data.get('dst_dir', None)
            if not dst_repo_id:
                error_msg = 'dst_repo invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            if not dst_dir:
                error_msg = 'dst_dir invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            # resource check for source file
            try:
                file_id = syncwerk_api.get_file_id_by_path(repo_id, path)
            except RpcsyncwerkError as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            if not file_id:
                error_msg = 'File %s not found.' % path
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

            # resource check for dst repo and dir
            dst_repo = syncwerk_api.get_repo(dst_repo_id)
            if not dst_repo:
                error_msg = 'Library %s not found.' % dst_repo_id
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

            dst_dir_id = syncwerk_api.get_dir_id_by_path(dst_repo_id, dst_dir)
            if not dst_dir_id:
                error_msg = 'Folder %s not found.' % dst_dir
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

            # permission check for source file
            src_repo_id = repo_id
            src_dir = os.path.dirname(path)
            if check_folder_permission(request, src_repo_id, src_dir) != 'rw':
                error_msg = 'Permission denied.'
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)

            # permission check for dst dir
            if check_folder_permission(request, dst_repo_id, dst_dir) != 'rw':
                error_msg = 'Permission denied.'
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)

            # move file
            if dst_dir[-1] != '/': # Append '/' to the end of directory if necessary
                dst_dir += '/'

            if src_repo_id == dst_repo_id and src_dir == dst_dir:
                file_info = self.get_file_info(username, repo_id, path)
                # return Response(file_info)
                return api_response(data=file_info)

            filename = os.path.basename(path)
            new_file_name = check_filename_with_rename(dst_repo_id, dst_dir, filename)
            try:
                syncwerk_api.move_file(src_repo_id, src_dir, filename,
                        dst_repo_id, dst_dir, new_file_name, replace=False,
                        username=username, need_progress=0, synchronous=1)
            except RpcsyncwerkError as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            dst_file_path = posixpath.join(dst_dir, new_file_name)
            dst_file_info = self.get_file_info(username, dst_repo_id, dst_file_path)
            # return Response(dst_file_info)
            return api_response(data=dst_file_info, msg='File moved successfully.')

        if operation == 'copy':
            # argument check
            dst_repo_id = request.data.get('dst_repo', None)
            dst_dir = request.data.get('dst_dir', None)
            if not dst_repo_id:
                error_msg = 'dst_repo_id invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            if not dst_dir:
                error_msg = 'dst_dir invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            # resource check for source file
            try:
                file_id = syncwerk_api.get_file_id_by_path(repo_id, path)
            except RpcsyncwerkError as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            if not file_id:
                error_msg = 'File %s not found.' % path
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

            # resource check for dst repo and dir
            dst_repo = syncwerk_api.get_repo(dst_repo_id)
            if not dst_repo:
                error_msg = 'Library %s not found.' % dst_repo_id
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

            dst_dir_id = syncwerk_api.get_dir_id_by_path(dst_repo_id, dst_dir)
            if not dst_dir_id:
                error_msg = 'Folder %s not found.' % dst_dir
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

            # permission check for source file
            src_repo_id = repo_id
            src_dir = os.path.dirname(path)
            if not check_folder_permission(request, src_repo_id, src_dir):
                error_msg = 'Permission denied.'
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)

            # permission check for dst dir
            if check_folder_permission(request, dst_repo_id, dst_dir) != 'rw':
                error_msg = 'Permission denied.'
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)

            # copy file
            if dst_dir[-1] != '/': # Append '/' to the end of directory if necessary
                dst_dir += '/'

            if src_repo_id == dst_repo_id and src_dir == dst_dir:
                file_info = self.get_file_info(username, repo_id, path)
                # return Response(file_info)
            return api_response(data=file_info)

            filename = os.path.basename(path)
            new_file_name = check_filename_with_rename(dst_repo_id, dst_dir, filename)
            try:
                syncwerk_api.copy_file(src_repo_id, src_dir, filename, dst_repo_id,
                          dst_dir, new_file_name, username, 0, synchronous=1)
            except RpcsyncwerkError as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            dst_file_path = posixpath.join(dst_dir, new_file_name)
            dst_file_info = self.get_file_info(username, dst_repo_id, dst_file_path)
            # return Response(dst_file_info)
            return api_response(data=dst_file_info, msg='File copied successfully.')

        if operation == 'revert':
            commit_id = request.data.get('commit_id', None)
            if not commit_id:
                error_msg = 'commit_id invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            if syncwerk_api.get_file_id_by_path(repo_id, path):
                # file exists in repo
                if check_folder_permission(request, repo_id, parent_dir) != 'rw':
                    error_msg = 'Permission denied.'
                    return api_error(status.HTTP_403_FORBIDDEN, error_msg)

                is_locked, locked_by_me = check_file_lock(repo_id, path, username)
                if (is_locked, locked_by_me) == (None, None):
                    error_msg = _("Check file lock error")
                    return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

                if is_locked and not locked_by_me:
                    error_msg = _("File is locked")
                    return api_error(status.HTTP_403_FORBIDDEN, error_msg)

            else:
                # file NOT exists in repo
                if check_folder_permission(request, repo_id, '/') != 'rw':
                    error_msg = 'Permission denied.'
                    return api_error(status.HTTP_403_FORBIDDEN, error_msg)

            try:
                syncwerk_api.revert_file(repo_id, commit_id, path, username)
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            # return Response({'success': True})
            return api_response(msg=_('File reverted successfully.'))

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Lock / unlock files',
        operation_description='''Lock / unlock a specific file''',
        tags=['files'],
        manual_parameters=[
            openapi.Parameter(
                name="repo_id",
                in_="path",
                type='string',
                description='id of the folder contains the file'
            ),
            openapi.Parameter(
                name="p",
                in_="query",
                type='string',
                description='path to the file',
                required=True
            ),          
        ],
        request_body=openapi.Schema(
            type='object',
            properties={
                'operation': openapi.Schema(
                    type='string',
                    description='"lock" or "unlock"'
                ),
                'operation': openapi.Schema(
                    type='number',
                    description='file lock expiration days'
                ),
            },
        ),
        responses={
            200: openapi.Response(
                description='Operation success.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "repo_id": "bc90a682-dcc5-4bf2-b5a5-e575934c69e8",
                            "name": "ttt.md",
                            "mtime": "2019-02-01T02:21:40+00:00",
                            "is_locked": True,
                            "permission": "rw",
                            "last_update": "<time datetime=\"2019-02-01T02:21:40\" is=\"relative-time\" title=\"Fri, 1 Feb 2019 02:21:40 +0000\" >2019-02-01</time>",
                            "type": "file",
                            "id": "0000000000000000000000000000000000000000",
                            "parent_dir": "/",
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
    def put(self, request, repo_id, format=None):
        if not is_pro_version():
            error_msg = 'file lock feature only supported in professional edition.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # argument check
        path = request.GET.get('p', None)
        if not path:
            error_msg = 'p invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        operation = request.data.get('operation', None)
        if not operation:
            error_msg = 'operation invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        operation = operation.lower()
        if operation not in ('lock', 'unlock'):
            error_msg = "operation can only be 'lock', or 'unlock'."
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        file_id = syncwerk_api.get_file_id_by_path(repo_id, path)
        if not file_id:
            error_msg = 'File %s not found.' % path
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        parent_dir = os.path.dirname(path)
        if check_folder_permission(request, repo_id, parent_dir) != 'rw':
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        username = request.user.username
        is_locked, locked_by_me = check_file_lock(repo_id, path, username)
        if operation == 'lock':
            if not is_locked:
                # lock file
                expire = request.data.get('expire', FILE_LOCK_EXPIRATION_DAYS)
                try:
                    lock_file(repo_id, path.lstrip('/'), username, expire)
                except RpcsyncwerkError, e:
                    logger.error(e)
                    error_msg = 'Internal Server Error'
                    return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if operation == 'unlock':
            if is_locked:
                if locked_by_me != 2:
                    error_msg = 'You can not unlock this file.'
                    return api_error(status.HTTP_403_FORBIDDEN, error_msg)

                # unlock file
                try:
                    unlock_file(repo_id, path.lstrip('/'))
                except RpcsyncwerkError, e:
                    logger.error(e)
                    error_msg = 'Internal Server Error'
                    return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        file_info = self.get_file_info(username, repo_id, path)
        # return Response(file_info)
        return api_response(data=file_info)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Delete file',
        operation_description='''Delete a specific file''',
        tags=['files'],
        manual_parameters=[
            openapi.Parameter(
                name="repo_id",
                in_="path",
                type='string',
                description='id of the folder contains the file'
            ),
            openapi.Parameter(
                name="p",
                in_="query",
                type='string',
                description='path to the file',
                required=True
            ),
        ],
        responses={
            200: openapi.Response(
                description='Operation success.',
                examples={
                    'application/json': {
                        "message": "Delete file successfully.",
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

        # resource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = _('Folder %s not found.') % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        file_id = syncwerk_api.get_file_id_by_path(repo_id, path)
        if not file_id:
            error_msg = _('File %s not found.') % path
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        parent_dir = os.path.dirname(path)
        if check_folder_permission(request, repo_id, parent_dir) != 'rw':
            error_msg = _('Permission denied.')
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # delete file
        file_name = os.path.basename(path)
        try:
            syncwerk_api.del_file(repo_id, parent_dir,
                                 file_name, request.user.username)
            try:
                # remove file share link
                fileshare = FileShare.objects.get(repo_id=repo_id,path=path)
                if fileshare:
                    fileshare.delete();
            except FileShare.DoesNotExist as e:
                logger.debug('Can not found the file %s in repo %', path, repo_id)

        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = _('Internal Server Error')
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # return Response({'success': True})
        return api_response(msg=_('Delete file successfully.'))


class FileDetailView(APIView):
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='File info',
        operation_description='''Get file info''',
        tags=['files'],
        manual_parameters=[
            openapi.Parameter(
                name="repo_id",
                in_="path",
                type='string',
                description='id of the folder contains the file'
            ),
            openapi.Parameter(
                name="p",
                in_="query",
                type='string',
                description='path to the file',
                required=True
            ),
        ],
        responses={
            200: openapi.Response(
                description='Successfully retrieve information.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {}
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
        repo = syncwerk_api.get_repo(repo_id)
        if repo is None:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Library not found.')

        path = request.GET.get('path', None)
        if path is None:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Path is missing.')

        commit_id = request.GET.get('commit_id', None)
        if commit_id:
            try:
                obj_id = syncwserv_threaded_rpc.get_file_id_by_commit_and_path(
                    repo.id, commit_id, path)
            except RpcsyncwerkError as e:
                logger.error(e)
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                                 'Failed to get file id.')
        else:
            try:
                obj_id = syncwerk_api.get_file_id_by_path(repo_id, path)
            except RpcsyncwerkError as e:
                logger.error(e)
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                                 'Failed to get file id.')

        if not obj_id:
            return api_error(status.HTTP_404_NOT_FOUND, 'File not found.')

        # fetch file contributors and latest contributor
        try:
            # get real path for sub repo
            real_path = repo.origin_path + path if repo.origin_path else path
            dirent = syncwerk_api.get_dirent_by_path(repo.store_id, real_path)
            if dirent:
                latest_contributor, last_modified = dirent.modifier, dirent.mtime
            else:
                latest_contributor, last_modified = None, 0
        except RpcsyncwerkError as e:
            logger.error(e)
            latest_contributor, last_modified = None, 0

        entry = {}
        try:
            entry["size"] = get_file_size(repo.store_id, repo.version, obj_id)
        except Exception, e:
            entry["size"] = 0

        entry["type"] = "file"
        entry["name"] = os.path.basename(path)
        entry["id"] = obj_id
        entry["mtime"] = last_modified

        return api_response(data=entry)
