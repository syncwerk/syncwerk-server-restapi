# Copyright (c) 2012-2016 Seafile Ltd.
import posixpath
import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.utils.translation import ugettext as _
from django.utils.html import escape

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response

from restapi.views import check_folder_permission
from restapi.utils import check_filename_with_rename
from restapi.settings import MAX_PATH

from synserv import syncwerk_api

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class CopyMoveTaskView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Create copy/move file/folder task',
        operation_description='''Create copy/move file/folder task''',
        tags=['folders', 'files'],
        manual_parameters=[
            openapi.Parameter(
                name='src_repo_id',
                in_='formData',
                type='string',
                description='source folder id',
                required=True
            ),
            openapi.Parameter(
                name='src_parent_dir',
                in_='formData',
                type='string',
                description='parent id of the item to be moved / copy',
                required=True
            ),
            openapi.Parameter(
                name='src_dirent_name',
                in_='formData',
                type='string',
                description='name of the item to be moved/copy',
                required=True
            ),
            openapi.Parameter(
                name='dst_repo_id',
                in_='formData',
                type='string',
                description='destination folder id',
                required=True
            ),
            openapi.Parameter(
                name='dst_parent_dir',
                in_='formData',
                type='string',
                description='destination parent folder',
                required=True
            ),
            openapi.Parameter(
                name='operation',
                in_='formData',
                type='string',
                description='"move" or "copy"',
                enum=['move','copy'],
                required=True
            ),
            openapi.Parameter(
                name='dirent_type',
                in_='formData',
                type='string',
                description='"file" or "dir"',
                enum=['file','dir'],
                required=True
            ),
        ],
        responses={
            200: openapi.Response(
                description='Successfully create moved/copy task',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "task_id": "id of the task"
                        }
                    },
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
                        "detail": 'Token invalid'
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
    def post(self, request):
        src_repo_id = request.data.get('src_repo_id', None)
        src_parent_dir = request.data.get('src_parent_dir', None)
        src_dirent_name = request.data.get('src_dirent_name', None)
        dst_repo_id = request.data.get('dst_repo_id', None)
        dst_parent_dir = request.data.get('dst_parent_dir', None)
        operation = request.data.get('operation', None)
        dirent_type = request.data.get('dirent_type', None)

        # argument check
        if not src_repo_id:
            error_msg = _('src_repo_id invalid.')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if not src_parent_dir:
            error_msg = _('src_parent_dir invalid.')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if not src_dirent_name:
            error_msg = _('src_dirent_name invalid.')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if not dst_repo_id:
            error_msg = _('dst_repo_id invalid.')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if not dst_parent_dir:
            error_msg = _('dst_parent_dir invalid.')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if not operation:
            error_msg = _('operation invalid.')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if not dirent_type:
            error_msg = _('dirent_type invalid.')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if src_repo_id == dst_repo_id and src_parent_dir == dst_parent_dir:
            error_msg = _('Invalid destination path')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if len(dst_parent_dir + src_dirent_name) > MAX_PATH:
            error_msg = _('Destination path is too long.')
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        operation = operation.lower()
        if operation not in ('move', 'copy'):
            error_msg = _("operation can only be 'move' or 'copy'.")
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        dirent_type = dirent_type.lower()
        if dirent_type not in ('file', 'dir'):
            error_msg = _("dirent_type can only be 'file' or 'dir'.")
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # src resource check
        src_dirent_path = posixpath.join(src_parent_dir, src_dirent_name)
        if dirent_type == 'file':
            if not syncwerk_api.get_file_id_by_path(src_repo_id,
                    src_dirent_path):
                error_msg = _('File %s not found.' % src_dirent_path)
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if dirent_type == 'dir':
            if not syncwerk_api.get_dir_id_by_path(src_repo_id,
                    src_dirent_path):
                error_msg = _('Folder %s not found.' % src_dirent_path)
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # dst resource check
        if not syncwerk_api.get_dir_id_by_path(dst_repo_id,
                dst_parent_dir):
            error_msg = _('Folder %s not found.' % dst_parent_dir)
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check for dst parent dir
        if check_folder_permission(request, dst_repo_id, dst_parent_dir) != 'rw':
            error_msg = _('Permission denied.')
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        new_dirent_name = check_filename_with_rename(dst_repo_id,
                dst_parent_dir, src_dirent_name)

        username = request.user.username
        if operation == 'move':
            if dirent_type == 'dir' and src_repo_id == dst_repo_id and \
                    dst_parent_dir.startswith(src_dirent_path + '/'):

                error_msg = _(u'Can not move directory %(src)s to its subdirectory %(des)s') \
                    % {'src': escape(src_dirent_path), 'des': escape(dst_parent_dir)}
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            # permission check for src parent dir
            if check_folder_permission(request, src_repo_id, src_parent_dir) != 'rw':
                error_msg = _('Permission denied.')
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)

            try:
                res = syncwerk_api.move_file(src_repo_id, src_parent_dir,
                        src_dirent_name, dst_repo_id, dst_parent_dir,
                        new_dirent_name, replace=False, username=username,
                        need_progress=1)
            except Exception as e:
                logger.error(e)
                error_msg = _('Internal Server Error')
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if operation == 'copy':
            # permission check for src parent dir
            if not check_folder_permission(request, src_repo_id, src_parent_dir):
                error_msg = _('Permission denied.')
                return api_error(status.HTTP_403_FORBIDDEN, error_msg)

            try:
                res = syncwerk_api.copy_file(src_repo_id, src_parent_dir,
                        src_dirent_name, dst_repo_id, dst_parent_dir,
                        new_dirent_name, username=username,
                        need_progress=1)
            except Exception as e:
                logger.error(e)
                error_msg = _('Internal Server Error')
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if not res:
            error_msg = _('Internal Server Error')
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        result = {}
        if res.background:
            result['task_id'] = res.task_id

        msg = ''
        if dirent_type == 'file':
            if operation == 'move':
                msg = _('Successfully moved file %s.') % (src_dirent_name)
            else:
                msg = _('Successfully copied file %s.') % (src_dirent_name)
        if dirent_type == 'dir':
            if operation == 'move':
                msg = _('Successfully moved folder %s.') % (src_dirent_name)
            else:
                msg = _('Successfully copied folder %s.') % (src_dirent_name)

        # return Response(result)
        return api_response(data=result, msg=msg)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Copy/move file/folder',
        operation_description='''Copy/move file/folder''',
        tags=['folders', 'files'],
        manual_parameters=[
            openapi.Parameter(
                name='task_id',
                in_='formData',
                type='string',
                description='task id',
                required=True
            ),
        ],
        responses={
            200: openapi.Response(
                description='Task canceled.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    },
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
                        "detail": 'Token invalid'
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
    def delete(self, request):
        # argument check
        task_id = request.data.get('task_id')
        if not task_id:
            error_msg = 'task_id invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            res = syncwerk_api.cancel_copy_task(task_id) # returns 0 or -1
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if res == 0:
            # return Response({'success': True})
            return api_response()
        else:
            error_msg = _('Cancel failed')
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)
