# Copyright (c) 2012-2016 Seafile Ltd.
import os
import stat
import logging
import posixpath

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.template.defaultfilters import filesizeformat
from django.utils.translation import ugettext as _

from synserv import syncwerk_api, syncwserv_threaded_rpc
from pyrpcsyncwerk import RpcsyncwerkError

from restapi.utils.timeutils import timestamp_to_isoformat_timestr
from restapi.views.sysadmin import can_view_sys_admin_repo
from restapi.views.file import send_file_access_msg
from restapi.utils import is_org_context, gen_file_get_url, \
    check_filename_with_rename, is_valid_dirent_name
from restapi.views import get_system_default_repo_id

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema


def get_dirent_info(dirent):

    if stat.S_ISDIR(dirent.mode):
        is_file = False
    else:
        is_file = True

    result = {}
    result['is_file'] = is_file
    result['type'] = 'file' if is_file else 'dir'
    result['obj_name'] = dirent.obj_name
    result['name'] = dirent.obj_name
    result['file_size'] = filesizeformat(dirent.size) if is_file else ''
    result['size'] = dirent.size if is_file else ''
    result['last_update'] = timestamp_to_isoformat_timestr(dirent.mtime)
    result['mtime'] = timestamp_to_isoformat_timestr(dirent.mtime)

    return result


class AdminLibraryDirents(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - get all files/subfolders in a folder',
        operation_description='''get all files/subfolders in a folder''',
        tags=['admin-folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='parent_dir',
                in_="query",
                type='string',
                description='Default to "/"',
            ),
        ],
        responses={
            200: openapi.Response(
                description='List retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "repo_id": "32c13cd4-3752-46bc-b1cf-cff4d50a671f",
                            "dirent_list": [
                                {
                                    "name": "home.md",
                                    "obj_name": "home.md",
                                    "last_update": "2019-02-01T02:37:29+00:00",
                                    "mtime": "2019-02-01T02:37:29+00:00",
                                    "is_file": True,
                                    "file_size": "37\u00a0bytes",
                                    "type": "file",
                                    "size": 37
                                }
                            ],
                            "is_system_library": False,
                            "repo_name": "test wiki"
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
    def get(self, request, repo_id, format=None):

        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # if not can_view_sys_admin_repo(repo):
        #     error_msg = 'Feature disabled.'
        #     return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        repo_owner = syncwerk_api.get_repo_owner(repo_id)
        if not repo_owner:
            repo_owner = syncwerk_api.get_org_repo_owner(repo_id)

        if repo.encrypted \
            and not syncwerk_api.is_password_set(repo.id, repo_owner):
            err_msg = _(u'Library is encrypted.')
            return api_response(data={'lib_need_decrypt': True}, msg=err_msg)

        parent_dir = request.GET.get('parent_dir', '/')
        if not parent_dir:
            error_msg = 'parent_dir invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if parent_dir[-1] != '/':
            parent_dir = parent_dir + '/'

        dir_id = syncwerk_api.get_dir_id_by_path(repo_id, parent_dir)
        if not dir_id:
            error_msg = 'Folder %s not found.' % parent_dir
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if is_org_context(request):
            repo_owner = syncwerk_api.get_org_repo_owner(repo_id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo_id)

        try:
            dirs = syncwserv_threaded_rpc.list_dir_with_perm(repo_id,
                parent_dir, dir_id, repo_owner, -1, -1)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return_results = {}
        return_results['repo_name'] = repo.repo_name
        return_results['repo_id'] = repo.repo_id
        return_results['is_system_library'] = True if \
            repo.id == get_system_default_repo_id() else False
        return_results['dirent_list'] = []

        for dirent in dirs:
            dirent_info = get_dirent_info(dirent)
            return_results['dirent_list'].append(dirent_info)

        # return Response(return_results)
        return api_response(data=return_results)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - create file/subfolder in a folder',
        operation_description='''create file/subfolder in a folder''',
        tags=['admin-folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='parent_dir',
                in_="formData",
                type='string',
                description='parent folder',
                required=True,
            ),
            openapi.Parameter(
                name='obj_name',
                in_="formData",
                type='string',
                description='name of the new subfolder / file',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='New folder / file created successfully',
                examples={
                    'application/json': {
                        "message": "",
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
    def post(self, request, repo_id, format=None):
        
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if not can_view_sys_admin_repo(repo):
            error_msg = 'Feature disabled.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        parent_dir = request.GET.get('parent_dir', '/')
        if not parent_dir:
            error_msg = 'parent_dir invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if parent_dir[-1] != '/':
            parent_dir = parent_dir + '/'

        dir_id = syncwerk_api.get_dir_id_by_path(repo_id, parent_dir)
        if not dir_id:
            error_msg = 'Folder %s not found.' % parent_dir
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        obj_name = request.data.get('obj_name', None)
        if not obj_name or not is_valid_dirent_name(obj_name):
            error_msg = 'obj_name invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        obj_name = check_filename_with_rename(repo_id, parent_dir, obj_name)

        username = request.user.username
        try:
            syncwerk_api.post_dir(repo_id, parent_dir, obj_name, username)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        dirent_path = posixpath.join(parent_dir, obj_name)
        dirent = syncwerk_api.get_dirent_by_path(repo_id, dirent_path)
        dirent_info = get_dirent_info(dirent)

        # return Response(dirent_info)
        return api_response(data=dirent_info, msg=_('Folder was created successfully.'))

class AdminLibraryDirent(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - get info of a single file/subfolder in a folder',
        operation_description='''get info of a single file/subfolder in a folder''',
        tags=['admin-folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='path',
                in_="query",
                type='string',
                description='path to the file / folder',
                required=True,
            ),
            openapi.Parameter(
                name='dl',
                in_="query",
                type='string',
                description='if provided, then download link of the file / folder will be returned',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Info retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
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
    def get(self, request, repo_id):
        

        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if not can_view_sys_admin_repo(repo):
            error_msg = 'Feature disabled.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        path = request.GET.get('path', None)
        if not path:
            error_msg = 'path invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if path[0] != '/':
            path = '/' + path

        try:
            dirent = syncwerk_api.get_dirent_by_path(repo_id, path)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if not dirent:
            error_msg = 'file/folder %s not found.' % path
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if stat.S_ISDIR(dirent.mode):
            is_file = False
        else:
            is_file = True

        username = request.user.username
        if is_file and request.GET.get('dl', '0') == '1':

            token = syncwerk_api.get_fileserver_access_token(repo_id,
                    dirent.obj_id, 'download', username, use_onetime=True)

            if not token:
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

            dl_url = gen_file_get_url(token, dirent.obj_name)
            send_file_access_msg(request, repo, path, 'web')
            # return Response({'download_url': dl_url})
            resp = {'download_url': dl_url}
            return api_response(data=resp)

        dirent_info = get_dirent_info(dirent)

        # return Response(dirent_info)
        return api_response(data=dirent_info)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - delete a single file/subfolder in a folder',
        operation_description='''delete a single file/subfolder in a folder''',
        tags=['admin-folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='path',
                in_="query",
                type='string',
                description='path to the file / folder',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='File/Folder removed successfully',
                examples={
                    'application/json': {
                        "message": "",
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
    def delete(self, request, repo_id):
        

        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if not can_view_sys_admin_repo(repo):
            error_msg = 'Feature disabled.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        path = request.GET.get('path', None)
        if not path:
            error_msg = 'path invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if path[0] != '/':
            path = '/' + path

        file_id = None
        dir_id = None
        try:
            file_id = syncwerk_api.get_file_id_by_path(repo_id, path)
            dir_id = syncwerk_api.get_dir_id_by_path(repo_id, path)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if not file_id and not dir_id:
            # return Response({'success': True})
            return api_response()

        parent_dir = os.path.dirname(path)
        file_name = os.path.basename(path)
        try:
            syncwerk_api.del_file(repo_id,
                parent_dir, file_name, request.user.username)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # return Response({'success': True})
        return api_response(msg=_("Item was deleted successfully."))
