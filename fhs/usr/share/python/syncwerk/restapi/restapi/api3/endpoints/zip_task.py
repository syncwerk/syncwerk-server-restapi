# Copyright (c) 2012-2016 Seafile Ltd.
import logging
import json
import stat
import posixpath

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.utils.translation import ugettext as _

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response

from restapi.views import check_folder_permission
from restapi.views.file import send_file_access_msg
from restapi.utils import is_windows_operating_system, gen_dir_zip_download_url

import synserv
from synserv import syncwerk_api

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

logger = logging.getLogger(__name__)

class ZipTaskView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get server token for zipping / multi-download task',
        operation_description='''Get server token for zipping / multi-download task''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='folder id.',
            ),
            openapi.Parameter(
                name='parent_dir',
                in_="query",
                type='string',
                description='parent folder.',
            ),
            openapi.Parameter(
                name='dirents',
                in_="query",
                type='string',
                description='file / folder name in the parent_dir that you want to download. Provide multiple of this parameter for each file / folder you want to bundle.',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Server token retrieved successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "url": "https://alpha.syncwerk.com/seafhttp/zip/908d6753-3f23-47bb-8927-25ed07553ebe",
                            "zip_token": "908d6753-3f23-47bb-8927-25ed07553ebe"
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
            403: openapi.Response(
                description='Operation not permitted',
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
        # argument check
        parent_dir = request.GET.get('parent_dir', None)
        if not parent_dir:
            error_msg = 'parent_dir invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        dirent_name_list = request.GET.getlist('dirents', None)
        if not dirent_name_list:
            error_msg = 'dirents invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if len(dirent_name_list) == 1:
            download_type = 'download-dir'
        elif len(dirent_name_list) > 1:
            download_type = 'download-multi'
        else:
            error_msg = 'dirents invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # recourse check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if not syncwerk_api.get_dir_id_by_path(repo_id, parent_dir):
            error_msg = 'Folder %s not found.' % parent_dir
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if not check_folder_permission(request, repo_id, parent_dir):
            error_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # get file server access token
        is_windows = 0
        if is_windows_operating_system(request):
            is_windows = 1

        if download_type == 'download-dir':
            dir_name = dirent_name_list[0].strip('/')
            full_dir_path = posixpath.join(parent_dir, dir_name)

            dir_id = syncwerk_api.get_dir_id_by_path(repo_id, full_dir_path)
            if not dir_id:
                error_msg = 'Folder %s not found.' % full_dir_path
                return api_error(status.HTTP_404_NOT_FOUND, error_msg)

            dir_size = syncwerk_api.get_dir_size(
                    repo.store_id, repo.version, dir_id)

            if dir_size > synserv.MAX_DOWNLOAD_DIR_SIZE:
                error_msg = 'Unable to download directory "%s": size is too large.' % dir_name
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            fake_obj_id = {
                'obj_id': dir_id,
                'dir_name': dir_name,
                'is_windows': is_windows
            }

        if download_type == 'download-multi':
            dirent_list = []
            total_size = 0
            for dirent_name in dirent_name_list:
                dirent_name = dirent_name.strip('/')
                dirent_list.append(dirent_name)

                full_dirent_path = posixpath.join(parent_dir, dirent_name)
                current_dirent = syncwerk_api.get_dirent_by_path(repo_id, full_dirent_path)
                if not current_dirent:
                    continue

                if stat.S_ISDIR(current_dirent.mode):
                    total_size += syncwerk_api.get_dir_size(repo.store_id,
                        repo.version, current_dirent.obj_id)
                else:
                    total_size += current_dirent.size

            if total_size > synserv.MAX_DOWNLOAD_DIR_SIZE:
                error_msg = _('Total size exceeds limit.')
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            fake_obj_id = {
                'parent_dir': parent_dir,
                'file_list': dirent_list,
                'is_windows': is_windows
            }

        username = request.user.username
        try:
            zip_token = syncwerk_api.get_fileserver_access_token(
                    repo_id, json.dumps(fake_obj_id), download_type, username)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if not zip_token:
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if len(dirent_name_list) > 10:
            send_file_access_msg(request, repo, parent_dir, 'web')
        else:
            for dirent_name in dirent_name_list:
                full_dirent_path = posixpath.join(parent_dir, dirent_name)
                send_file_access_msg(request, repo, full_dirent_path, 'web')

        # return Response({'zip_token': zip_token})
        url = gen_dir_zip_download_url(zip_token)
        resp = {
            'url': url,
            'zip_token': zip_token
        }
        return api_response(data=resp)
