# Copyright (c) 2012-2016 Seafile Ltd.
import logging
import json
import os
import stat
import posixpath

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.utils.translation import ugettext as _
from constance import config

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response

from restapi.views import check_folder_permission
from restapi.views.file import send_file_access_msg
from restapi.utils import is_windows_operating_system, gen_dir_zip_download_url, get_file_type_and_ext, gen_file_get_url

import synserv
from synserv import syncwerk_api, get_commits, get_file_id_by_path

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema
from restapi.api3.utils.file import _file_view

logger = logging.getLogger(__name__)



def recursive_dir_files_only(repo_id, dir_id, username, full_dir_path):
    dir_files = syncwerk_api.list_dir_by_dir_id(repo_id, dir_id)
    urls = []
    for node in dir_files:
        name, ext = os.path.splitext(node.obj_name)
        full_name = posixpath.join(full_dir_path, name + ext)
        if not stat.S_ISDIR(node.mode):
            token = syncwerk_api.get_fileserver_access_token(repo_id,
                                                             node.obj_id, 'download', username, use_onetime=True)

            if not token:
                return api_error(status.HTTP_403_FORBIDDEN, 'Unable to view file')
            dl_url = gen_file_get_url(token, full_name.strip('/').replace('/', '_'))
            urls.append(dl_url)
        else:
            dir_files = recursive_dir_files_only(repo_id, node.obj_id, username, full_name)
            urls += dir_files
    return urls


class BatchDownloadView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Batch Download files without zipping',
        operation_description='''Batch Download files without zipping''',
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
                            "urls": ["https://alpha.syncwerk.com/seafhttp/zip/908d6753-3f23-47bb-8927-25ed07553ebe"]
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
        allowFoldersInBatch = getattr(config, 'ALLOW_FOLDERS_IN_BATCH')
        batchMaxFilesCount = getattr(config, 'BATCH_MAX_FILES_COUNT')
        # argument check
        parent_dir = request.GET.get('parent_dir', None)
        if not parent_dir:
            error_msg = 'parent_dir invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        dirent_name_list = request.GET.getlist('dirents', None)
        if not dirent_name_list:
            error_msg = 'dirents invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if len(dirent_name_list) == 0:
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
        username = request.user.username
        download_urls = []
        total_size = 0
        for dirent_name in dirent_name_list:
            dirent_name = dirent_name.strip('/')
            full_dir_path = posixpath.join(parent_dir, dirent_name)
            u_filename = os.path.basename(full_dir_path)
            current_commit = get_commits(repo_id, 0, 1)[0]
            filetype, fileext = get_file_type_and_ext(u_filename)
            file_perm = syncwerk_api.check_permission_by_path(repo_id, full_dir_path, username)
            if not file_perm:
                return api_error(status.HTTP_403_FORBIDDEN, _(u'Unable to view file'))
            obj_id = syncwerk_api.get_dir_id_by_path(repo_id, full_dir_path)
            if not obj_id:
                obj_id = get_file_id_by_path(repo_id, full_dir_path)
                token = syncwerk_api.get_fileserver_access_token(repo_id,
                                                                 obj_id, 'download', username, use_onetime=True)

                if not token:
                    return api_error(status.HTTP_403_FORBIDDEN, 'Unable to view file')
                dl_url = gen_file_get_url(token, u_filename)
                download_urls.append(dl_url)
                if not obj_id:
                    return api_error(status.HTTP_404_NOT_FOUND, _(u'File or Folder does not exist'))
            else:
                if str(allowFoldersInBatch) != '1':
                    return api_error(status.HTTP_404_NOT_FOUND, _(u"Folders aren't allowed in batch download")+str(allowFoldersInBatch))
                dir_files = recursive_dir_files_only(repo_id, obj_id, username, full_dir_path)
                download_urls += dir_files
            if len(download_urls) > batchMaxFilesCount:
                return api_error(status.HTTP_404_NOT_FOUND, _(u'A lot of files selected for batch download, maximum allowed')+':{}'.format(batchMaxFilesCount))
        if len(download_urls) > batchMaxFilesCount:
            return api_error(status.HTTP_404_NOT_FOUND, _(u'A lot of files selected for batch download, maximum allowed')+':{}'.format(batchMaxFilesCount))
        if len(dirent_name_list) > 10:
            send_file_access_msg(request, repo, parent_dir, 'web')
        else:
            for dirent_name in dirent_name_list:
                full_dirent_path = posixpath.join(parent_dir, dirent_name)
                send_file_access_msg(request, repo, full_dirent_path, 'web')


        resp = {
            'urls': download_urls,

        }
        return api_response(data=resp)
