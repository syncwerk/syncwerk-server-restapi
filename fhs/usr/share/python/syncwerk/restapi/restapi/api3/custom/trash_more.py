import stat
import logging

from django.http import Http404
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response

from restapi.settings import MEDIA_URL
from restapi.views import check_folder_permission
from restapi.utils.timeutils import timestamp_to_isoformat_timestr
from restapi.base.templatetags.restapi_tags import translate_restapi_time

from synserv import syncwerk_api, get_repo
from pyrpcsyncwerk import RpcsyncwerkError

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

logger = logging.getLogger(__name__)

class TrashMore(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='List first/"more" batch of repo/dir trash.',
        operation_description='''List first/'more' batch of repo/dir trash.''',
        tags=['folders'],
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
                description='path',
            ),
            openapi.Parameter(
                name='show_days',
                in_="query",
                type='string',
                description='number of days to show',
            ),
            openapi.Parameter(
                name='scan_stat',
                in_="query",
                type='string',
                description='',
            ),
            openapi.Parameter(
                name='limit',
                in_="query",
                type='string',
                description='',
            ),
        ],
        responses={
            200: openapi.Response(
                description='snapshot dirents retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "new_scan_stat": None,
                            "trash": {
                                "repo": {
                                    "repo_id": "83b3ca02-1809-40eb-89b0-65bc1de3807d",
                                    "name": "My Folder"
                                },
                                "show_recycle_root": True,
                                "dir_entries": [
                                    {
                                        "commit_id": "c0f365c3d2843e8e7a3499fccc27c723d7bdb791",
                                        "delete_time": "<time datetime=\"2019-02-19T07:01:52\" is=\"relative-time\" title=\"Tue, 19 Feb 2019 07:01:52 +0000\" >3 seconds ago</time>",
                                        "name": "fefe",
                                        "mtime": "2019-02-19T07:01:52+00:00",
                                        "basedir": "/",
                                        "type": "dir",
                                        "id": "f927aeae939e0c2b121b8a216cbabc9d5e9378d0",
                                        "size": 0
                                    },
                                    {
                                        "commit_id": "f7a4c55dd401889ea132f991a808209b0547b17c",
                                        "delete_time": "<time datetime=\"2019-02-19T07:01:48\" is=\"relative-time\" title=\"Tue, 19 Feb 2019 07:01:48 +0000\" >7 seconds ago</time>",
                                        "name": "Tro-choi-hoi-cho.docx",
                                        "mtime": "2019-02-19T07:01:48+00:00",
                                        "basedir": "/",
                                        "type": "file",
                                        "id": "db04c7a315dba932beedbe20c667fa7201c1dd8d",
                                        "size": 9
                                    }
                                ],
                                "dir_path": "/",
                                "MEDIA_URL": "/rest/media/"
                            },
                            "trash_more": False
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
            404: openapi.Response(
                description='Folder not found',
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
        
        result = {}

        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            err_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, err_msg,)

        path = request.GET.get('path', '/')
        path = '/' if path == '' else path
        if check_folder_permission(request, repo_id, path) != 'rw':
            err_msg = 'Permission denied.'
            return api_error(status.HTTP_403_FORBIDDEN, err_msg,)

        try:
            show_days = int(request.GET.get('show_days', '0'))
        except ValueError:
            show_days = 0

        if show_days < 0:
            error_msg = 'show_days invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        scan_stat = request.GET.get('scan_stat', None)
        limit = int(request.GET.get('limit', '100'))
        try:
            # a list will be returned, with at least 1 item in it
            # the last item is not a deleted entry, and it contains an attribute named 'scan_stat'
            deleted_entries = syncwerk_api.get_deleted(repo_id, show_days, path, scan_stat, limit)
        except RpcsyncwerkError as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Internal server error',)

        new_scan_stat = deleted_entries[-1].scan_stat
        trash_more = True if new_scan_stat is not None else False

        ctx = {
            'show_recycle_root': True,
            'repo': {
                'repo_id': repo.repo_id,
                'name': repo.name
            },
            'dir_entries': [],
            'dir_path': path,
            'MEDIA_URL': MEDIA_URL
        }
        if len(deleted_entries) > 1:
            deleted_entries = deleted_entries[0:-1]
            for dirent in deleted_entries:
                if stat.S_ISDIR(dirent.mode):
                    dirent.is_dir = True
                else:
                    dirent.is_dir = False

            # Entries sort by deletion time in descending order.
            deleted_entries.sort(lambda x, y : cmp(y.delete_time, x.delete_time))

            dirents = []
            for dirent in deleted_entries:
                dirents.append({
                    'type': 'dir' if dirent.is_dir else 'file',
                    'name': dirent.obj_name,
                    'id': dirent.obj_id,
                    'mtime': timestamp_to_isoformat_timestr(dirent.delete_time),
                    'delete_time': translate_restapi_time(dirent.delete_time),
                    'commit_id': dirent.commit_id,
                    'size': dirent.file_size,
                    'basedir': dirent.basedir
                })

            ctx['dir_entries'] = dirents

        result = {
            'trash': ctx,
            'trash_more': trash_more,
            'new_scan_stat': new_scan_stat,
        }

        return api_response(data=result)
