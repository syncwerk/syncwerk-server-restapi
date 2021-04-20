import stat
import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import status

from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response
from restapi.api3.utils.trash import gen_path_link

from restapi.base.templatetags.restapi_tags import translate_restapi_time
from restapi.utils import is_org_context
from restapi.utils.timeutils import timestamp_to_isoformat_timestr
from restapi.views import check_folder_permission

from synserv import syncwerk_api, get_repo, syncwserv_threaded_rpc
from pyrpcsyncwerk import RpcsyncwerkError

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

logger = logging.getLogger(__name__)


def render_recycle_root(request, repo_id):
    repo = get_repo(repo_id)
    if not repo:
        return api_error(status.HTTP_404_NOT_FOUND, 'Repo not found.')

    username = request.user.username
    if is_org_context(request):
        repo_owner = syncwerk_api.get_org_repo_owner(repo.id)
    else:
        repo_owner = syncwerk_api.get_repo_owner(repo.id)
    is_repo_owner = True if repo_owner == username else False

    enable_clean = False
    if is_repo_owner:
        enable_clean = True

    dirents, dir_path, trash_more, new_scan_stat = get_deleted(request, repo_id)

    resp = {
        'show_recycle_root': True,
        'repo': {
            'id': repo.repo_id,
            'name': repo.name
        },
        'repo_dir_name': repo.name,
        'enable_clean': enable_clean,
        # 'dir_entries': dirents,
        # 'dir_path': dir_path,
        # 'trash_more': trash_more,
        # 'new_scan_stat': new_scan_stat
    }

    return api_response(data=resp)


def render_recycle_dir(request, repo_id, commit_id):
    basedir = request.GET.get('base', '')
    path = request.GET.get('p', '')
    if not basedir or not path:
        return render_recycle_root(request, repo_id)

    if basedir[0] != '/':
        basedir = '/' + basedir
    if path[-1] != '/':
        path += '/'

    repo = get_repo(repo_id)
    if not repo:
        return api_error(status.HTTP_404_NOT_FOUND, 'Repo not found.')

    try:
        commit = syncwserv_threaded_rpc.get_commit(repo.id, repo.version, commit_id)
    except RpcsyncwerkError as e:
        logger.error(e)
        return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, '')

    if not commit:
        return api_error(status.HTTP_404_NOT_FOUND, 'Commit not found.')

    zipped = gen_path_link(path, '')

    dir_entries = syncwerk_api.list_dir_by_commit_and_path(commit.repo_id,
                                                   commit.id, basedir+path,
                                                   -1, -1)

    entries = []
    for dirent in dir_entries:
        if stat.S_ISDIR(dirent.mode):
            dirent.is_dir = True
        else:
            dirent.is_dir = False
        entry = {
            'type': 'dir' if dirent.is_dir else 'file',
            'name': dirent.obj_name,
            'id': dirent.obj_id,
            'mtime': timestamp_to_isoformat_timestr(dirent.mtime),
            'last_update': translate_restapi_time(dirent.mtime)
        }
        entries.append(entry)

    resp = {
        'show_recycle_root': False,
        'repo': {
            'id': repo.repo_id,
            'name': repo.name
        },
        'repo_dir_name': repo.name,
        'zipped': zipped,
        'dir_entries': entries,
        'commit_id': commit_id,
        'basedir': basedir,
        'path': path,
    }
    return api_response(data=resp)


def get_deleted(request, repo_id):
    result = {}

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
                'mtime': timestamp_to_isoformat_timestr(dirent.mtime),
                'last_update': translate_restapi_time(dirent.mtime)
            })

    return dirents, path, trash_more, new_scan_stat


class RepoTrash(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get folder trash items',
        operation_description='''Get items in the trash''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
            openapi.Parameter(
                name='commit_id',
                in_="query",
                type='string',
                description='commit id',
            ),
            openapi.Parameter(
                name='base',
                in_="query",
                type='string',
                description='base folder',
            ),
            openapi.Parameter(
                name='p',
                in_="query",
                type='string',
                description='path of the folder in the trash',
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
        
        if not syncwerk_api.get_dir_id_by_path(repo_id, '/') or \
            check_folder_permission(request, repo_id, '/') != 'rw':
            return api_error(status.HTTP_403_FORBIDDEN, 'Unable to view recycle page')

        commit_id = request.GET.get('commit_id', '')
        if not commit_id:
            return render_recycle_root(request, repo_id)
        else:
            return render_recycle_dir(request, repo_id, commit_id)
