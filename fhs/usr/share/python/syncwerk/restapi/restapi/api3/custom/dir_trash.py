import os
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

from restapi.views import check_folder_permission
from restapi.utils.timeutils import timestamp_to_isoformat_timestr
from restapi.base.templatetags.restapi_tags import translate_restapi_time

from synserv import syncwerk_api, get_repo, syncwserv_threaded_rpc
from pyrpcsyncwerk import RpcsyncwerkError

logger = logging.getLogger(__name__)

def render_dir_recycle_root(request, repo_id, dir_path):
    repo = get_repo(repo_id)
    if not repo:
        return api_error(status.HTTP_404_NOT_FOUND, 'Repo not found.')

    # dirents, path, trash_more, new_scan_stat = get_deleted(request, repo_id)

    resp = {
        'show_recycle_root': True,
        'repo': {
            'id': repo.repo_id,
            'name': repo.name
        },
        'repo_dir_name': os.path.basename(dir_path.rstrip('/')),
        # 'dir_entries': dirents,
        'dir_path': dir_path,
        # 'trash_more': trash_more,
        # 'new_scan_stat': new_scan_stat
    }
    return api_response(data=resp)

def render_dir_recycle_dir(request, repo_id, commit_id, dir_path):
    basedir = request.GET.get('base', '')
    path = request.GET.get('p', '')
    if not basedir or not path:
        return render_dir_recycle_root(request, repo_id, dir_path)

    if basedir[0] != '/':
        basedir = '/' + basedir
    if path[-1] != '/':
        path += '/'

    repo = get_repo(repo_id)
    if not repo:
        return api_error(status.HTTP_404_NOT_FOUND, 'Repo not found.')

    try :
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
            'repo_id': repo.repo_id,
            'name': repo.name
        },
        'repo_dir_name': os.path.basename(dir_path.rstrip('/')),
        'zipped': zipped,
        'dir_entries': entries,
        'commit_id': commit_id,
        'basedir': basedir,
        'path': path,
        'dir_path': dir_path
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


class DirTrash(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )
    swagger_schema = None
    def get(self, request, repo_id, format=None):
        """ Get items in directory trash.
        ---
        # YAML

        type:
          Authorization:
            required: true
            type: string
          dir_path:
            required: false
            type: string
          commit_id:
            required: false
            type: string
          base:
            required: false
            type: string
          p:
            required: false
            type: string

        parameters:
            - name: Authorization
              required: true
              type: string
              paramType: header
            - name: dir_path
              required: false
              type: string
              paramType: query
            - name: commit_id
              required: false
              type: string
              paramType: query
            - name: base
              required: false
              type: string
              paramType: query
            - name: p
              required: false
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
        dir_path = request.GET.get('dir_path', '')

        if not syncwerk_api.get_dir_id_by_path(repo_id, dir_path) or \
            check_folder_permission(request, repo_id, dir_path) != 'rw':
            return api_error(status.HTTP_403_FORBIDDEN, 'Unable to view recycle page')

        commit_id = request.GET.get('commit_id', '')
        if not commit_id:
            return render_dir_recycle_root(request, repo_id, dir_path)
        else:
            return render_dir_recycle_dir(request, repo_id, commit_id, dir_path)
