from es import es_search
from synserv import syncwerk_api
from restapi.utils.timeutils import timestamp_to_isoformat_timestr
from restapi.base.templatetags.restapi_tags import translate_restapi_time
import os
from restapi.api3.utils.file import lock_file, check_file_lock, unlock_file, get_file_lock_info


def get_dir_info(repo_id, dir_path):
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


def get_file_info(username, repo_id, file_path):
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


def get_search_results(request, repo, path, dir_id, search_query):
    results = es_search(search_query, {
        "repo_id": repo.id,
        "parent_path": path
    })
    api_results = []
    for result in results:
        dir_id = syncwerk_api.get_dir_id_by_path(result['repo_id'], result['file_path'])
        if dir_id:
            api_results.append(get_dir_info(repo.id, result['file_path']))
        else:
            api_results.append(get_file_info(request.user.username, result['repo_id'], result['file_path']))
    return {'data': api_results}
