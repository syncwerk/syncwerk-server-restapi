import logging
import stat

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated

from restapi.api3.base import APIView
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response, get_file_size

from restapi.base.templatetags.restapi_tags import email2nickname, email2contact_email
from restapi.views import check_folder_permission
from restapi.utils import is_pro_version, get_no_duplicate_obj_name

from pyrpcsyncwerk import RpcsyncwerkError
import synserv
from synserv import get_repo, syncwerk_api, syncwserv_threaded_rpc

logger = logging.getLogger(__name__)


def get_dir_entrys_by_id(request, repo, path, dir_id, request_type=None):
    """ Get dirents in a dir

    if request_type is 'f', only return file list,
    if request_type is 'd', only return dir list,
    else, return both.
    """
    username = request.user.username
    try:
        dirs = syncwserv_threaded_rpc.list_dir_with_perm(repo.id, path, dir_id,
                username, -1, -1)
        dirs = dirs if dirs else []
    except RpcsyncwerkError, e:
        logger.error(e)
        return api_error(HTTP_520_OPERATION_FAILED,
                         "Failed to list dir.")

    dir_list, file_list = [], []
    for dirent in dirs:
        entry = {}
        if stat.S_ISDIR(dirent.mode):
            dtype = "dir"
        else:
            dtype = "file"
            entry['modifier_email'] = dirent.modifier
            if repo.version == 0:
                entry["size"] = get_file_size(repo.store_id, repo.version,
                                              dirent.obj_id)
            else:
                entry["size"] = dirent.size
            if is_pro_version():
                entry["is_locked"] = dirent.is_locked
                entry["lock_owner"] = dirent.lock_owner
                entry["lock_time"] = dirent.lock_time
                if username == dirent.lock_owner:
                    entry["locked_by_me"] = True
                else:
                    entry["locked_by_me"] = False

        entry["type"] = dtype
        entry["name"] = dirent.obj_name
        entry["id"] = dirent.obj_id
        entry["mtime"] = dirent.mtime
        entry["permission"] = dirent.permission
        if dtype == 'dir':
            dir_list.append(entry)
        else:
            file_list.append(entry)

    # Use dict to reduce memcache fetch cost in large for-loop.
    contact_email_dict = {}
    nickname_dict = {}
    modifiers_set = set([x['modifier_email'] for x in file_list])
    for e in modifiers_set:
        if e not in contact_email_dict:
            contact_email_dict[e] = email2contact_email(e)
        if e not in nickname_dict:
            nickname_dict[e] = email2nickname(e)

    for e in file_list:
        e['modifier_contact_email'] = contact_email_dict.get(e['modifier_email'], '')
        e['modifier_name'] = nickname_dict.get(e['modifier_email'], '')

    dir_list.sort(lambda x, y: cmp(x['name'].lower(), y['name'].lower()))
    file_list.sort(lambda x, y: cmp(x['name'].lower(), y['name'].lower()))

    if request_type == 'f':
        dentrys = file_list
    elif request_type == 'd':
        dentrys = dir_list
    else:
        dentrys = dir_list + file_list

    # response = HttpResponse(json.dumps(dentrys), status=200,
    #                         content_type=json_content_type)
    response = dentrys
    response["oid"] = dir_id
    response["dir_perm"] = syncwerk_api.check_permission_by_path(repo.id, path, username)
    # return response
    return api_response(data=response)


def reloaddir(request, repo, parent_dir):
    try:
        dir_id = syncwerk_api.get_dir_id_by_path(repo.id, parent_dir)
    except RpcsyncwerkError, e:
        logger.error(e)
        return api_error(HTTP_520_OPERATION_FAILED,
                         "Failed to get dir id by path")

    if not dir_id:
        return api_error(status.HTTP_404_NOT_FOUND, "Path does not exist")

    return get_dir_entrys_by_id(request, repo, parent_dir, dir_id)


def reloaddir_if_necessary(request, repo, parent_dir, obj_info=None):
    reload_dir = False
    s = request.GET.get('reloaddir', None)
    if s and s.lower() == 'true':
        reload_dir = True

    if not reload_dir:
        if obj_info:
            # return Response(obj_info)
            return api_response(data=obj_info)
        else:
            # return Response('success')
            return api_response()

    return reloaddir(request, repo, parent_dir)


class OpDeleteView(APIView):
    """
    Delete files.
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    swagger_schema = None

    def post(self, request, repo_id, format=None):
        repo = get_repo(repo_id)
        if not repo:
            return api_error(status.HTTP_404_NOT_FOUND, 'Library not found.')

        username = request.user.username
        if check_folder_permission(request, repo_id, '/') != 'rw':
            return api_error(status.HTTP_403_FORBIDDEN,
                             'You do not have permission to delete this file.')

        if not check_folder_permission(request, repo_id, '/'):
            return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')

        parent_dir = request.GET.get('p')
        file_names = request.POST.get("file_names")

        if not parent_dir or not file_names:
            return api_error(status.HTTP_404_NOT_FOUND,
                             'File or directory not found.')

        try:
            multi_files = "\t".join(file_names.split(':'))
            syncwerk_api.del_file(repo_id, parent_dir,
                                 multi_files, username)
        except RpcsyncwerkError as e:
            logger.error(e)
            return api_error(HTTP_520_OPERATION_FAILED,
                             "Failed to delete file.")

        return reloaddir_if_necessary(request, repo, parent_dir)

class OpMoveView(APIView):
    """
    Move files.
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    swagger_schema = None

    def post(self, request, repo_id, format=None):

        username = request.user.username
        parent_dir = request.GET.get('p', '/')
        dst_repo = request.POST.get('dst_repo', None)
        dst_dir = request.POST.get('dst_dir', None)
        obj_names = request.POST.get("file_names", None)

        # argument check
        if not parent_dir or not obj_names or not dst_repo or not dst_dir:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'Missing argument.')

        if repo_id == dst_repo and parent_dir == dst_dir:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'The destination directory is the same as the source.')

        # src resource check
        repo = get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if not syncwerk_api.get_dir_id_by_path(repo_id, parent_dir):
            error_msg = 'Folder %s not found.' % parent_dir
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # dst resource check
        if not get_repo(dst_repo):
            error_msg = 'Library %s not found.' % dst_repo
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if not syncwerk_api.get_dir_id_by_path(dst_repo, dst_dir):
            error_msg = 'Folder %s not found.' % dst_dir
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if check_folder_permission(request, repo_id, parent_dir) != 'rw':
            return api_error(status.HTTP_403_FORBIDDEN,
                    'You do not have permission to move file in this folder.')

        if check_folder_permission(request, dst_repo, dst_dir) != 'rw':
            return api_error(status.HTTP_403_FORBIDDEN,
                    'You do not have permission to move file to destination folder.')

        # check if all file/dir existes
        obj_names = obj_names.strip(':').split(':')
        dirents = syncwerk_api.list_dir_by_path(repo_id, parent_dir)
        exist_obj_names = [dirent.obj_name for dirent in dirents]
        if not set(obj_names).issubset(exist_obj_names):
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'file_names invalid.')

        # make new name
        dst_dirents = syncwerk_api.list_dir_by_path(dst_repo, dst_dir)
        dst_obj_names = [dirent.obj_name for dirent in dst_dirents]

        new_obj_names = []
        for obj_name in obj_names:
            new_obj_name = get_no_duplicate_obj_name(obj_name, dst_obj_names)
            new_obj_names.append(new_obj_name)

        # move file
        try:
            src_multi_objs = "\t".join(obj_names)
            dst_multi_objs = "\t".join(new_obj_names)

            syncwerk_api.move_file(repo_id, parent_dir, src_multi_objs,
                    dst_repo, dst_dir, dst_multi_objs, replace=False,
                    username=username, need_progress=0, synchronous=1)
        except RpcsyncwerkError as e:
            logger.error(e)
            return api_error(HTTP_520_OPERATION_FAILED,
                             "Failed to move file.")

        obj_info_list = []
        for new_obj_name in new_obj_names:
            obj_info = {}
            obj_info['repo_id'] = dst_repo
            obj_info['parent_dir'] = dst_dir
            obj_info['obj_name'] = new_obj_name
            obj_info_list.append(obj_info)

        return reloaddir_if_necessary(request, repo, parent_dir, obj_info_list)


class OpCopyView(APIView):
    """
    Copy files.
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    swagger_schema = None

    def post(self, request, repo_id, format=None):

        username = request.user.username
        parent_dir = request.GET.get('p', '/')
        dst_repo = request.POST.get('dst_repo', None)
        dst_dir = request.POST.get('dst_dir', None)
        obj_names = request.POST.get("file_names", None)

        # argument check
        if not parent_dir or not obj_names or not dst_repo or not dst_dir:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'Missing argument.')

        if repo_id == dst_repo and parent_dir == dst_dir:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'The destination directory is the same as the source.')

        # src resource check
        repo = get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if not syncwerk_api.get_dir_id_by_path(repo_id, parent_dir):
            error_msg = 'Folder %s not found.' % parent_dir
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # dst resource check
        if not get_repo(dst_repo):
            error_msg = 'Library %s not found.' % dst_repo
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if not syncwerk_api.get_dir_id_by_path(dst_repo, dst_dir):
            error_msg = 'Folder %s not found.' % dst_dir
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if check_folder_permission(request, repo_id, parent_dir) is None:
            return api_error(status.HTTP_403_FORBIDDEN,
                    'You do not have permission to copy file of this folder.')

        if check_folder_permission(request, dst_repo, dst_dir) != 'rw':
            return api_error(status.HTTP_403_FORBIDDEN,
                    'You do not have permission to copy file to destination folder.')

        # check if all file/dir existes
        obj_names = obj_names.strip(':').split(':')
        dirents = syncwerk_api.list_dir_by_path(repo_id, parent_dir)
        exist_obj_names = [dirent.obj_name for dirent in dirents]
        if not set(obj_names).issubset(exist_obj_names):
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'file_names invalid.')

        # make new name
        dst_dirents = syncwerk_api.list_dir_by_path(dst_repo, dst_dir)
        dst_obj_names = [dirent.obj_name for dirent in dst_dirents]

        new_obj_names = []
        for obj_name in obj_names:
            new_obj_name = get_no_duplicate_obj_name(obj_name, dst_obj_names)
            new_obj_names.append(new_obj_name)

        # copy file
        try:
            src_multi_objs = "\t".join(obj_names)
            dst_multi_objs = "\t".join(new_obj_names)

            syncwerk_api.copy_file(repo_id, parent_dir, src_multi_objs,
                    dst_repo, dst_dir, dst_multi_objs, username, 0, synchronous=1)
        except RpcsyncwerkError as e:
            logger.error(e)
            return api_error(HTTP_520_OPERATION_FAILED,
                             "Failed to copy file.")

        obj_info_list = []
        for new_obj_name in new_obj_names:
            obj_info = {}
            obj_info['repo_id'] = dst_repo
            obj_info['parent_dir'] = dst_dir
            obj_info['obj_name'] = new_obj_name
            obj_info_list.append(obj_info)

        return reloaddir_if_necessary(request, repo, parent_dir, obj_info_list)
