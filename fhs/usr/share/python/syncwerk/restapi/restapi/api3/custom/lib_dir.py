import os
import stat
import logging
import posixpath

from django.utils.http import urlquote
from django.template.defaultfilters import filesizeformat

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated

from django.utils.translation import ugettext as _

from restapi.api3.base import APIView
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response

from restapi.views import check_folder_permission
from restapi.utils import is_org_context, get_file_type_and_ext, is_pro_version
from restapi.utils.star import get_dir_starred_files
from restapi.base.templatetags.restapi_tags import translate_restapi_time, email2nickname
from restapi.thumbnail.utils import get_thumbnail_src
from restapi.utils.file_types import IMAGE, VIDEO

import restapi.settings as settings
from restapi.settings import ENABLE_THUMBNAIL, THUMBNAIL_ROOT, THUMBNAIL_DEFAULT_SIZE

import synserv
from synserv import syncwerk_api, syncwserv_threaded_rpc
from pyrpcsyncwerk import RpcsyncwerkError

logger = logging.getLogger(__name__)

def get_repo(repo_id):
    return syncwerk_api.get_repo(repo_id)

def get_commit(repo_id, repo_version, commit_id):
    return synserv.get_commit(repo_id, repo_version, commit_id)

class LibDirView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)
    swagger_schema = None

    def get(self, request, repo_id, format=None):
        '''
            New API for list library directory
        '''
        result = {}

        repo = get_repo(repo_id)
        if not repo:
            err_msg = _(u'Library does not exist.')
            # return HttpResponse(json.dumps({'error': err_msg}),
            #                     status=400, content_type=content_type)
            return api_error(status.HTTP_400_BAD_REQUEST, err_msg)

        username = request.user.username
        path = request.GET.get('p', '/')
        if path[-1] != '/':
            path = path + '/'

        # perm for current dir
        user_perm = check_folder_permission(request, repo.id, path)
        if user_perm is None:
            err_msg = _(u'Permission denied.')
            # return HttpResponse(json.dumps({'error': err_msg}),
            #                     status=403, content_type=content_type)
            return api_error(status.HTTP_403_FORBIDDEN, err_msg, )

        if repo.encrypted \
                and not syncwerk_api.is_password_set(repo.id, username):
            err_msg = _(u'Library is encrypted.')
            # return HttpResponse(json.dumps({'error': err_msg, 'lib_need_decrypt': True}),
            #                     status=403, content_type=content_type)
            resp = {'lib_need_decrypt': True}
            return api_error(status.HTTP_403_FORBIDDEN, err_msg, resp)

        head_commit = get_commit(repo.id, repo.version, repo.head_cmmt_id)
        if not head_commit:
            err_msg = _(u'Error: no head commit id')
            # return HttpResponse(json.dumps({'error': err_msg}),
            #                     status=500, content_type=content_type)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, err_msg)

        dir_list = []
        file_list = []

        try:
            dir_id = syncwerk_api.get_dir_id_by_path(repo.id, path)
        except RpcsyncwerkError as e:
            logger.error(e)
            err_msg = 'Internal Server Error'
            # return HttpResponse(json.dumps({'error': err_msg}),
            #                     status=500, content_type=content_type)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, err_msg)

        if not dir_id:
            err_msg = 'Folder not found.'
            # return HttpResponse(json.dumps({'error': err_msg}),
            #                     status=404, content_type=content_type)
            return api_error(status.HTTP_404_NOT_FOUND, err_msg)

        dirs = syncwserv_threaded_rpc.list_dir_with_perm(repo_id, path, dir_id,
                username, -1, -1)
        starred_files = get_dir_starred_files(username, repo_id, path)

        for dirent in dirs:
            dirent.last_modified = dirent.mtime
            if stat.S_ISDIR(dirent.mode):
                dpath = posixpath.join(path, dirent.obj_name)
                if dpath[-1] != '/':
                    dpath += '/'
                dir_list.append(dirent)
            else:
                if repo.version == 0:
                    file_size = syncwerk_api.get_file_size(repo.store_id, repo.version, dirent.obj_id)
                else:
                    file_size = dirent.size
                dirent.file_size = file_size if file_size else 0

                dirent.starred = False
                fpath = posixpath.join(path, dirent.obj_name)
                if fpath in starred_files:
                    dirent.starred = True

                file_list.append(dirent)

        if is_org_context(request):
            repo_owner = syncwerk_api.get_org_repo_owner(repo.id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo.id)

        result["is_repo_owner"] = False
        result["has_been_shared_out"] = False
        if repo_owner == username:
            result["is_repo_owner"] = True

            try:
                if is_org_context(request):
                    org_id = request.user.org.org_id

                    is_inner_org_pub_repo = False
                    # check if current repo is pub-repo
                    org_pub_repos = syncwerk_api.list_org_inner_pub_repos_by_owner(
                            org_id, username)
                    for org_pub_repo in org_pub_repos:
                        if repo_id == org_pub_repo.id:
                            is_inner_org_pub_repo = True
                            break

                    if syncwerk_api.list_org_repo_shared_group(org_id, username, repo_id) or \
                            syncwerk_api.list_org_repo_shared_to(org_id, username, repo_id) or \
                            is_inner_org_pub_repo:
                        result["has_been_shared_out"] = True
                else:
                    if syncwerk_api.list_repo_shared_to(username, repo_id) or \
                            syncwerk_api.list_repo_shared_group_by_user(username, repo_id) or \
                            (not request.cloud_mode and syncwerk_api.is_inner_pub_repo(repo_id)):
                        result["has_been_shared_out"] = True
            except Exception as e:
                logger.error(e)

        result["is_virtual"] = repo.is_virtual
        result["repo_name"] = repo.name
        result["user_perm"] = user_perm
        # check quota for fileupload
        result["no_quota"] = True if synserv.check_quota(repo.id) < 0 else False
        result["encrypted"] = repo.encrypted

        dirent_list = []
        for d in dir_list:
            d_ = {}
            d_['is_dir'] = True
            d_['obj_name'] = d.obj_name
            d_['last_modified'] = d.last_modified
            d_['last_update'] = translate_restapi_time(d.last_modified)
            d_['p_dpath'] = posixpath.join(path, d.obj_name)
            d_['perm'] = d.permission # perm for sub dir in current dir
            dirent_list.append(d_)

        size = int(request.GET.get('thumbnail_size', THUMBNAIL_DEFAULT_SIZE))

        for f in file_list:
            f_ = {}
            f_['is_file'] = True
            f_['obj_name'] = f.obj_name
            f_['last_modified'] = f.last_modified
            f_['last_update'] = translate_restapi_time(f.last_modified)
            f_['starred'] = f.starred
            f_['file_size'] = filesizeformat(f.file_size)
            f_['obj_id'] = f.obj_id
            f_['perm'] = f.permission # perm for file in current dir

            file_type, file_ext = get_file_type_and_ext(f.obj_name)
            if file_type == IMAGE:
                f_['is_img'] = True
            if file_type == VIDEO:
                f_['is_video'] = True
            if file_type == IMAGE or file_type == VIDEO:
                if not repo.encrypted and ENABLE_THUMBNAIL and \
                    os.path.exists(os.path.join(THUMBNAIL_ROOT, str(size), f.obj_id)):
                    file_path = posixpath.join(path, f.obj_name)
                    src = get_thumbnail_src(repo_id, size, file_path)
                    f_['encoded_thumbnail_src'] = urlquote(src)

            if is_pro_version():
                f_['is_locked'] = True if f.is_locked else False
                f_['lock_owner'] = f.lock_owner
                f_['lock_owner_name'] = email2nickname(f.lock_owner)
                if username == f.lock_owner:
                    f_['locked_by_me'] = True
                else:
                    f_['locked_by_me'] = False

            dirent_list.append(f_)

        result["dirent_list"] = dirent_list

        # return HttpResponse(json.dumps(result), content_type=content_type)
        return api_response(status.HTTP_200_OK, '', result)