# Copyright (c) 2012-2016 Seafile Ltd.
# -*- coding: utf-8 -*-
import os
import posixpath
import logging

from django.core.urlresolvers import reverse
from django.db.models import F
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.utils.translation import ugettext as _
from django.utils.http import urlquote

from rest_framework import status

import synserv
from synserv import syncwerk_api

from restapi.auth.decorators import login_required
from restapi.options.models import UserOptions, CryptoOptionNotSetError
from restapi.share.decorators import share_link_audit
from restapi.share.models import FileShare, UploadLinkShare, \
    check_share_link_common
from restapi.views import gen_path_link, get_repo_dirents, \
    check_folder_permission
from restapi.utils import gen_file_upload_url, gen_dir_share_link, \
    gen_shared_upload_link, user_traffic_over_limit, render_error, \
    get_file_type_and_ext
from restapi.settings import ENABLE_UPLOAD_FOLDER, \
    ENABLE_RESUMABLE_FILEUPLOAD, ENABLE_THUMBNAIL, \
    THUMBNAIL_ROOT, THUMBNAIL_DEFAULT_SIZE, THUMBNAIL_SIZE_FOR_GRID, \
    MAX_NUMBER_OF_FILES_FOR_FILEUPLOAD
from restapi.utils.file_types import IMAGE, VIDEO
from restapi.thumbnail.utils import get_share_link_thumbnail_src
from restapi.base.templatetags.restapi_tags import email2nickname, translate_restapi_time

from restapi.api3.utils import api_error, api_response, user_to_dict, translate_time

# Get an instance of a logger
logger = logging.getLogger(__name__)

def get_repo(repo_id):
    return syncwerk_api.get_repo(repo_id)

def get_commit(repo_id, repo_version, commit_id):
    return synserv.get_commit(repo_id, repo_version, commit_id)

def get_repo_size(repo_id):
    return syncwerk_api.get_repo_size(repo_id)

def is_password_set(repo_id, username):
    return syncwerk_api.is_password_set(repo_id, username)

def get_path_from_request(request):
    path = request.GET.get('p', '/')
    if path[-1] != '/':
        path = path + '/'
    return path

def get_next_url_from_request(request):
    return request.GET.get('next', None)

def get_nav_path(path, repo_name):
    return gen_path_link(path, repo_name)

def is_no_quota(repo_id):
    return True if synserv.check_quota(repo_id) < 0 else False

def get_upload_url(request, repo_id):
    username = request.user.username
    if check_folder_permission(request, repo_id, '/') == 'rw':
        token = syncwerk_api.get_fileserver_access_token(repo_id,
                'dummy', 'upload', username)

        if not token:
            return ''

        return gen_file_upload_url(token, 'upload')
    else:
        return ''

def get_fileshare(repo_id, username, path):
    if path == '/':    # no shared link for root dir
        return None

    l = FileShare.objects.filter(repo_id=repo_id).filter(
        username=username).filter(path=path)
    return l[0] if len(l) > 0 else None

def get_dir_share_link(fileshare):
    # dir shared link
    if fileshare:
        dir_shared_link = gen_dir_share_link(fileshare.token)
    else:
        dir_shared_link = ''
    return dir_shared_link

def get_uploadlink(repo_id, username, path):
    if path == '/':    # no shared upload link for root dir
        return None

    l = UploadLinkShare.objects.filter(repo_id=repo_id).filter(
        username=username).filter(path=path)
    return l[0] if len(l) > 0 else None

def get_dir_shared_upload_link(uploadlink):
    # dir shared upload link
    if uploadlink:
        dir_shared_upload_link = gen_shared_upload_link(uploadlink.token)
    else:
        dir_shared_upload_link = ''
    return dir_shared_upload_link

@login_required
def repo_history_view(request, repo_id):
    """View repo in history.
    """
    repo = get_repo(repo_id)
    if not repo:
        raise Http404

    username = request.user.username
    path = get_path_from_request(request)
    user_perm = check_folder_permission(request, repo.id, '/')
    if user_perm is None:
        return render_error(request, _(u'Permission denied'))

    try:
        server_crypto = UserOptions.objects.is_server_crypto(username)
    except CryptoOptionNotSetError:
        # Assume server_crypto is ``False`` if this option is not set.
        server_crypto = False

    if repo.encrypted and \
        (repo.enc_version == 1 or (repo.enc_version == 2 and server_crypto)) \
        and not is_password_set(repo.id, username):
        return render_to_response('decrypt_repo_form.html', {
                'repo': repo,
                'next': get_next_url_from_request(request) or reverse("view_common_lib_dir", args=[repo_id, '']),
                }, context_instance=RequestContext(request))

    commit_id = request.GET.get('commit_id', None)
    if commit_id is None:
        return HttpResponseRedirect(reverse("view_common_lib_dir", args=[repo_id, '']))
    current_commit = get_commit(repo.id, repo.version, commit_id)
    if not current_commit:
        current_commit = get_commit(repo.id, repo.version, repo.head_cmmt_id)

    file_list, dir_list, dirent_more = get_repo_dirents(request, repo,
                                                        current_commit, path)
    zipped = get_nav_path(path, repo.name)

    repo_owner = syncwerk_api.get_repo_owner(repo.id)
    is_repo_owner = True if username == repo_owner else False

    referer = request.GET.get('referer', '')

    return render_to_response('repo_history_view.html', {
            'repo': repo,
            "is_repo_owner": is_repo_owner,
            'user_perm': user_perm,
            'current_commit': current_commit,
            'dir_list': dir_list,
            'file_list': file_list,
            'path': path,
            'zipped': zipped,
            'referer': referer,
            }, context_instance=RequestContext(request))

########## shared dir/uploadlink
def view_shared_dir(request, fileshare):
    token = fileshare.token

    password_check_passed, err_msg = check_share_link_common(request, fileshare)
    if not password_check_passed:
        # d = {'token': token, 'view_name': 'view_shared_dir', 'err_msg': err_msg}
        # return render_to_response('share_access_validation.html', d,
        #                           context_instance=RequestContext(request))
        # return api_error(status.HTTP_403_FORBIDDEN, _(u'Incorrect password'))
        return api_response(data={
            'password_protected': True,
            'share_link_audit': False,
        }, msg='Incorrect password.')

    username = fileshare.username
    repo_id = fileshare.repo_id

    # Get path from frontend, use '/' if missing, and construct request path
    # with fileshare.path to real path, used to fetch dirents by RPC.
    req_path = request.GET.get('p', '/')
    if req_path[-1] != '/':
        req_path += '/'

    if req_path == '/':
        real_path = fileshare.path
    else:
        real_path = posixpath.join(fileshare.path, req_path.lstrip('/'))
    if real_path[-1] != '/':         # Normalize dir path
        real_path += '/'

    repo = get_repo(repo_id)
    if not repo:
        # raise Http404
        return api_error(status.HTTP_404_NOT_FOUND, _(u'Repo does not exist'))

    # Check path still exist, otherwise show error
    if not syncwerk_api.get_dir_id_by_path(repo.id, fileshare.path):
        # return render_error(request, _('"%s" does not exist.') % fileshare.path)
        return api_error(status.HTTP_404_NOT_FOUND, _('"%s" does not exist.') % fileshare.path)

    if fileshare.path == '/':
        # use repo name as dir name if share whole library
        dir_name = repo.name
    else:
        dir_name = os.path.basename(real_path[:-1])

    current_commit = synserv.get_commits(repo_id, 0, 1)[0]
    file_list, dir_list, dirent_more = get_repo_dirents(request, repo,
                                                        current_commit, real_path)

    # generate dir navigator
    if fileshare.path == '/':
        zipped = gen_path_link(req_path, repo.name)
    else:
        zipped = gen_path_link(req_path, os.path.basename(fileshare.path[:-1]))

    if req_path == '/':  # When user view the root of shared dir..
        # increase shared link view_cnt,
        fileshare = FileShare.objects.get(token=token)
        fileshare.view_cnt = F('view_cnt') + 1
        fileshare.save()

    traffic_over_limit = user_traffic_over_limit(fileshare.username)

    permissions = fileshare.get_permissions()

    # mode to view dir/file items
    mode = request.GET.get('mode', 'list')
    if mode != 'list':
        mode = 'grid'
    thumbnail_size = THUMBNAIL_DEFAULT_SIZE if mode == 'list' else THUMBNAIL_SIZE_FOR_GRID

    if fileshare.expire_date:
        expire_date = translate_time(fileshare.expire_date)
    else:
        expire_date = ''

    for f in file_list:
        file_type, file_ext = get_file_type_and_ext(f.obj_name)
        if file_type == IMAGE:
            f.is_img = True
        if file_type == VIDEO:
            f.is_video = True

        if (file_type == IMAGE or file_type == VIDEO) and ENABLE_THUMBNAIL:
            if os.path.exists(os.path.join(THUMBNAIL_ROOT, str(thumbnail_size), f.obj_id)):
                req_image_path = posixpath.join(req_path, f.obj_name)
                src = get_share_link_thumbnail_src(token, thumbnail_size, req_image_path)
                f.encoded_thumbnail_src = urlquote(src)

    files = []
    for f in file_list:
        files.append({
            'obj_name': f.obj_name,
            'file_size': f.file_size,
            'last_modified': f.last_modified,
            'mtime': f.last_modified,
            'last_modified': translate_restapi_time(f.last_modified),
            'is_img': f.is_img,
            'is_video': f.is_video,
            'encoded_thumbnail_src': f.encoded_thumbnail_src,
            'type': 'file'
        })
    dirs = []
    for d in dir_list:
        dirs.append({
            'obj_name': d.obj_name,
            'mtime': d.last_modified,
            'last_modified': translate_restapi_time(d.last_modified),
            'type': 'dir'
        })

    # return render_to_response('view_shared_dir.html', {
    #         'repo': repo,
    #         'token': token,
    #         'path': req_path,
    #         'username': username,
    #         'dir_name': dir_name,
    #         'file_list': file_list,
    #         'dir_list': dir_list,
    #         'zipped': zipped,
    #         'traffic_over_limit': traffic_over_limit,
    #         'permissions': permissions,
    #         'ENABLE_THUMBNAIL': ENABLE_THUMBNAIL,
    #         'mode': mode,
    #         'thumbnail_size': thumbnail_size,
    #         }, context_instance=RequestContext(request))
    resp = {
        'password_protected': False,
        'share_link_audit': False,
        'repo_id': repo.id,
        'repo_name': repo.name,
        'token': token,
        'path': req_path,
        'parent_dir': fileshare.path,
        'shared_by': user_to_dict(username),
        'dir_name': dir_name,
        'file_list': files,
        'dir_list': dirs,
        'zipped': zipped,
        'expire_date': expire_date,
        'is_expired': fileshare.is_expired(),
        'traffic_over_limit': traffic_over_limit,
        'permissions': permissions,
        'ENABLE_THUMBNAIL': ENABLE_THUMBNAIL,
        'mode': mode,
        'thumbnail_size': thumbnail_size,
    }
    return api_response(data=resp)


def view_shared_upload_link(request, uploadlink):
    token = uploadlink.token

    password_check_passed, err_msg = check_share_link_common(request,
                                                             uploadlink,
                                                             is_upload_link=True)
    if not password_check_passed:
        # d = {'token': token, 'view_name': 'view_shared_upload_link', 'err_msg': err_msg}
        # return render_to_response('share_access_validation.html', d,
        #     context_instance=RequestContext(request))
        # return api_error(status.HTTP_403_FORBIDDEN, _(u'Incorrect password'))
        return api_response(data={
            'password_protected': True,
            'share_link_audit': False,
        }, msg='Incorrect password.')

    username = uploadlink.username
    repo_id = uploadlink.repo_id
    repo = get_repo(repo_id)
    if not repo:
        # raise Http404
        return api_error(code=status.HTTP_404_NOT_FOUND, msg=_(u'Repo does not exist'))

    path = uploadlink.path
    if path == '/':
        # use repo name as dir name if share whole library
        dir_name = repo.name
    else:
        dir_name = os.path.basename(path[:-1])

    repo = get_repo(repo_id)
    if not repo:
        # raise Http404
        return api_error(code=status.HTTP_404_NOT_FOUND, msg=_(u'Repo does not exist'))

    uploadlink.view_cnt = F('view_cnt') + 1
    uploadlink.save()

    no_quota = True if synserv.check_quota(repo_id) < 0 else False

    # return render_to_response('view_shared_upload_link.html', {
    #         'repo': repo,
    #         'path': path,
    #         'username': username,
    #         'dir_name': dir_name,
    #         'max_upload_file_size': synserv.MAX_UPLOAD_FILE_SIZE,
    #         'no_quota': no_quota,
    #         'uploadlink': uploadlink,
    #         'enable_upload_folder': ENABLE_UPLOAD_FOLDER,
    #         'enable_resumable_fileupload': ENABLE_RESUMABLE_FILEUPLOAD,
    #         'max_number_of_files_for_fileupload': MAX_NUMBER_OF_FILES_FOR_FILEUPLOAD,
    #         }, context_instance=RequestContext(request))
    resp = {
        'password_protected': False,
        'share_link_audit': False,
        'repo_id': repo.id,
        'repo_name': repo.name,
        'path': path,
        'shared_by': user_to_dict(username),
        'dir_name': dir_name,
        'max_upload_file_size': synserv.MAX_UPLOAD_FILE_SIZE,
        'no_quota': no_quota,
        'token': uploadlink.token,
        'enable_upload_folder': ENABLE_UPLOAD_FOLDER,
        'enable_resumable_fileupload': ENABLE_RESUMABLE_FILEUPLOAD,
        'max_number_of_files_for_fileupload': MAX_NUMBER_OF_FILES_FOR_FILEUPLOAD,
    }
    return api_response(data=resp)
