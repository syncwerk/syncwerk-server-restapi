# Copyright (c) 2012-2016 Seafile Ltd.
# -*- coding: utf-8 -*-
"""
File related views, including view_file, view_history_file, view_trash_file,
view_snapshot_file, view_shared_file, file_edit, etc.
"""

import sys
import os
import json
import stat
import urllib2
import chardet
import logging
import posixpath
import re
import mimetypes
import urlparse
import datetime
import hashlib
import time
import synserv

from django.core import signing
from django.core.cache import cache
from django.contrib.sites.requests import RequestSite
from django.contrib import messages
from django.core.urlresolvers import reverse
from django.db.models import F
from django.http import HttpResponse, Http404, HttpResponseRedirect, HttpResponseBadRequest, HttpResponseForbidden
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.utils.http import urlquote
from django.utils.encoding import force_bytes
from django.utils.translation import ugettext as _
from django.views.decorators.http import require_POST
from django.template.defaultfilters import filesizeformat
from django.views.decorators.csrf import csrf_exempt
from constance import config

from rest_framework import status

from restapi.api3.utils import api_error, api_response, gen_shared_link, user_to_dict, translate_time

from restapi.api3.decorators.base import repo_passwd_set_required

from restapi.syncwerk_server_models.models import FileLocks, FileLockTimestamp

from synserv import syncwerk_api
from synserv import get_repo, send_message, get_commits, \
    get_file_id_by_path, get_commit, get_file_size, \
    syncwserv_threaded_rpc
from pyrpcsyncwerk import RpcsyncwerkError

from restapi.base.templatetags.restapi_tags import email2nickname
from restapi.profile.models import Profile
from restapi.wopi.utils import get_wopi_dict
from restapi.avatar.templatetags.group_avatar_tags import grp_avatar
from restapi.auth.decorators import login_required
# from restapi.base.decorators import repo_passwd_set_required
from restapi.share.models import FileShare, check_share_link_common
from restapi.share.decorators import share_link_audit
from restapi.wiki.utils import get_wiki_dirent
from restapi.wiki.models import WikiDoesNotExist, WikiPageMissing
from restapi.utils import render_error, is_org_context, \
    get_file_type_and_ext, gen_file_get_url, gen_file_share_link, \
    render_permission_error, is_pro_version, is_textual_file, \
    mkstemp, EMPTY_SHA1, HtmlDiff, gen_inner_file_get_url, \
    user_traffic_over_limit, get_file_audit_events_by_path, \
    generate_file_audit_event_type, FILE_AUDIT_ENABLED, gen_token, \
    get_site_scheme_and_netloc, get_conf_text_ext
from restapi.utils.ip import get_remote_ip
from restapi.utils.timeutils import utc_to_local
from restapi.utils.file_types import (IMAGE, PDF, DOCUMENT, SPREADSHEET, AUDIO,
                                     MARKDOWN, TEXT, VIDEO)
from restapi.utils.star import is_file_starred
from restapi.utils import HAS_OFFICE_CONVERTER, FILEEXT_TYPE_MAP
from restapi.utils.http import json_response, int_param, BadRequestException, RequestForbbiddenException
from restapi.views import check_folder_permission, check_file_lock, \
    get_unencry_rw_repos_by_user
from restapi.utils.timeutils import timestamp_to_isoformat_timestr

if HAS_OFFICE_CONVERTER:
    from restapi.utils import (
        query_office_convert_status, add_office_convert_task,
        prepare_converted_html, OFFICE_PREVIEW_MAX_SIZE, get_office_converted_page
    )

import restapi.settings as settings
from restapi.settings import FILE_ENCODING_LIST, FILE_PREVIEW_MAX_SIZE, \
    FILE_ENCODING_TRY_LIST, USE_PDFJS, MEDIA_URL

try:
    from restapi.settings import ENABLE_OFFICE_WEB_APP
except ImportError:
    ENABLE_OFFICE_WEB_APP = False

try:
    from restapi.settings import ENABLE_OFFICE_WEB_APP_EDIT
except ImportError:
    ENABLE_OFFICE_WEB_APP_EDIT = False

try:
    from restapi.settings import OFFICE_WEB_APP_FILE_EXTENSION
except ImportError:
    OFFICE_WEB_APP_FILE_EXTENSION = ()

try:
    from restapi.settings import OFFICE_WEB_APP_EDIT_FILE_EXTENSION
except ImportError:
    OFFICE_WEB_APP_EDIT_FILE_EXTENSION = ()

try:
    from restapi.settings import ENABLE_ONLYOFFICE
    from restapi.onlyoffice.settings import ONLYOFFICE_APIJS_URL, \
            ONLYOFFICE_FILE_EXTENSION, ONLYOFFICE_EDIT_FILE_EXTENSION
except ImportError:
    ENABLE_ONLYOFFICE = False

from restapi.signals import file_access_signal

# Get an instance of a logger
logger = logging.getLogger(__name__)

def gen_path_link(path, repo_name):
    """
    Generate navigate paths and links in repo page.

    """
    if path and path[-1] != '/':
        path += '/'

    paths = []
    links = []
    if path and path != '/':
        paths = path[1:-1].split('/')
        i = 1
        for name in paths:
            link = '/' + '/'.join(paths[:i])
            i = i + 1
            links.append(link)
    if repo_name:
        paths.insert(0, repo_name)
        links.insert(0, '/')

    zipped = zip(paths, links)

    return zipped

def get_file_content(file_type, raw_path, file_enc):
    """Get textual file content, including txt/markdown/syncw.
    """
    return repo_file_get(raw_path, file_enc) if is_textual_file(
        file_type=file_type) else ('', '', '')

def repo_file_get(raw_path, file_enc):
    """
    Get file content and encoding.
    """
    err = ''
    file_content = ''
    encoding = None
    if file_enc != 'auto':
        encoding = file_enc

    try:
        file_response = urllib2.urlopen(raw_path)
        content = file_response.read()
    except urllib2.HTTPError, e:
        logger.error(e)
        err = _(u'HTTPError: failed to open file online')
        return err, '', None
    except urllib2.URLError as e:
        logger.error(e)
        err = _(u'URLError: failed to open file online')
        return err, '', None
    else:
        if encoding:
            try:
                u_content = content.decode(encoding)
            except UnicodeDecodeError:
                err = _(u'The encoding you chose is not proper.')
                return err, '', encoding
        else:
            for enc in FILE_ENCODING_TRY_LIST:
                try:
                    u_content = content.decode(enc)
                    encoding = enc
                    break
                except UnicodeDecodeError:
                    if enc != FILE_ENCODING_TRY_LIST[-1]:
                        continue
                    else:
                        encoding = chardet.detect(content)['encoding']
                        if encoding:
                            try:
                                u_content = content.decode(encoding)
                            except UnicodeDecodeError:
                                err = _(u'Unknown file encoding')
                                return err, '', ''
                        else:
                            err = _(u'Unknown file encoding')
                            return err, '', ''

        file_content = u_content

    return err, file_content, encoding


def get_file_view_path_and_perm(request, repo_id, obj_id, path, use_onetime=True):
    """ Get path and the permission to view file.

    Returns:
    	outer fileserver file url, inner fileserver file url, permission
    """
    username = request.user.username
    filename = os.path.basename(path)

    user_perm = check_folder_permission(request, repo_id, '/')
    if user_perm is None:
        return ('', '', user_perm)
    else:
        # Get a token to visit file
        token = syncwerk_api.get_fileserver_access_token(repo_id,
                obj_id, 'view', username, use_onetime=use_onetime)

        if not token:
            return ('', '', None)

        outer_url = gen_file_get_url(token, filename)
        inner_url = gen_inner_file_get_url(token, filename)
        return (outer_url, inner_url, user_perm)

def handle_textual_file(request, filetype, raw_path, ret_dict):
    # encoding option a user chose
    file_enc = request.GET.get('file_enc', 'auto')
    if not file_enc in FILE_ENCODING_LIST:
        file_enc = 'auto'
    err, file_content, encoding = get_file_content(filetype,
                                                   raw_path, file_enc)
    file_encoding_list = FILE_ENCODING_LIST
    if encoding and encoding not in FILE_ENCODING_LIST:
        file_encoding_list.append(encoding)
    # populate return value dict
    ret_dict['err'] = err
    ret_dict['file_content'] = file_content
    ret_dict['encoding'] = encoding
    ret_dict['file_enc'] = file_enc
    ret_dict['file_encoding_list'] = file_encoding_list

def handle_document(raw_path, obj_id, fileext, ret_dict):
    if HAS_OFFICE_CONVERTER:
        err = prepare_converted_html(raw_path, obj_id, fileext, ret_dict)
        # populate return value dict
        ret_dict['err'] = err
    else:
        ret_dict['filetype'] = 'Unknown'

def handle_spreadsheet(raw_path, obj_id, fileext, ret_dict):
    handle_document(raw_path, obj_id, fileext, ret_dict)

def handle_pdf(raw_path, obj_id, fileext, ret_dict):
    if USE_PDFJS:
        # use pdfjs to preview PDF
        pass
    elif HAS_OFFICE_CONVERTER:
        # use pdf2htmlEX to prefiew PDF
        err = prepare_converted_html(raw_path, obj_id, fileext, ret_dict)
        # populate return value dict
        ret_dict['err'] = err
    else:
        # can't preview PDF
        ret_dict['filetype'] = 'Unknown'

def convert_md_link(file_content, repo_id, username):
    def repl(matchobj):
        if matchobj.group(2):   # return origin string in backquotes
            return matchobj.group(2)

        link_alias = link_name = matchobj.group(1).strip()
        if len(link_name.split('|')) > 1:
            link_alias = link_name.split('|')[0]
            link_name = link_name.split('|')[1]

        filetype, fileext = get_file_type_and_ext(link_name)
        if fileext == '':
            # convert link_name that extension is missing to a markdown page
            try:
                dirent = get_wiki_dirent(repo_id, link_name)
                path = "/" + dirent.obj_name
                href = reverse('view_lib_file', args=[repo_id, path])
                a_tag = '''<a href="%s">%s</a>'''
                return a_tag % (href, link_alias)
            except (WikiDoesNotExist, WikiPageMissing):
                a_tag = '''<p class="wiki-page-missing">%s</p>'''
                return a_tag % (link_alias)
        elif filetype == IMAGE:
            # load image to current page
            path = "/" + link_name
            filename = os.path.basename(path)
            obj_id = get_file_id_by_path(repo_id, path)
            if not obj_id:
                return '''<p class="wiki-page-missing">%s</p>''' %  link_name

            token = syncwerk_api.get_fileserver_access_token(repo_id,
                    obj_id, 'view', username)

            if not token:
                return '''<p class="wiki-page-missing">%s</p>''' %  link_name

            return '<img class="wiki-image" src="%s" alt="%s" />' % (gen_file_get_url(token, filename), filename)
        else:
            from restapi.base.templatetags.restapi_tags import file_icon_filter

            # convert other types of filelinks to clickable links
            path = "/" + link_name
            icon = file_icon_filter(link_name)
            s = reverse('view_lib_file', args=[repo_id, path])
            a_tag = '''<img src="%simg/file/%s" alt="%s" class="vam" /> <a href="%s" target="_blank" class="vam">%s</a>'''
            return a_tag % (MEDIA_URL, icon, icon, s, link_name)

    return re.sub(r'\[\[(.+?)\]\]|(`.+?`)', repl, file_content)

def file_size_exceeds_preview_limit(file_size, file_type):
    """Check whether file size exceeds the preview limit base on different
    type of file.
    """
    if file_type in (DOCUMENT, PDF) and HAS_OFFICE_CONVERTER:
        if file_size > OFFICE_PREVIEW_MAX_SIZE:
            err = _(u'File size surpasses %s, can not be opened online.') % \
                filesizeformat(OFFICE_PREVIEW_MAX_SIZE)
            return True, err
        else:
            return False, ''
    elif file_type in (VIDEO, AUDIO):
            return False, ''
    else:
        if file_size > FILE_PREVIEW_MAX_SIZE:
            err = _(u'File size surpasses %s, can not be opened online.') % \
                filesizeformat(FILE_PREVIEW_MAX_SIZE)
            return True, err
        else:
            return False, ''

def can_preview_file(file_name, file_size, repo=None, username=''):
    """Check whether a file can be viewed online.
    Returns (True, None) if file can be viewed online, otherwise
    (False, erro_msg).
    """

    file_type, file_ext = get_file_type_and_ext(file_name)

    # if repo and repo.encrypted and (file_type in (DOCUMENT, SPREADSHEET, PDF)):
    if repo:
        if repo.encrypted and not syncwerk_api.is_password_set(repo.id, username):
            return (False, _(u'The library is encrypted, can not open file online.'))

    if file_ext in FILEEXT_TYPE_MAP or file_ext in get_conf_text_ext():  # check file extension
        exceeds_limit, err_msg = file_size_exceeds_preview_limit(file_size,
                                                                 file_type)
        if exceeds_limit:
            return (False, err_msg)
        else:
            return (True, None)
    else:
        # TODO: may need a better way instead of return string, and compare
        # that string in templates
        return (False, "invalid extension")

def send_file_access_msg_when_preview(request, repo, path, access_from):
    """ send file access msg when user preview file from web
    """
    filename = os.path.basename(path)
    filetype, fileext = get_file_type_and_ext(filename)

    if filetype in (TEXT, IMAGE, MARKDOWN, VIDEO, AUDIO):
        send_file_access_msg(request, repo, path, access_from)

    if filetype in (DOCUMENT, SPREADSHEET, PDF) and \
        HAS_OFFICE_CONVERTER:
        send_file_access_msg(request, repo, path, access_from)

    if filetype == PDF and USE_PDFJS:
        send_file_access_msg(request, repo, path, access_from)

@login_required
@repo_passwd_set_required
def view_repo_file(request, repo_id):
    """
    Old 'file view' that put path in parameter
    """
    path = request.GET.get('p', '/').rstrip('/')
    return _file_view(request, repo_id, path)

@login_required
@repo_passwd_set_required
def view_lib_file(request, repo_id, path):
    """
    New 'file view' that not put path in parameter
    """
    return _file_view(request, repo_id, path)

def _file_view(request, repo_id, path):
    """
    Steps to view file:
    1. Get repo id and file path.
    2. Check user's permission.
    3. Check whether this file can be viewed online.
    4.1 Get file content if file is text file.
    4.2 Prepare flash if file is document.
    4.3 Prepare or use pdfjs if file is pdf.
    4.4 Other file return it's raw path.
    """
    username = request.user.username
    # check arguments
    repo = get_repo(repo_id)
    if not repo:
        # raise Http404
        return api_error(status.HTTP_404_NOT_FOUND, _(u'Repo does not exist'))

    obj_id = get_file_id_by_path(repo_id, path)
    if not obj_id:
        # return render_error(request, _(u'File does not exist'))
        return api_error(status.HTTP_404_NOT_FOUND, _(u'File does not exist'))

    # construct some varibles
    u_filename = os.path.basename(path)
    current_commit = get_commits(repo_id, 0, 1)[0]
    # get file type and extension
    filetype, fileext = get_file_type_and_ext(u_filename)

    # Check whether user has permission to view file and get file raw path,
    # render error page if permission deny.
    file_perm = syncwerk_api.check_permission_by_path(repo_id, path, username)
    if not file_perm:
        # return render_permission_error(request, _(u'Unable to view file'))
        return api_error(status.HTTP_403_FORBIDDEN, _(u'Unable to view file'))

    # Pass permission check, start download or render file.

    if request.GET.get('dl', '0') == '1':
        token = syncwerk_api.get_fileserver_access_token(repo_id,
                obj_id, 'download', username, use_onetime=True)

        if not token:
            # return render_permission_error(request, _(u'Unable to view file'))
            return api_error(status.HTTP_403_FORBIDDEN, 'Unable to view file')

        dl_url = gen_file_get_url(token, u_filename)
        # send stats message
        send_file_access_msg(request, repo, path, 'web')
        # return HttpResponseRedirect(dl_url)
        resp = {
            'dl_url': dl_url
        }
        return api_response(data=resp)

    if request.GET.get('raw', '0') == '1':
        token = syncwerk_api.get_fileserver_access_token(repo_id,
                obj_id, 'view', username, use_onetime=True)

        if not token:
            # return render_permission_error(request, _(u'Unable to view file'))
            return api_error(status.HTTP_403_FORBIDDEN, 'Unable to view file')

        raw_url = gen_file_get_url(token, u_filename)
        # send stats message
        send_file_access_msg(request, repo, path, 'web')
        # return HttpResponseRedirect(raw_url)
        resp = {
            'raw_url': raw_url,
            'filetype': filetype,
            'fileext': fileext,
            'filename': u_filename,
            'path': path,
            'repo_encrypted': repo.encrypted,
        }
        return api_response(data=resp)

    # Get file view raw path, ``user_perm`` is not used anymore.
    if filetype == VIDEO or filetype == AUDIO:
        raw_path, inner_path, user_perm = get_file_view_path_and_perm(
            request, repo_id, obj_id, path, use_onetime=False)
    else:
        raw_path, inner_path, user_perm = get_file_view_path_and_perm(
            request, repo_id, obj_id, path)

    is_locked, locked_by_me = check_file_lock(repo_id, path, username)

    # check if use office web app to view/edit file
    if not repo.encrypted and ENABLE_OFFICE_WEB_APP:
        action_name = None
        # first check if can view file
        if fileext in OFFICE_WEB_APP_FILE_EXTENSION:
            action_name = 'view'

        # then check if can edit file
        if ENABLE_OFFICE_WEB_APP_EDIT and file_perm == 'rw' and \
                fileext in OFFICE_WEB_APP_EDIT_FILE_EXTENSION and \
                ((not is_locked) or (is_locked and locked_by_me)):
            action_name = 'edit'

        wopi_dict = get_wopi_dict(username, repo_id, path, action_name)
        if wopi_dict:
            send_file_access_msg(request, repo, path, 'web')
            # return render_to_response('view_wopi_file.html', wopi_dict,
            #           context_instance=RequestContext(request))
            return api_response(data=wopi_dict)

    if ENABLE_ONLYOFFICE and not repo.encrypted and \
       fileext in ONLYOFFICE_FILE_EXTENSION:
        doc_key = hashlib.md5(force_bytes(repo_id + path + obj_id)).hexdigest()[:20]
        if fileext in ('xls', 'xlsx', 'ods', 'fods', 'csv'):
            document_type = 'spreadsheet'
        elif fileext in ('pptx', 'ppt', 'odp', 'fodp', 'ppsx', 'pps'):
            document_type = 'presentation'
        else:
            document_type = 'text'
        doc_title = os.path.basename(path)

        dl_token = syncwerk_api.get_fileserver_access_token(repo.id,
                obj_id, 'download', username, use_onetime=True)

        if not dl_token:
            # return render_permission_error(request, _(u'Unable to view file'))
            return api_error(status.HTTP_403_FORBIDDEN, 'Unable to view file')

        doc_url = gen_file_get_url(dl_token, u_filename)
        doc_info = json.dumps({'repo_id': repo_id, 'file_path': path,
                               'username': username})
        assert len(ONLYOFFICE_APIJS_URL) > 1
        cache.set("ONLYOFFICE_%s" % doc_key, doc_info, None)

        if file_perm == 'rw' and ((not is_locked) or (is_locked and locked_by_me)) and \
                   fileext in ONLYOFFICE_EDIT_FILE_EXTENSION:
            can_edit = True
        else:
            can_edit = False

        if file_perm == 'rw' and ((not is_locked) or (is_locked and locked_by_me)):
            can_lock_unlock_file = True
        else:
            can_lock_unlock_file = False

        # return render_to_response('onlyoffice/view_file_via_onlyoffice.html', {
        #     'ONLYOFFICE_APIJS_URL': ONLYOFFICE_APIJS_URL,
        #     'file_type': fileext,
        #     'doc_key': doc_key,
        #     'doc_title': doc_title,
        #     'doc_url': doc_url,
        #     'lang_code': Profile.objects.get_user_language(username),
        #     'document_type': document_type,
        #     'callback_url': get_site_scheme_and_netloc().rstrip('/') + reverse('onlyoffice_editor_callback'),
        #     'can_edit': can_edit,
        #     'username': username,
        # }, context_instance=RequestContext(request))
        token = syncwerk_api.get_fileserver_access_token(repo_id,
                obj_id, 'view', username, use_onetime=True)
        raw_url = gen_file_get_url(token, u_filename)
        onlyoffice_info = {
            'ONLYOFFICE_APIJS_URL': ONLYOFFICE_APIJS_URL,
            'file_type': fileext,
            'doc_key': doc_key,
            'doc_title': doc_title,
            'doc_url': doc_url,
            'lang_code': Profile.objects.get_user_language(username),
            'document_type': document_type,
            'callback_url': get_site_scheme_and_netloc().rstrip('/') + reverse('api3_onlyoffice_editor_callback'),
            'can_edit': can_edit,
            'username': username,
        }
        resp = {
            'raw_url': raw_url,
            'filetype': filetype,
            'fileext': fileext,
            'filename': u_filename,
            'path': path,
            'current_commit': get_commit_info(current_commit),
            'onlyoffice_info': onlyoffice_info,
            'file_encoding_list': [],
            'file_locked': is_locked,
            'locked_by_me': locked_by_me,
            'can_lock_unlock_file': can_lock_unlock_file,
            'repo_id': repo_id,
            'repo_encrypted': repo.encrypted,
        }
        return api_response(data=resp)

    # check if the user is the owner or not, for 'private share'
    if is_org_context(request):
        repo_owner = syncwerk_api.get_org_repo_owner(repo.id)
        is_repo_owner = True if repo_owner == username else False
    else:
        is_repo_owner = syncwerk_api.is_repo_owner(username, repo.id)

    img_prev = None
    img_next = None
    ret_dict = {'err': '', 'file_content': '', 'encoding': '', 'file_enc': '',
                'file_encoding_list': [], 'filetype': filetype}

    fsize = get_file_size(repo.store_id, repo.version, obj_id)
    can_preview, err_msg = can_preview_file(u_filename, fsize, repo, username)
    if can_preview:
        send_file_access_msg_when_preview(request, repo, path, 'web')

        """Choose different approach when dealing with different type of file."""
        if is_textual_file(file_type=filetype):
            handle_textual_file(request, filetype, inner_path, ret_dict)
            if filetype == MARKDOWN:
                c = ret_dict['file_content']
                ret_dict['file_content'] = convert_md_link(c, repo_id, username)
        elif filetype == DOCUMENT:
            handle_document(inner_path, obj_id, fileext, ret_dict)
        elif filetype == SPREADSHEET:
            handle_spreadsheet(inner_path, obj_id, fileext, ret_dict)
        elif filetype == PDF:
            handle_pdf(inner_path, obj_id, fileext, ret_dict)
        elif filetype == IMAGE:
            parent_dir = os.path.dirname(path)
            dirs = syncwerk_api.list_dir_by_commit_and_path(current_commit.repo_id,
                                                           current_commit.id, parent_dir)
            if not dirs:
                # raise Http404
                return api_error(status.HTTP_404_NOT_FOUND, '')

            img_list = []
            for dirent in dirs:
                if not stat.S_ISDIR(dirent.props.mode):
                    fltype, flext = get_file_type_and_ext(dirent.obj_name)
                    if fltype == 'Image':
                        img_list.append(dirent.obj_name)

            if len(img_list) > 1:
                img_list.sort(lambda x, y : cmp(x.lower(), y.lower()))
                cur_img_index = img_list.index(u_filename)
                if cur_img_index != 0:
                    img_prev = posixpath.join(parent_dir, img_list[cur_img_index - 1])
                if cur_img_index != len(img_list) - 1:
                    img_next = posixpath.join(parent_dir, img_list[cur_img_index + 1])
    else:
        ret_dict['err'] = err_msg
        if repo.encrypted and not syncwerk_api.is_password_set(repo.id, username):
            return api_response(data={ 'lib_need_decrypt': True }, msg=err_msg)

    # generate file path navigator
    zipped = gen_path_link(path, repo.name)

    parent_dir = os.path.dirname(path)

    # file shared link
    l = FileShare.objects.filter(repo_id=repo_id).filter(
        username=username).filter(path=path)
    fileshare = l[0] if len(l) > 0 else None
    http_or_https = request.is_secure() and 'https' or 'http'
    domain = RequestSite(request).domain
    if fileshare:
        file_shared_link = gen_file_share_link(fileshare.token)
    else:
        file_shared_link = ''

    # fetch file contributors and latest contributor
    try:
        # get real path for sub repo
        real_path = repo.origin_path + path if repo.origin_path else path
        dirent = syncwerk_api.get_dirent_by_path(repo.store_id, real_path)
        if dirent:
            latest_contributor, last_modified = dirent.modifier, dirent.mtime
        else:
            latest_contributor, last_modified = None, 0
    except RpcsyncwerkError as e:
        logger.error(e)
        latest_contributor, last_modified = None, 0

    # check whether file is starred
    is_starred = False
    org_id = -1
    if request.user.org:
        org_id = request.user.org.org_id
    is_starred = is_file_starred(username, repo.id, path.encode('utf-8'), org_id)

    can_edit_file = True
    if file_perm == 'r':
        can_edit_file = False
    elif is_locked and not locked_by_me:
        can_edit_file = False

    if is_pro_version() and file_perm == 'rw':
        can_lock_unlock_file = True
    else:
        can_lock_unlock_file = False

    f_share = None
    if fileshare:
        f_share = {
            'permission': fileshare.permission,
            's_type': fileshare.s_type,
            'token': fileshare.token,
            'password': fileshare.password
        }

    # return render_to_response(template, {
    #         'repo': repo,
    #         'is_repo_owner': is_repo_owner,
    #         'obj_id': obj_id,
    #         'filename': u_filename,
    #         'path': path,
    #         'zipped': zipped,
    #         'parent_dir': parent_dir,
    #         'current_commit': current_commit,
    #         'fileext': fileext,
    #         'raw_path': raw_path,
    #         'fileshare': fileshare,
    #         'protocol': http_or_https,
    #         'domain': domain,
    #         'file_shared_link': file_shared_link,
    #         'err': ret_dict['err'],
    #         'file_content': ret_dict['file_content'],
    #         'file_enc': ret_dict['file_enc'],
    #         'encoding': ret_dict['encoding'],
    #         'file_encoding_list': ret_dict['file_encoding_list'],
    #         'filetype': ret_dict['filetype'],
    #         'use_pdfjs': USE_PDFJS,
    #         'latest_contributor': latest_contributor,
    #         'last_modified': last_modified,
    #         'last_commit_id': repo.head_cmmt_id,
    #         'is_starred': is_starred,
    #         'user_perm': user_perm,
    #         'file_perm': file_perm,
    #         'file_locked': is_locked,
    #         'is_pro': is_pro_version(),
    #         'locked_by_me': locked_by_me,
    #         'can_edit_file': can_edit_file,
    #         'can_lock_unlock_file': can_lock_unlock_file,
    #         'img_prev': img_prev,
    #         'img_next': img_next,
    #         'highlight_keyword': settings.HIGHLIGHT_KEYWORD,
    #         }, context_instance=RequestContext(request))
    resp = {
        'repo_id': repo.id,
        'repo_name': repo.name,
        'is_repo_owner': is_repo_owner,
        'obj_id': obj_id,
        'filename': u_filename,
        'path': path,
        'zipped': zipped,
        'parent_dir': parent_dir,
        'current_commit': get_commit_info(current_commit),
        'fileext': fileext,
        'raw_path': raw_path,
        'fileshare': f_share,
        'protocol': http_or_https,
        'domain': domain,
        'file_shared_link': file_shared_link,
        'err': ret_dict['err'],
        'file_content': ret_dict['file_content'],
        'file_enc': ret_dict['file_enc'],
        'encoding': ret_dict['encoding'],
        'file_encoding_list': ret_dict['file_encoding_list'],
        'filetype': ret_dict['filetype'],
        'use_pdfjs': USE_PDFJS,
        'latest_contributor': latest_contributor,
        'last_modified': last_modified,
        'last_commit_id': repo.head_cmmt_id,
        'is_starred': is_starred,
        'user_perm': user_perm,
        'file_perm': file_perm,
        'file_locked': is_locked,
        'is_pro': is_pro_version(),
        'locked_by_me': locked_by_me,
        'can_edit_file': can_edit_file,
        'can_lock_unlock_file': can_lock_unlock_file,
        'img_prev': img_prev,
        'img_next': img_next,
        'highlight_keyword': settings.HIGHLIGHT_KEYWORD,
        'repo_encrypted': repo.encrypted,
        'is_share_public_link': check_permission_share_public_link(request.user),
    }
    return api_response(data=resp)

def check_permission_share_public_link(user):
    # User is admin or user has right "can_generate_share_link" and "can_generate_upload_link" => User can share public link
    # is_staff => User is admin
    share_public_link = False
    if user.is_staff:
        share_public_link = True
    else:
        share_public_link = user.permissions.can_generate_share_link() and user.permissions.can_generate_upload_link()
    return share_public_link

def view_history_file_common(request, repo_id, ret_dict=None):
    # check arguments
    repo = get_repo(repo_id)
    if not repo:
        # raise Http404
        return api_error(status.HTTP_404_NOT_FOUND, _(u'Repo does not exist'))

    path = request.GET.get('p', '/')

    commit_id = request.GET.get('commit_id', '')
    if not commit_id:
        # raise Http404
        return api_error(status.HTTP_404_NOT_FOUND, _(u'Unable to view file'))

    obj_id = request.GET.get('obj_id', '')
    if not obj_id:
        # raise Http404
        return api_error(status.HTTP_404_NOT_FOUND, _(u'Unable to view file'))

    # construct some varibles
    u_filename = os.path.basename(path)
    current_commit = get_commit(repo.id, repo.version, commit_id)
    if not current_commit:
        # raise Http404
        return api_error(status.HTTP_404_NOT_FOUND, _(u'Commit does not exist'))
    # get file type and extension
    filetype, fileext = get_file_type_and_ext(u_filename)

    # Check whether user has permission to view file and get file raw path,
    # render error page if permission  deny.
    if filetype == VIDEO or filetype == AUDIO:
        raw_path, inner_path, user_perm = get_file_view_path_and_perm(
            request, repo_id, obj_id, path, use_onetime=False)
    else:
        raw_path, inner_path, user_perm = get_file_view_path_and_perm(
            request, repo_id, obj_id, path)

    ret_dict = {}
    request.user_perm = user_perm
    if not user_perm:
        # return render_permission_error(request, _(u'Unable to view file'))
        return api_error(status.HTTP_403_FORBIDDEN, _(u'Unable to view file'))
    if user_perm:
        # Check if can preview file
        fsize = get_file_size(repo.store_id, repo.version, obj_id)
        can_preview, err_msg = can_preview_file(u_filename, fsize, repo, request.user.username)
        if can_preview:
            send_file_access_msg_when_preview(request, repo, path, 'web')
            """Choose different approach when dealing with different type of file."""
            if is_textual_file(file_type=filetype):
                handle_textual_file(request, filetype, inner_path, ret_dict)
            elif filetype == DOCUMENT:
                handle_document(inner_path, obj_id, fileext, ret_dict)
            elif filetype == SPREADSHEET:
                handle_spreadsheet(inner_path, obj_id, fileext, ret_dict)
            elif filetype == PDF:
                handle_pdf(inner_path, obj_id, fileext, ret_dict)
            else:
                pass
        else:
            ret_dict['err'] = err_msg
    else:
        return api_error(status.HTTP_403_FORBIDDEN, _(u'Unable to view file'))

    # populate return value dict
    # ret_dict['repo'] = repo
    ret_dict['repo_id'] = repo.id
    ret_dict['repo_name'] = repo.name
    ret_dict['obj_id'] = obj_id
    ret_dict['file_name'] = u_filename
    ret_dict['path'] = path
    ret_dict['current_commit'] = get_commit_info(current_commit)
    ret_dict['fileext'] = fileext
    ret_dict['raw_path'] = raw_path
    if not ret_dict.has_key('filetype'):
        ret_dict['filetype'] = filetype
    ret_dict['use_pdfjs'] = USE_PDFJS

    # generate file path navigator
    ret_dict['zipped'] = gen_path_link(path, repo.name)

    if ENABLE_ONLYOFFICE and not repo.encrypted and \
       fileext in ONLYOFFICE_FILE_EXTENSION:
        username = request.user.email
        doc_key = hashlib.md5(force_bytes(repo_id + path + obj_id)).hexdigest()[:20]
        if fileext in ('xls', 'xlsx', 'ods', 'fods', 'csv'):
            document_type = 'spreadsheet'
        elif fileext in ('pptx', 'ppt', 'odp', 'fodp', 'ppsx', 'pps'):
            document_type = 'presentation'
        else:
            document_type = 'text'
        doc_title = os.path.basename(path)

        dl_token = syncwerk_api.get_fileserver_access_token(repo.id,
                obj_id, 'download', username, use_onetime=True)

        if not dl_token:
            # return render_permission_error(request, _(u'Unable to view file'))
            return api_error(status.HTTP_403_FORBIDDEN, 'Unable to view file')

        doc_url = gen_file_get_url(dl_token, u_filename)
        doc_info = json.dumps({'repo_id': repo_id, 'file_path': path,
                               'username': username})
        assert len(ONLYOFFICE_APIJS_URL) > 1
        cache.set("ONLYOFFICE_%s" % doc_key, doc_info, None)

        # return render_to_response('onlyoffice/view_file_via_onlyoffice.html', {
        #     'ONLYOFFICE_APIJS_URL': ONLYOFFICE_APIJS_URL,
        #     'file_type': fileext,
        #     'doc_key': doc_key,
        #     'doc_title': doc_title,
        #     'doc_url': doc_url,
        #     'lang_code': Profile.objects.get_user_language(username),
        #     'document_type': document_type,
        #     'callback_url': get_site_scheme_and_netloc().rstrip('/') + reverse('onlyoffice_editor_callback'),
        #     'can_edit': can_edit,
        #     'username': username,
        # }, context_instance=RequestContext(request))
        token = syncwerk_api.get_fileserver_access_token(repo_id,
                obj_id, 'view', username, use_onetime=True)
        raw_url = gen_file_get_url(token, u_filename)
        onlyoffice_info = {
            'ONLYOFFICE_APIJS_URL': ONLYOFFICE_APIJS_URL,
            'file_type': fileext,
            'doc_key': doc_key,
            'doc_title': doc_title,
            'doc_url': doc_url,
            'lang_code': Profile.objects.get_user_language(username),
            'document_type': document_type,
            'callback_url': get_site_scheme_and_netloc().rstrip('/') + reverse('api3_onlyoffice_editor_callback'),
            'username': username,
        }
        # resp = {
        #     'raw_url': raw_url,
        #     'filetype': filetype,
        #     'fileext': fileext,
        #     'filename': u_filename,
        #     'path': path,
        #     'current_commit': get_commit_info(current_commit),
        #     'onlyoffice_info': onlyoffice_info,
        #     'file_encoding_list': [],
        #     'repo_id': repo_id,
        # }
        ret_dict['onlyoffice_info']=onlyoffice_info

    return api_response(data=ret_dict)

@repo_passwd_set_required
def view_history_file(request, repo_id):
    ret_dict = {}
    # if not request.user_perm:
        # return render_permission_error(request, _(u'Unable to view file'))
        # return api_error(status.HTTP_403_FORBIDDEN, _(u'Unable to view file'))

    # generate file path navigator
    # path = ret_dict['path']
    # repo = ret_dict['repo']
    # ret_dict['zipped'] = gen_path_link(path, repo.name)


    # return render_to_response('view_history_file.html', ret_dict,
    #                           context_instance=RequestContext(request))
    return view_history_file_common(request, repo_id, ret_dict)

@repo_passwd_set_required
def view_trash_file(request, repo_id):
    ret_dict = {}
    # if not request.user_perm:
        # return render_permission_error(request, _(u'Unable to view file'))
        # return api_error(status.HTTP_403_FORBIDDEN, _(u'Unable to view file'))

    basedir = request.GET.get('base', '')
    if not basedir:
        # raise Http404
        return api_error(status.HTTP_404_NOT_FOUND, _(u'File not found'))

    path = request.GET.get('p', '/')
    if basedir != '/':
        tmp_path = posixpath.join(basedir.rstrip('/'), path.lstrip('/'))
        ret_dict['basedir'] = tmp_path

    # return render_to_response('view_trash_file.html', ret_dict,
    #                           context_instance=RequestContext(request), )
    return view_history_file_common(request, repo_id, ret_dict)

@repo_passwd_set_required
def view_snapshot_file(request, repo_id):
    ret_dict = {}
    # if not request.user_perm:
        # return render_permission_error(request, _(u'Unable to view file'))
        # return api_error(status.HTTP_403_FORBIDDEN, _(u'Unable to view file'))

    # generate file path navigator
    # path = ret_dict['path']
    # repo = ret_dict['repo']
    # ret_dict['zipped'] = gen_path_link(path, repo.name)

    # return render_to_response('view_snapshot_file.html', ret_dict,
    #                           context_instance=RequestContext(request), )
    return view_history_file_common(request, repo_id, ret_dict)

def _download_file_from_share_link(request, fileshare):
    """Download shared file.
    `path` need to be provided by frontend, if missing, use `fileshare.path`
    """
    next = request.META.get('HTTP_REFERER', settings.SITE_ROOT)

    username = request.user.username
    shared_by = fileshare.username
    repo = get_repo(fileshare.repo_id)
    if not repo:
        # raise Http404
        return api_error(code=status.HTTP_404_NOT_FOUND, msg=_(u'Repo does not exist'))

    # Construct real file path if download file in shared dir, otherwise, just
    # use path in DB.
    if isinstance(fileshare, FileShare) and fileshare.is_dir_share_link():
        req_path = request.GET.get('p', '')
        if not req_path:
            # messages.error(request, _(u'Unable to download file, invalid file path'))
            # return HttpResponseRedirect(next)
            return api_error(code=status.HTTP_400_BAD_REQUEST, msg=_(u'Unable to download file, invalid file path'))
        real_path = posixpath.join(fileshare.path, req_path.lstrip('/'))
    else:
        real_path = fileshare.path

    filename = os.path.basename(real_path)
    obj_id = syncwerk_api.get_file_id_by_path(repo.id, real_path)
    if not obj_id:
        # messages.error(request, _(u'Unable to download file, wrong file path'))
        # return HttpResponseRedirect(next)
        return api_error(code=status.HTTP_400_BAD_REQUEST, msg=_(u'Unable to download file, wrong file path'))

    # check whether owner's traffic over the limit
    if user_traffic_over_limit(fileshare.username):
        # messages.error(request, _(u'Unable to download file, share link traffic is used up.'))
        # return HttpResponseRedirect(next)
        return api_error(code=status.HTTP_404_NOT_FOUND, msg=_(u'Unable to download file, share link traffic is used up.'))

    send_file_access_msg(request, repo, real_path, 'share-link')
    try:
        file_size = syncwerk_api.get_file_size(repo.store_id, repo.version,
                                              obj_id)
        send_message('restapi.stats', 'file-download\t%s\t%s\t%s\t%s' %
                     (repo.id, shared_by, obj_id, file_size))
    except Exception as e:
        logger.error('Error when sending file-download message: %s' % str(e))

    # dl_token = syncwerk_api.get_fileserver_access_token(repo.id,
    #         obj_id, 'download', username, use_onetime=False)
    dl_token = syncwerk_api.get_fileserver_access_token(repo.id,
            obj_id, 'download-link', fileshare.username, use_onetime=False)

    if not dl_token:
        # messages.error(request, _(u'Unable to download file.'))
        return api_error(code=status.HTTP_404_NOT_FOUND, msg=_(u'Unable to download file.'))

    # return HttpResponseRedirect(gen_file_get_url(dl_token, filename))
    resp = {
        'dl_url': gen_file_get_url(dl_token, filename)
    }
    return api_response(data=resp)


def view_shared_file(request, fileshare):
    """
    View file via shared link.
    Download share file if `dl` in request param.
    View raw share file if `raw` in request param.
    """
    token = fileshare.token

    password_check_passed, err_msg = check_share_link_common(request, fileshare)
    if not password_check_passed:
        # d = {'token': token, 'view_name': 'view_shared_file', 'err_msg': err_msg}
        # return render_to_response('share_access_validation.html', d,
        #                           context_instance=RequestContext(request))
        # return api_error(status.HTTP_403_FORBIDDEN, _(u'Incorrect password'))
        return api_response(data={
            'password_protected': True,
            'share_link_audit': False,
        }, msg='Incorrect password.')

    shared_by = fileshare.username
    repo_id = fileshare.repo_id
    repo = get_repo(repo_id)
    if not repo:
        # raise Http404
        return api_error(status.HTTP_404_NOT_FOUND, _(u'Repo does not exist'))

    path = fileshare.path.rstrip('/')  # Normalize file path
    obj_id = syncwerk_api.get_file_id_by_path(repo_id, path)
    if not obj_id:
        # return render_error(request, _(u'File does not exist'))
        return api_error(status.HTTP_404_NOT_FOUND, _(u'File does not exist'))

    filename = os.path.basename(path)
    filetype, fileext = get_file_type_and_ext(filename)

    # Increase file shared link view_cnt, this operation should be atomic
    fileshare.view_cnt = F('view_cnt') + 1
    fileshare.save()

    # send statistic messages
    file_size = syncwerk_api.get_file_size(repo.store_id, repo.version, obj_id)
    if request.GET.get('dl', '') == '1':
        if fileshare.get_permissions()['can_download'] is False:
            # raise Http404
            return api_error(status.HTTP_403_FORBIDDEN, _(u'Unable to download file'))

        # download shared file
        return _download_file_from_share_link(request, fileshare)

    access_token = syncwerk_api.get_fileserver_access_token(repo.id,
            obj_id, 'view', '', use_onetime=False)

    if not access_token:
        # return render_error(request, _(u'Unable to view file'))
        return api_error(status.HTTP_403_FORBIDDEN, _(u'Unable to view file'))


    raw_path = gen_file_get_url(access_token, filename)
    if request.GET.get('raw', '') == '1':
        if fileshare.get_permissions()['can_download'] is False:
            # raise Http404
            return api_error(status.HTTP_403_FORBIDDEN, _(u'Unable to download file'))

        # check whether owner's traffic over the limit
        if user_traffic_over_limit(shared_by):
            # messages.error(request, _(u'Unable to view raw file, share link traffic is used up.'))
            # next = request.META.get('HTTP_REFERER', settings.SITE_ROOT)
            # return HttpResponseRedirect(next)
            return api_error(status.HTTP_403_FORBIDDEN, _(u'Unable to view raw file, share link traffic is used up.'))

        send_file_access_msg(request, repo, path, 'share-link')
        send_message('restapi.stats', 'file-download\t%s\t%s\t%s\t%s' %
                     (repo_id, shared_by, obj_id, file_size))

        # view raw shared file, directly show/download file depends on
        # browsers
        # return HttpResponseRedirect(raw_path)
        resp = {
            'raw_path': raw_path
        }
        return api_response(data=resp)

    # get file content
    ret_dict = {'err': '', 'file_content': '', 'encoding': '', 'file_enc': '',
                'file_encoding_list': [], 'filetype': filetype}
    fsize = get_file_size(repo.store_id, repo.version, obj_id)
    can_preview, err_msg = can_preview_file(filename, fsize, repo, request.user.username)
    if can_preview:
        send_file_access_msg_when_preview(request, repo, path, 'share-link')

        """Choose different approach when dealing with different type of file."""
        inner_path = gen_inner_file_get_url(access_token, filename)
        if is_textual_file(file_type=filetype):
            handle_textual_file(request, filetype, inner_path, ret_dict)
        elif filetype == DOCUMENT:
            handle_document(inner_path, obj_id, fileext, ret_dict)
        elif filetype == SPREADSHEET:
            handle_spreadsheet(inner_path, obj_id, fileext, ret_dict)
        elif filetype == PDF:
            handle_pdf(inner_path, obj_id, fileext, ret_dict)
    else:
        ret_dict['err'] = err_msg

    # accessible_repos = get_unencry_rw_repos_by_user(request)
    save_to_link = reverse('save_shared_link') + '?t=' + token
    traffic_over_limit = user_traffic_over_limit(shared_by)

    permissions = fileshare.get_permissions()

    if fileshare.expire_date:
        expire_date = translate_time(fileshare.expire_date)
    else:
        expire_date = ''

    # return render_to_response('shared_file_view.html', {
    #         'repo': repo,
    #         'obj_id': obj_id,
    #         'path': path,
    #         'file_name': filename,
    #         'file_size': file_size,
    #         'shared_token': token,
    #         'access_token': access_token,
    #         'fileext': fileext,
    #         'raw_path': raw_path,
    #         'shared_by': shared_by,
    #         'err': ret_dict['err'],
    #         'file_content': ret_dict['file_content'],
    #         'encoding': ret_dict['encoding'],
    #         'file_encoding_list': ret_dict['file_encoding_list'],
    #         'filetype': ret_dict['filetype'],
    #         'use_pdfjs': USE_PDFJS,
    #         'accessible_repos': accessible_repos,
    #         'save_to_link': save_to_link,
    #         'traffic_over_limit': traffic_over_limit,
    #         'permissions': permissions,
    #         }, context_instance=RequestContext(request))
    if ENABLE_ONLYOFFICE and not repo.encrypted and \
        fileext in ONLYOFFICE_FILE_EXTENSION:
        doc_key = hashlib.md5(force_bytes(repo_id + path + obj_id)).hexdigest()[:20]
        if fileext in ('xls', 'xlsx', 'ods', 'fods', 'csv'):
            document_type = 'spreadsheet'
        elif fileext in ('pptx', 'ppt', 'odp', 'fodp', 'ppsx', 'pps'):
            document_type = 'presentation'
        else:
            document_type = 'text'
        doc_title = os.path.basename(path)
        dl_token = syncwerk_api.get_fileserver_access_token(repo.id,
                obj_id, 'download', request.user.username, use_onetime=True)
        doc_url = gen_file_get_url(dl_token, doc_title);
        onlyoffice_info = {
            'ONLYOFFICE_APIJS_URL': ONLYOFFICE_APIJS_URL,
            'file_type': fileext,
            'doc_key': doc_key,
            'doc_title': doc_title,
            'doc_url': doc_url,
            'lang_code': Profile.objects.get_user_language(request.user.username),
            'document_type': document_type,
            'callback_url': get_site_scheme_and_netloc().rstrip('/') + reverse('api3_onlyoffice_editor_callback'),
            'username': request.user.username,
            'download-link': gen_shared_link(token, fileshare.s_type),
        }
    else:
        onlyoffice_info = None
    resp = {
        'password_protected': False,
        'share_link_audit': False,
        'repo_id': repo.id,
        'repo_name': repo.name,
        'obj_id': obj_id,
        'path': path,
        'file_name': filename,
        'file_size': file_size,
        'token': token,
        'access_token': access_token,
        'fileext': fileext,
        'raw_path': raw_path,
        'shared_by': user_to_dict(shared_by),
        'download_link': gen_shared_link(token, fileshare.s_type),
        'err': ret_dict['err'],
        'file_content': ret_dict['file_content'],
        'encoding': ret_dict['encoding'],
        'file_encoding_list': ret_dict['file_encoding_list'],
        'filetype': ret_dict['filetype'],
        'use_pdfjs': USE_PDFJS,
        'expire_date': expire_date,
        'is_expired': fileshare.is_expired(),
        # 'accessible_repos': accessible_repos,
        'save_to_link': save_to_link,
        'traffic_over_limit': traffic_over_limit,
        'permissions': permissions,
        'onlyoffice_info': onlyoffice_info,
    }
    return api_response(data=resp)

def view_raw_shared_file(request, token, obj_id, file_name):
    """Returns raw content of a shared file.

    Arguments:
    - `request`:
    - `token`:
    - `obj_id`:
    - `file_name`:
    """
    fileshare = FileShare.objects.get_valid_file_link_by_token(token)
    if fileshare is None:
        raise Http404

    password_check_passed, err_msg = check_share_link_common(request, fileshare)
    if not password_check_passed:
        d = {'token': token, 'err_msg': err_msg}
        if fileshare.is_file_share_link():
            d['view_name'] = 'view_shared_file'
        else:
            d['view_name'] = 'view_shared_dir'

        return render_to_response('share_access_validation.html', d,
                                  context_instance=RequestContext(request))

    repo_id = fileshare.repo_id
    repo = get_repo(repo_id)
    if not repo:
        raise Http404

    # Normalize file path based on file or dir share link
    req_path = request.GET.get('p', '').rstrip('/')
    if req_path:
        file_path = posixpath.join(fileshare.path, req_path.lstrip('/'))
    else:
        if fileshare.is_file_share_link():
            file_path = fileshare.path.rstrip('/')
        else:
            file_path = fileshare.path.rstrip('/') + '/' + file_name

    real_obj_id = syncwerk_api.get_file_id_by_path(repo_id, file_path)
    if not real_obj_id:
        raise Http404

    if real_obj_id != obj_id:   # perm check
        raise Http404

    filename = os.path.basename(file_path)
    username = request.user.username
    token = syncwerk_api.get_fileserver_access_token(repo_id,
            real_obj_id, 'view', username, use_onetime=False)

    if not token:
        raise Http404

    outer_url = gen_file_get_url(token, filename)
    return HttpResponseRedirect(outer_url)

def view_file_via_shared_dir(request, fileshare):
    token = fileshare.token
    req_path = request.GET.get('p', '').rstrip('/')
    if not req_path:
        return api_error(status.HTTP_400_BAD_REQUEST, _('Invalid file path.'))

    password_check_passed, err_msg = check_share_link_common(request, fileshare)
    if not password_check_passed:
        # d = {'token': token,
        #      'view_name': 'view_file_via_shared_dir',
        #      'path': req_path,
        #      'err_msg': err_msg,
        #  }
        # return render_to_response('share_access_validation.html', d,
        #                           context_instance=RequestContext(request))
        return api_response(data={
            'password_protected': True,
            'share_link_audit': False,
        }, msg='Incorrect password.')

    if request.GET.get('dl', '') == '1':
        if fileshare.get_permissions()['can_download'] is False:
            # raise Http404
            return api_error(status.HTTP_403_FORBIDDEN, _(u'Unable to download file'))

        # download shared file
        repo_id = fileshare.repo_id
        repo = get_repo(repo_id)
        if not repo:
            return api_error(status.HTTP_404_NOT_FOUND, _(u'File does not exist'))
        shared_by = fileshare.username
        real_path = posixpath.join(fileshare.path, req_path)
        obj_id = syncwerk_api.get_file_id_by_path(repo_id, real_path)
        if not obj_id:
            return api_error(status.HTTP_404_NOT_FOUND, _(u'File does not exist'))
        file_size = syncwerk_api.get_file_size(repo.store_id, repo.version, obj_id)
        send_message('restapi.stats', 'file-download\t%s\t%s\t%s\t%s' %
                     (repo_id, shared_by, obj_id, file_size))
        return _download_file_from_share_link(request, fileshare)

    shared_by = fileshare.username
    repo_id = fileshare.repo_id
    repo = get_repo(repo_id)
    if not repo:
        # raise Http404
        return api_error(status.HTTP_404_NOT_FOUND, _(u'Repo does not exist'))

    # Get file path from frontend, and construct request file path
    # with fileshare.path to real path, used to fetch file content by RPC.
    real_path = posixpath.join(fileshare.path, req_path.lstrip('/'))

    # generate dir navigator
    if fileshare.path == '/':
        zipped = gen_path_link(req_path, repo.name)
    else:
        zipped = gen_path_link(req_path, os.path.basename(fileshare.path[:-1]))

    obj_id = syncwerk_api.get_file_id_by_path(repo_id, real_path)
    if not obj_id:
        # return render_error(request, _(u'File does not exist'))
        return api_error(status.HTTP_404_NOT_FOUND, _(u'File does not exist'))

    filename = os.path.basename(req_path)
    if request.GET.get('raw', '0') == '1':
        if fileshare.get_permissions()['can_download'] is False:
            # raise Http404
            return api_error(status.HTTP_403_FORBIDDEN, _(u'Unable to download file'))

        username = request.user.username
        token = syncwerk_api.get_fileserver_access_token(repo_id,
                obj_id, 'view', username, use_onetime=True)

        if not token:
            # return render_error(request, _(u'Unable to view file'))
            return api_error(status.HTTP_403_FORBIDDEN, _(u'Unable to view file'))

        raw_url = gen_file_get_url(token, filename)
        # send stats message
        send_file_access_msg(request, repo, real_path, 'share-link')
        # return HttpResponseRedirect(raw_url)
        resp = {
            'raw_url': raw_url
        }
        return api_response(data=resp)

    file_size = syncwerk_api.get_file_size(repo.store_id, repo.version, obj_id)
    filetype, fileext = get_file_type_and_ext(filename)
    access_token = syncwerk_api.get_fileserver_access_token(repo.id,
            obj_id, 'view', '', use_onetime=False)

    if not access_token:
        # return render_error(request, _(u'Unable to view file'))
        return api_error(status.HTTP_403_FORBIDDEN, _(u'Unable to view file'))

    raw_path = gen_file_get_url(access_token, filename)
    inner_path = gen_inner_file_get_url(access_token, filename)

    img_prev = None
    img_next = None

    # get file content
    ret_dict = {'err': '', 'file_content': '', 'encoding': '', 'file_enc': '',
                'file_encoding_list': [], 'filetype': filetype}
    fsize = get_file_size(repo.store_id, repo.version, obj_id)
    can_preview, err_msg = can_preview_file(filename, fsize, repo, request.user.username)
    if can_preview:
        send_file_access_msg_when_preview(request, repo, real_path, 'share-link')

        """Choose different approach when dealing with different type of file."""
        if is_textual_file(file_type=filetype):
            handle_textual_file(request, filetype, inner_path, ret_dict)
        elif filetype == DOCUMENT:
            handle_document(inner_path, obj_id, fileext, ret_dict)
        elif filetype == SPREADSHEET:
            handle_spreadsheet(inner_path, obj_id, fileext, ret_dict)
        elif filetype == PDF:
            handle_pdf(inner_path, obj_id, fileext, ret_dict)
        elif filetype == IMAGE:
            current_commit = get_commits(repo_id, 0, 1)[0]
            real_parent_dir = os.path.dirname(real_path)
            parent_dir = os.path.dirname(req_path)
            dirs = syncwerk_api.list_dir_by_commit_and_path(current_commit.repo_id,
                                                           current_commit.id, real_parent_dir)
            if not dirs:
                # raise Http404
                return api_error(status.HTTP_404_NOT_FOUND, _(u'Dir does not exist'))

            img_list = []
            for dirent in dirs:
                if not stat.S_ISDIR(dirent.props.mode):
                    fltype, flext = get_file_type_and_ext(dirent.obj_name)
                    if fltype == 'Image':
                        img_list.append(dirent.obj_name)

            if len(img_list) > 1:
                img_list.sort(lambda x, y : cmp(x.lower(), y.lower()))
                cur_img_index = img_list.index(filename)
                if cur_img_index != 0:
                    img_prev = posixpath.join(parent_dir, img_list[cur_img_index - 1])
                if cur_img_index != len(img_list) - 1:
                    img_next = posixpath.join(parent_dir, img_list[cur_img_index + 1])

    else:
        ret_dict['err'] = err_msg

    traffic_over_limit = user_traffic_over_limit(shared_by)
    permissions = fileshare.get_permissions()

    # return render_to_response('shared_file_view.html', {
    #         'repo': repo,
    #         'obj_id': obj_id,
    #         'from_shared_dir': True,
    #         'path': req_path,
    #         'file_name': filename,
    #         'file_size': file_size,
    #         'shared_token': token,
    #         'access_token': access_token,
    #         'fileext': fileext,
    #         'raw_path': raw_path,
    #         'shared_by': shared_by,
    #         'token': token,
    #         'err': ret_dict['err'],
    #         'file_content': ret_dict['file_content'],
    #         'encoding': ret_dict['encoding'],
    #         'file_encoding_list':ret_dict['file_encoding_list'],
    #         'filetype': ret_dict['filetype'],
    #         'use_pdfjs':USE_PDFJS,
    #         'zipped': zipped,
    #         'img_prev': img_prev,
    #         'img_next': img_next,
    #         'traffic_over_limit': traffic_over_limit,
    #         'permissions': permissions,
    #         }, context_instance=RequestContext(request))
    if ENABLE_ONLYOFFICE and not repo.encrypted and \
        fileext in ONLYOFFICE_FILE_EXTENSION:
        doc_key = hashlib.md5(force_bytes(repo_id + req_path + obj_id)).hexdigest()[:20]
        if fileext in ('xls', 'xlsx', 'ods', 'fods', 'csv'):
            document_type = 'spreadsheet'
        elif fileext in ('pptx', 'ppt', 'odp', 'fodp', 'ppsx', 'pps'):
            document_type = 'presentation'
        else:
            document_type = 'text'
        doc_title = os.path.basename(req_path)
        dl_token = syncwerk_api.get_fileserver_access_token(repo.id,
                obj_id, 'download', request.user.username, use_onetime=True)
        doc_url = gen_file_get_url(dl_token, doc_title);
        onlyoffice_info = {
            'ONLYOFFICE_APIJS_URL': ONLYOFFICE_APIJS_URL,
            'file_type': fileext,
            'doc_key': doc_key,
            'doc_title': doc_title,
            'doc_url': doc_url,
            'lang_code': Profile.objects.get_user_language(request.user.username),
            'document_type': document_type,
            'callback_url': get_site_scheme_and_netloc().rstrip('/') + reverse('api3_onlyoffice_editor_callback'),
            'username': request.user.username,
            'download-link': gen_shared_link(token, fileshare.s_type),
        }
    else:
        onlyoffice_info = None
    resp = {
        'password_protected': False,
        'share_link_audit': False,
        'repo_id': repo.id,
        'repo_name': repo.name,
        'obj_id': obj_id,
        'from_shared_dir': True,
        'path': req_path,
        'file_name': filename,
        'file_size': file_size,
        'token': token,
        'access_token': access_token,
        'fileext': fileext,
        'raw_path': raw_path,
        'shared_by': user_to_dict(shared_by),
        'download_link': gen_shared_link(token, fileshare.s_type),
        'err': ret_dict['err'],
        'file_content': ret_dict['file_content'],
        'encoding': ret_dict['encoding'],
        'file_encoding_list':ret_dict['file_encoding_list'],
        'filetype': ret_dict['filetype'],
        'use_pdfjs':USE_PDFJS,
        'zipped': zipped,
        'img_prev': img_prev,
        'img_next': img_next,
        'traffic_over_limit': traffic_over_limit,
        'permissions': permissions,
        'onlyoffice_info': onlyoffice_info
    }
    return api_response(data=resp)

def file_edit_submit(request, repo_id):
    content_type = 'application/json; charset=utf-8'
    def error_json(error_msg=_(u'Internal Error'), op=None):
        return HttpResponse(json.dumps({'error': error_msg, 'op': op}),
                            status=400,
                            content_type=content_type)

    path = request.GET.get('p')
    username = request.user.username
    parent_dir = os.path.dirname(path)

    # edit file, so check parent_dir's permission
    if check_folder_permission(request, repo_id, parent_dir) != 'rw':
        return error_json(_(u'Permission denied'))

    is_locked, locked_by_me = check_file_lock(repo_id, path, username)
    if (is_locked, locked_by_me) == (None, None):
        return error_json(_(u'Check file lock error'))

    if is_locked and not locked_by_me:
        return error_json(_(u'File is locked'))

    repo = get_repo(repo_id)
    if not repo:
        return error_json(_(u'The library does not exist.'))
    if repo.encrypted:
        repo.password_set = syncwerk_api.is_password_set(repo_id, username)
        if not repo.password_set:
            return error_json(_(u'The library is encrypted.'), 'decrypt')

    content = request.POST.get('content')
    encoding = request.POST.get('encoding')

    if content is None or not path or encoding not in FILE_ENCODING_LIST:
        return error_json(_(u'Invalid arguments.'))
    head_id = request.GET.get('head', None)

    # first dump the file content to a tmp file, then update the file
    fd, tmpfile = mkstemp()
    def remove_tmp_file():
        try:
            os.remove(tmpfile)
        except:
            pass

    if encoding == 'auto':
        encoding = sys.getfilesystemencoding()

    try:
        content = content.encode(encoding)
    except UnicodeEncodeError as e:
        remove_tmp_file()
        return error_json(_(u'The encoding you chose is not proper.'))

    try:
        bytesWritten = os.write(fd, content)
    except:
        bytesWritten = -1
    finally:
        os.close(fd)

    if bytesWritten != len(content):
        remove_tmp_file()
        return error_json()

    req_from = request.GET.get('from', '')
    if req_from == 'wiki_page_edit' or req_from == 'wiki_page_new':
        try:
            gid = int(request.GET.get('gid', 0))
        except ValueError:
            gid = 0

        wiki_name = os.path.splitext(os.path.basename(path))[0]
        next = reverse('group_wiki', args=[gid, wiki_name])
    elif req_from == 'personal_wiki_page_edit' or req_from == 'personal_wiki_page_new':
        wiki_name = os.path.splitext(os.path.basename(path))[0]
        next = reverse('personal_wiki', args=[wiki_name])
    else:
        next = reverse('view_lib_file', args=[repo_id, path])

    parent_dir = os.path.dirname(path).encode('utf-8')
    filename = os.path.basename(path).encode('utf-8')
    try:
        syncwserv_threaded_rpc.put_file(repo_id, tmpfile, parent_dir,
                                 filename, username, head_id)
        remove_tmp_file()
        return HttpResponse(json.dumps({'href': next}),
                            content_type=content_type)
    except RpcsyncwerkError, e:
        remove_tmp_file()
        return error_json(str(e))

@login_required
def file_edit(request, repo_id):
    repo = get_repo(repo_id)
    if not repo:
        raise Http404

    if request.method == 'POST':
        return file_edit_submit(request, repo_id)

    path = request.GET.get('p', '/')
    if path[-1] == '/':
        path = path[:-1]
    u_filename = os.path.basename(path)
    filename = urllib2.quote(u_filename.encode('utf-8'))
    parent_dir = os.path.dirname(path)

    if check_folder_permission(request, repo.id, parent_dir) != 'rw':
        return render_permission_error(request, _(u'Unable to edit file'))

    head_id = repo.head_cmmt_id

    obj_id = get_file_id_by_path(repo_id, path)
    if not obj_id:
        return render_error(request, _(u'The file does not exist.'))

    token = syncwerk_api.get_fileserver_access_token(repo_id,
            obj_id, 'view', request.user.username)

    if not token:
        return render_error(request, _(u'Unable to view file'))

    # generate path and link
    zipped = gen_path_link(path, repo.name)

    filetype, fileext = get_file_type_and_ext(filename)

    op = None
    err = ''
    file_content = None
    encoding = None
    file_encoding_list = FILE_ENCODING_LIST
    if filetype == TEXT or filetype == MARKDOWN:
        if repo.encrypted:
            repo.password_set = syncwerk_api.is_password_set(repo_id, request.user.username)
            if not repo.password_set:
                op = 'decrypt'
        if not op:
            inner_path = gen_inner_file_get_url(token, filename)
            file_enc = request.GET.get('file_enc', 'auto')
            if not file_enc in FILE_ENCODING_LIST:
                file_enc = 'auto'
            err, file_content, encoding = repo_file_get(inner_path, file_enc)
            if encoding and encoding not in FILE_ENCODING_LIST:
                file_encoding_list.append(encoding)
    else:
        err = _(u'Edit online is not offered for this type of file.')

    # Redirect to different place according to from page when user click
    # cancel button on file edit page.
    cancel_url = reverse('view_lib_file', args=[repo.id, path])
    page_from = request.GET.get('from', '')
    gid = request.GET.get('gid', '')
    wiki_name = os.path.splitext(u_filename)[0]
    if page_from == 'wiki_page_edit' or page_from == 'wiki_page_new':
        cancel_url = reverse('group_wiki', args=[gid, wiki_name])
    elif page_from == 'personal_wiki_page_edit' or page_from == 'personal_wiki_page_new':
        cancel_url = reverse('personal_wiki', args=[wiki_name])

    return render_to_response('file_edit.html', {
        'repo':repo,
        'u_filename':u_filename,
        'wiki_name': wiki_name,
        'path':path,
        'zipped':zipped,
        'filetype':filetype,
        'fileext':fileext,
        'op':op,
        'err':err,
        'file_content':file_content,
        'encoding': encoding,
        'file_encoding_list':file_encoding_list,
        'head_id': head_id,
        'from': page_from,
        'gid': gid,
        'cancel_url': cancel_url,
    }, context_instance=RequestContext(request))

@login_required
def view_raw_file(request, repo_id, file_path):
    """Returns raw content of a file.
    Used when use viewer.js to preview opendocument file.

    Arguments:
    - `request`:
    - `repo_id`:
    """
    repo = get_repo(repo_id)
    if not repo:
        raise Http404

    file_path = file_path.rstrip('/')
    if file_path[0] != '/':
        file_path = '/' + file_path

    obj_id = get_file_id_by_path(repo_id, file_path)
    if not obj_id:
        raise Http404

    raw_path, inner_path, user_perm = get_file_view_path_and_perm(
        request, repo.id, obj_id, file_path)
    if user_perm is None:
        raise Http404

    send_file_access_msg(request, repo, file_path, 'web')
    return HttpResponseRedirect(raw_path)

def send_file_access_msg(request, repo, path, access_from):
    """Send file downlaod msg.

    Arguments:
    - `request`:
    - `repo`:
    - `obj_id`:
    - `access_from`: web or api
    """
    username = request.user.username

    ip = get_remote_ip(request)
    user_agent = request.META.get("HTTP_USER_AGENT")

    msg = 'file-download-%s\t%s\t%s\t%s\t%s\t%s' % \
        (access_from, username, ip, user_agent, repo.id, path)
    msg_utf8 = msg.encode('utf-8')

    send_file_access_signal(request,repo,path,access_from)

    try:
        send_message('restapi.stats', msg_utf8)
    except Exception as e:
        logger.error("Error when sending file-download-%s message: %s" %
                     (access_from, str(e)))

@login_required
def download_file(request, repo_id, obj_id):
    """Download file in repo/file history page.

    Arguments:
    - `request`:
    - `repo_id`:
    - `obj_id`:
    """
    username = request.user.username
    repo = get_repo(repo_id)
    if not repo:
        raise Http404

    if repo.encrypted and not syncwerk_api.is_password_set(repo_id, username):
        return HttpResponseRedirect(reverse('view_common_lib_dir', args=[repo_id, '']))

    # only check the permissions at the repo level
    # to prevent file can not be downloaded on the history page
    # if it has been renamed
    if check_folder_permission(request, repo_id, '/'):
        # Get a token to access file
        token = syncwerk_api.get_fileserver_access_token(repo_id,
                obj_id, 'download', username)

        if not token:
            messages.error(request, _(u'Unable to download file'))
            next = request.META.get('HTTP_REFERER', settings.SITE_ROOT)
            return HttpResponseRedirect(next)

    else:
        messages.error(request, _(u'Unable to download file'))
        next = request.META.get('HTTP_REFERER', settings.SITE_ROOT)
        return HttpResponseRedirect(next)

    path = request.GET.get('p', '')
    send_file_access_msg(request, repo, path, 'web') # send stats message
    file_name = os.path.basename(path.rstrip('/'))
    redirect_url = gen_file_get_url(token, file_name) # generate download link

    return HttpResponseRedirect(redirect_url)

########## text diff
def get_file_content_by_commit_and_path(request, repo_id, commit_id, path, file_enc):
    try:
        obj_id = syncwserv_threaded_rpc.get_file_id_by_commit_and_path( \
                                        repo_id, commit_id, path)
    except:
        return None, 'bad path'

    if not obj_id or obj_id == EMPTY_SHA1:
        return '', None
    else:
        permission = check_folder_permission(request, repo_id, '/')
        if permission:
            # Get a token to visit file
            token = syncwerk_api.get_fileserver_access_token(repo_id,
                    obj_id, 'view', request.user.username)

            if not token:
                return None, 'FileServer access token invalid'

        else:
            return None, 'permission denied'

        filename = os.path.basename(path)
        inner_path = gen_inner_file_get_url(token, filename)

        try:
            err, file_content, encoding = repo_file_get(inner_path, file_enc)
        except Exception, e:
            return None, 'error when read file from fileserver: %s' % e
        return file_content, err

@login_required
def text_diff(request, repo_id):
    commit_id = request.GET.get('commit', '')
    path = request.GET.get('p', '')
    u_filename = os.path.basename(path)
    file_enc = request.GET.get('file_enc', 'auto')
    if not file_enc in FILE_ENCODING_LIST:
        file_enc = 'auto'

    if not (commit_id and path):
        return render_error(request, 'bad params')

    repo = get_repo(repo_id)
    if not repo:
        return render_error(request, 'bad repo')

    current_commit = syncwserv_threaded_rpc.get_commit(repo.id, repo.version, commit_id)
    if not current_commit:
        return render_error(request, 'bad commit id')

    prev_commit = syncwserv_threaded_rpc.get_commit(repo.id, repo.version, current_commit.parent_id)
    if not prev_commit:
        return render_error('bad commit id')

    path = path.encode('utf-8')

    current_content, err = get_file_content_by_commit_and_path(request, \
                                    repo_id, current_commit.id, path, file_enc)
    if err:
        return render_error(request, err)

    prev_content, err = get_file_content_by_commit_and_path(request, \
                                    repo_id, prev_commit.id, path, file_enc)
    if err:
        return render_error(request, err)

    is_new_file = False
    diff_result_table = ''
    if prev_content == '' and current_content == '':
        is_new_file = True
    else:
        diff = HtmlDiff()
        diff_result_table = diff.make_table(prev_content.splitlines(),
                                        current_content.splitlines(), True)

    zipped = gen_path_link(path, repo.name)

    referer = request.GET.get('referer', '')

    return render_to_response('text_diff.html', {
        'u_filename':u_filename,
        'repo': repo,
        'path': path,
        'zipped': zipped,
        'current_commit': current_commit,
        'prev_commit': prev_commit,
        'diff_result_table': diff_result_table,
        'is_new_file': is_new_file,
        'referer': referer,
    }, context_instance=RequestContext(request))

########## office related
@require_POST
@csrf_exempt
@json_response
def office_convert_add_task(request):
    try:
        file_id = request.POST.get('file_id')
        doctype = request.POST.get('doctype')
        raw_path = request.POST.get('raw_path')
    except KeyError:
        return HttpResponseBadRequest('invalid params')

    if not _check_cluster_internal_token(request, file_id):
        return HttpResponseForbidden()

    if len(file_id) != 40:
        return HttpResponseBadRequest('invalid params')

    return add_office_convert_task(file_id, doctype, raw_path, internal=True)

def _check_office_convert_perm(request, repo_id, path, ret):
    token = request.GET.get('token', '')
    if not token:
        # Work around for the images embedded in excel files
        referer = request.META.get('HTTP_REFERER', '')
        if referer:
            token = urlparse.parse_qs(
                urlparse.urlparse(referer).query).get('token', [''])[0]
    if token:
        fileshare = FileShare.objects.get_valid_file_link_by_token(token)
        if not fileshare or fileshare.repo_id != repo_id:
            return False
        if fileshare.is_file_share_link() and fileshare.path == path:
            return True
        if fileshare.is_dir_share_link():
            ret['dir_share_path'] = fileshare.path
            return True
        return False
    else:
        return request.user.is_authenticated() and \
            check_folder_permission(request, repo_id, '/') is not None

def _check_cluster_internal_token(request, file_id):
    token = request.META.get('Syncwerk-Office-Preview-Token', '')
    if not token:
        return HttpResponseForbidden()
    try:
        s = '-'.join([file_id, datetime.datetime.now().strftime('%Y%m%d')])
        return signing.Signer().unsign(token) == s
    except signing.BadSignature:
        return False

def _office_convert_get_file_id_internal(request):
    file_id = request.GET.get('file_id', '')
    if len(file_id) != 40:
        raise BadRequestException()
    if not _check_cluster_internal_token(request, file_id):
        raise RequestForbbiddenException()
    return file_id

def _office_convert_get_file_id(request, repo_id=None, commit_id=None, path=None):
    repo_id = repo_id or request.GET.get('repo_id', '')
    commit_id = commit_id or request.GET.get('commit_id', '')
    path = path or request.GET.get('path', '')
    if not (repo_id and path and commit_id):
        raise BadRequestException()
    if '../' in path:
        raise BadRequestException()

    ret = {'dir_share_path': None}
    if not _check_office_convert_perm(request, repo_id, path, ret):
        raise BadRequestException()

    if ret['dir_share_path']:
        path = posixpath.join(ret['dir_share_path'], path.lstrip('/'))
    return syncwserv_threaded_rpc.get_file_id_by_commit_and_path(repo_id, commit_id, path)

@json_response
def office_convert_query_status(request, cluster_internal=False):
    if not cluster_internal and not request.is_ajax():
        raise Http404

    doctype = request.GET.get('doctype', None)
    page = 0 if doctype == 'spreadsheet' else int_param(request, 'page')
    if cluster_internal:
        file_id = _office_convert_get_file_id_internal(request)
    else:
        file_id = _office_convert_get_file_id(request)

    ret = {'success': False}
    try:
        ret = query_office_convert_status(file_id, page, cluster_internal=cluster_internal)
    except Exception, e:
        logging.exception('failed to call query_office_convert_status')
        ret['error'] = str(e)

    return ret

_OFFICE_PAGE_PATTERN = re.compile(r'^[\d]+\.page|file\.css|file\.outline|index.html|index_html_.*.png$')
def office_convert_get_page(request, repo_id, commit_id, path, filename, cluster_internal=False):
    """Valid static file path inclueds:
    - "1.page" "2.page" for pdf/doc/ppt
    - index.html for spreadsheets and index_html_xxx.png for images embedded in spreadsheets
    """
    if not HAS_OFFICE_CONVERTER:
        raise Http404

    if not _OFFICE_PAGE_PATTERN.match(filename):
        return HttpResponseForbidden()

    path = u'/' + path
    if cluster_internal:
        file_id = _office_convert_get_file_id_internal(request)
    else:
        file_id = _office_convert_get_file_id(request, repo_id, commit_id, path)

    resp = get_office_converted_page(
        request, repo_id, commit_id, path, filename, file_id, cluster_internal=cluster_internal)
    if filename.endswith('.page'):
        content_type = 'text/html'
    else:
        content_type = mimetypes.guess_type(filename)[0] or 'text/html'
    resp['Content-Type'] = content_type
    return resp

@login_required
def file_access(request, repo_id):
    """List file access log.
    """

    if not is_pro_version() or not FILE_AUDIT_ENABLED:
        raise Http404

    referer = request.META.get('HTTP_REFERER', None)
    next = settings.SITE_ROOT if referer is None else referer

    repo = get_repo(repo_id)
    if not repo:
        messages.error(request, _("Library does not exist"))
        return HttpResponseRedirect(next)

    path = request.GET.get('p', None)
    if not path:
        messages.error(request, _("Argument missing"))
        return HttpResponseRedirect(next)

    if not syncwerk_api.get_file_id_by_path(repo_id, path):
        messages.error(request, _("File does not exist"))
        return HttpResponseRedirect(next)

    # perm check
    if check_folder_permission(request, repo_id, path) != 'rw':
        messages.error(request, _("Permission denied"))
        return HttpResponseRedirect(next)

    # Make sure page request is an int. If not, deliver first page.
    try:
        current_page = int(request.GET.get('page', '1'))
        per_page = int(request.GET.get('per_page', '100'))
    except ValueError:
        current_page = 1
        per_page = 100

    start = per_page * (current_page - 1)
    limit = per_page + 1

    if is_org_context(request):
        org_id = request.user.org.org_id
        events = get_file_audit_events_by_path(None, org_id, repo_id, path, start, limit)
    else:
        events = get_file_audit_events_by_path(None, 0, repo_id, path, start, limit)

    events = events if events else []
    if len(events) == per_page + 1:
        page_next = True
    else:
        page_next = False

    events = events[:per_page]

    for ev in events:
        ev.repo = get_repo(ev.repo_id)
        ev.filename = os.path.basename(ev.file_path)
        ev.time = utc_to_local(ev.timestamp)
        ev.event_type, ev.show_device = generate_file_audit_event_type(ev)

    filename = os.path.basename(path)
    zipped = gen_path_link(path, repo.name)
    extra_href = "&p=%s" % urlquote(path)
    return render_to_response('file_access.html', {
        'repo': repo,
        'path': path,
        'filename': filename,
        'zipped': zipped,
        'events': events,
        'extra_href': extra_href,
        'current_page': current_page,
        'prev_page': current_page-1,
        'next_page': current_page+1,
        'per_page': per_page,
        'page_next': page_next,
        }, context_instance=RequestContext(request))

def get_commit_info(commit):
    email = commit.creator_name
    item_info = {
        "name": email2nickname(email),
        "contact_email": Profile.objects.get_contact_email_by_user(email),
        'email': email,
        'time': timestamp_to_isoformat_timestr(commit.ctime),
        'description': commit.desc,
        'commit_id': commit.id,
        'client_version': commit.client_version,
        'device_name': commit.device_name
    }
    return item_info

def check_file_lock(repo_id, path, username):
    """
    0: not locked
    1: locked by other
    2: locked by me
    -1: error

    Return (is_locked, locked_by_me)
    """
    try:
        print('check lock')
        print repo_id
        print path
        print username
        file_lock = FileLocks.objects.using('syncwerk-server').filter(repo_id=repo_id, path=path.lstrip('/'))
        print len(file_lock)
        if len(file_lock) <= 0:
            return (False, False)
        if file_lock[0].email == username:
            return (True, 2)
        return (True, 1)
    except Exception as e:
        print e
        return (False, -1)

def get_file_lock_info(repo_id, path):
    try:
        print repo_id
        print path
        file_lock_info = FileLocks.objects.using('syncwerk-server').get(repo_id=repo_id, path=path)
        return file_lock_info
    except Exception as e:
        return None

def lock_file(repo_id, path, email, expire=0):
    file_lock = FileLocks(
        repo_id=repo_id,
        path=path,
        email=email,
        lock_time=int(time.time()),
        expire=expire
    )

    file_lock.save()

    file_lock_time_stamp_cnt = FileLockTimestamp.objects.filter(repo_id=repo_id).count()
    if file_lock_time_stamp_cnt <= 0:
        file_lock_ts = FileLockTimestamp(
            repo_id=repo_id,
            update_time=int(time.time())
        )
        file_lock_ts.save()

def unlock_file(repo_id, path):
    FileLocks.objects.filter(repo_id=repo_id, path=path).delete()
    file_lock_repo_cnt = FileLocks.objects.filter(repo_id=repo_id)
    if file_lock_repo_cnt <= 0:
        FileLockTimestamp.objects.filter(repo_id=repo_id).delete()


def get_max_upload_file_size():
    """Get max upload file size from config file, defaults to no limit.

    Returns ``None`` if this value is not set.
    """
    return synserv.MAX_UPLOAD_FILE_SIZE

def send_file_access_signal(request, repo, path, access_from):
    """Send file access signal
    
    Arguments:
        request {request} -- [description]
        repo {str} -- [description]
        path {str} -- [description]
        access_from {str} -- [description]
    """
    try:
        file_access_signal.send(sender=request.user, request=request, repo=repo, path=path)
    except Exception as e:
        logger.error("Error when send_file_access_signal %s message: %s" %
                     (access_from, str(e)))