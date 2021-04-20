import logging
import os
import stat
import json
import datetime
import posixpath
import re
import pytz

from importlib import import_module

from .utils import get_token_v1

from rest_framework import parsers
from rest_framework import renderers
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from django.core.urlresolvers import reverse
from django.http import HttpResponse
from django.template.defaultfilters import filesizeformat
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters
from django.conf import settings
from django.utils.http import urlquote
from django.utils import timezone

from wsgidav.addons.syncwerk.syncwerk_dav_provider import get_groups_by_user, get_group_repos, get_repo_last_modify

from restapi.share.models import UploadLinkShare, FileShare

from restapi.tenants.models import (Tenant, TenantAdmin,
                                        TenantQuota)
from restapi.api3.base import APIView
from restapi.api3.constants import EventLogActionType
from restapi.base.accounts import User
from restapi.api2.models import TokenV2, DESKTOP_PLATFORMS
from restapi.api3.throttling import ScopedRateThrottle, AnonRateThrottle, UserRateThrottle
from restapi.api3.authentication import TokenAuthentication
from restapi.api3.serializers import AuthTokenSerializer, PasswordChangeSerializer, ThirdPartyTokenSerializer
from restapi.api3.utils import get_diff_details, \
    api_error, get_file_size, prepare_starred_files, \
    get_groups, \
    api_group_check, get_timestamp, json_response, is_syncwerk_pro, api_response, \
    get_request_domain, send_html_email, get_device_name_from_token

from restapi.api3.utils.file import check_file_lock, get_file_lock_info
from restapi.api3.models import CcnetUser, SharedRepo
from restapi.profile.models import Profile, DetailedProfile
from restapi.base.templatetags.restapi_tags import email2nickname
from restapi.utils import gen_file_get_url, gen_token, gen_file_upload_url, \
    check_filename_with_rename, is_valid_username, EVENTS_ENABLED, \
    get_user_events, EMPTY_SHA1, get_syncwerk_server_ccnet_addr_port, is_pro_version, \
    gen_block_get_url, get_file_type_and_ext, HAS_FILE_SEARCH, \
    gen_file_share_link, gen_dir_share_link, is_org_context, \
    get_org_user_events, calculate_repos_last_modify, send_perm_audit_msg, \
    gen_shared_upload_link, convert_cmmt_desc_link, is_valid_dirent_name, \
    is_windows_operating_system, \
    get_no_duplicate_obj_name, is_org_context, \
    get_system_traffic_by_day, is_ldap_user
from restapi.base.templatetags.restapi_tags import email2nickname, \
    translate_restapi_time, translate_commit_desc_escape, \
    email2contact_email
from restapi.views import is_registered_user, \
    group_events_data, get_diff, \
    list_inner_pub_repos, check_folder_permission

# from restapi.views.ajax import get_groups_by_user, get_group_repos
from restapi.signals import (repo_created, repo_deleted, repo_update_signal)
from restapi.auth.signals import user_logged_in, user_logged_in_failed, user_logged_in_success_event, user_logged_in_failed_event
from restapi.utils.timeutils import utc_to_local, datetime_to_isoformat_timestr
from restapi.utils.devices import do_unlink_device
from restapi.utils.star import get_dir_starred_files
from restapi.notifications.models import UserNotification
from restapi.notifications.models import get_cache_key_of_unseen_notifications
from restapi.options.models import UserOptions
from restapi.avatar.templatetags.avatar_tags import api_avatar_url, get_default_avatar_url
from restapi.avatar.templatetags.group_avatar_tags import api_grp_avatar_url
from restapi.auth.forms import CaptchaAuthenticationForm, AuthenticationForm

from django.utils.translation import ugettext as _
from django.core.cache import cache

from restapi.settings import SHOW_TRAFFIC, SESSION_COOKIE_AGE, SESSION_EXPIRE_AT_BROWSER_CLOSE, ENABLED_ADMIN_ROLE_PERMISSIONS, ENABLED_ROLE_PERMISSIONS, LOGIN_REMEMBER_DAYS
from restapi.avatar.models import Avatar
from restapi.avatar.signals import avatar_updated
from restapi.avatar.settings import (AVATAR_MAX_AVATARS_PER_USER,
                                    AVATAR_MAX_SIZE, AVATAR_ALLOWED_FILE_EXTS, AVATAR_DEFAULT_SIZE)

from restapi.profile.forms import DetailedProfileForm
from restapi.utils.ip import get_remote_ip
from restapi.utils import get_system_admins

from pyrpcsyncwerk import RpcsyncwerkError, RpcsyncwerkObjEncoder
import synserv
from synserv import syncwserv_threaded_rpc, \
    get_personal_groups_by_user, get_session_info, is_personal_repo, \
    get_repo, check_permission, get_commits, is_passwd_set,\
    check_quota, list_share_repos, get_group_repos_by_owner, get_group_repoids, \
    is_group_user, remove_share, get_group, \
    get_commit, get_file_id_by_path, MAX_DOWNLOAD_DIR_SIZE, edit_repo, \
    ccnet_threaded_rpc, get_personal_groups, syncwerk_api, \
    create_org, ccnet_api

from constance import config
from captcha.fields import CaptchaField
from captcha.models import CaptchaStore
from captcha.helpers import captcha_image_url

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

from restapi.constants import DEFAULT_USER

logger = logging.getLogger(__name__)
json_content_type = 'application/json; charset=utf-8'
_REPO_ID_PATTERN = re.compile(r'[-0-9a-f]{36}')

HTTP_440_REPO_PASSWD_REQUIRED = 440
HTTP_441_REPO_PASSWD_MAGIC_REQUIRED = 441
HTTP_520_OPERATION_FAILED = 520

sensitive_post_parameters_m = method_decorator(
    sensitive_post_parameters(
        'password', 'old_password', 'new_password1', 'new_password2'
    )
)

LOGIN_ATTEMPT_PREFIX = 'UserLoginAttempt_'

def get_init_data(start_time, end_time, init_data=0):
    res = {}
    start_time = start_time.replace(hour=0).replace(minute=0).replace(second=0)
    end_time = end_time.replace(hour=0).replace(minute=0).replace(second=0)
    time_delta = end_time - start_time
    date_length = time_delta.days + 1
    for offset in range(date_length):
        offset = offset * 24
        dt = start_time + datetime.timedelta(hours=offset)
        if isinstance(init_data, dict):
            res[dt] = init_data.copy()
        else:
            res[dt] = init_data
    return res

def get_time_offset():
    timezone_name = timezone.get_current_timezone_name()
    offset = pytz.timezone(timezone_name).localize(datetime.datetime.now()).strftime('%z')
    return offset[:3] + ':' + offset[3:]

def repo_download_info(request, repo_id, gen_sync_token=True):
    repo = get_repo(repo_id)
    if not repo:
        return api_error(status.HTTP_404_NOT_FOUND, 'Library not found.')

    # generate download url for client
    relay_id = get_session_info().id
    addr, port = get_syncwerk_server_ccnet_addr_port()
    email = request.user.username
    if gen_sync_token:
        token = syncwerk_api.generate_repo_token(repo_id, email)
    else:
        token = ''
    repo_name = repo.name
    repo_desc = repo.desc
    repo_size = repo.size
    repo_size_formatted = filesizeformat(repo.size)
    enc = 1 if repo.encrypted else ''
    magic = repo.magic if repo.encrypted else ''
    random_key = repo.random_key if repo.random_key else ''
    enc_version = repo.enc_version
    repo_version = repo.version

    calculate_repos_last_modify([repo])

    info_json = {
        'relay_id': relay_id,
        'relay_addr': addr,
        'relay_port': port,
        'email': email,
        'token': token,
        'repo_id': repo_id,
        'repo_name': repo_name,
        'repo_desc': repo_desc,
        'repo_size': repo_size,
        'repo_size_formatted': repo_size_formatted,
        'mtime': repo.latest_modify,
        'mtime_relative': translate_restapi_time(repo.latest_modify),
        'encrypted': enc,
        'enc_version': enc_version,
        'magic': magic,
        'random_key': random_key,
        'repo_version': repo_version,
        'head_commit_id': repo.head_cmmt_id,
    }
    return Response(info_json)


def set_repo_password(request, repo, password):
    assert password, 'password must not be none'

    try:
        syncwerk_api.set_passwd(repo.id, request.user.username, password)
    except RpcsyncwerkError, e:
        if e.msg == 'Bad arguments':
            return api_error(status.HTTP_400_BAD_REQUEST, e.msg)
        elif e.msg == 'Repo is not encrypted':
            return api_error(status.HTTP_409_CONFLICT, e.msg)
        elif e.msg == 'Incorrect password':
            return api_error(status.HTTP_400_BAD_REQUEST, e.msg)
        elif e.msg == 'Internal server error':
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, e.msg)
        else:
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, e.msg)


def check_set_repo_password(request, repo):
    if not check_permission(repo.id, request.user.username):
        return api_error(status.HTTP_403_FORBIDDEN,
                         _('You do not have permission to access this library.'))

    if repo.encrypted:
        password = request.REQUEST.get('password', default=None)
        if not password:
            return api_error(HTTP_440_REPO_PASSWD_REQUIRED,
                             _('The folder password is needed.'))

        return set_repo_password(request, repo, password)


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
                         _("Failed to list dir."))

    dir_list, file_list = [], []

    starred_files = get_dir_starred_files(username, repo.id, path)

    for dirent in dirs:
        entry = {}
        if stat.S_ISDIR(dirent.mode):
            dtype = "dir"
        else:
            dtype = "file"
            entry['modifier_email'] = dirent.modifier

            fpath = posixpath.join(path, dirent.obj_name)
            entry['starred'] = False
            if fpath in starred_files:
                entry['starred'] = True

            if repo.version == 0:
                entry["size"] = get_file_size(repo.store_id, repo.version,
                                              dirent.obj_id)
            else:
                entry["size"] = dirent.size
            # if is_pro_version():
            file_lock_info = get_file_lock_info(repo.id, path.lstrip('/')+dirent.obj_name)
            print file_lock_info
            if file_lock_info is not None:
                entry["is_locked"] = True
                entry["lock_owner"] = file_lock_info.email
                entry["lock_time"] = file_lock_info.expire
                if username == file_lock_info.email:
                    entry["locked_by_me"] = True
                else:
                    entry["locked_by_me"] = False
            else:
                entry["is_locked"] = False
                entry["lock_owner"] = ''
                entry["lock_time"] = 0
                entry["locked_by_me"] = False
        entry["type"] = dtype
        entry["name"] = dirent.obj_name
        entry["id"] = dirent.obj_id
        entry["mtime"] = dirent.mtime
        entry["last_update"] = translate_restapi_time(dirent.mtime)
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
        e['modifier_contact_email'] = contact_email_dict.get(
            e['modifier_email'], '')
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


    resp = {'dirent_list': dentrys}
    resp['repo_id'] = repo.repo_id
    resp['repo_name'] = repo.name
    resp['owner'] = syncwerk_api.get_repo_owner(repo.id)
    resp['oid'] = dir_id
    resp['dir_perm'] = syncwerk_api.check_permission_by_path(
        repo.id, path, username)
    resp['permission'] = check_permission(repo.id, request.user.username)
    resp['encrypted'] = repo.encrypted

    # Check history permission
    if request.user.email == syncwerk_api.get_repo_owner(repo.id):
        resp['allow_view_history'] = True
        resp['allow_view_snapshot'] = True
        resp['allow_restore_snapshot'] = True
    else:
        try:
            share_item = SharedRepo.objects.using('syncwerk-server').get(repo_id=repo.repo_id,from_email=resp['owner'],to_email=request.user.email)
            resp['allow_view_history'] = share_item.allow_view_history
            resp['allow_view_snapshot'] = share_item.allow_view_snapshot
            resp['allow_restore_snapshot'] = share_item.allow_restore_snapshot
        except Exception as e:
            resp['allow_view_history'] = True
            resp['allow_view_snapshot'] = False
            resp['allow_restore_snapshot'] = False

    return resp


def get_dir_recursively(username, repo_id, path, all_dirs):
    path_id = syncwerk_api.get_dir_id_by_path(repo_id, path)
    dirs = syncwserv_threaded_rpc.list_dir_with_perm(repo_id, path,
                                                    path_id, username, -1, -1)

    for dirent in dirs:
        if stat.S_ISDIR(dirent.mode):
            entry = {}
            entry["type"] = 'dir'
            entry["parent_dir"] = path
            entry["id"] = dirent.obj_id
            entry["name"] = dirent.obj_name
            entry["mtime"] = dirent.mtime
            entry["last_update"] = translate_restapi_time(dirent.mtime)
            entry["permission"] = dirent.permission
            all_dirs.append(entry)

            sub_path = posixpath.join(path, dirent.obj_name)
            get_dir_recursively(username, repo_id, sub_path, all_dirs)

    return all_dirs


def get_shared_link(request, repo_id, path):
    l = FileShare.objects.filter(repo_id=repo_id).filter(
        username=request.user.username).filter(path=path)
    token = None
    if len(l) > 0:
        fileshare = l[0]
        token = fileshare.token
    else:
        token = gen_token(max_length=10)

        fs = FileShare()
        fs.username = request.user.username
        fs.repo_id = repo_id
        fs.path = path
        fs.token = token

        try:
            fs.save()
        except IntegrityError, e:
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, e.msg)

    http_or_https = request.is_secure() and 'https' or 'http'
    domain = RequestSite(request).domain
    file_shared_link = '%s://%s%sf/%s/' % (http_or_https, domain,
                                           settings.SITE_ROOT, token)
    return file_shared_link


def get_repo_file(request, repo_id, file_id, file_name, op, use_onetime=True):
    if op == 'download':
        token = syncwerk_api.get_fileserver_access_token(repo_id,
                                                        file_id, op, request.user.username, use_onetime)

        if not token:
            error_msg = _('Internal Server Error')
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        redirect_url = gen_file_get_url(token, file_name)
        response = HttpResponse(json.dumps(redirect_url), status=200,
                                content_type=json_content_type)
        response["oid"] = file_id
        return response

    if op == 'downloadblks':
        blklist = []
        encrypted = False
        enc_version = 0
        if file_id != EMPTY_SHA1:
            try:
                blks = syncwerk_api.list_blocks_by_file_id(repo_id, file_id)
                blklist = blks.split('\n')
            except RpcsyncwerkError as e:
                logger.error(e)
                return api_error(HTTP_520_OPERATION_FAILED,
                                 _('Failed to get file block list'))
        blklist = [i for i in blklist if len(i) == 40]
        if len(blklist) > 0:
            repo = get_repo(repo_id)
            encrypted = repo.encrypted
            enc_version = repo.enc_version

        res = {
            'file_id': file_id,
            'blklist': blklist,
            'encrypted': encrypted,
            'enc_version': enc_version,
        }
        response = HttpResponse(json.dumps(res), status=200,
                                content_type=json_content_type)
        response["oid"] = file_id
        return response

    if op == 'sharelink':
        path = request.GET.get('p', None)
        if path is None:
            return api_error(status.HTTP_400_BAD_REQUEST, _('Path is missing.'))

        file_shared_link = get_shared_link(request, repo_id, path)
        return Response(file_shared_link)


def reloaddir(request, repo, parent_dir):
    try:
        dir_id = syncwerk_api.get_dir_id_by_path(repo.id, parent_dir)
    except RpcsyncwerkError, e:
        logger.error(e)
        return api_error(HTTP_520_OPERATION_FAILED,
                         _("Failed to get dir id by path"))

    if not dir_id:
        return api_error(status.HTTP_404_NOT_FOUND, _("Path does not exist"))

    return get_dir_entrys_by_id(request, repo, parent_dir, dir_id)


def reloaddir_if_necessary(request, repo, parent_dir, obj_info=None):

    reload_dir = False
    s = request.GET.get('reloaddir', None)
    if s and s.lower() == 'true':
        reload_dir = True

    if not reload_dir:
        if obj_info:
            return Response(obj_info)
        else:
            return Response('success')

    return reloaddir(request, repo, parent_dir)


_default_repo_id = None


def get_system_default_repo_id():
    global _default_repo_id
    if not _default_repo_id:
        try:
            _default_repo_id = synserv.syncwserv_threaded_rpc.get_system_default_repo_id()
        except RpcsyncwerkError as e:
            logger.error(e)
    return _default_repo_id


def create_default_library(username, org_id=None):
    """Create a default library for user.

    Arguments:
    - `username`:
    """

    # Disable user guide no matter user permission error or creation error,
    # so that the guide popup only show once.
    UserOptions.objects.disable_user_guide(username)

    # if not request.user.permissions.can_add_repo():
    #     return

    if org_id:
        default_repo = syncwerk_api.create_org_repo(name=_("My Folder"),
                                                   desc=_("My Folder"),
                                                   username=username,
                                                   passwd=None,
                                                   org_id=org_id)
    else:
        default_repo = syncwerk_api.create_repo(name=_("My Folder"),
                                               desc=_("My Folder"),
                                               username=username,
                                               passwd=None)
    sys_repo_id = get_system_default_repo_id()
    if sys_repo_id is None:
        return

    try:
        dirents = syncwerk_api.list_dir_by_path(sys_repo_id, '/')
        for e in dirents:
            obj_name = e.obj_name
            syncwerk_api.copy_file(sys_repo_id, '/', obj_name,
                                  default_repo, '/', obj_name, username, 0)
    except RpcsyncwerkError as e:
        logger.error(e)
        return

    UserOptions.objects.set_default_repo(username, default_repo)
    return default_repo


def _get_login_failed_attempts(username=None, ip=None):
    """Get login failed attempts base on username and ip.
    If both username and ip are provided, return the max value.

    Arguments:
    - `username`:
    - `ip`:
    """
    if username is None and ip is None:
        return 0

    username_attempts = ip_attempts = 0

    if username:
        username_attempts = cache.get(LOGIN_ATTEMPT_PREFIX + username, 0)

    if ip:
        ip_attempts = cache.get(LOGIN_ATTEMPT_PREFIX + ip, 0)

    return max(username_attempts, ip_attempts)


def _incr_login_failed_attempts(username=None, ip=None):
    """Increase login failed attempts by 1 for both username and ip.

    Arguments:
    - `username`:
    - `ip`:

    Returns new value of failed attempts.
    """
    timeout = settings.LOGIN_ATTEMPT_TIMEOUT
    username_attempts = 1
    ip_attempts = 1

    if username:
        try:
            username_attempts = cache.incr(LOGIN_ATTEMPT_PREFIX + username)
        except ValueError:
            cache.set(LOGIN_ATTEMPT_PREFIX + username, 1, timeout)

    if ip:
        try:
            ip_attempts = cache.incr(LOGIN_ATTEMPT_PREFIX + ip)
        except ValueError:
            cache.set(LOGIN_ATTEMPT_PREFIX + ip, 1, timeout)

    return max(username_attempts, ip_attempts)


def _clear_login_failed_attempts(request, username):
    """Clear login failed attempts records.

    Arguments:
    - `request`:
    """
    ip = get_remote_ip(request)

    cache.delete(LOGIN_ATTEMPT_PREFIX + username)
    cache.delete(LOGIN_ATTEMPT_PREFIX + ip)
    p = Profile.objects.get_profile_by_user(username)
    if p and p.login_id:
        cache.delete(LOGIN_ATTEMPT_PREFIX + urlquote(p.login_id))


def get_captcha():
    """  Return json with new captcha for ajax refresh request """

    new_key = CaptchaStore.generate_key()
    to_json_response = {
        'key': new_key,
        'image_url': captcha_image_url(new_key),
    }
    return to_json_response

# Create your views here.


class Ping(APIView):
    """
    Returns a simple `pong` message when client calls `api2/ping/`.
    For example:
        curl http://127.0.0.1:8000/api3/ping/
    """
    throttle_classes = (ScopedRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_description='Check if the server is up or not',
        operation_summary='Basic ping-pong check.',
        tags=['other',],
        responses={
            200: openapi.Response(
                description='Server is up and ready',
                examples={
                    'application/json': {  
                        "message":"pong",
                        "data": None
                    }
                },
            ),
            502: openapi.Response(
                description='Server is not reachable',
                examples={
                    'application/json': {
                        'msg': ''
                    }
                },
            )
        }
    )
    def get(self, request, format=None):
        return api_response(status.HTTP_200_OK, 'pong')

    def head(self, request, format=None):
        return Response(headers={'foo': 'bar', })

class ObtainThirdPartyAuthToken(APIView):
    permission_classes = ()
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser,)
    renderer_classes = (renderers.JSONRenderer,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='Get third party token',
        operation_description='Get third party token',
        tags=['user'],
        request_body=openapi.Schema(
            type='object',
            properties={
                'username': openapi.Schema(
                    type='string',
                    description='Username or email of user'
                ),
                'password': openapi.Schema(
                    type='string',
                    description='password'
                ),
            }
        ),
        responses={
            200: openapi.Response(
                description='Get token successfully',
                examples={
                    'application/json': {
                        "message": "User registered successfully.",
                        "data": {
                            "key": "access token"
                        }
                    }
                },
            ),
            400: openapi.Response(
                description='Bad request',
                examples={
                    'application/json': {
                        "message": "",
                        "data": "{\"email\": [{\"message\": \"Error message\", \"code\": \"Error code\"}]}"
                    }
                },
            ),
        }
    )
    def post(self, request):
        context = { 'request': request }
        print request.data
        serializer = ThirdPartyTokenSerializer(data=request.data, context=context)
        if serializer.is_valid():
            key = serializer.validated_data

            # trust_dev = False
            # try:
            #     trust_dev_header = int(request.META.get('HTTP_X_SYNCWERK_2FA_TRUST_DEVICE', ''))
            #     trust_dev = True if trust_dev_header == 1 else False
            # except ValueError:
            #     trust_dev = False

            # skip_2fa_header = request.META.get('HTTP_X_SYNCWERK_S2FA', None)
            # if skip_2fa_header is None:
            #     if trust_dev:
            #         # 2fa login with trust device,
            #         # create new session, and return session id.
            #         pass
            #     else:
            #         # No 2fa login or 2fa login without trust device,
            #         # return token only.
            #         # return Response({'token': key})
            #         return api_response(code=200, data={'token': key})
            # else:
            #     # 2fa login without OTP token,
            #     # get or create session, and return session id
            #     pass

            from restapi.two_factor.views.login import remember_device
            remember_device(request.data['username'])
            # return Response({'token': key}, headers=headers)

            # Send login successfully signal
            try:
                user = User.objects.get(email=request.data['username'])
                user_logged_in_success_event.send(sender=None, request=request, user=user, key=key)
            except Exception as e:
                logger.error(e)

            return api_response(code=200, data={'token': key})
        
        # Send login failed signal
        try:
            # TODO on api3 currently not get device name via header (hard coded: apiv3), checkout ThirdPartyTokenSerializer validator for device name 
            user_logged_in_failed_event.send(sender=None, request=request, device_name=None)
        except Exception as e:
            logger.error(e)

        return api_error(code=400, msg=serializer.errors)
        # return Response(serializer.errors,
        #                 status=status.HTTP_400_BAD_REQUEST,
        #                 headers=headers)

class OtherObtainAuthToken(APIView):
    throttle_classes = (AnonRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='Login',
        operation_description='User login to the system',
        tags=['user'],
        manual_parameters=[
            openapi.Parameter(
                name='login',
                in_="formData",
                type='string',
                description='Email or username for logging in',
                required=True
            ),
            openapi.Parameter(
                name='password',
                in_="formData",
                type='string',
                description='Password for logging in',
                required=True
            ),
            openapi.Parameter(
                name='captcha_0',
                in_="formData",
                type='string',
                description='Captcha key',
            ),
            openapi.Parameter(
                name='captcha_1',
                in_="formData",
                type='string',
                description='Captcha answer',
            ),
            openapi.Parameter(
                name='remember_me',
                in_="formData",
                type='string',
                description='Remember me. Default is "1"',
                enum=['0','1']
            ),
        ],
        responses={
            200: openapi.Response(
                description='User registration successfully',
                examples={
                    'application/json': {
                        "message": "User registered successfully.",
                        "data": None
                    }
                },
            ),
            400: openapi.Response(
                description='Bad request',
                examples={
                    'application/json': {
                        "message": "",
                        "data": "{\"email\": [{\"message\": \"Error message\", \"code\": \"Error code\"}]}"
                    }
                },
            ),
        }
    )
    def post(self, request):
        login = request.POST.get('login')
        remember_me = int(request.POST.get('remember_me', '0'))
        ip = get_remote_ip(request)
        failed_attempt = _get_login_failed_attempts(username=login, ip=ip)
        logger.debug('number of failed attempt = %s', failed_attempt)
        # select the correct form
        if bool(config.FREEZE_USER_ON_LOGIN_FAILED) is True:
            form = AuthenticationForm(data=request.POST)
        else:
            if failed_attempt >= config.LOGIN_ATTEMPT_LIMIT:
                form = CaptchaAuthenticationForm(data=request.POST)
            else:
                form = AuthenticationForm(data=request.POST)
        # validate + authenticate
        if form.is_valid():
            _clear_login_failed_attempts(request, login)
            guide_enabled = UserOptions.objects.is_user_guide_enabled(login)
            if guide_enabled:
                request.user.username = login
                create_default_library(login)
            # Process of get token
            token = get_token_v1(login)
            reps = {}
            if UserOptions.objects.passwd_change_required(login):
                reps['force_passwd_change'] = True
            response = Response(reps, status=status.HTTP_200_OK)
            if remember_me == 1:
                cookie_max_age = 60 * 60 * 24 * LOGIN_REMEMBER_DAYS
            elif SESSION_EXPIRE_AT_BROWSER_CLOSE:
                cookie_max_age = None
            else:
                cookie_max_age = SESSION_COOKIE_AGE
            response.set_cookie('token', token, max_age=cookie_max_age, httponly=True, secure=request.is_secure())
            # user_logged_in = 
            user = User.objects.get(email=login)
            user.last_login = datetime.datetime.now()

            # update user role if LDAP user
            if is_ldap_user(user):
                if not user.role:
                    User.objects.update_role(user.email, DEFAULT_USER)
            # user.save()
            user_logged_in.send(sender=user.__class__, request=request, user=user)

            # Send signal for event log
            try:
                user_logged_in_success_event.send(sender=user.__class__, request=request, user=user)
            except Exception as e:
                logger.error(e)
            return response
        user_logged_in_failed.send(sender=None, request=request)

        # Send login failed signal
        try:
            # TODO on api3 currently not get device name via header (hard coded: apiv3), checkout ThirdPartyTokenSerializer validator for device name 
            user_logged_in_failed_event.send(sender=None, request=request, device_name=None)
        except Exception as e:
            logger.error(e)

        #Form invalid
        failed_attempt = _incr_login_failed_attempts(username=login,
                                                     ip=ip)
        if failed_attempt >= config.LOGIN_ATTEMPT_LIMIT:
            if bool(config.FREEZE_USER_ON_LOGIN_FAILED) is True:
                logger.warn('Login attempt limit reached, try freeze the user, email/username: %s, ip: %s, attemps: %d' %
                            (login, ip, failed_attempt))
                email = Profile.objects.get_username_by_login_id(login)
                if email is None:
                    email = login
                try:
                    user = User.objects.get(email)
                    if user.is_active:
                        user.freeze_user(notify_admins=False)
                        # Send mail of frozen user
                        site_name = request.META['HTTP_HOST']
                        email_template_name = 'api3/sysadmin/account_frozen_admin_notification.html'
                        c = {
                            'user_email': user.username,
                            'user': user,
                            'request_domain': get_request_domain(request)
                        }
                        # notify admin
                        
                        admins = get_system_admins()
                        admin_arr = []
                        for u in admins:
                            admin_arr.append(u.email)

                        send_html_email(_("Account %s frozen on %s") % (user.username, site_name),
                                        email_template_name, c, None, admin_arr, request=request)

                        logger.warn('Login attempt limit reached, freeze the user email/username: %s, ip: %s, attemps: %d' %
                                    (login, ip, failed_attempt))
                except User.DoesNotExist:
                    logger.warn('Login attempt limit reached with invalid email/username: %s, ip: %s, attemps: %d' %
                                (login, ip, failed_attempt))
                    pass
                return api_error(code=401, msg='This account has been frozen due to too many failed login attempts.', error_code='account_has_been_frozen_failed_login_attempts')
            else:
                return api_error(code=401, msg='', data=form.errors, error_code='incorrect_username_or_password')
        else:
            return api_error(code=401, msg='', data=form.errors, error_code='incorrect_username_or_password')


class LoginConfiguration(APIView):
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='Get login page configurations',
        operation_description='Get login page configuration. Including the flag to notify if the user account is currently locked or the captcha is shown or not',
        tags=['user'],
        responses={
            200: openapi.Response(
                description='Retrieve login page configuration successfully.\n - "captcha" will be null if IS_SHOWING_CAPTCHA is falsy',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "IS_SHOWING_CAPTCHA": True,
                            "captcha": {
                                "image_url": "captcha img url",
                                "key": "captcha img key"
                            }
                        }
                    }
                },
            ),
        }
    )
    def get(self, request):
        # get ip of the request
        ip = get_remote_ip(request)
        # get number of failed attemps
        failed_attempt = _get_login_failed_attempts(ip=ip)
        if failed_attempt >= config.LOGIN_ATTEMPT_LIMIT:
            if bool(config.FREEZE_USER_ON_LOGIN_FAILED) is True:
                data = {
                    'IS_SHOWING_CAPTCHA': False,
                }
                return api_response(msg="This account has been frozen due to too many failed login attempts.", data=data)
            else:
                logger.warn('Login attempt limit reached, show Captcha, ip: %s, attempts: %d' %
                            (ip, failed_attempt))
                captcha = get_captcha()
                captcha['image_url'] = config.SERVICE_URL + '/api3' + \
                    captcha.get('image_url')
                data = {
                    'IS_SHOWING_CAPTCHA': True,
                    'captcha': captcha,
                }
                return api_response(data=data)
        else:
            data = {
                'IS_SHOWING_CAPTCHA': False,
            }
            return api_response(data=data)


class GetCaptcha(APIView):
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        security=[],
        operation_summary='Get captcha',
        operation_description='Get captcha for login page',
        tags=['user'],
        responses={
            200: openapi.Response(
                description='Retrieve captcha data successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "image_url": "captcha image link",
                            "key": "captcha key"
                        }
                    }
                },
            ),
        }
    )
    def get(self, request):
        captcha = get_captcha()
        captcha['image_url'] = config.SERVICE_URL + "/api3" + \
            captcha.get('image_url')
        return api_response(data=captcha)


class AuthStatus(APIView):
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get user auth status',
        operation_description='Get details about user authentication status',
        tags=['user'],
        responses={
            200: openapi.Response(
                description='User authentication status retrieve successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "is_auth": True,
                            "force_passwd_change": False,
                            "is_staff": True,
                            "role": "",
                            "is_guest": False,
                            "permissions": {
                                "can_add_repo": True,
                                "can_view_org": True,
                                "can_add_group": True,
                                "can_use_global_address_book": True,
                                "can_generate_share_link": True,
                                "can_generate_upload_link": True
                            }
                        }
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / unauthorized.',
                examples={
                    'application/json': {
                        "detail": "Invalid token"
                    }
                }
            )
        }
    )
    def get(self, request, format=None):
        resp = {
            'role': request.user.role,
            'is_auth': True,
            'is_staff': request.user.is_staff,
            'is_guest': request.user.role == 'guest',
            'permissions': {
                'can_add_repo': request.user.permissions.can_add_repo(),
                'can_add_group': request.user.permissions.can_add_group(),
                'can_generate_share_link': request.user.permissions.can_generate_share_link(),
                'can_generate_upload_link': request.user.permissions.can_generate_upload_link(),
                'can_use_global_address_book': request.user.permissions.can_use_global_address_book(),
                'can_view_org': request.user.permissions.can_view_org()
            }
        }
        if UserOptions.objects.passwd_change_required(request.user.email):
            resp['force_passwd_change'] = True
        else:
            resp['force_passwd_change'] = False
        return api_response(data=resp)


class AccountInfo(APIView):
    """
    Show account info.
    """
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Account info',
        operation_description='Get current user account information',
        tags=['admin'],
        responses={
            200: openapi.Response(
                description='Retrieve user login tokens successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            {
                                "type": "webapp",
                                "ctime": "2019-02-15T04:00:33.508308",
                                "key": "b0334fcdc41a512fc5cf094c28d07690e5cb0810"
                            },
                            {
                                "last_accessed": "2019-02-11T02:54:53",
                                "device_name": "Nexus 5",
                                "platform_version": "6.0.1",
                                "platform": "android",
                                "user": "admin@alpha.syncwerk.com",
                                "key": "f6afe84b11820433c506fbaedb1b1bc35a60f313",
                                "wiped_at": None,
                                "client_version": "2.2.11",
                                "last_login_ip": "::ffff:192.168.1.250",
                                "device_id": "8974b51d0c0875e2"
                            }
                        ]
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / unauthorized.',
                examples={
                    'application/json': {
                        "detail": "Invalid token"
                    }
                }
            )
        }
    )
    def get(self, request, format=None):
        info = {}
        email = request.user.username
        ccnet_user_info = CcnetUser.objects.get(email=email)
        p = Profile.objects.get_profile_by_user(email)
        d_p = DetailedProfile.objects.get_detailed_profile_by_user(email)

        if is_org_context(request):
            org_id = request.user.org.org_id
            quota_total = syncwerk_api.get_org_user_quota(org_id, email)
            quota_usage = syncwerk_api.get_org_user_quota_usage(org_id, email)
        else:
            quota_total = syncwerk_api.get_user_quota(email)
            quota_usage = syncwerk_api.get_user_self_usage(email)
        info['email'] = email
        info['name'] = email2nickname(email)
        info['total'] = quota_total
        info['usage'] = quota_usage
        info['login_id'] = p.login_id if p and p.login_id else ""
        info['department'] = d_p.department if d_p else ""
        info['contact_email'] = p.contact_email if p else ""
        # info['tenant'] = p.tenant if p and p.tenant else ""
        info['language'] = ccnet_user_info.language
        info['roles'] = request.user.role
        info['is_staff'] = request.user.is_staff

        if p and p.tenant:
            tenant_details = Tenant.objects.get(name=p.tenant)
            info['tenant'] = tenant_details.name
            info['tenant_id'] = tenant_details.id
            try:
                inst_admin = TenantAdmin.objects.get(user=request.user.email, tenant_id=tenant_details.id)
                info['is_tenant_admin'] = True
            except TenantAdmin.DoesNotExist:
                info['is_tenant_admin'] = False
        else:
            info['tenant'] = ''
            info['tenant_id'] = None
            info['is_tenant_admin'] = False
        if request.user.role in ENABLED_ROLE_PERMISSIONS:
            info['permissions'] = ENABLED_ROLE_PERMISSIONS[request.user.role]
        elif request.user.role in ENABLED_ADMIN_ROLE_PERMISSIONS:
            info['permissions'] = ENABLED_ADMIN_ROLE_PERMISSIONS[request.user.role]
        else:
            info['permissions'] = {} ## Means allow all

        avatar_size = AVATAR_DEFAULT_SIZE
        try:
            avatar_url, is_default, date_uploaded = api_avatar_url(
                email, avatar_size)
        except Exception as e:
            logger.error(e)
            avatar_url = get_default_avatar_url()
            is_default = True

        info['avatar_url'] = '%s%s' % (config.SERVICE_URL, avatar_url)
        info['avatar_size'] = avatar_size
        info['is_default_avatar'] = is_default
        # return Response(info)
        return api_response(code=status.HTTP_200_OK, data=info)


class Repos(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )
    parser_classes=(parsers.JSONParser, )
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get folder list',
        operation_description='''Get folder list''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name="type",
                in_="query",
                type='string',
                description='''Types of folder to retrieve. Can be one or multiple below values (seperated by comma): \n
- mine: current user own folders.\n
- shared: folders shared to the current user.\n
- group: folders of the group that the current user is in.\n
- org: publi folders.\n

Default value contains all the types above.                
                '''
            )
        ],
        responses={
            200: openapi.Response(
                description='Successfully retrieve result.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            {
                                "permission": "rw",
                                "encrypted": False,
                                "mtime_relative": "<time datetime=\"2019-02-14T08:34:13\" is=\"relative-time\" title=\"Thu, 14 Feb 2019 08:34:13 +0000\" >1 day ago</time>",
                                "mtime": 1550133253,
                                "owner": "admin@alpha.syncwerk.com",
                                "root": "",
                                "id": "5162d1dd-428d-4a6f-9d44-c60ad57abebb",
                                "size": 1630,
                                "name": "tgregr",
                                "type": "repo",
                                "virtual": False,
                                "version": 1,
                                "head_commit_id": "10f6c325a0d602667f6d11281f2e2aed8c8ff6a0",
                                "desc": "",
                                "size_formatted": "1.6\u00a0KB"
                            },
                            {
                                "owner_nickname": "test10@grr.la",
                                "name": "this folder will be corrupted",
                                "share_type": "personal",
                                "permission": "rw",
                                "size_formatted": "13.3\u00a0MB",
                                "mtime_relative": "<time datetime=\"2019-02-01T10:06:46\" is=\"relative-time\" title=\"Fri, 1 Feb 2019 10:06:46 +0000\" >13 days ago</time>",
                                "head_commit_id": "b169ba38dccdb6d62f2d4cb97118cc17f4c8fd55",
                                "encrypted": False,
                                "version": 1,
                                "mtime": 1549015606,
                                "owner": "test10@grr.la",
                                "root": "",
                                "desc": None,
                                "type": "srepo",
                                "id": "b50d8399-dafb-4682-950f-a35142ed9169",
                                "size": 13920226
                            },
                            {
                                "permission": "rw",
                                "encrypted": False,
                                "mtime_relative": "<time datetime=\"2019-02-13T02:39:51\" is=\"relative-time\" title=\"Wed, 13 Feb 2019 02:39:51 +0000\" >2 days ago</time>",
                                "mtime": 1550025591,
                                "owner": None,
                                "id": "de138e58-9e0e-4e79-907c-f2a8ad003f5e",
                                "size": 0,
                                "name": "share to group admin",
                                "root": "",
                                "version": 1,
                                "head_commit_id": "4b41e44de461edacf608adca73786a584c239814",
                                "desc": None,
                                "type": "grepo"
                            }
                        ]
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid"
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
    def get(self, request, format=None):
        # parse request params
        filter_by = {
            'mine': False,
            'shared': False,
            'group': False,
            'org': False,
        }

        rtype = request.GET.get('type', '')
        if not rtype:
            # set all to True, no filter applied
            filter_by = filter_by.fromkeys(filter_by.iterkeys(), True)

        for f in rtype.split(','):
            f = f.strip()
            filter_by[f] = True

        email = request.user.username

        repos_json = []
        if filter_by['mine']:
            if is_org_context(request):
                org_id = request.user.org.org_id
                owned_repos = syncwerk_api.get_org_owned_repo_list(org_id,
                                                                  email, ret_corrupted=True)
            else:
                owned_repos = syncwerk_api.get_owned_repo_list(email,
                                                              ret_corrupted=True)

            owned_repos.sort(lambda x, y: cmp(y.last_modify, x.last_modify))
            for r in owned_repos:
                # do not return virtual repos
                if r.is_virtual:
                    continue

                repo_info = syncwerk_api.get_repo(r.id)

                repo = {
                    "type": "repo",
                    "id": r.id,
                    "owner": email,
                    "name": r.name,
                    "mtime": r.last_modify,
                    "mtime_relative": translate_restapi_time(r.last_modify),
                    "size": r.size,
                    "size_formatted": filesizeformat(r.size),
                    "encrypted": r.encrypted,
                    "permission": 'rw',  # Always have read-write permission to owned repo
                    "virtual": False,
                    "root": '',
                    "head_commit_id": r.head_cmmt_id,
                    "version": r.version,
                    'desc': repo_info.desc
                }
                repos_json.append(repo)

        if filter_by['shared']:

            if is_org_context(request):
                org_id = request.user.org.org_id
                shared_repos = syncwerk_api.get_org_share_in_repo_list(org_id,
                                                                      email, -1, -1)
            else:
                shared_repos = syncwerk_api.get_share_in_repo_list(
                    email, -1, -1)

            shared_repos.sort(lambda x, y: cmp(y.last_modify, x.last_modify))
            for r in shared_repos:
                r.password_need = is_passwd_set(r.repo_id, email)
                repo = {
                    "type": "srepo",
                    "id": r.repo_id,
                    "owner": r.user,
                    "name": r.repo_name,
                    "owner_nickname": email2nickname(r.user),
                    "mtime": r.last_modify,
                    "mtime_relative": translate_restapi_time(r.last_modify),
                    "size": r.size,
                    "size_formatted": filesizeformat(r.size),
                    "encrypted": r.encrypted,
                    "permission": r.permission,
                    "share_type": r.share_type,
                    "root": '',
                    "head_commit_id": r.head_cmmt_id,
                    "version": r.version,
                    'desc': r.desc
                }
                repos_json.append(repo)

        if filter_by['group']:
            groups = get_groups_by_user(request.user.username, None)
            group_repos_id = get_group_repos(request.user.username, None, groups)
            group_repos = [];
            for r_id in group_repos_id:
                group_repos.append(syncwerk_api.get_repo(r_id))
            group_repos.sort(lambda x, y: cmp(y.last_modify, x.last_modify))
            for r in group_repos:
                repo = {
                    "type": "grepo",
                    "id": r.id,
                    "owner": r.owner,
                    # "owner": r.group.group_name,
                    # "groupid": r.group.id,
                    "name": r.name,
                    "mtime": r.last_modify,
                    "mtime_relative": translate_restapi_time(r.last_modify),
                    "size": r.size,
                    "encrypted": r.encrypted,
                    "permission": check_permission(r.id, email),
                    "root": '',
                    "head_commit_id": r.head_cmmt_id,
                    "version": r.version,
                    'desc': r.description
                }
                repos_json.append(repo)

        if filter_by['org'] and request.user.permissions.can_view_org():
            public_repos = list_inner_pub_repos(request)
            for r in public_repos:
                repo = {
                    "type": "grepo",
                    "id": r.repo_id,
                    "name": r.repo_name,
                    "owner": "Organization",
                    "mtime": r.last_modified,
                    "mtime_relative": translate_restapi_time(r.last_modified),
                    "size": r.size,
                    "size_formatted": filesizeformat(r.size),
                    "encrypted": r.encrypted,
                    "permission": r.permission,
                    "share_from": r.user,
                    "share_type": r.share_type,
                    "root": '',
                    "head_commit_id": r.head_cmmt_id,
                    "version": r.version,
                    'desc': r.description
                }
                repos_json.append(repo)

        response = HttpResponse(json.dumps(repos_json), status=200,
                                content_type=json_content_type)
        response["enable_encrypted_library"] = config.ENABLE_ENCRYPTED_FOLDER
        # return response
        return api_response(data=repos_json)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Create a new folder',
        operation_description='''Create a new folder''',
        tags=['folders'],
        request_body=openapi.Schema(
            type='object',
            properties={
                'from': openapi.Schema(
                    type='string',
                    description='Platform used to create the folder. Should be "web" by default'
                ),
                'name': openapi.Schema(
                    type='string',
                    description='Name of the new folder'
                ),
                'desc': openapi.Schema(
                    type='string',
                    description='Description of the new folder'
                ),
                'passwd': openapi.Schema(
                    type='string',
                    description='folder password. Only for creating encrypted folder. When creating unencrypted folder, the value should be None, not an empty string'
                ),
            }
        ),
        responses={
            201: openapi.Response(
                description='Successfully retrieve result.',
                examples={
                    'application/json': {
                        "message": "The folder has been created successfully.",
                        "data": {
                            "repo_size": 0,
                            "repo_size_formatted": "0\u00a0bytes",
                            "repo_id": "fc22da80-58e6-4cd9-b045-9240c94a4d63",
                            "magic": "",
                            "encrypted": "",
                            "repo_desc": "",
                            "random_key": "",
                            "relay_id": "99e7afa5B84aAC3C951Bce204ABaEbfcAD1c1a28",
                            "enc_version": 0,
                            "mtime_relative": "<time datetime=\"2019-02-15T10:04:24\" is=\"relative-time\" title=\"Fri, 15 Feb 2019 10:04:24 +0000\" >Just now</time>",
                            "relay_addr": "alpha.syncwerk.com",
                            "token": "976c184fbd2e6c9fea6531210927b9f4af6f6990",
                            "repo_version": 1,
                            "head_commit_id": "7c058c90df891b6f23f6404894f2cb5518c4644e",
                            "relay_port": 10001,
                            "mtime": 1550225064,
                            "email": "admin@alpha.syncwerk.com",
                            "repo_name": "test repo name"
                        }
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid"
                    }
                }
            ),
            403: openapi.Response(
                description='You don\'t have permission to perform this operation.',
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
            520: openapi.Response(
                description='Failed to create folder',
                examples={
                    'application/json': {
                        "message": "Failed to create folder",
                        "data": None
                    }
                }
            ),
        }
    )
    def post(self, request, format=None):
        if not request.user.permissions.can_add_repo():
            return api_error(status.HTTP_403_FORBIDDEN,
                             _('You do not have permission to create library.'))

        req_from = request.GET.get('from', "")
        if req_from == 'web':
            gen_sync_token = False  # Do not generate repo sync token
        else:
            gen_sync_token = True

        username = request.user.username
        repo_name = request.data.get("name", None)
        if not repo_name:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             _('Folder name is required.'))

        if not is_valid_dirent_name(repo_name):
            return api_error(status.HTTP_400_BAD_REQUEST,
                             _('name invalid.'))

        repo_desc = request.data.get("desc", '')
        org_id = -1
        if is_org_context(request):
            org_id = request.user.org.org_id

        repo_id = request.data.get('repo_id', '')
        try:
            if repo_id:
                # client generates magic and random key
                repo_id, error = self._create_enc_repo(
                    request, repo_id, repo_name, repo_desc, username, org_id)
            else:
                repo_id, error = self._create_repo(
                    request, repo_name, repo_desc, username, org_id)
        except RpcsyncwerkError as e:
            logger.error(e)
            return api_error(HTTP_520_OPERATION_FAILED,
                             _('Failed to create folder.'))
        if error is not None:
            return error
        if not repo_id:
            return api_error(HTTP_520_OPERATION_FAILED,
                             _('Failed to create folder.'))
        else:
            library_template = request.data.get("library_template", '')
            repo_created.send(sender=None,
                              org_id=org_id,
                              creator=username,
                              repo_id=repo_id,
                              repo_name=repo_name,
                              library_template=library_template)
            repo_update_signal.send(sender=request.user,
                                            request=request,
                                            action_type=EventLogActionType.ADDED_DIR.value,
                                            repo_id=repo_id,
                                            repo_name=repo_name)
            resp = repo_download_info(request, repo_id,
                                      gen_sync_token=gen_sync_token)

            # FIXME: according to the HTTP spec, need to return 201 code and
            # with a corresponding location header
            # resp['Location'] = reverse('api2-repo', args=[repo_id])
            # return resp
            return api_response(status.HTTP_201_CREATED, _('The folder has been created successfully.'), resp.data)

    def _create_repo(self, request, repo_name, repo_desc, username, org_id):
        passwd = request.data.get("passwd", None)

        # to avoid 'Bad magic' error when create repo, passwd should be 'None'
        # not an empty string when create unencrypted repo
        if not passwd:
            passwd = None

        if (passwd is not None) and (not config.ENABLE_ENCRYPTED_FOLDER):
            return api_error(status.HTTP_403_FORBIDDEN,
                             'NOT allow to create encrypted library.')

        if org_id > 0:
            repo_id = syncwerk_api.create_org_repo(repo_name, repo_desc,
                                                  username, passwd, org_id)
        else:
            repo_id = syncwerk_api.create_repo(repo_name, repo_desc,
                                              username, passwd)
        return repo_id, None

    def _create_enc_repo(self, request, repo_id, repo_name, repo_desc, username, org_id):
        if not _REPO_ID_PATTERN.match(repo_id):
            return api_error(status.HTTP_400_BAD_REQUEST, _('Repo id must be a valid uuid'))
        magic = request.data.get('magic', '')
        random_key = request.data.get('random_key', '')
        try:
            enc_version = int(request.data.get('enc_version', 0))
        except ValueError:
            return None, api_error(status.HTTP_400_BAD_REQUEST,
                                   _('Invalid enc_version param.'))
        if len(magic) != 64 or len(random_key) != 96 or enc_version < 0:
            return None, api_error(status.HTTP_400_BAD_REQUEST,
                                   _('You must provide magic, random_key and enc_version.'))

        if org_id > 0:
            repo_id = syncwerk_api.create_org_enc_repo(repo_id, repo_name, repo_desc,
                                                      username, magic, random_key, enc_version, org_id)
        else:
            repo_id = syncwerk_api.create_enc_repo(
                repo_id, repo_name, repo_desc, username,
                magic, random_key, enc_version)
        return repo_id, None


class Repo(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication, )
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    parser_classes=(parsers.JSONParser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get folder detail',
        operation_description='''Get details of a specific folder''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name="repo_id",
                in_="path",
                type='string',
                description='id of the folder to get details'
            ),
        ],
        responses={
            201: openapi.Response(
                description='Successfully retrieve result.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "permission": "rw",
                            "encrypted": True,
                            "enc_version": 2,
                            "mtime": 1550225455,
                            "owner": "self",
                            "id": "515a1b5a-62fa-4be9-aeb0-edf0788510fd",
                            "desc": "",
                            "magic": "bce4ec9572f31021e949c1844b1c35e9e3c6138c3b5dc36d4c204070b966db3d",
                            "name": "test22",
                            "root": "0000000000000000000000000000000000000000",
                            "file_count": 0,
                            "random_key": "e00d065cb7ffcca87db3db5b46c947df34ef5dadec5e8ca19e1563cee2e2e248d8fb37c0a9f40e4d45dac107402d10e6",
                            "size": 0,
                            "type": "repo"
                        }
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid"
                    }
                }
            ),
            403: openapi.Response(
                description='You don\'t have permission to perform this operation.',
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
                        "message": "Folder not found",
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
        repo = get_repo(repo_id)
        if not repo:
            return api_error(status.HTTP_404_NOT_FOUND, 'Folder not found.')

        username = request.user.username
        if not check_folder_permission(request, repo_id, '/'):
            return api_error(status.HTTP_403_FORBIDDEN,
                             _('You do not have permission to access this folder.'))

        # check whether user is repo owner
        if is_org_context(request):
            repo_owner = syncwerk_api.get_org_repo_owner(repo.id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo.id)
        owner = "self" if username == repo_owner else "share"

        last_commit = get_commits(repo.id, 0, 1)[0]
        repo.latest_modify = last_commit.ctime if last_commit else None

        # query repo infomation
        repo.size = syncwerk_api.get_repo_size(repo_id)
        current_commit = get_commits(repo_id, 0, 1)[0]
        root_id = current_commit.root_id if current_commit else None

        repo_json = {
            "type": "repo",
            "id": repo.id,
            "owner": owner,
            "name": repo.name,
            "mtime": repo.latest_modify,
            "size": repo.size,
            "encrypted": repo.encrypted,
            "root": root_id,
            "permission": check_permission(repo.id, username),
            "file_count": repo.file_count,
            'desc': repo.desc
        }
        if repo.encrypted:
            repo_json["enc_version"] = repo.enc_version
            repo_json["magic"] = repo.magic
            repo_json["random_key"] = repo.random_key

        # return Response(repo_json)
        return api_response(status.HTTP_200_OK, '', repo_json)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Edit folder details',
        operation_description='''Edit folder details. Support for rename and update folder currently.''',
        operation_id='repo_update_info',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name="repo_id",
                in_="path",
                type='string',
                description='id of the folder to be updated',
            ),
            openapi.Parameter(
                name="op",
                in_="query",
                type='string',
                description='Operation type. Supported values:\n- rename: currenly for both rename and update folder description.' 
            ),
        ],
        request_body=openapi.Schema(
            type='object',
            properties={
                'repo_name': openapi.Schema(
                    type='string',
                    description='Folder new name'
                ),
                'repo_desc': openapi.Schema(
                    type='string',
                    description='Folder new description'
                ),
            }
        ),
        responses={
            200: openapi.Response(
                description='Operation completed successfully',
                examples={
                    'application/json': {
                        "message": "Rename library successfully.",
                        "data": None
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid"
                    }
                }
            ),
            403: openapi.Response(
                description='You don\'t have permission to perform this operation.',
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
                        "message": "Folder not found",
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
    def post(self, request, repo_id, format=None):
        repo = get_repo(repo_id)
        if not repo:
            return api_error(status.HTTP_404_NOT_FOUND, _('Folder not found.'))
        op = request.GET.get('op', 'setpassword')
        if op == 'checkpassword':
            magic = request.REQUEST.get('magic', default=None)
            if not magic:
                return api_error(HTTP_441_REPO_PASSWD_MAGIC_REQUIRED,
                                 _('Folder password magic is needed.'))

            if not check_folder_permission(request, repo_id, '/'):
                return api_error(status.HTTP_403_FORBIDDEN, _('Permission denied.'))

            try:
                syncwerk_api.check_passwd(repo.id, magic)
            except RpcsyncwerkError as e:
                logger.error(e)
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                                 "RpcsyncwerkError:" + e.msg)
            return api_response(status.HTTP_200_OK, 'success', )
        elif op == 'setpassword':
            resp = check_set_repo_password(request, repo)
            if resp:
                return resp
            return api_response(status.HTTP_200_OK, 'success', )
        elif op == 'rename':
            username = request.user.username
            repo_name = request.data.get('repo_name')
            repo_desc = request.data.get('repo_desc')
            if not is_valid_dirent_name(repo_name):
                return api_error(status.HTTP_400_BAD_REQUEST,
                                 'name invalid.')
            # check permission
            if is_org_context(request):
                repo_owner = syncwerk_api.get_org_repo_owner(repo.id)
            else:
                repo_owner = syncwerk_api.get_repo_owner(repo.id)
            is_owner = True if username == repo_owner else False
            if not is_owner:
                return api_error(status.HTTP_403_FORBIDDEN,
                                 _('You do not have permission to rename this library.'))
            if edit_repo(repo_id, repo_name, repo_desc, username):
                # For audit log
                repo_update_signal.send(sender=request.user,
                                            request=request,
                                            action_type=EventLogActionType.RENAMED_DIR.value,
                                            repo_id=repo_id,
                                            repo_name="%s > %s"%(repo_name,repo.name))
                return api_response(status.HTTP_200_OK, _('Rename library successfully.'), )
            else:
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                                 _("Unable to rename folder"))
        # return Response("unsupported operation")
        return api_response(status.HTTP_200_OK, _('unsupported operation'), )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Remove a folder',
        operation_description='''Remove a folder by it's id.''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name="repo_id",
                in_="path",
                type='string',
                description='id of the folder to be deleted',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Successfully retrieve result.',
                examples={
                    'application/json': {
                        "message": "Folder has been deleted successfully.",
                        "data": None
                    }
                },
            ),
            400: openapi.Response(
                description='Bad request due to folder not found',
                examples={
                    'application/json': {
                        "message": "Folder not found",
                        "data": None
                    }
                }
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid"
                    }
                }
            ),
            403: openapi.Response(
                description='You don\'t have permission to perform this operation.',
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
    def delete(self, request, repo_id, format=None):
        username = request.user.username
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             _('Folder does not exist.'))

        # check permission
        if is_org_context(request):
            repo_owner = syncwerk_api.get_org_repo_owner(repo.id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo.id)
        is_owner = True if username == repo_owner else False
        if not is_owner:
            return api_error(
                status.HTTP_403_FORBIDDEN,
                _('You do not have permission to delete this library.')
            )

        usernames = synserv.get_related_users_by_repo(repo_id)
        syncwerk_api.remove_repo(repo_id)
        repo_deleted.send(sender=None,
                          org_id=-1,
                          usernames=usernames,
                          repo_owner=repo_owner,
                          repo_id=repo_id,
                          repo_name=repo.name)
        repo_update_signal.send(sender=request.user,
                                            request=request,
                                            action_type=EventLogActionType.DELETED_DIR.value,
                                            repo_id=repo_id,
                                            repo_name=repo.name)
        # return Response('success', status=status.HTTP_200_OK)
        return api_response(status.HTTP_200_OK, _('Folder has been deleted successfully.'))


class PubRepos(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.MultiPartParser,)
    
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get public folders',
        operation_description='''Get list of public folders''',
        tags=['folders'],
        responses={
            200: openapi.Response(
                description='Successfully retrieve information.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "id": "",
                            "name": "",
                            "desc": "",
                            "owner": "",
                            "owner_nickname": "",
                            "mtime": "",
                            "mtime_relative": "",
                            "size": 0,
                            "size_formatted": "",
                            "encrypted": False,
                            "permission": "",
                            "root": "",
                            "enc_version": "",
                            "magic": "",
                            "random_key": ""
                        }
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid"
                    }
                }
            ),
            403: openapi.Response(
                description='You don\'t have permission to perform this operation.',
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
    def get(self, request, format=None):
        # Remove the permission check of getting public folders
        # if not request.user.permissions.can_view_org():
        #     return api_error(status.HTTP_403_FORBIDDEN,
        #                      _('You do not have permission to view public libraries.'))

        repos_json = []
        public_repos = list_inner_pub_repos(request)
        for r in public_repos:
            repo = {
                "id": r.repo_id,
                "name": r.repo_name,
                "desc": r.repo_desc,
                "owner": r.user,
                "owner_nickname": email2nickname(r.user),
                "mtime": r.last_modified,
                "mtime_relative": translate_restapi_time(r.last_modified),
                "size": r.size,
                "size_formatted": filesizeformat(r.size),
                "encrypted": r.encrypted,
                "permission": r.permission,
                "root": r.root,
            }
            if r.encrypted:
                repo["enc_version"] = r.enc_version
                repo["magic"] = r.magic
                repo["random_key"] = r.random_key
            repos_json.append(repo)

        # return Response(repos_json)
        return api_response(status.HTTP_200_OK, '', repos_json)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Create public folders',
        operation_description='''Create a new public folder''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name="name",
                in_="formData",
                type='string',
                description='Name of the new public folder',
                required=True
            ),
            openapi.Parameter(
                name="desc",
                in_="formData",
                type='string',
                description='Description of the folder',
            ),
            openapi.Parameter(
                name="passwd",
                in_="formData",
                type='string',
                description='Password of the folder if you want to create an encrypted public folder',
            ),
            openapi.Parameter(
                name="permission",
                in_="formData",
                type='string',
                description='Permission of the new folder. Default is "rw"',
                enum=['r','w','rw']
            ), 
        ],
        responses={
            201: openapi.Response(
                description='Public folder create successfully.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "id": "",
                            "name": "",
                            "desc": '',
                            "size": '',
                            "size_formatted": '',
                            "mtime": '',
                            "mtime_relative": '',
                            "encrypted": '',
                            "permission": 'rw',  # Always have read-write permission to owned repo
                            "owner": '',
                            "owner_nickname": '',
                        }
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid"
                    }
                }
            ),
            403: openapi.Response(
                description='You don\'t have permission to perform this operation.',
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
    def post(self, request, format=None):
        
        if not request.user.permissions.can_add_repo():
            return api_error(status.HTTP_403_FORBIDDEN,
                             _('You do not have permission to create folder.'))

        username = request.user.username
        repo_name = request.data.get("name", None)
        if not repo_name:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             _('Folder name is required.'))
        repo_desc = request.data.get("desc", '')
        passwd = request.data.get("passwd", None)

        # to avoid 'Bad magic' error when create repo, passwd should be 'None'
        # not an empty string when create unencrypted repo
        if not passwd:
            passwd = None

        if (passwd is not None) and (not config.ENABLE_ENCRYPTED_FOLDER):
            return api_error(status.HTTP_403_FORBIDDEN,
                             _('NOT allow to create encrypted folder.'))

        permission = request.data.get("permission", 'r')
        if permission != 'r' and permission != 'rw':
            return api_error(status.HTTP_400_BAD_REQUEST, _('Invalid permission'))

        org_id = -1
        if is_org_context(request):
            org_id = request.user.org.org_id
            repo_id = syncwerk_api.create_org_repo(repo_name, repo_desc,
                                                  username, passwd, org_id)
            repo = syncwerk_api.get_repo(repo_id)
            synserv.syncwserv_threaded_rpc.set_org_inner_pub_repo(
                org_id, repo.id, permission)
        else:
            repo_id = syncwerk_api.create_repo(repo_name, repo_desc,
                                              username, passwd)
            repo = syncwerk_api.get_repo(repo_id)
            syncwerk_api.add_inner_pub_repo(repo.id, permission)

        library_template = request.data.get("library_template", '')
        repo_created.send(sender=None,
                          org_id=org_id,
                          creator=username,
                          repo_id=repo_id,
                          repo_name=repo_name,
                          library_template=library_template)
        repo_update_signal.send(sender=request.user,
                                            request=request,
                                            action_type=EventLogActionType.ADDED_DIR.value,
                                            repo_id=repo_id,
                                            repo_name=repo_name)
        pub_repo = {
            "id": repo.id,
            "name": repo.name,
            "desc": repo.desc,
            "size": repo.size,
            "size_formatted": filesizeformat(repo.size),
            "mtime": repo.last_modify,
            "mtime_relative": translate_restapi_time(repo.last_modify),
            "encrypted": repo.encrypted,
            "permission": 'rw',  # Always have read-write permission to owned repo
            "owner": username,
            "owner_nickname": email2nickname(username),
        }

        # return Response(pub_repo, status=201)
        return api_response(status.HTTP_201_CREATED, _('The public folder has been created successfully.'), pub_repo)


class RepoHistory(APIView):
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )

    def get(self, request, repo_id, format=None):
        try:
            current_page = int(request.GET.get('page', '1'))
            per_page = int(request.GET.get('per_page', '25'))
        except ValueError:
            current_page = 1
            per_page = 25

        commits_all = get_commits(repo_id, per_page * (current_page - 1),
                                  per_page + 1)
        commits = commits_all[:per_page]

        if len(commits_all) == per_page + 1:
            page_next = True
        else:
            page_next = False

        return HttpResponse(json.dumps({"commits": commits,
                                        "page_next": page_next},
                                       cls=RpcsyncwerkObjEncoder),
                            status=200, content_type=json_content_type)


class RepoOwner(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    parser_classes=(parsers.JSONParser,)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Folder owner info',
        operation_description='''Got folder onwer information''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name="repo_id",
                in_="path",
                type='string',
                description='id of the folder'
            ),
        ],
        responses={
            200: openapi.Response(
                description='Successfully retrieve result.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {}
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid"
                    }
                }
            ),
            403: openapi.Response(
                description='You don\'t have permission to perform this operation.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            404: openapi.Response(
                description='Sub folder not found',
                examples={
                    'application/json': {
                        "message": "Folder not found",
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
        repo = get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        org_id = None
        if is_org_context(request):
            org_id = request.user.org.org_id

        # check permission
        if org_id:
            repo_owner = syncwerk_api.get_org_repo_owner(repo_id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo_id)

        if request.user.username != repo_owner:
            error_msg = _('Permission denied.')
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        # return HttpResponse(json.dumps({"owner": repo_owner}), status=200,
            # content_type=json_content_type)
        resp = {"owner": repo_owner}
        return api_response(status.HTTP_200_OK, '', resp)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Transfer folder',
        operation_description='''Transfer folder to another user''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name="repo_id",
                in_="path",
                type='string',
                description='id of the folder'
            ),
        ],
        request_body=openapi.Schema(
            type="object",
            properties={
                "owner": openapi.Schema(
                    type="string",
                    description="email of the new owner"
                )
            }
        ),
        responses={
            200: openapi.Response(
                description='Successfully retrieve result.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {}
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid"
                    }
                }
            ),
            403: openapi.Response(
                description='You don\'t have permission to perform this operation.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": None
                    }
                }
            ),
            404: openapi.Response(
                description='Sub folder not found',
                examples={
                    'application/json': {
                        "message": "Folder not found",
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
    def put(self, request, repo_id, format=None):
        """ Currently only for transfer repo.

        Permission checking:
        1. only repo owner can transfer repo.
        """

        org_id = None
        if is_org_context(request):
            org_id = request.user.org.org_id

        # argument check
        new_owner = request.data.get('owner', '').lower()
        if not new_owner:
            error_msg = 'owner invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # resource check
        repo = syncwerk_api.get_repo(repo_id)
        if not repo:
            error_msg = 'Library %s not found.' % repo_id
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        try:
            new_owner_obj = User.objects.get(email=new_owner)
        except User.DoesNotExist:
            error_msg = 'User %s not found.' % new_owner
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        if org_id and not ccnet_api.org_user_exists(org_id, new_owner):
            error_msg = _(u'User %s not found in organization.') % new_owner
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # permission check
        if org_id:
            repo_owner = syncwerk_api.get_org_repo_owner(repo_id)
        else:
            repo_owner = syncwerk_api.get_repo_owner(repo_id)

        username = request.user.username
        if username != repo_owner:
            error_msg = _('Permission denied.')
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        if not new_owner_obj.permissions.can_add_repo():
            error_msg = 'Transfer failed: role of %s is %s, can not add library.' % \
                (new_owner, new_owner_obj.role)
            return api_error(status.HTTP_403_FORBIDDEN, error_msg)

        pub_repos = []
        if org_id:
            # get repo shared to user/group list
            shared_users = syncwerk_api.list_org_repo_shared_to(org_id,
                                                               repo_owner, repo_id)
            shared_groups = syncwerk_api.list_org_repo_shared_group(org_id,
                                                                   repo_owner, repo_id)

            # get all org pub repos
            pub_repos = synserv.syncwserv_threaded_rpc.list_org_inner_pub_repos_by_owner(
                org_id, repo_owner)
        else:
            # get repo shared to user/group list
            shared_users = syncwerk_api.list_repo_shared_to(
                repo_owner, repo_id)
            shared_groups = syncwerk_api.list_repo_shared_group_by_user(
                repo_owner, repo_id)

            # get all pub repos
            # if not request.cloud_mode:
            pub_repos = syncwerk_api.list_inner_pub_repos_by_owner(
                repo_owner)

        # Remove all current upload link
        uls = UploadLinkShare.objects.filter(repo_id=repo_id)
        for ul in uls:
            try:
                ul.username = new_owner
                ul.save()
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # Remove all the download links
        dls = FileShare.objects.filter(repo_id=repo_id)
        for dl in dls:
            try:
                dl.username = new_owner
                dl.save()
            except Exception as e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # transfer repo
        try:
            if org_id:
                syncwerk_api.set_org_repo_owner(org_id, repo_id, new_owner)
            else:
                if ccnet_api.get_orgs_by_user(new_owner):
                    # can not transfer library to organization user %s.
                    error_msg = 'Email %s invalid.' % new_owner
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
                else:
                    syncwerk_api.set_repo_owner(repo_id, new_owner)
        except RpcsyncwerkError as e:
            logger.error(e)
            error_msg = _('Internal Server Error')
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        # reshare repo to user
        for shared_user in shared_users:
            shared_username = shared_user.user

            if new_owner == shared_username:
                continue

            if org_id:
                synserv.syncwserv_threaded_rpc.org_add_share(org_id, repo_id,
                                                            new_owner, shared_username, shared_user.perm)
            else:
                syncwerk_api.share_repo(repo_id, new_owner,
                                       shared_username, shared_user.perm)

        # reshare repo to group
        for shared_group in shared_groups:
            shared_group_id = shared_group.group_id

            if not ccnet_api.is_group_user(shared_group_id, new_owner):
                continue

            if org_id:
                syncwerk_api.add_org_group_repo(repo_id, org_id,
                                               shared_group_id, new_owner, shared_group.perm)
            else:
                syncwerk_api.set_group_repo(repo_id, shared_group_id,
                                           new_owner, shared_group.perm)

        # check if current repo is pub-repo
        # if YES, reshare current repo to public
        for pub_repo in pub_repos:
            if repo_id != pub_repo.id:
                continue

            if org_id:
                syncwerk_api.set_org_inner_pub_repo(org_id, repo_id,
                                                   pub_repo.permission)
            else:
                synserv.syncwserv_threaded_rpc.set_inner_pub_repo(
                    repo_id, pub_repo.permission)

            break

        # return HttpResponse(json.dumps({'success': True}),
            # content_type=json_content_type)
        resp = {'success': True}
        return api_response(status.HTTP_200_OK, _('The folder has been transferred successfully'), resp)


class UserAvatarView(APIView):
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )
    
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get user avatar',
        operation_description='''Get avatar of a specific user''',
        tags=['user'],
        manual_parameters=[
            openapi.Parameter(
                name='user',
                in_="path",
                type='string',
                description='email of the user',
            ),
            openapi.Parameter(
                name='size',
                in_="path",
                type='string',
                description='size of the avatar thumbnail.',
            ),
        ],
        responses={
            200: openapi.Response(
                description='User avatar retrieved.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "url": 'avatar url',
                            "is_default": True,
                            "mtime": 'last modified time. should be in ISO format'
                        }
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid",
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
    def get(self, request, user, size, format=None):
        url, is_default, date_uploaded = api_avatar_url(user, int(size))
        ret = {
            "url": request.build_absolute_uri(url),
            "is_default": is_default,
            "mtime": get_timestamp(date_uploaded)}
        return Response(ret)


class GroupAvatarView(APIView):
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get group avatar',
        operation_description='''Get avatar of a specific group''',
        tags=['groups'],
        manual_parameters=[
            openapi.Parameter(
                name='group_id',
                in_="path",
                type='string',
                description='id of the group',
            ),
            openapi.Parameter(
                name='size',
                in_="path",
                type='string',
                description='size of the avatar thumbnail.',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Group avatar retrieved.',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "url": 'avatar url',
                            "is_default": True,
                            "mtime": 'last modified time. should be in ISO format'
                        }
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / Unauthorized',
                examples={
                    'application/json': {
                        "detail": "Token invalid",
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
    def get(self, request, group_id, size, format=None):
        url, is_default, date_uploaded = api_grp_avatar_url(
            group_id, int(size))
        ret = {
            "url": request.build_absolute_uri(url),
            "is_default": is_default,
            "mtime": get_timestamp(date_uploaded)}
        return Response(ret)


class DeleteAccountView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication, )
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Delete user account',
        operation_description='User delete their account themself',
        tags=['user'],
        responses={
            200: openapi.Response(
                description='Account removed successfully',
                examples={
                    'application/json': {
                        "message": "User registered successfully.",
                        "data": None
                    }
                },
            ),
            400: openapi.Response(
                description='Bad request',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {}
                    }
                },
            ),
            401: openapi.Response(
                description='Unauthenticated / unauthorized.',
                examples={
                    'application/json': {
                        "detail": "Invalid token"
                    }
                }
            )
        }
    )
    def post(self, request):
        username = request.user.username
        if username == 'admin@syncwerk.com':
            return api_error(status.HTTP_400_BAD_REQUEST, _(u'Admin account can not be deleted.'))
        if username == 'demo@syncwerk.com':
            return api_error(status.HTTP_400_BAD_REQUEST, _(u'Demo account can not be deleted.'))

        user = User.objects.get(email=username)
        user.delete()

        if is_org_context(request):
            org_id = request.user.org.org_id
            synserv.ccnet_threaded_rpc.remove_org_user(org_id, username)

        return api_response(status.HTTP_200_OK, '', )


class SpaceTrafficView(APIView):
    """
    Get space and traffic info
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication, )
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )
    swagger_schema = None
    
    def get(self, request, format=None):
        op_type_list = ['web-file-upload', 'web-file-download',
                        'sync-file-download', 'sync-file-upload',
                        'link-file-upload', 'link-file-download']
        init_count = [0] * 6
        init_data = get_init_data(start_time, end_time,
                                  dict(zip(op_type_list, init_count)))

        for e in get_system_traffic_by_day(start_time, end_time,
                                           get_time_offset()):
            dt, op_type, count = e
            init_data[dt].update({op_type: count})

        res_data = []
        for k, v in init_data.items():
            res = {'datetime': datetime_to_isoformat_timestr(k)}
            res.update(v)
            res_data.append(res)

        return api_response(code=200, data=sorted(res_data, key=lambda x: x['datetime']))
        # username = request.user.username
        # # space & quota calculation
        # org = ccnet_api.get_orgs_by_user(username)
        # if not org:
        #     space_quota = syncwerk_api.get_user_quota(username)
        #     space_usage = syncwerk_api.get_user_self_usage(username)
        # else:
        #     org_id = org[0].org_id
        #     space_quota = syncwerk_api.get_org_user_quota(org_id, username)
        #     space_usage = syncwerk_api.get_org_user_quota_usage(
        #         org_id, username)

        # rates = {}
        # if space_quota > 0:
        #     rates['space_usage'] = str(
        #         float(space_usage) / space_quota * 100) + '%'
        # else:                       # no space quota set in config
        #     rates['space_usage'] = '0%'

        # # traffic calculation
        # traffic_stat = 0
        # # User's network traffic stat in this month
        # try:
        #     stat = get_user_traffic_stat(username)
        # except Exception as e:
        #     logger.error(e)
        #     stat = None

        # if stat:
        #     traffic_stat = stat['file_view'] + \
        #         stat['file_download'] + stat['dir_download']

        # # payment url, TODO: need to remove from here.
        # payment_url = ''
        # ENABLE_PAYMENT = getattr(settings, 'ENABLE_PAYMENT', False)
        # if ENABLE_PAYMENT:
        #     if is_org_context(request):
        #         if request.user.org and bool(request.user.org.is_staff) is True:
        #             # payment for org admin
        #             payment_url = reverse('org_plan')
        #         else:
        #             # no payment for org members
        #             ENABLE_PAYMENT = False
        #     else:
        #         # payment for personal account
        #         payment_url = reverse('plan')

        # ctx = {
        #     "org": org,
        #     "space_quota": space_quota,
        #     "space_usage": space_usage,
        #     "rates": rates,
        #     "SHOW_TRAFFIC": SHOW_TRAFFIC,
        #     "traffic_stat": traffic_stat,
        #     "ENABLE_PAYMENT": ENABLE_PAYMENT,
        #     "payment_url": payment_url,
        # }

        return api_response(status.HTTP_200_OK, '')


class DownloadRepo(APIView):
    authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated, )
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Get folder download info',
        operation_description='''Get folder download info''',
        tags=['folders'],
        manual_parameters=[
            openapi.Parameter(
                name='repo_id',
                in_="path",
                type='string',
                description='id of the folder',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Info retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "repo_size": 0,
                            "repo_size_formatted": "0 Bytes",
                            "repo_id": "bc90a682-dcc5-4bf2-b5a5-e575934c69e8",
                            "magic": "",
                            "encrypted": "",
                            "repo_desc": "Wiki",
                            "random_key": "",
                            "relay_id": "99e7afa5B84aAC3C951Bce204ABaEbfcAD1c1a28",
                            "enc_version": 0,
                            "mtime_relative": "<time datetime=\"2019-02-18T03:42:14\" is=\"relative-time\" title=\"Mon, 18 Feb 2019 03:42:14 +0000\" >vor 23 Stunden</time>",
                            "relay_addr": "alpha.syncwerk.com",
                            "token": "3e4e0585053d917b5e37e5a2cd13440a7e334eb0",
                            "repo_version": 1,
                            "head_commit_id": "36e72cc6f6cb2b6601e870f59cafd330f5b131c8",
                            "relay_port": 10001,
                            "mtime": 1550461334,
                            "email": "admin@alpha.syncwerk.com",
                            "repo_name": "test wiki 4"
                        }
                    }
                },
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
        if not check_folder_permission(request, repo_id, '/'):
            return api_error(status.HTTP_403_FORBIDDEN,
                             _('You do not have permission to access this library.'))

        resp = repo_download_info(request, repo_id)
        return api_response(status.HTTP_200_OK, '', resp.data)
