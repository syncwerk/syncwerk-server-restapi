# Copyright (c) 2012-2016 Seafile Ltd.
# encoding: utf-8
# Utility functions for api2

import os
import time
import json
import re
import logging
import synserv

from collections import defaultdict
from constance import config
from datetime import datetime
from functools import wraps

from django.core.mail import EmailMessage
from django.core.paginator import EmptyPage, InvalidPage
from django.http import HttpResponse
from django.template import Context, loader
from rest_framework.response import Response
from rest_framework import status, serializers
from synserv import syncwerk_api, get_personal_groups_by_user, \
    is_group_user, get_group, syncwserv_threaded_rpc, ccnet_api, get_repo
from pyrpcsyncwerk import RpcsyncwerkError

from restapi.shortcuts import get_first_object_or_none
from restapi.base.accounts import User
from restapi.base.templatetags.restapi_tags import email2nickname, \
    translate_restapi_time, file_icon_filter
from restapi.group.models import GroupMessage, MessageReply, \
    MessageAttachment, PublicGroup
from restapi.group.views import is_group_staff
from restapi.notifications.models import UserNotification
from restapi.utils import get_file_type_and_ext, \
    gen_file_get_url, get_site_scheme_and_netloc
from restapi.utils.paginator import Paginator
from restapi.utils.file_types import IMAGE
from restapi.api2.models import DESKTOP_PLATFORMS
from restapi.api3.models import Token, TokenV2
from restapi.api3.constants import EventLogActionType
from restapi.avatar.settings import AVATAR_DEFAULT_SIZE
from restapi.avatar.templatetags.avatar_tags import api_avatar_url, \
    get_default_avatar_url
from restapi.profile.models import Profile

from restapi.settings import INSTALLED_APPS, SITE_NAME, MEDIA_URL, LOGO_PATH, LANGUAGE_COOKIE_NAME, LANGUAGE_CODE, DEFAULT_EVENT_LOG_DEVICE_NAME

try:
    from restapi.settings import EMAIL_HOST
    IS_EMAIL_CONFIGURED = True
except ImportError:
    IS_EMAIL_CONFIGURED = False

from restapi.signals import perm_audit_signal, share_upload_link_signal, send_email_signal

logger = logging.getLogger(__name__)


def api_error(code, msg, data=None, error_code=None):
    resp = {'message': msg}
    if data:
        resp['data'] = data
    if error_code:
        resp['error_code'] = error_code
    return Response(resp, status=code)


def api_response(code=status.HTTP_200_OK, msg='', data=None):
    resp = {'message': msg, 'data': data}
    return Response(resp, status=code)


def get_file_size(store_id, repo_version, file_id):
    size = syncwerk_api.get_file_size(store_id, repo_version, file_id)
    return size if size else 0

def get_request_locale(request):
    return request.session.get(LANGUAGE_COOKIE_NAME, LANGUAGE_CODE)

def prepare_starred_files(files):
    array = []
    for f in files:
        sfile = {'org': f.org_id,
                 'repo': f.repo.id,
                 'repo_id': f.repo.id,
                 'repo_name': f.repo.name,
                 'path': f.path,
                 'icon_path': file_icon_filter(f.path),
                 'file_name': os.path.basename(f.path),
                 'mtime': f.last_modified,
                 'mtime_relative': translate_restapi_time(f.last_modified),
                 'dir': f.is_dir
                 }
        if not f.is_dir:
            try:
                file_id = syncwerk_api.get_file_id_by_path(f.repo.id, f.path)
                sfile['oid'] = file_id
                sfile['size'] = get_file_size(
                    f.repo.store_id, f.repo.version, file_id)
            except RpcsyncwerkError as e:
                logger.error(e)
                pass

        array.append(sfile)

    return array


def get_groups(email):
    group_json = []

    joined_groups = get_personal_groups_by_user(email)
    grpmsgs = {}
    for g in joined_groups:
        grpmsgs[g.id] = 0

    notes = UserNotification.objects.get_user_notifications(email, seen=False)
    replynum = 0
    for n in notes:
        if n.is_group_msg():
            try:
                gid = n.group_message_detail_to_dict().get('group_id')
            except UserNotification.InvalidDetailError:
                continue
            if gid not in grpmsgs:
                continue
            grpmsgs[gid] = grpmsgs[gid] + 1

    for g in joined_groups:
        msg = GroupMessage.objects.filter(
            group_id=g.id).order_by('-timestamp')[:1]
        mtime = 0
        if len(msg) >= 1:
            mtime = get_timestamp(msg[0].timestamp)
        group = {
            "id": g.id,
            "name": g.group_name,
            "creator": g.creator_name,
            "ctime": g.timestamp,
            "mtime": mtime,
            "msgnum": grpmsgs[g.id],
        }
        group_json.append(group)

    return group_json, replynum


def get_msg_group_id(msg_id):
    try:
        msg = GroupMessage.objects.get(id=msg_id)
    except GroupMessage.DoesNotExist:
        return None

    return msg.group_id


# def prepare_events(event_groups):
#     for g in event_groups:
#         for e in g["events"]:
#             if e.etype != "repo-delete":
#                 e.link = "api://repos/%s" % e.repo_id

#             if e.etype == "repo-update":
#                 api_convert_desc_link(e)


def get_group_msgs(groupid, page, username):

    # Show 15 group messages per page.
    paginator = Paginator(GroupMessage.objects.filter(
        group_id=groupid).order_by('-timestamp'), 15)

    # If page request (9999) is out of range, return None
    try:
        group_msgs = paginator.page(page)
    except (EmptyPage, InvalidPage):
        return None

    # Force evaluate queryset to fix some database error for mysql.
    group_msgs.object_list = list(group_msgs.object_list)

    attachments = MessageAttachment.objects.filter(
        group_message__in=group_msgs.object_list)

    msg_replies = MessageReply.objects.filter(
        reply_to__in=group_msgs.object_list)
    reply_to_list = [r.reply_to_id for r in msg_replies]

    for msg in group_msgs.object_list:
        msg.reply_cnt = reply_to_list.count(msg.id)
        msg.replies = []
        for r in msg_replies:
            if msg.id == r.reply_to_id:
                msg.replies.append(r)
        msg.replies = msg.replies[-3:]

        for att in attachments:
            if att.group_message_id != msg.id:
                continue

            # Attachment name is file name or directory name.
            # If is top directory, use repo name instead.
            path = att.path
            if path == '/':
                repo = syncwerk_api.get_repo(att.repo_id)
                if not repo:
                    # TODO: what should we do here, tell user the repo
                    # is no longer exists?
                    continue
                att.name = repo.name
            else:
                path = path.rstrip('/')  # cut out last '/' if possible
                att.name = os.path.basename(path)

            # Load to discuss page if attachment is a image and from recommend.
            if att.attach_type == 'file' and att.src == 'recommend':
                att.filetype, att.fileext = get_file_type_and_ext(att.name)
                if att.filetype == IMAGE:
                    att.obj_id = syncwerk_api.get_file_id_by_path(
                        att.repo_id, path)
                    if not att.obj_id:
                        att.err = 'File does not exist'
                    else:
                        token = syncwerk_api.get_fileserver_access_token(att.repo_id,
                                                                        att.obj_id, 'view', username)

                        if not token:
                            att.err = 'File does not exist'
                        else:
                            att.token = token
                            att.img_url = gen_file_get_url(att.token, att.name)

            msg.attachment = att

    return group_msgs


def get_timestamp(msgtimestamp):
    if not msgtimestamp:
        return 0
    timestamp = int(time.mktime(msgtimestamp.timetuple()))
    return timestamp


def group_msg_to_json(msg, get_all_replies):
    ret = {
        'from_email': msg.from_email,
        'nickname': email2nickname(msg.from_email),
        'timestamp': get_timestamp(msg.timestamp),
        'msg': msg.message,
        'msgid': msg.id,
    }

    atts_json = []
    atts = MessageAttachment.objects.filter(group_message_id=msg.id)
    for att in atts:
        att_json = {
            'path': att.path,
            'repo': att.repo_id,
            'type': att.attach_type,
            'src': att.src,
        }
        atts_json.append(att_json)
    if len(atts_json) > 0:
        ret['atts'] = atts_json

    reply_list = MessageReply.objects.filter(reply_to=msg)
    msg.reply_cnt = reply_list.count()
    if not get_all_replies and msg.reply_cnt > 3:
        msg.replies = reply_list[msg.reply_cnt - 3:]
    else:
        msg.replies = reply_list
    replies = []
    for reply in msg.replies:
        r = {
            'from_email': reply.from_email,
            'nickname': email2nickname(reply.from_email),
            'timestamp': get_timestamp(reply.timestamp),
            'msg': reply.message,
            'msgid': reply.id,
        }
        replies.append(r)

    ret['reply_cnt'] = msg.reply_cnt
    ret['replies'] = replies
    return ret


def get_group_msgs_json(groupid, page, username):
    # Show 15 group messages per page.
    paginator = Paginator(GroupMessage.objects.filter(
        group_id=groupid).order_by('-timestamp'), 15)

    # If page request (9999) is out of range, return None
    try:
        group_msgs = paginator.page(page)
    except (EmptyPage, InvalidPage):
        return None, -1

    if group_msgs.has_next():
        next_page = group_msgs.next_page_number()
    else:
        next_page = -1

    group_msgs.object_list = list(group_msgs.object_list)
    msgs = [group_msg_to_json(msg, True) for msg in group_msgs.object_list]
    return msgs, next_page


def get_group_message_json(group_id, msg_id, get_all_replies):
    try:
        msg = GroupMessage.objects.get(id=msg_id)
    except GroupMessage.DoesNotExist:
        return None

    if group_id and group_id != msg.group_id:
        return None
    return group_msg_to_json(msg, get_all_replies)


def get_email(id_or_email):
    try:
        uid = int(id_or_email)
        try:
            user = User.objects.get(id=uid)
        except User.DoesNotExist:
            user = None
        if not user:
            return None
        to_email = user.email
    except ValueError:
        to_email = id_or_email

    return to_email


def api_group_check(func):
    """
    Decorator for initial group permission check tasks

    un-login user & group not pub --> login page
    un-login user & group pub --> view_perm = "pub"
    login user & non group member & group not pub --> public info page
    login user & non group member & group pub --> view_perm = "pub"
    group member --> view_perm = "joined"
    sys admin --> view_perm = "sys_admin"
    """
    @wraps(func)
    def _decorated(view, request, group_id, *args, **kwargs):
        group_id_int = int(group_id)  # Checked by URL Conf
        group = get_group(group_id_int)
        if not group:
            return api_error(status.HTTP_404_NOT_FOUND, 'Group not found.')
        group.is_staff = False
        if PublicGroup.objects.filter(group_id=group.id):
            group.is_pub = True
        else:
            group.is_pub = False

        joined = is_group_user(group_id_int, request.user.username)
        if joined:
            group.view_perm = "joined"
            group.is_staff = is_group_staff(group, request.user)
            return func(view, request, group, *args, **kwargs)
        if request.user.is_staff:
            # viewed by system admin
            group.view_perm = "sys_admin"
            return func(view, request, group, *args, **kwargs)

        if group.is_pub:
            group.view_perm = "pub"
            return func(view, request, group, *args, **kwargs)

        # Return group public info page.
        return api_error(status.HTTP_403_FORBIDDEN, 'Forbid to access this group.')

    return _decorated


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR', '')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR', '')

    return ip


def get_diff_details(repo_id, commit1, commit2):
    result = defaultdict(list)

    diff_result = syncwserv_threaded_rpc.get_diff(repo_id, commit1, commit2)
    if not diff_result:
        return result

    for d in diff_result:
        if d.status == 'add':
            result['added_files'].append(d.name)
        elif d.status == 'del':
            result['deleted_files'].append(d.name)
        elif d.status == 'mov':
            result['renamed_files'].extend((d.name, d.new_name))
        elif d.status == 'mod':
            result['modified_files'].append(d.name)
        elif d.status == 'newdir':
            result['added_dirs'].append(d.name)
        elif d.status == 'deldir':
            result['deleted_dirs'].append(d.name)

    return result


JSON_CONTENT_TYPE = 'application/json; charset=utf-8'


def json_response(func):
    @wraps(func)
    def wrapped(*a, **kw):
        result = func(*a, **kw)
        if isinstance(result, HttpResponse):
            return result
        else:
            return HttpResponse(json.dumps(result), status=200,
                                content_type=JSON_CONTENT_TYPE)
    return wrapped


def get_token_v1(username):
    token, _ = Token.objects.get_or_create(user=username)
    return token


_ANDROID_DEVICE_ID_PATTERN = re.compile('^[a-f0-9]{1,16}$')


def get_token_v2(request, username, platform, device_id, device_name,
                 client_version, platform_version):

    if platform in DESKTOP_PLATFORMS:
        # desktop device id is the peer id, so it must be 40 chars
        if len(device_id) != 40:
            raise serializers.ValidationError('invalid device id')

    elif platform == 'android':
        # See http://developer.android.com/reference/android/provider/Settings.Secure.html#ANDROID_ID
        # android device id is the 64bit secure id, so it must be 16 chars in hex representation
        # but some user reports their device ids are 14 or 15 chars long. So we relax the validation.
        if not _ANDROID_DEVICE_ID_PATTERN.match(device_id.lower()):
            raise serializers.ValidationError('invalid device id')
    elif platform == 'ios':
        if len(device_id) != 36:
            raise serializers.ValidationError('invalid device id')
    elif platform == 'apiv3':
        pass
    else:
        raise serializers.ValidationError('invalid platform')

    return TokenV2.objects.get_or_create_token(
        username, platform, device_id, device_name,
        client_version, platform_version, get_client_ip(request))


def to_python_boolean(string):
    """Convert a string to boolean.
    """
    string = string.lower()
    if string in ('t', 'true', '1'):
        return True
    if string in ('f', 'false', '0'):
        return False
    raise ValueError("Invalid boolean value: '%s'" % string)


def is_syncwerk_pro():
    return any(['restapi_extra' in app for app in INSTALLED_APPS])


def get_user_common_info(email, avatar_size=AVATAR_DEFAULT_SIZE):
    try:
        avatar_url, is_default, date_uploaded = api_avatar_url(
            email, avatar_size)
    except Exception as e:
        logger.error(e)
        avatar_url = get_default_avatar_url()

    p = Profile.objects.get_profile_by_user(email)
    if p:
        login_id = p.login_id if p.login_id else ''
    else:
        login_id = ''

    ava_url = '%s%s' % (config.SERVICE_URL, avatar_url)
    nick_name = None
    profile = get_first_object_or_none(Profile.objects.filter(user=email))
    if profile is not None and profile.nickname and profile.nickname.strip():
        nick_name = profile.nickname.strip()
    return {
        "email": email,
        "name": email2nickname(email),
        "nick_name": nick_name,
        "avatar_url": ava_url,
        "login_id": login_id,
        'avatar_size': avatar_size,
        'is_default_avatar': is_default
    }


def user_to_dict(email, request=None, avatar_size=AVATAR_DEFAULT_SIZE):
    d = get_user_common_info(email, avatar_size)

    # if request is None:
    #     avatar_url = '%s%s' % (get_site_scheme_and_netloc(), d['avatar_url'])
    # else:
    #     avatar_url = request.build_absolute_uri(d['avatar_url'])

    # avatar_url = '%s%s' % (config.SERVICE_URL, d['avatar_url'])

    return {
        'user_name': d['name'],
        'user_email': d['email'],
        'user_login_id': d['login_id'],
        'avatar_url': d['avatar_url'],
    }


def get_request_domain(request=None):
    return '{}://{}'.format(request.scheme, request.META['HTTP_HOST'])


def gen_shared_link(token, s_type):
    service_url = config.SERVICE_URL
    if s_type == 'f':
        # return '%s/f/%s/' % (service_url, token)
        return 'f/%s/' % (token)
    else:
        # return '%s/f/%s/' % (service_url, token)
        return 'd/%s/' % (token)


def gen_shared_upload_link(token):
    service_url = config.SERVICE_URL
    service_url = service_url.rstrip('/')
    # return '%s/u/d/%s/' % (service_url, token)
    return 'u/d/%s/' % (token)


def gen_shared_link_webapp(request, token, s_type, prefix=''):
    service_url = get_request_domain(request)
    return '%s%s/%s/%s/' % (service_url, prefix, s_type, token)


def gen_shared_upload_link_webapp(request, token, prefix=''):
    service_url = get_request_domain(request)
    service_url = service_url.rstrip('/')
    return '%s%s/u/d/%s/' % (service_url, prefix, token)


def send_html_email(subject, con_template, con_context, from_email, to_email,
                    reply_to=None, request=None):
    """Send HTML email
    """
    base_context = {
        'url_base': get_site_scheme_and_netloc(),
        'site_name': SITE_NAME,
        'media_url': MEDIA_URL,
        'logo_path': LOGO_PATH,
    }
    t = loader.get_template(con_template)
    con_context.update(base_context)
    

    headers = {}
    if IS_EMAIL_CONFIGURED:
        if reply_to is not None:
            headers['Reply-to'] = reply_to

    msg = EmailMessage(subject, t.render(con_context), from_email,
                       to_email, headers=headers)
    msg.content_subtype = "html"
    msg.send()

    # Auditlog Email
    send_email_signal.send(sender=None, request=request, recipient=to_email[0])


def translate_time(value):
    if isinstance(value, int) or isinstance(value, long):
        try:
            # convert timestamp to datetime
            val = datetime.fromtimestamp(value)
        except ValueError as e:
            return ""
    elif isinstance(value, datetime):
        val = value
    else:
        return value
    return val.strftime('%Y-%m-%d')

def get_char_mode(n):
    """Return different num according to the type of given letter:
       '1': num,
       '2': upper_letter,
       '4': lower_letter,
       '8': other symbols
    """
    if (n >= 48 and n <= 57): #nums
        return 1;
    if (n >= 65 and n <= 90): #uppers
        return 2;
    if (n >= 97 and n <= 122): #lowers
        return 4;
    else:
        return 8;

def calculate_bitwise(num):
    """Return different level according to the given num:
    """
    level = 0
    for i in range(4):
        # bitwise AND
        if (num&1):
            level += 1
        # Right logical shift
        num = num >> 1
    return level


def is_user_password_strong(password):
    """Return ``True`` if user's password is STRONG, otherwise ``False``.
       STRONG means password has at least USER_PASSWORD_STRENGTH_LEVEL(3) types of the bellow:
       num, upper letter, lower letter, other symbols
    """

    if len(password) < config.USER_PASSWORD_MIN_LENGTH:
        return False, (u'Password must have at least %d characters' % config.USER_PASSWORD_MIN_LENGTH)
    else:
        num = 0
        for letter in password:
            # get ascii dec
            # bitwise OR
            num |= get_char_mode(ord(letter))

        if calculate_bitwise(num) < config.USER_PASSWORD_STRENGTH_LEVEL:
            return False, (u'Password must have at least %d types of below: num, upper letter, lower letter, other symbols' % config.USER_PASSWORD_STRENGTH_LEVEL)
        else:
            return True, ''

def send_perm_audit_signal(request, etype, repo_id, path, permission, recipient_id, recipient_type):
    """[summary]
    
    Arguments:
        request {[type]} -- [HTTP request]
        etype {[type]} -- [add/modify/delete-repo-perm]
        repo_id {[type]} -- [Repository ID]
        path {[type]} -- [sub_folder or file path]
        permission {[type]} -- [r or rw]
        recipient_id {[type]} -- [To user id]
        recipient_type {[type]} -- [user_email, user_username, group or all]
    """    
    
    # Get repo
    repo = get_repo(repo_id)

    # User name
    recipient = recipient_id
    
    if recipient_type == 'group':
        group = ccnet_api.get_group(recipient_id)
        recipient = group.group_name

    elif recipient_type == 'user_email' or recipient_type == "user_username":
        recipient = recipient_id


    perm_audit_signal.send(sender=request.user, request=request, etype=etype, to=recipient, recipient_type=recipient_type, repo = repo, path=path, perm=permission)

def send_share_link_audit_signal(request, action_type, repo_id, path, perm):
    
    # Get repo
    repo = get_repo(repo_id)

    share_upload_link_signal.send(sender= request.user, 
                            request= request, 
                            action_type=action_type,
                            repo=repo, 
                            path=path, 
                            perm=perm)

def send_upload_link_audit_signal(request, action_type, repo_id, path):
    
    # Get repo
    repo = get_repo(repo_id)

    share_upload_link_signal.send(sender= request.user, 
                            request= request, 
                            action_type=action_type,
                            repo=repo, 
                            path=path, 
                            perm=None)


# Utils for AuditLog and UserActivity
def get_client_ip_for_event_log(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR', '')
    if x_forwarded_for:
        ip = x_forwarded_for.split(':')[-1]
    else:
        ip = request.META.get('REMOTE_ADDR', '')

    return ip

def get_agent(recipient_type=None):
    # Agent
    agent_list = {
        'group':'group',
        'user_email':'user',
        'user_username':'user',
        'all':'all'
    }
    if recipient_type in agent_list:
        # Get an agent
        return agent_list[recipient_type]
    else:
        # Get all agent
        return list(set(agent_list.values()))


def get_action_type(etype=None, agent=None):
    action_type_list = {
        'login-success':'Login successfully',
        'login-failed':'Login failed',
        'send-mail': 'Send Email',
        'add-repo-perm': 'Share to %s',
        'modify-repo-perm': 'Change %s permission',
        'delete-repo-perm' : 'Remove %s share',
        'create-share-link': 'Create share link',
        'delete-share-link': 'Remove share link',
        'create-upload-link':'Create upload link',
        'delete-upload-link':'Remove upload link',
        'file-access': 'File access',
        'added-file':'Added file',
        'deleted-file':'Deleted file',
        'added-dir':'Added dir',
        'deleted-dir':'Deleted dir',
        'modified-file':'Modified file',
        'renamed-file':'Renamed file',
        'moved-file':'Moved file',
        'renamed-dir':'Renamed dir',
        'moved-dir':'Moved dir'
    }
    if etype:
        # Get an action type
        if etype in action_type_list:
            if '%s' in action_type_list[etype]:
                if agent:
                    return action_type_list[etype]%get_agent(agent)
                else:
                    raise ValueError('This action type need input agent')
            else:
                return action_type_list[etype]
                
        else:
            raise ValueError('Invalid input etype')
    else:
        # Get all action type
        action_types = []
        for action_type in action_type_list:
            if '%s' in action_type_list[action_type]:
                for agent in get_agent():
                    action_types.append(action_type_list[action_type]%agent)
            else:
                action_types.append(action_type_list[action_type])
        return sorted(action_types)

def get_perm(permission=None):
    perm_list = {
        'r':'read only',
        'rw':'read/write',
        'view_download':'view_download',
        '-': None
    }
    if permission in perm_list:
        return perm_list[permission]
    else:
        return sorted([ perm for perm in perm_list.values() if perm ])

def get_repo_update_changes(commit_differ):
    # Change type
    change_types = [
        {
            'type': 'add',
            'action_type': 'added-file',
            'path': '%s'
        },
        {
            'type': 'delete',
            'action_type': 'deleted-file',
            'path': '%s'
        },
        {
            'type': 'add',
            'action_type': 'added-dir',
            'path': '%s'
        },
        {
            'type': 'delete',
            'action_type': 'deleted-dir',
            'path': '%s'
        },
        {
            'type': 'modify',
            'action_type': 'modified-file',
            'path': '%s'
        },
        {
            'type': 'rename',
            'action_type': 'renamed-file',
            'path': '%s > %s'
        },
        {
            'type': 'move',
            'action_type': 'moved-file',
            'path': '%s > %s'
        },
        {
            'type': 'rename',
            'action_type': 'renamed-dir',
            'path': '%s > %s'
        },
        {
            'type': 'move',
            'action_type': 'moved-dir',
            'path': '%s > %s'
        }
    ]

    repo_changes = []

    for change_type_id, changes in enumerate(commit_differ.diff()):
        if len(changes) > 0:
            for change in changes:
                change_type = change_types[change_type_id]

                # Action type
                action_type = None
                path = None
                if change_type['type'] in ['add', 'delete', 'modify']:
                    action_type = EventLogActionType.get_value_by_etype(
                        change_type['action_type'])
                    path = change_type['path'] % (change.path)
                elif change_type['type'] in ['rename', 'move']:
                    action_type = EventLogActionType.get_value_by_etype(
                        change_type['action_type'])
                    path = change_type['path'] % (
                        change.path, change.new_path)

                # Save audit log
                repo_changes.append({
                    'action_type': action_type,
                    'path':path
                })

    return repo_changes
    
def get_device_name_from_token(key):
    try:
        # Get token from table api3_token_v2, this has token device name
        token = TokenV2.objects.get(key=key)
        return token.device_name

    except TokenV2.DoesNotExist:
        # Get token from table api3_token
        try:
            token = Token.objects.get(key=key)
            return DEFAULT_EVENT_LOG_DEVICE_NAME
        except Token.DoesNotExist:
            return None

def get_device_name_from_request(request):
    key = request.COOKIES.get('token', None)
    
    return get_device_name_from_token(key)
