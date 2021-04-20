import logging
import json
import csv, chardet, StringIO
import os

from types import FunctionType
from constance import config

from django.conf import settings as dj_settings
from django.contrib import messages
from django.http import HttpResponse, Http404, HttpResponseRedirect, HttpResponseNotAllowed
from django.db.models import Q
from django.utils.translation import ugettext as _

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.views import APIView

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
from restapi.api3.utils import api_error, api_response, get_user_common_info
from restapi.api3.permissions import IsSystemAdminOrTenantAdmin
from restapi.api3.models import MeetingRoom, MeetingRoomShare, ProfileSetting

from restapi.api3.utils.licenseInfo import parse_license_to_json, is_pro_version

from restapi.api3.forms import AddUserForm, user_number_over_limit

from restapi.api3.views import _clear_login_failed_attempts

import synserv
from synserv import ccnet_threaded_rpc, syncwserv_threaded_rpc, \
    syncwerk_api, get_group, get_group_members, ccnet_api, \
    get_related_users_by_repo, get_related_users_by_org_repo

from restapi.utils.user_permissions import (get_basic_user_roles,
                                           get_user_role)
from restapi.utils.licenseparse import parse_license
from restapi.utils.mail import send_html_email_with_dj_template

from restapi.base.accounts import User
from restapi.base.models import UserLastLogin
from restapi.options.models import UserOptions
from restapi.profile.models import Profile, DetailedProfile
from restapi.utils.sysinfo import get_platform_name
from restapi.role_permissions.utils import get_available_roles
from restapi.constants import GUEST_USER, DEFAULT_USER
from restapi.tenants.models import (Tenant, TenantAdmin,
                                        TenantQuota)
from restapi.tenants.utils import get_tenant_space_usage
from restapi.utils.ldap import get_ldap_info
from restapi.utils.file_size import get_file_size_unit
from restapi.base.templatetags.restapi_tags import tsstr_sec, email2nickname
from restapi.utils.ms_excel import write_xls
from restapi.utils.rpc import mute_syncwerk_api

from restapi.utils import IS_EMAIL_CONFIGURED, string2list, is_valid_username, \
    is_pro_version, send_html_email, get_server_id, \
    handle_virus_record, get_virus_record_by_id, \
    get_virus_record, FILE_AUDIT_ENABLED, get_max_upload_file_size, ldap


from pyrpcsyncwerk import RpcsyncwerkError

from restapi.admin_log.signals import admin_operation
from restapi.admin_log.models import USER_DELETE, USER_ADD
from restapi.settings import INIT_PASSWD, SITE_NAME, SITE_ROOT, \
    SEND_EMAIL_ON_ADDING_SYSTEM_MEMBER, SEND_EMAIL_ON_RESETTING_USER_PASSWD, \
    ENABLE_SYS_ADMIN_VIEW_REPO, ENABLE_GUEST_INVITATION
from restapi.forms import SetUserQuotaForm, BatchAddUserForm, \
    TermsAndConditionsForm
from restapi.share.models import FileShare, UploadLinkShare
from restapi.utils.two_factor_auth import has_two_factor_auth

try:
    from restapi.settings import ENABLE_TRIAL_ACCOUNT
except:
    ENABLE_TRIAL_ACCOUNT = False
if ENABLE_TRIAL_ACCOUNT:
    from restapi_extra.trialaccount.models import TrialAccount

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

def populate_user_info(user):
    """Populate contact email and name to user.
    """
    user_profile = Profile.objects.get_profile_by_user(user.email)
    if user_profile:
        user.contact_email = user_profile.contact_email
        user.name = user_profile.nickname
    else:
        user.contact_email = ''
        user.name = ''

def _populate_user_quota_usage(user):
    """Populate space/share quota to user.

    Arguments:
    - `user`:
    """
    orgs = ccnet_api.get_orgs_by_user(user.email)
    try:
        if orgs:
            user.org = orgs[0]
            org_id = user.org.org_id
            user.space_usage = syncwerk_api.get_org_user_quota_usage(org_id, user.email)
            user.space_quota = syncwerk_api.get_org_user_quota(org_id, user.email)
        else:
            user.space_usage = syncwerk_api.get_user_self_usage(user.email)
            user.space_quota = syncwerk_api.get_user_quota(user.email)
    except RpcsyncwerkError as e:
        logger.error(e)
        user.space_usage = -1
        user.space_quota = -1

def send_user_reset_email(request, email, password):
    """
    Send email when reset user password.
    """

    c = {
        'email': email,
        'password': password,
        }
    send_html_email((u'Password has been reset on %s') % SITE_NAME,
            'sysadmin/user_reset_email.html', c, None, [email],request=request)

def send_user_add_mail(request, email, password):
    """Send email when add new user."""
    c = {
        'user': request.user.username,
        'org': request.user.org,
        'email': email,
        'password': password,
        }
    send_html_email((u'You are invited to join %s') % SITE_NAME,
            'api3/sysadmin/user_add_email.html', c, None, [email],request=request)

def email_user_on_activation(user):
    """Send an email to user when admin activate his/her account.
    """
    c = {
        'username': user.email,
        }
    send_html_email(_(u'Your account on %s is activated') % SITE_NAME,
            'sysadmin/user_activation_email.html', c, None, [user.email])

class AdminUsers(APIView):
    """ System admin user lists
    Administrator permission is required.
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsSystemAdminOrTenantAdmin, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - List all users',
        operation_description='''List all users''',
        tags=['admin-users'],
        manual_parameters=[
            openapi.Parameter(
                name='filter',
                in_="query",
                type='string',
                description='"free" for getting free users only, "paid" for getting paid users only',
            ),
            openapi.Parameter(
                name='avatar_size',
                in_="query",
                type='string',
                description='size of user avatar thumbnail',
            ),
        ],
        responses={
            200: openapi.Response(
                description='User list retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "prev_page": -2,
                            "users": [
                                {
                                    "is_active": True,
                                    "is_default": True,
                                    "is_staff": True,
                                    "contact_email": "",
                                    "space_usage": 168213379,
                                    "tenant": "",
                                    "space_quota": 1000000000,
                                    "last_login": "2019-02-21T02:30:43",
                                    "name": "",
                                    "create_time": 1548148348642376,
                                    "role": "",
                                    "is_guest": False,
                                    "email": "admin@alpha.syncwerk.com"
                                },
                                {
                                    "is_active": True,
                                    "is_default": True,
                                    "is_staff": False,
                                    "contact_email": None,
                                    "space_usage": 0,
                                    "tenant": "ten1",
                                    "space_quota": 1000000000,
                                    "last_login": None,
                                    "name": "test@zubeh\u00f6r.tld",
                                    "create_time": 1548313183054387,
                                    "role": "default",
                                    "is_guest": False,
                                    "email": "test@zubeh\u00f6r.tld"
                                },

                            ],
                            "number_of_total_users": 106,
                            "show_tenant": True,
                            "extra_user_roles": [
                                "employee"
                            ],
                            "current_page": -1,
                            "next_page": 0,
                            "platform": "linux",
                            "pro_server": 1,
                            "guest_user": "guest",
                            "is_pro": True,
                            "per_page": -1,
                            "server_id": "99e7afa5",
                            "default_user": "default",
                            "tenants": [
                                "ten1",
                                "ten10"
                            ],
                            "enable_user_plan": False,
                            "page_next": False,
                            "have_ldap": None
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
            404: openapi.Response(
                description='User not found',
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
        try:
            from restapi_extra.plan.models import UserPlan
            enable_user_plan = True
        except ImportError:
            enable_user_plan = False

        if enable_user_plan and request.GET.get('filter', '') == 'paid':
            # show paid users
            users = []
            ups = UserPlan.objects.all()
            for up in ups:
                try:
                    u = User.objects.get(up.username)
                except User.DoesNotExist:
                    continue

                _populate_user_quota_usage(u)
                users.append(u)

            last_logins = UserLastLogin.objects.filter(username__in=[x.username for x in users])
            for u in users:
                for e in last_logins:
                    if e.username == u.username:
                        u.last_login = e.last_login
            data = {
                'users': users,
                'enable_user_plan': enable_user_plan,
            }
            return api_response(data=data)

        ### List all users
        # Make sure page request is an int. If not, deliver first page.        
        try:
            current_page = int(request.GET.get('page', '1'))
            per_page = int(request.GET.get('per_page', '25'))
        except ValueError:
            current_page = 1
            per_page = 25

        # Get source is DB or LDAP
        # Please consider that LDAP and LDAPImport are different type
        # LDAP: Search all user from LDAP
        # LDAPImport: Search LDAP user exist on Syncwerk database
        ALLOW_SOURCES = ['DB','LDAPImport']
        source = request.GET.get('source','DB')

        if source not in ALLOW_SOURCES:
            err_msg = 'Not allow %s source'%source
            return api_response(msg=err_msg, code=400) 

        if current_page is -1:
            logger.debug('Load all user...')
            users_plus_one = synserv.get_emailusers(source, -1, -1)
        else:
            users_plus_one = synserv.get_emailusers(source, per_page * (current_page - 1),
                                                per_page + 1)
        number_of_total_users = synserv.ccnet_api.count_emailusers(source)
        if len(users_plus_one) == per_page + 1:
            page_next = True
        else:
            page_next = False
        if current_page is -1:
            users = users_plus_one
        else:
            users = users_plus_one[:per_page]
        last_logins = UserLastLogin.objects.filter(username__in=[x.email for x in users])
        if ENABLE_TRIAL_ACCOUNT:
            trial_users = TrialAccount.objects.filter(user_or_org__in=[x.email for x in users])
        else:
            trial_users = []

        for user in users:
            if user.email == request.user.email:
                user.is_self = True

            populate_user_info(user)
            _populate_user_quota_usage(user)

            # check user's role
            user.is_guest = True if get_user_role(user) == GUEST_USER else False
            user.is_default = True if get_user_role(user) == DEFAULT_USER else False

            # populate user last login time
            user.last_login = None
            for last_login in last_logins:
                if last_login.username == user.email:
                    user.last_login = last_login.last_login

            user.trial_info = None
            for trial_user in trial_users:
                if trial_user.user_or_org == user.email:
                    user.trial_info = {'expire_date': trial_user.expire_date}

        platform = get_platform_name()
        server_id = get_server_id()
        pro_server = 1 if is_pro_version() else 0
        extra_user_roles = [x for x in get_available_roles()
                            if x not in get_basic_user_roles()]

        multi_tenant = getattr(dj_settings, 'MULTI_INSTITUTION', False)
        show_tenant = False
        tenants = None
        if multi_tenant:
            show_tenant = True
            tenants = [inst.name for inst in Tenant.objects.all()]
            for user in users:
                profile = Profile.objects.get_profile_by_user(user.email)
                user.tenant =  profile.tenant if profile else ''
        user_list = [];
        for user in users:
            resp_user = {
                'email': user.email,
                'name': user.name,
                'contact_email': user.contact_email,
                'is_active': user.is_active,
                'is_guest': user.is_guest,
                'is_default': user.is_default,
                'is_staff': user.is_staff,
                'role': user.role,
                'space_usage': user.space_usage,
                'space_quota': user.space_quota,
                'tenant': user.tenant,
                'create_time': user.ctime,
                'last_login': user.last_login,
            }
            user_list.append(resp_user);

        data = {
                'users': user_list,
                'number_of_total_users': number_of_total_users,
                'current_page': current_page,
                'prev_page': current_page-1,
                'next_page': current_page+1,
                'per_page': per_page,
                'page_next': page_next,
                'have_ldap': get_ldap_info(),
                'platform': platform,
                'server_id': server_id[:8],
                'default_user': DEFAULT_USER,
                'guest_user': GUEST_USER,
                'is_pro': is_pro_version(),
                'pro_server': pro_server,
                'enable_user_plan': enable_user_plan,
                'extra_user_roles': extra_user_roles,
                'show_tenant': show_tenant,
                'tenants': tenants,
            }
        return api_response(data=data)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Add new user',
        operation_description='''Add new user''',
        tags=['admin-users'],
        manual_parameters=[
            openapi.Parameter(
                name='email',
                in_="formData",
                type='string',
                description='email of the new user',
                required=True,
            ),
           openapi.Parameter(
                name='name',
                in_="formData",
                type='string',
                description='fullname of the new user',
                required=False,
            ),
            openapi.Parameter(
                name='department',
                in_="formData",
                type='string',
                description='department of the new user',
                required=False,
            ),
            openapi.Parameter(
                name='role',
                in_="formData",
                type='string',
                description='role of the new user. Default to "default"',
                required=False,
            ),
            openapi.Parameter(
                name='password1',
                in_="formData",
                type='string',
                description='password of the new user',
                required=True,
            ),
            openapi.Parameter(
                name='password2',
                in_="formData",
                type='string',
                description='confirm password',
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description='User created successfully',
                examples={
                    'application/json': {
                        "message": "Successfully added user. An email notification has been sent.",
                        "data": None
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
                description='Not found',
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
        # if not request.user.is_staff or request.method != 'POST':
        #     return api_response(code=404, msg='Method not found')

        content_type = 'application/json; charset=utf-8'

        post_values = request.POST.copy()
        post_email = request.POST.get('email', '')
        post_role = request.POST.get('role', DEFAULT_USER)
        post_values.update({
                            'email': post_email.lower(),
                            'role': post_role,
                        })
        if not request.user.is_staff:
            if post_role in dj_settings.ENABLED_ADMIN_ROLE_PERMISSIONS.keys():
                return api_error(403, msg=_("You are not allow to create user with admin roles."))
        form = AddUserForm(post_values)
        if form.is_valid():
            email = form.cleaned_data['email']
            name = form.cleaned_data['name']
            department = form.cleaned_data['department']
            role = form.cleaned_data['role']
            password = form.cleaned_data['password1']
            
            is_staff = False
            if role in dj_settings.ENABLED_ADMIN_ROLE_PERMISSIONS.keys():
                is_staff = True
            try:
                user = User.objects.create_user(email, password, is_staff=is_staff,
                                                is_active=True)
            except User.DoesNotExist as e:
                logger.error(e)
                err_msg = (u'Fail to add user %s.') % email
                return api_response(msg=err_msg, code=403)
                # return HttpResponse(json.dumps({'error': err_msg}), status=403, content_type=content_type)

            # send admin operation log signal
            admin_op_detail = {
                "email": email,
            }
            admin_operation.send(sender=None, admin_name=request.user.username,
                    operation=USER_ADD, detail=admin_op_detail)

            if user:
                User.objects.update_role(email, role)
                if config.FORCE_PASSWORD_CHANGE:
                    UserOptions.objects.set_force_passwd_change(email)
                if name:
                    Profile.objects.add_or_update(email, name, '')
                if department:
                    DetailedProfile.objects.add_or_update(email, department, '')

            if request.user.org:
                org_id = request.user.org.org_id
                ccnet_threaded_rpc.add_org_user(org_id, email, 0)
                message = '',
                if IS_EMAIL_CONFIGURED:
                    try:
                        send_user_add_mail(request, email, password)
                        message = _('Successfully added user. An email notification has been sent.')
                        # messages.success(request, _(u'Successfully added user %s. An email notification has been sent.') % email)
                    except Exception, e:
                        logger.error(str(e))
                        message = _('Successfully added user. An error accurs when sending email notification, please check your email configuration.')
                        # messages.success(request, _(u'Successfully added user %s. An error accurs when sending email notification, please check your email configuration.') % email)
                else:
                    message = _("Successfully added user.")
                    # messages.success(request, _(u'Successfully added user %s.') % email)

                return api_response(msg=message)
            else:
                if IS_EMAIL_CONFIGURED:
                    if SEND_EMAIL_ON_ADDING_SYSTEM_MEMBER:
                        try:
                            send_user_add_mail(request, email, password)
                            message = _('Successfully added user. An email notification has been sent.')
                            # messages.success(request, _(u'') % email)
                        except Exception, e:
                            logger.error(str(e))
                            message = _('Successfully added user. An error accurs when sending email notification, please check your email configuration.')
                            # messages.success(request, _(u'Successfully added user %s. An error accurs when sending email notification, please check your email configuration.') % email)
                    else:
                        message = 'Successfully added user.'
                        # messages.success(request, _(u'Successfully added user %s.') % email)
                else:
                    message = _('Successfully added user. But email notification can not be sent, because Email service is not properly configured.')
                    # messages.success(request, _(u'Successfully added user %s. But email notification can not be sent, because Email service is not properly configured.') % email)

                return api_response(msg=message)
        else:
            return api_error(400, msg=_("Bad request or a user with this email already exists."), data=json.dumps({'error': str(form.errors.values()[0])}))
            # return HttpResponse(json.dumps({'error': str(form.errors.values()[0])}), status=400, content_type=content_type)

class AdminUsersSearch(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsSystemAdminOrTenantAdmin, )
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Search users',
        operation_description='''Search users''',
        tags=['admin-users'],
        manual_parameters=[
            openapi.Parameter(
                name='q',
                in_="query",
                type='string',
                description='search query',
            ),
        ],
        responses={
            200: openapi.Response(
                description='User list retrieved successfully',
                examples={
                    'application/json': {
                    "message": "",
                    "data": {
                        "prev_page": -2,
                        "users": [
                            {
                                "is_active": True,
                                "is_default": True,
                                "is_staff": True,
                                "contact_email": "",
                                "space_usage": 168213379,
                                "tenant": "",
                                "space_quota": 1000000000,
                                "last_login": "2019-02-21T02:30:43",
                                "name": "",
                                "create_time": 1548148348642376,
                                "role": "",
                                "is_guest": False,
                                "email": "admin@alpha.syncwerk.com"
                            },
                            {
                                "is_active": True,
                                "is_default": True,
                                "is_staff": False,
                                "contact_email": None,
                                "space_usage": 0,
                                "tenant": "ten1",
                                "space_quota": 1000000000,
                                "last_login": None,
                                "name": "test@zubeh\u00f6r.tld",
                                "create_time": 1548313183054387,
                                "role": "default",
                                "is_guest": False,
                                "email": "test@zubeh\u00f6r.tld"
                            },

                        ],
                        "number_of_total_users": 106,
                        "show_tenant": True,
                        "extra_user_roles": [
                            "employee"
                        ],
                        "current_page": -1,
                        "next_page": 0,
                        "platform": "linux",
                        "pro_server": 1,
                        "guest_user": "guest",
                        "is_pro": True,
                        "per_page": -1,
                        "server_id": "99e7afa5",
                        "default_user": "default",
                        "tenants": [
                            "ten1",
                            "ten10"
                        ],
                        "enable_user_plan": False,
                        "page_next": False,
                        "have_ldap": None
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
            404: openapi.Response(
                description='User not found',
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
    def get(self, request):
        email = request.GET.get('q', '')
        per_page = int(request.GET.get('per_page', '25'))
        current_page = int(request.GET.get('page', '1'))
        start = per_page * (current_page - 1)
        end = start + per_page

        user_emails = []
        # search user from ccnet db
        users_from_ccnet = ccnet_api.search_emailusers('DB', email, -1, -1)
        for user in users_from_ccnet:
            user_emails.append(user.email)

        # search user from ccnet ldap
        users_from_ldap = ccnet_api.search_emailusers('LDAP', email, -1, -1)
        for user in users_from_ldap:
            user_emails.append(user.email)

        # search user from profile
        users_from_profile = Profile.objects.filter((Q(nickname__icontains=email)) |
                Q(contact_email__icontains=email))
        for user in users_from_profile:
            user_emails.append(user.user)

        # remove duplicate emails
        user_emails = {}.fromkeys(user_emails).keys()

        users = []
        for user_email in user_emails:
            try:
                user_obj = User.objects.get(email=user_email)
            except User.DoesNotExist:
                continue

            users.append(user_obj)

        last_logins = UserLastLogin.objects.filter(username__in=[x.email for x in users])
        if ENABLE_TRIAL_ACCOUNT:
            trial_users = TrialAccount.objects.filter(user_or_org__in=[x.email for x in users])
        else:
            trial_users = []

        user_for_process = users[start:end]

        for user in user_for_process:
            populate_user_info(user)
            _populate_user_quota_usage(user)

            # check user's role
            user.is_guest = True if get_user_role(user) == GUEST_USER else False
            user.is_default = True if get_user_role(user) == DEFAULT_USER else False
            # populate user last login time
            user.last_login = None
            for last_login in last_logins:
                if last_login.username == user.email:
                    user.last_login = last_login.last_login

            user.trial_info = None
            for trial_user in trial_users:
                if trial_user.user_or_org == user.email:
                    user.trial_info = {'expire_date': trial_user.expire_date}

        extra_user_roles = [x for x in get_available_roles()
                            if x not in get_basic_user_roles()]
        resp_user_result = []
        for user in user_for_process:
            resp_user = {
                'email': user.email,
                'name': user.name,
                'contact_email': user.contact_email,
                'is_active': user.is_active,
                'is_guest': user.is_guest,
                'is_default': user.is_default,
                'role': user.role,
                'space_usage': user.space_usage,
                'space_quota': user.space_quota,
                'create_time': user.ctime,
                'last_login': user.last_login,
            }
            resp_user_result.append(resp_user)

        return api_response(data={
            'users': resp_user_result,
            'default_user': DEFAULT_USER,
            'guest_user': GUEST_USER,
            'is_pro': is_pro_version(),
            'extra_user_roles': extra_user_roles,
            'number_of_total_users': len(users)
        })
class AdminUser(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get user info',
        operation_description='''Get user info''',
        tags=['admin-users'],
        manual_parameters=[
            openapi.Parameter(
                name='user_email',
                in_="path",
                type='string',
                description='user email',
            ),
        ],
        responses={
            200: openapi.Response(
                description='User info retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "profile": {
                                "login_id": None,
                                "intro": None,
                                "contact_email": None,
                                "user": "test1@grr.la",
                                "lang_code": None,
                                "nickname": "test1@grr.la",
                                "tenant": "ten10"
                            },
                            "org_name": None,
                            "d_profile": {
                                "department": "test",
                                "telephone": None
                            },
                            "space_usage": 0,
                            "owned_repos": [],
                            "enable_sys_admin_view_repo": True,
                            "space_quota": 1000000000,
                            "default_device": False,
                            "in_repos": [],
                            "personal_groups": [
                                {
                                    "timestamp": 1548301308074436,
                                    "role": "Member",
                                    "id": 3,
                                    "group_name": "3"
                                }
                            ],
                            "user_shared_links": [],
                            "email": "test1@grr.la",
                            "common_info": {
                                "login_id": "",
                                "avatar_size": 80,
                                "name": "test1@grr.la",
                                "nick_name": "test1@grr.la",
                                "is_default_avatar": True,
                                "avatar_url": "https://alpha.syncwerk.com/rest/media/avatars/default.png",
                                "email": "test1@grr.la"
                            }
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
            404: openapi.Response(
                description='User not found',
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
    def get(self, request, user_email):
        email = user_email
        org_name = None
        space_quota = space_usage = 0

        # Shared from group
        in_group_repos = []

        org = ccnet_api.get_orgs_by_user(email)
        if not org:
            owned_repos = mute_syncwerk_api.get_owned_repo_list(email,
                                                            ret_corrupted=True)
            
            space_usage = mute_syncwerk_api.get_user_self_usage(email)
            space_quota = mute_syncwerk_api.get_user_quota(email)

            # Get shared from 
            # personal
            in_repos = mute_syncwerk_api.get_share_in_repo_list(email, -1, -1)
            # group
            in_group_repos = syncwerk_api.get_group_repos_by_user(email)

            # Get shared to
            # Repo
            shared_repos = []
            shared_repos += syncwerk_api.get_share_out_repo_list(email, -1, -1)
            shared_repos += syncwerk_api.get_group_repos_by_owner(email)
            if not request.cloud_mode:
                shared_repos += syncwerk_api.list_inner_pub_repos_by_owner(email)

            # Folder
            shared_folders = []
            shared_folders += syncwerk_api.get_share_out_repo_list(email, -1, -1)
            shared_folders += syncwerk_api.get_group_repos_by_owner(email)
            
        else:
            org_id = org[0].org_id
            org_name = org[0].org_name
            space_usage = syncwerk_api.get_org_user_quota_usage(org_id, email)
            space_quota = syncwerk_api.get_org_user_quota(org_id, email)
            owned_repos = syncwerk_api.get_org_owned_repo_list(org_id, email,
                                                            ret_corrupted=True)

            # Get share from
            in_repos = syncwerk_api.get_org_share_in_repo_list(org_id, email, -1, -1)

            # Get share to
            # Repo
            shared_repos = []
            shared_repos += syncwerk_api.get_org_share_out_repo_list(org_id, email, -1, -1)
            shared_repos += synserv.syncwserv_threaded_rpc.get_org_group_repos_by_owner(org_id, email)
            shared_repos += synserv.syncwserv_threaded_rpc.list_org_inner_pub_repos_by_owner(org_id, email)

            # Folder
            shared_folders = []
            shared_folders += syncwerk_api.get_org_share_out_repo_list(org_id, email, -1, -1)
            shared_folders += synserv.syncwserv_threaded_rpc.get_org_group_repos_by_owner(org_id, email)


        owned_repos = filter(lambda r: not r.is_virtual, owned_repos)

        # get user profile
        profile = Profile.objects.get_profile_by_user(email)
        d_profile = DetailedProfile.objects.get_detailed_profile_by_user(email)
        profile_setting = ProfileSetting.objects.get_profile_setting_by_user(email)

        user_shared_links = []
        # download links
        p_fileshares = []
        fileshares = list(FileShare.objects.filter(username=email))
        for fs in fileshares:
            try:
                r = syncwerk_api.get_repo(fs.repo_id)
                if not r:
                    fs.delete()
                    continue

                if fs.is_file_share_link():
                    if syncwerk_api.get_file_id_by_path(r.id, fs.path) is None:
                        fs.delete()
                        continue

                    fs.filename = os.path.basename(fs.path)
                    path = fs.path.rstrip('/')  # Normalize file path
                    obj_id = syncwerk_api.get_file_id_by_path(r.id, path)
                    fs.file_size = syncwerk_api.get_file_size(r.store_id,
                                                            r.version, obj_id)
                else:
                    if syncwerk_api.get_dir_id_by_path(r.id, fs.path) is None:
                        fs.delete()
                        continue

                    if fs.path == '/':
                        fs.filename = '/'
                    else:
                        fs.filename = os.path.basename(fs.path.rstrip('/'))

                    path = fs.path
                    if path[-1] != '/':         # Normalize dir path
                        path += '/'
                    # get dir size
                    dir_id = syncwerk_api.get_dir_id_by_commit_and_path(r.id, r.head_cmmt_id, path)
                    fs.dir_size = syncwerk_api.get_dir_size(r.store_id, r.version, dir_id)

                fs.is_download = True
                p_fileshares.append(fs)
            except RpcsyncwerkError as e:
                logger.error(e)
                continue
        p_fileshares.sort(key=lambda x: x.view_cnt, reverse=True)
        user_shared_links += p_fileshares

        # upload links
        uploadlinks = list(UploadLinkShare.objects.filter(username=email))
        p_uploadlinks = []
        for link in uploadlinks:
            try:
                r = syncwerk_api.get_repo(link.repo_id)
                if not r:
                    link.delete()
                    continue
                if syncwerk_api.get_dir_id_by_path(r.id, link.path) is None:
                    link.delete()
                    continue

                if link.path == '/':
                    link.dir_name = '/'
                else:
                    link.dir_name = os.path.basename(link.path.rstrip('/'))

                link.is_upload = True
                p_uploadlinks.append(link)
            except RpcsyncwerkError as e:
                logger.error(e)
                continue
        p_uploadlinks.sort(key=lambda x: x.view_cnt, reverse=True)
        user_shared_links += p_uploadlinks

        try:
            personal_groups = synserv.get_personal_groups_by_user(email)
        except RpcsyncwerkError as e:
            logger.error(e)
            personal_groups = []

        for g in personal_groups:
            try:
                is_group_staff = synserv.check_group_staff(g.id, email)
            except RpcsyncwerkError as e:
                logger.error(e)
                is_group_staff = False

            if email == g.creator_name:
                g.role = _('Owner')
            elif is_group_staff:
                g.role = _('Admin')
            else:
                g.role = _('Member')

        _default_device = False
        # _has_two_factor_auth = has_two_factor_auth()
        # if _has_two_factor_auth:
        #     from restapi_extra.two_factor.utils import default_device
        #     _user = User.objects.get(email=email)
        #     _default_device = default_device(_user)
        # Populate owned repo
        return_owned_repos = []
        for repo in owned_repos:
            repo_info = {
                'encrypted': repo.encrypted,
                'name': repo.name,
                'id': repo.id,
                'size': repo.size,
                'last_modify': repo.last_modify,
                'permission': repo.permission,
            }
            return_owned_repos.append(repo_info)
        # Populate in repo
        # Personal
        return_in_repos = []
        for repo in in_repos:
            repo_info = {
                'encrypted': repo.encrypted,
                'name': repo.name,
                'id': repo.id,
                'size': repo.size,
                'last_modify': repo.last_modify,
                'permission': repo.permission,
                'props': {
                    'id' : None,
                    'from': repo.props.user
                },
                'share_type': 'personal'
            }
            return_in_repos.append(repo_info)
        # Group
        for repo in in_group_repos:
            # Skip share by current user
            if repo.user != email:
                repo_info = {
                'encrypted': repo.encrypted,
                'name': repo.repo_name,
                'id': repo.id,
                'size': repo.size,
                'last_modify': repo.last_modify,
                'permission': repo.permission,
                'props': {
                    'id' : repo.group_id,
                    'from': repo.group_name
                },
                'share_type': repo.share_type
                }
                return_in_repos.append(repo_info)
        # shared repo to return_in_repos
        for repo in shared_repos:
            if repo.is_virtual:
                    continue
            repo_info = {
                'encrypted': repo.encrypted,
                'name': repo.repo_name,
                'id': repo.repo_id,
                'size': repo.size,
                'last_modify': repo.last_modify,
                'permission': repo.permission,
                'props': {},
                'share_type': repo.share_type
            }

            if repo.share_type == 'personal':
                repo_info['props']['id'] = None
                repo_info['props']['to'] = Profile.objects.get_contact_email_by_user(repo.user)

            if repo.share_type == 'group':
                group = ccnet_api.get_group(repo.group_id)
                repo_info['props']['id'] = repo.group_id
                repo_info['props']['to'] = group.group_name

            return_in_repos.append(repo_info)

        # Shared folder in return_in_repos
        for repo in shared_folders:
            if not repo.is_virtual:
                    continue
            repo_info = {
                'encrypted': repo.encrypted,
                'name': repo.name,
                'id': repo.id,
                'size': repo.size,
                'last_modify': repo.last_modify,
                'permission': repo.permission,
                'props': {},
                'share_type': repo.share_type
            }

            if repo.share_type == 'personal':
                repo_info['props']['id'] = None
                repo_info['props']['to'] = Profile.objects.get_contact_email_by_user(repo.user)

            if repo.share_type == 'group':
                group = ccnet_api.get_group(repo.group_id)
                repo_info['props']['id'] = repo.group_id
                repo_info['props']['to'] = group.group_name

            return_in_repos.append(repo_info)
        return_in_repos.sort(key = lambda x : x['name'],reverse=False)

        # Populate personal groups
        return_personal_groups = []
        for group in personal_groups:
            group_info = {
                'id': group.id,
                'group_name': group.group_name,
                'role': group.role,
                'timestamp': group.timestamp
            }
            return_personal_groups.append(group_info)
        # Populate list of user share links
        return_user_share_links = []
        for link in user_shared_links:
            if isinstance(link, UploadLinkShare):
                link_info = {
                    'username': link.username,
                    'repo_id': link.repo_id,
                    'path': link.path,
                    'token': link.token,
                    'ctime': link.ctime,
                    'view_cnt': link.view_cnt,
                    'password': link.password,
                    'expire_date': link.expire_date,
                    'is_encrypted': link.is_encrypted(),
                    'is_owner': link.is_owner(email),
                    'dir_name': link.dir_name,
                    'is_upload': link.is_upload
                }
            else:
                link_info = {
                    'username': link.username,
                    'repo_id': link.repo_id,
                    'path': link.path,
                    'ctime': link.ctime,
                    's_type': link.s_type,
                    'password': link.password,
                    'expire_date': link.expire_date,
                    'permission': link.permission,
                    'is_download': link.is_download,
                    'is_file_share_link': link.is_file_share_link(),
                    'is_dir_share_link': link.is_dir_share_link(),
                    'is_encrypted': link.is_encrypted(),
                    'is_expired': link.is_expired(),
                    'is_owner': link.is_owner(email),
                    'perm_dict': link.get_permissions(),
                    'item_name': link.filename,
                    'file_size': link.file_size if link.is_file_share_link() else None,
                    'dir_size': link.dir_size if link.is_dir_share_link() else None,
                    'view_cnt': link.view_cnt,
                    'token': link.token,
                }
            return_user_share_links.append(link_info)
        # Populated list of own meeting rooms
        all_meeting_rooms = MeetingRoom.objects.filter(owner_id=email)
        
        meetings_rooms = []

        for r in all_meeting_rooms:
            meetings_rooms.append({
                "id": r.id,
                "room_name": r.room_name,
                "status": r.status,
                "owner_id": r.owner_id,
                "updated_at": r.updated_at,
                "created_at": r.created_at,
                "share_token": r.share_token,
            })

        print 'config.BBB_MAX_MEETINGS_PER_USER'
        print config.BBB_MAX_MEETINGS_PER_USER
        print 'profile_setting'
        print profile_setting
        max_meetings = profile_setting.max_meetings if profile_setting and profile_setting.max_meetings else config.BBB_MAX_MEETINGS_PER_USER
        
        return api_response(data={
                'owned_repos': return_owned_repos,
                'space_quota': space_quota,
                'space_usage': space_usage,
                'in_repos': return_in_repos,
                'email': email,
                'common_info': get_user_common_info(email),
                'profile': {
                    'user': profile.user if profile and profile.user else None,
                    'nickname': profile.nickname if profile and profile.nickname else None,
                    'intro': profile.intro if profile and profile.intro else None,
                    'lang_code': profile.lang_code if profile and profile.lang_code else None,
                    # Login id can be email or anything else used to login.
                    'login_id': profile.login_id if profile and profile.login_id else None,
                    # Contact email is used to receive emails.
                    'contact_email': profile.contact_email if profile and profile.contact_email else None,
                    'tenant': profile.tenant if profile and profile.tenant else None,
                },
                'd_profile': {
                    'department': d_profile.department if d_profile and d_profile.department else None,
                    'telephone': d_profile.telephone if d_profile and d_profile.telephone else None,
                },
                'org_name': org_name,
                'user_shared_links': return_user_share_links,
                'enable_sys_admin_view_repo': ENABLE_SYS_ADMIN_VIEW_REPO,
                'personal_groups': return_personal_groups,
                # 'two_factor_auth_enabled': _has_two_factor_auth,
                'default_device': _default_device,
                'meeting_rooms': meetings_rooms,
                'p_setting': {
                    'max_meetings': max_meetings
                }
            })
    
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Reset user password',
        operation_description='''Reset user password''',
        operation_id='admin_user_reset_password',
        tags=['admin-users'],
        manual_parameters=[
            openapi.Parameter(
                name='user_email',
                in_="path",
                type='string',
                description='user email',
            ),
        ],
        responses={
            200: openapi.Response(
                description='User password reseted successfully',
                examples={
                    'application/json': {
                        "message": "Successfully reset password to 0LY0psmtNL, an email has been sent to dgrishukhin0@berkeley.edu.",
                        "data": None
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
            404: openapi.Response(
                description='User not found',
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
    def post(self, request, user_email):
        try:
            email = user_email
            user = User.objects.get(email=email)
            if isinstance(INIT_PASSWD, FunctionType):
                new_password = INIT_PASSWD()
            else:
                new_password = INIT_PASSWD
            
            user.set_password(new_password)
            result = user.save()
            logger.info('ehre is the result')
            logger.info(result)
            logger.debug('config.FORCE_PASSWORD_CHANGE: %s' % config.FORCE_PASSWORD_CHANGE)

            if config.FORCE_PASSWORD_CHANGE:
                UserOptions.objects.set_force_passwd_change(user.username)
            message = '';
            if IS_EMAIL_CONFIGURED:
                if SEND_EMAIL_ON_RESETTING_USER_PASSWD:
                    try:
                        contact_email = Profile.objects.get_contact_email_by_user(user.email)
                        send_user_reset_email(request, contact_email, new_password)
                        message = _('Successfully reset password to %(new_password)s, an email has been sent to %(email)s.') % {'new_password': new_password, 'email': contact_email}
                    except Exception, e:
                        logger.error(str(e))
                        message = _('Successfully reset password to %(new_password)s, but failed to send email to %(email)s, please check your email configuration.') % {'new_password': new_password, 'email': contact_email}
                else:
                    message = _('Successfully reset password to %(new_password)s for user %(email)s.') % {'new_password': new_password, 'email': user.email}
            else:
                message = _("Successfully reset password to %(new_password)s for user %(email)s. But email notification can not be sent, because Email service is not properly configured.") % {'new_password': new_password, 'email': user.email}
        except User.DoesNotExist:
            message = _('Failed to reset password: user does not exist')

        return api_response(msg=message)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Remove user',
        operation_description='''Remove user''',
        tags=['admin-users'],
        manual_parameters=[
            openapi.Parameter(
                name='user_email',
                in_="path",
                type='string',
                description='user email',
            ),
        ],
        responses={
            200: openapi.Response(
                description='User removed successfully',
                examples={
                    'application/json': {
                        "message": "User removed successfully",
                        "data": None
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
            404: openapi.Response(
                description='User not found',
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
    def delete(self, request, user_email):
        try:
            email = user_email
            user = User.objects.get(email=email)
            org = ccnet_api.get_orgs_by_user(user.email)
            if org:
                if org[0].creator == user.email:
                    return api_error(403, msg=_('Failed to delete: the user is an organization creator'))
            user.delete()
            # send admin operation log signal
            admin_op_detail = {
                "email": email,
            }
            admin_operation.send(sender=None, admin_name=request.user.username,
                    operation=USER_DELETE, detail=admin_op_detail)
            # Remove user from tenant admin too
            TenantAdmin.objects.filter(user=user_email).delete()

            # Remove link public share from share_fileshare
            FileShare.objects.filter(username=user_email).delete()

            # Remove link public share from share_uploadlinkshare
            UploadLinkShare.objects.filter(username=user_email).delete()

            return api_response(msg=_('User has been removed successfully'))

        except User.DoesNotExist:
            return api_error(404, msg=_('Failed to delete: the user does not exist'))

class AdminUserSource(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get user source',
        operation_description='''Get user source''',
        tags=['admin-users'],
        responses={
            200: openapi.Response(
                description='User source retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": [
                            "DB",
                            "LDAP"
                        ]
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
            404: openapi.Response(
                description='User not found',
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
        # Get source list type of USER

        # default have DB
        data = ['DB']

        # Check is LDAP is enabled
        try:
            if get_ldap_info():
                data.append('LDAPImport')
        except Exception as e:
            logger.error(e)

        return api_response(data=data)

class AdminAdmins(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get all admins',
        operation_description='''Get all admins''',
        tags=['admin-users'],
        responses={
            200: openapi.Response(
                description='Admin list retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "users": [
                                {
                                    "is_default": None,
                                    "space_quota": 1000000000,
                                    "create_time": 1548148348642376,
                                    "role": "",
                                    "space_usage": 168213379,
                                    "is_guest": False,
                                    "last_login": "2019-02-21T02:30:43",
                                    "is_active": True,
                                    "email": "admin@alpha.syncwerk.com"
                                },
                            ],
                            "extra_user_roles": [
                                "employee"
                            ],
                            "guest_user": "guest",
                            "have_ldap": None,
                            "is_pro": True,
                            "default_user": "default"
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
    def get(self, request, format=None):
        
        db_users = synserv.get_emailusers('DB', -1, -1)
        ldpa_imported_users = synserv.get_emailusers('LDAPImport', -1, -1)

        admin_users = []
        not_admin_users = []

        for user in db_users + ldpa_imported_users:
            if user.is_staff is True:
                admin_users.append(user)
            else:
                not_admin_users.append(user)

        last_logins = UserLastLogin.objects.filter(username__in=[x.email for x in admin_users])

        for user in admin_users:
            # print user
            # if user.email == request.user.email:
            #     user.is_self = True

            _populate_user_quota_usage(user)

            # check db user's role
            if user.source == "DB":
                if user.role == GUEST_USER:
                    user.is_guest = True
                else:
                    user.is_guest = False

            # populate user last login time
            user.last_login = None
            for last_login in last_logins:
                if last_login.username == user.email:
                    user.last_login = last_login.last_login

        extra_user_roles = [x for x in get_available_roles()
                            if x not in get_basic_user_roles()]

        resp_admin_users = []
        resp_not_admin_users = []

        for user in admin_users:
            current_user = {
                'email': user.email,
                'is_active': user.is_active,
                'is_guest': user.is_guest,
                'is_default': user.is_default,
                'role': user.role,
                'space_usage': user.space_usage,
                'space_quota': user.space_quota,
                'create_time': user.ctime,
                'last_login': user.last_login,
            }
            resp_admin_users.append(current_user)
        for user in not_admin_users:
            current_user = {
                'email': user.email,
                'is_active': user.is_active,
                'is_guest': user.is_guest,
                'is_default': user.is_default,
                'role': user.role,
                'space_usage': user.space_usage,
                'space_quota': user.space_quota,
                'create_time': user.ctime,
                'last_login': user.last_login,
            }
            resp_not_admin_users.append(current_user)
        data = {
                'users': resp_admin_users,
                'not_admin_users': resp_not_admin_users,
                'have_ldap': get_ldap_info(),
                'default_user': DEFAULT_USER,
                'guest_user': GUEST_USER,
                'is_pro': is_pro_version(),
                'extra_user_roles': extra_user_roles,
            }
        return api_response(data=data)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Batch make users as admin',
        operation_description='''Batch make users as admin''',
        tags=['admin-users'],
        manual_parameters=[
            openapi.Parameter(
                name='set_admin_emails',
                in_="formData",
                type='string',
                description='emails of the users to set as admin, seperated by comma',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Operation completed',
                examples={
                    'application/json': {
                        "message": "Operation completed.",
                        "data": {
                            "failed": [],
                            "success": [
                                "dgrishukhin0@berkeley.edu"
                            ]
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
    def post(self, request):
        
        set_admin_emails = request.POST.get('set_admin_emails')
        set_admin_emails = string2list(set_admin_emails)
        success = []
        failed = []

        for email in set_admin_emails:
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                failed.append(email)
                continue

            user.is_staff = True
            user.save()
            success.append(email)
        response_data = {
            'success': success,
            'failed': failed,
        }
        return api_response(msg=_(u'Operation completed.'), data=response_data)

class AdminAdmin(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Revoke user admin',
        operation_description='''Revoke user admin''',
        operation_id='admin_user_admin_revoke',
        tags=['admin-users'],
        manual_parameters=[
            openapi.Parameter(
                name='user_email',
                in_="path",
                type='string',
                description='email fo the admin to be revoked',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Successfully revoke the admin permission',
                examples={
                    'application/json': {
                        "message": "Successfully revoke the admin permission of user@email.com",
                        "data": None
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
            404: openapi.Response(
                description='User not exist',
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
    def post(self, request, user_email):
        try:
            user = User.objects.get(email=user_email)
            user.is_staff = False
            user.save()
            return api_response(msg=_(u'Successfully revoke the admin permission of %s') % user.username)
        except User.DoesNotExist:
            return api_error(code=404, msg=_(u'Failed to revoke admin: the user does not exist'))

class AdminUsersExcelExport(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    throttle_classes = (UserRateThrottle, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Export user list to excel',
        operation_description='''Export user list to excel''',
        tags=['admin-users'],
        responses={
            200: openapi.Response(
                description='Export to excel successfully.',
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
                description='User not exist',
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
    def get(self, request):
        next = request.META.get('HTTP_REFERER', None)
        if not next:
            next = SITE_ROOT

        try:
            users = ccnet_api.get_emailusers('DB', -1, -1) + \
                    ccnet_api.get_emailusers('LDAPImport', -1, -1)
        except Exception as e:
            logger.error(e)
            messages.error(request, (u'Failed to export Excel'))
            return HttpResponseRedirect(next)

        if is_pro_version():
            is_pro = True
        else:
            is_pro = False

        if is_pro:
            head = [("Email"), ("Name"), ("Contact Email"), ("Status"), ("Role"),
                    ("Space Usage") + "(MB)", ("Space Quota") + "(MB)",
                    ("Create At"), ("Last Login"), ("Admin"), ("LDAP(imported)"),]
        else:
            head = [("Email"), ("Name"), ("Contact Email"), ("Status"),
                    ("Space Usage") + "(MB)", ("Space Quota") + "(MB)",
                    ("Create At"), ("Last Login"), ("Admin"), ("LDAP(imported)"),]

        # only operate 100 users for every `for` loop
        looped = 0
        limit = 100
        data_list = []

        while looped < len(users):

            current_users = users[looped:looped+limit]

            last_logins = UserLastLogin.objects.filter(username__in=[x.email \
                    for x in current_users])
            user_profiles = Profile.objects.filter(user__in=[x.email \
                    for x in current_users])

            for user in current_users:
                # populate name and contact email
                user.contact_email = ''
                user.name = ''
                for profile in user_profiles:
                    if profile.user == user.email:
                        user.contact_email = profile.contact_email
                        user.name = profile.nickname

                # populate space usage and quota
                MB = get_file_size_unit('MB')

                _populate_user_quota_usage(user)
                if user.space_usage > 0:
                    try:
                        space_usage_MB = round(float(user.space_usage) / MB, 2)
                    except Exception as e:
                        logger.error(e)
                        space_usage_MB = '--'
                else:
                    space_usage_MB = ''

                if user.space_quota > 0:
                    try:
                        space_quota_MB = round(float(user.space_quota) / MB, 2)
                    except Exception as e:
                        logger.error(e)
                        space_quota_MB = '--'
                else:
                    space_quota_MB = ''

                # populate user last login time
                user.last_login = None
                for last_login in last_logins:
                    if last_login.username == user.email:
                        user.last_login = last_login.last_login

                if user.is_active:
                    status = ('Active')
                else:
                    status = ('Inactive')

                create_at = tsstr_sec(user.ctime) if user.ctime else ''
                last_login = user.last_login.strftime("%Y-%m-%d %H:%M:%S") if \
                    user.last_login else ''

                is_admin = ('Yes') if user.is_staff else ''
                ldap_import = ('Yes') if user.source == 'LDAPImport' else ''

                if is_pro:
                    if user.role:
                        if user.role == GUEST_USER:
                            role = ('Guest')
                        elif user.role == DEFAULT_USER:
                            role = ('Default')
                        else:
                            role = user.role
                    else:
                        role = ('Default')

                    row = [user.email, user.name, user.contact_email, status, role,
                            space_usage_MB, space_quota_MB, create_at,
                            last_login, is_admin, ldap_import]
                else:
                    row = [user.email, user.name, user.contact_email, status,
                            space_usage_MB, space_quota_MB, create_at,
                            last_login, is_admin, ldap_import]

                data_list.append(row)

            # update `looped` value when `for` loop finished
            looped += limit

        wb = write_xls('users', head, data_list)
        if not wb:
            return api_response(code=500, msg=_('Failed to export to excel'))

        response = HttpResponse(content_type='application/ms-excel')
        response['Content-Disposition'] = 'attachment; filename=users.xlsx'
        wb.save(response)
        return response

class AdminUsersToggleRoles(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Update user role',
        operation_description='''Update user role''',
        tags=['admin-users'],
        manual_parameters=[
            openapi.Parameter(
                name='user_email',
                in_="path",
                type='string',
                description='email fo the admin to be revoked',
            ),
            openapi.Parameter(
                name='r',
                in_="formData",
                type='string',
                description='user new role. Default to "default"',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Changed user role successfully.',
                examples={
                    'application/json': {
                        "message": "Changed user role successfully.",
                        "data": None
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
            404: openapi.Response(
                description='User not exist',
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
    def post(self, request, user_email):
        # Disable this for enable to LDAP user
        # if not is_valid_username(user_email):
        #     return api_error(code=400, msg=_('User is not valid'))

        # if not is_pro_version():
        #     return api_error(code=403, msg=_('You don\'t have permission to change user role.'))

        try:
            user_role = request.POST.get('r', DEFAULT_USER)
        except ValueError:
            user_role = DEFAULT_USER

        try:
            user = User.objects.get(user_email)
            User.objects.update_role(user.email, user_role)
            return api_response(msg=_('Changed user role successfully.'))

        except User.DoesNotExist:
            return api_error(code=500, msg=_('User does not exist'))

class AdminUserToggleStatus(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsSystemAdminOrTenantAdmin, )
    throttle_classes = (UserRateThrottle, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Update user role',
        operation_description='''Update user roole''',
        tags=['admin-users'],
        manual_parameters=[
            openapi.Parameter(
                name='user_email',
                in_="path",
                type='string',
                description='email fo the admin to be revoked',
            ),
            openapi.Parameter(
                name='r',
                in_="formData",
                type='string',
                description='user new role. Default to "default"',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Changed user role successfully.',
                examples={
                    'application/json': {
                        "message": "Changed user role successfully.",
                        "data": None
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
            404: openapi.Response(
                description='User not exist',
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
    def post(self, request, user_email):
        # Disable check valid user name for LDAP Users
        # if not is_valid_username(user_email):
        #     return api_error(code=400, msg='User is not valid')

        try:
            user_status = int(request.POST.get('s', 0))
            if bool(user_status) == True:
                try:
                    active_db_users = ccnet_api.count_emailusers('DB')
                except Exception as e:
                    logger.error(e)
                    return api_error(code=500, msg=_('Internal server error.'))
                try:
                    active_ldap_users = ccnet_api.count_emailusers('LDAP')
                except Exception as e:
                    logger.error(e)
                    return api_error(code=500, msg=_('Internal server error.'))

                number_of_active_users = active_db_users + active_ldap_users if active_ldap_users > 0 \
                    else active_db_users
                # get number of user in license
                license_json_info = parse_license_to_json()
                number_of_max_users = int(
                    license_json_info['allowed_users'])
                if number_of_active_users >= number_of_max_users:
                    error_msg = _('You can\'t activate this user because you reach the limit of the number of user accounts on the license.')
                    return api_error(code=403, data={'show_upgrade_modal': True}, msg=error_msg)
        except ValueError:
            user_status = 0

        try:
            user = User.objects.get(user_email)
            user.is_active = bool(user_status)
            result_code = user.save()
            if result_code == -1:
                return api_error(code=403, msg=_('You don\'t have permission to change user status.'))

            if user.is_active is True:
                try:
                    _clear_login_failed_attempts(request, user_email)
                    email_user_on_activation(user)
                    email_sent = True
                except Exception as e:
                    logger.error(e)
                    email_sent = False
                if email_sent:
                    return api_response(msg=_('User activated. A notification has been sent to user email.'))
                else:
                    return api_response(msg=_('User activated but failed to send email, please check your email configuration.'))
            return api_response(msg=_('User deactivated successfully.'))
        except User.DoesNotExist:
            return api_error(code=500, msg=_("Server error"))

class AdminUserImport(APIView):

    parser_classes = (parsers.FormParser, parsers.MultiPartParser)

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Import user from csv',
        operation_description='''Import user from csv''',
        tags=['admin-users'],
        manual_parameters=[
            openapi.Parameter(
                name='user_email',
                in_="path",
                type='string',
                description='email fo the admin to be revoked',
            ),
            openapi.Parameter(
                name='file',
                in_="formData",
                type='file',
                description='csv file',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Import users successfully.',
                examples={
                    'application/json': {
                        "message": "Import users successfully.",
                        "data": None
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
            404: openapi.Response(
                description='User not exist',
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
    def post(self, request):
        form = BatchAddUserForm(request.POST, request.FILES)
        if form.is_valid():
            content = request.FILES['file'].read()
            encoding = chardet.detect(content)['encoding']
            if encoding != 'utf-8':
                content = content.decode(encoding, 'replace').encode('utf-8')

            filestream = StringIO.StringIO(content)
            reader = csv.reader(filestream)
            new_users_count = len(list(reader))
            if user_number_over_limit():
                return api_error(code=400, msg=_('The number of users exceeds the limit.'))

            # return to the top of the file
            filestream.seek(0)
            dialect = csv.Sniffer().sniff(filestream.read(), delimiters=";,")
            filestream.seek(0)
            reader = csv.reader(filestream, delimiter=dialect.delimiter)

            for row in reader:
                if not row:
                    continue

                try:
                    username = row[0].strip()
                    password = row[1].strip()
                    if not is_valid_username(username) or not password:
                        continue
                except Exception as e:
                    logger.error(e)
                    continue

                try:
                    User.objects.get(email=username)
                except User.DoesNotExist:
                    User.objects.create_user(
                        username, password, is_staff=False, is_active=True)

                    if config.FORCE_PASSWORD_CHANGE:
                        UserOptions.objects.set_force_passwd_change(username)

                    # then update the user's optional info
                    try:
                        nickname = row[2].strip()
                        if len(nickname) <= 64 and '/' not in nickname:
                            Profile.objects.add_or_update(username, nickname, '')
                    except Exception as e:
                        logger.error(e)

                    try:
                        department = row[3].strip()
                        if len(department) <= 512:
                            DetailedProfile.objects.add_or_update(username, department, '')
                    except Exception as e:
                        logger.error(e)

                    try:
                        role = row[4].strip()
                        if is_pro_version() and role in get_available_roles():
                            User.objects.update_role(username, role)
                    except Exception as e:
                        logger.error(e)

                    try:
                        space_quota_mb = row[5].strip()
                        space_quota_mb = int(space_quota_mb)
                        if space_quota_mb >= 0:
                            space_quota = int(space_quota_mb) * get_file_size_unit('MB')
                            syncwerk_api.set_user_quota(username, space_quota)
                    except Exception as e:
                        logger.error(e)

                    send_html_email_with_dj_template(
                        username, dj_template='sysadmin/user_batch_add_email.html',
                        subject=(u'You are invited to join %s') % SITE_NAME,
                        context={
                            'user': email2nickname(request.user.username),
                            'email': username,
                            'password': password,
                        },
                        request = request
                        )

                    # send admin operation log signal
                    admin_op_detail = {
                        "email": username,
                    }
                    admin_operation.send(sender=None, admin_name=request.user.username,
                                        operation=USER_ADD, detail=admin_op_detail)

            return api_response(msg='Import succeessfully.')
        else:
            return api_error(code=400, msg='Please select a valid csv file.')

        return HttpResponseRedirect(next)
