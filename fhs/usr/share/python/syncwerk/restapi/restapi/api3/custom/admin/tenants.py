import logging

from datetime import datetime

from synserv import ccnet_threaded_rpc, syncwserv_threaded_rpc, \
    syncwerk_api, get_group, get_group_members, ccnet_api, \
    get_related_users_by_org_repo
from pyrpcsyncwerk import RpcsyncwerkError

from rest_framework.views import APIView

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.utils import api_error, api_response

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from restapi.api3.permissions import IsSystemAdminOrTenantAdmin

from django.contrib import messages

from restapi.tenants.models import (Tenant, TenantAdmin,
                                        TenantQuota)
from restapi.signals import repo_deleted, tenant_deleted
from restapi.profile.models import Profile
from restapi.base.accounts import User
from restapi.base.models import UserLastLogin
from restapi.tenants.utils import get_tenant_space_usage
from restapi.utils.file_size import get_file_size_unit

from django.utils.translation import ugettext as _

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema
from restapi.api3.models import BBBPrivateSetting, ProfileSetting

from constance import config

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


class AdminTenants(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get list tenant',
        operation_description='''Get list tenant''',
        tags=['admin-tenants'],
        responses={
            200: openapi.Response(
                description='Tenant list retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "insts": [
                                {
                                    "space_quota": None,
                                    "ctime": "2019-01-24T06:59:56",
                                    "space_usage": 0,
                                    "id": 1,
                                    "name": "ten1"
                                },
                                {
                                    "space_quota": None,
                                    "ctime": "2019-01-30T03:12:53",
                                    "space_usage": 13920226,
                                    "id": 2,
                                    "name": "ten10"
                                }
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
    def get(self, request):
        """ Get all tenants
        """
        insts = Tenant.objects.all()
        list_insts = [];
        for tenant in insts:
            list_insts.append({
                'id': tenant.id,
                'name': tenant.name,
                'ctime': tenant.create_time,
                'space_quota': TenantQuota.objects.get_or_none(tenant=tenant),
                'space_usage': get_tenant_space_usage(tenant)
            });
        return api_response(data={
            'insts': list_insts
        })

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Create new tenant',
        operation_description='''Create new tenant''',
        tags=['admin-tenants'],
        manual_parameters=[
            openapi.Parameter(
                name='name',
                in_="formData",
                type='string',
                description='name of the new tenant',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Tenant created successfully',
                examples={
                    'application/json': {
                        "message": "Tenant created successfully",
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
        """ Create a new tenant
        """
        inst_name = request.POST.get('name').strip()
        if not inst_name:
            return api_error(code=400, msg=_('Tenant name is required.'))
        # Check if there's a tenant with the same name existed
        try:
            Tenant.objects.get(name=inst_name)
            return api_error(code=400, msg=_('Tenant existed. Please choose another name for the tenant.'))
        except Tenant.DoesNotExist:
            pass
        try:
            Tenant.objects.create(name=inst_name)
            return api_response(code=200, msg=_('New tenant created successfully.'))
        except Exception as e:
            logger.error(e)
            return api_error(code=500, msg=_('Internal server error.'))
        
class AdminTenant(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsSystemAdminOrTenantAdmin, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Get tenant details',
        operation_description='''Get tenant details''',
        tags=['admin-tenants'],
        manual_parameters=[
            openapi.Parameter(
                name='inst_id',
                in_="path",
                type='string',
                description='Tenant id',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Tenant info retrieved successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "space_quota": None,
                            "users": [
                                {
                                    "username": "dgrishukhin0@berkeley.edu",
                                    "is_tenant_admin": False,
                                    "is_staff": False,
                                    "last_login": None,
                                    "ctime": 1548817891371976,
                                    "usage": 0,
                                    "quota": 1000000000,
                                    "is_active": True,
                                    "email": "dgrishukhin0@berkeley.edu",
                                    "id": 5
                                },
                                {
                                    "username": "jgoscare@networksolutions.com",
                                    "is_tenant_admin": False,
                                    "is_staff": False,
                                    "last_login": None,
                                    "ctime": 1548817897529870,
                                    "usage": 0,
                                    "quota": 1000000000,
                                    "is_active": True,
                                    "email": "jgoscare@networksolutions.com",
                                    "id": 19
                                },
                                {
                                    "username": "test10@grr.la",
                                    "is_tenant_admin": True,
                                    "is_staff": True,
                                    "last_login": "2019-02-12T09:23:44",
                                    "ctime": 1548817954118969,
                                    "usage": 13920226,
                                    "quota": 1000000000,
                                    "is_active": True,
                                    "email": "test10@grr.la",
                                    "id": 105
                                },
                                {
                                    "username": "test1@grr.la",
                                    "is_tenant_admin": False,
                                    "is_staff": True,
                                    "last_login": None,
                                    "ctime": 1548673032734024,
                                    "usage": 0,
                                    "quota": 1000000000,
                                    "is_active": False,
                                    "email": "test1@grr.la",
                                    "id": 4
                                }
                            ],
                            "space_usage": 13920226,
                            "id": 2,
                            "name": "ten10"
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
            404: openapi.Response(
                description='Tenant not found',
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
    def get(self, request, inst_id):
        """ Get tenant details
        """
        try:
            inst = Tenant.objects.get(pk=inst_id)
        except Tenant.DoesNotExist:
            return api_error(code=404, msg=_('Tenant not existed.'))
        inst_admins = [x.user for x in TenantAdmin.objects.filter(tenant=inst)]
        usernames = [x.user for x in Profile.objects.filter(tenant=inst.name)]
        users = [User.objects.get(x) for x in usernames]
        last_logins = UserLastLogin.objects.filter(username__in=[x.email for x in users])
        user_list = [];
        for u in users:
            _populate_user_quota_usage(u)

            if u.username in inst_admins:
                u.inst_admin = True
            else:
                u.inst_admin = False

            # populate user last login time
            u.last_login = None
            for last_login in last_logins:
                if last_login.username == u.email:
                    u.last_login = last_login.last_login

            # get info about max meeting
            profile_setting = ProfileSetting.objects.get_profile_setting_by_user(u.email)
            if profile_setting is None:
                max_meeting_setting = None
            else:
                max_meeting_setting = profile_setting.max_meetings
            user_list.append({
                'username': u.username,
                'email': u.email,
                'id': u.id,
                'is_active': u.is_active,
                'quota': u.space_quota,
                'usage': u.space_usage,
                'is_tenant_admin': u.inst_admin,
                'is_staff': u.is_staff,
                'last_login': u.last_login,
                'ctime': u.ctime,
                'max_meetings': max_meeting_setting
            })          
        users_count = Profile.objects.filter(tenant=inst.name).count()
        space_quota = TenantQuota.objects.get_or_none(tenant=inst)
        space_usage = get_tenant_space_usage(inst)
        permissions = {
            "edit_bbb_setting": True if request.user.username in inst_admins and config.BBB_ALLOW_TENANTS_PRIVATE_SERVER == 1 else False
        }
        return api_response(code=200, data={
            'id': inst.id,
            'name': inst.name,
            'space_quota': space_quota,
            'space_usage': space_usage,
            'users': user_list,
            'permission': permissions,
        })

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Update tenant quota',
        operation_description='''Update tenant quota''',
        tags=['admin-tenants'],
        manual_parameters=[
            openapi.Parameter(
                name='inst_id',
                in_="path",
                type='string',
                description='Tenant id',
            ),
            openapi.Parameter(
                name='space_quota',
                in_="formData",
                type='number',
                description='quota for the tenant (in MB)',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Tenant quota updated successfully',
                examples={
                    'application/json': {
                        "message": "",
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
                description='Tenant not found',
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
    def put(self, request, inst_id):
        """ Update tenant quota
        """
        try:
            inst = Tenant.objects.get(pk=inst_id)
        except Tenant.DoesNotExist:
            return api_error(code=404, msg=_('Tenant is not existed.'))
            
        quota_mb = int(request.POST.get('space_quota', ''))
        quota = quota_mb * get_file_size_unit('MB')

        obj, created = TenantQuota.objects.update_or_create(
            tenant=inst,
            defaults={'quota': quota},
        )
        return api_response(code=200, msg=_('Set quota for tenant successfully.'))
    
    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Remove tenant',
        operation_description='''Remove tenant''',
        tags=['admin-tenants'],
        manual_parameters=[
            openapi.Parameter(
                name='inst_id',
                in_="path",
                type='string',
                description='Tenant id',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Tenant removed successfully',
                examples={
                    'application/json': {
                        "message": "",
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
                description='Tenant not found',
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
    def delete(self, request, inst_id):
        """Delete a tenant 
        """
        try:
            inst = Tenant.objects.get(pk=inst_id)
        except Tenant.DoesNotExist:
            return api_error(code=404, msg=_('Tenant not existed.'))
        
        inst_name = inst.name
        BBBPrivateSetting.objects.filter(tenant_id=inst_id).delete()
        inst.delete()
        tenant_deleted.send(sender=None, inst_name=inst_name)
        return api_response(code=200, msg=_('Tenant deleted successfully.'))

class AdminTenantUsers(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsSystemAdminOrTenantAdmin, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Add member to tenant',
        operation_description='''Add member to tenant''',
        tags=['admin-tenants'],
        manual_parameters=[
            openapi.Parameter(
                name='inst_id',
                in_="path",
                type='string',
                description='Tenant id',
            ),
            openapi.Parameter(
                name='emails',
                in_="path",
                type='string',
                description='email list of the users to be added to tenant, separated by comma.',
                required=True
            ),
        ],
        responses={
            200: openapi.Response(
                description='Added member to tenant successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "successful": [
                                "ctrehearn25@upenn.edu",
                                "wduggan1b@google.cn"
                            ],
                            "failed": []
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
                description='Tenant not found',
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
    def post(self, request, inst_id):
        """ Add users to tenant
        """
        emails = request.POST.get('emails', '')
        email_list = [em.strip() for em in emails.split(',') if em.strip()]
        if len(email_list) == 0:
            return api_error(code=400, msg=_('At least 1 user is required.'))
        try:
            inst = Tenant.objects.get(pk=inst_id)
        except Tenant.DoesNotExist:
            return api_error(code=404, msg=_('Tenant is not existed.'))
        successful = [];
        failed = [];
        for email in email_list:
            try:
                User.objects.get(email=email)
            except Exception as e:
                failed.append(email);
                continue

            profile = Profile.objects.get_profile_by_user(email)
            if not profile:
                profile = Profile.objects.add_or_update(email, email)
            if profile.tenant:
                failed.append(email);
                continue
            else:
                profile.tenant = inst.name
            profile.save()
            successful.append(email)

        return api_response(code=200, data={
            'successful': successful,
            'failed': failed,
        })

class AdminTenantUser(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsSystemAdminOrTenantAdmin, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Remove user from tenant',
        operation_description='''Remove user from tenant''',
        tags=['admin-tenants'],
        manual_parameters=[
            openapi.Parameter(
                name='inst_id',
                in_="path",
                type='string',
                description='Tenant id',
            ),
            openapi.Parameter(
                name='user_email',
                in_="path",
                type='string',
                description='email of the user to be removed from tenant',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Added member to tenant successfully',
                examples={
                    'application/json': {
                        "message": "",
                        "data": {
                            "successful": [
                                "ctrehearn25@upenn.edu",
                                "wduggan1b@google.cn"
                            ],
                            "failed": []
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
                description='Tenant / user not found',
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
    def delete(self, request, inst_id, user_email):
        """ Remove users from tenant
        """
        try:
            inst = Tenant.objects.get(pk=inst_id)
        except Tenant.DoesNotExist:
            return api_error(code=404, msg=_('Tenant is not existed.'))
        try:
            User.objects.get(email=user_email)
        except Exception as e:
            return api_error(code=404, msg=_('User not found.'))
        profile = Profile.objects.get_profile_by_user(user_email)
        if not profile:
            return api_error(code=404, msg=_('User profile not found.'))
        profile.tenant = None
        profile.save()
        # Remove user from tenant admin too
        TenantAdmin.objects.filter(user=user_email).delete()

        return api_response(code=200, msg=_('Remove user from tenant successfully.'))

class AdminTenantAdmins(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsSystemAdminOrTenantAdmin, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - Toggle user tenant admin role',
        operation_description='''Toggle user tenant admin role''',
        tags=['admin-tenants'],
        manual_parameters=[
            openapi.Parameter(
                name='inst_id',
                in_="path",
                type='string',
                description='Tenant id',
            ),
            openapi.Parameter(
                name='email',
                in_="path",
                type='string',
                description='email of the user',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Promote / provoke user tenant admin role successfully',
                examples={
                    'application/json': {
                        "message": "",
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
                description='Tenant not found',
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
    def post(self, request, inst_id, user_email):
        """ Promote or revoke tenant admin
        """
        try:
            inst = Tenant.objects.get(pk=inst_id)
        except Tenant.DoesNotExist:
            return api_error(code=404, msg=_('Tenant not existed.'))
        try:
            u = User.objects.get(email=user_email)
        except User.DoesNotExist:
            return api_error(code=404, msg=_('User is not existed.'))
        if u.is_staff:
            return api_error(code=403, msg=_('Can not assign tenant administration roles to global administrators.'))
        res = TenantAdmin.objects.filter(tenant=inst, user=user_email)
        if len(res) == 0:
            TenantAdmin.objects.create(tenant=inst, user=user_email)
            return api_response(code=200, msg=_('Successfully promote user to tenant admin.'))
        elif len(res) == 1:
            res[0].delete()
            return api_response(code=200, msg=_('Successfully revoke user\'s tenant admin rights.'))
        
class AdminTenantBBB(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsSystemAdminOrTenantAdmin, )
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    def get(self, request, inst_id):
        
        try:
            existing_bbb_config = BBBPrivateSetting.objects.get(
                tenant_id=inst_id
            )
        except BBBPrivateSetting.DoesNotExist:
            # not found => create one
            existing_bbb_config = None
        
        return_result = {}

        if existing_bbb_config is None:
            return_result = {
                "bbb_server": '',
                "bbb_secret": '',
                "is_active": False,
                "id": None
            }
        else:
            # found - update existing
            return_result = {
                "bbb_server": existing_bbb_config.bbb_server,
                "bbb_secret": existing_bbb_config.bbb_secret,
                "is_active": existing_bbb_config.is_active,
                "id": existing_bbb_config.id, # this is return only for test connection only
            }
            
        return api_response(code=200, data=return_result, msg=_('BBB configuration retrieved successfully.'))

    def post(self, request, inst_id):
        bbb_server_url = request.POST.get('bbb_server_url', '')
        bbb_server_secret = request.POST.get('bbb_server_secret', '')
        is_active = request.POST.get('bbb_is_active', 'false')
        
        try:
            existing_bbb_config = BBBPrivateSetting.objects.get(
                tenant_id=inst_id
            )
        except BBBPrivateSetting.DoesNotExist:
            # not found => create one
            existing_bbb_config = None
        
        if existing_bbb_config is None:
            new_bbb_config = BBBPrivateSetting()

            new_bbb_config.bbb_server = bbb_server_url
            new_bbb_config.bbb_secret = bbb_server_secret
            new_bbb_config.is_active = True if is_active == 'true' else False
            new_bbb_config.tenant_id = inst_id

            new_bbb_config.save()
        else:
            # found - update existing
            existing_bbb_config.bbb_server = bbb_server_url
            existing_bbb_config.bbb_secret = bbb_server_secret
            existing_bbb_config.is_active = True if is_active == 'true' else False
            existing_bbb_config.updated_at = datetime.now()

            existing_bbb_config.save()

        return api_response(code=200, msg=_('BBB configuration updated.'))
        