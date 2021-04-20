# Copyright (c) 2012-2016 Seafile Ltd.

import logging
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from django.utils.translation import ugettext as _

from synserv import syncwerk_api

from restapi.api3.authentication import TokenAuthentication
from restapi.api3.throttling import UserRateThrottle
# from restapi.api2.utils import api_error
from restapi.api3.utils import api_response, api_error

from restapi.base.accounts import User
from restapi.profile.models import Profile
from restapi.tenants.models import Tenant
from restapi.utils.file_size import get_file_size_unit
from restapi.admin_log.models import USER_DELETE
from restapi.admin_log.signals import admin_operation
from restapi.share.models import FileShare, UploadLinkShare

logger = logging.getLogger(__name__)

from rest_framework import parsers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from restapi.api3.swagger_auto_schemas import XcodeAutoSchema

class AdminUsersBatch(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, )

    @swagger_auto_schema(
        auto_schema=XcodeAutoSchema,
        operation_summary='Admin - User batch operations',
        operation_description='''Set user quota, set user tenant, delete users, in batch.''',
        tags=['admin-users'],
        manual_parameters=[
            openapi.Parameter(
                name='operation',
                in_="formData",
                type='string',
                description='"set-quota", "delete-user" or "set-tenant" ',
                enum=['set-quota', 'delete-user', 'set-tenant'],
                required=True,
            ),
            openapi.Parameter(
                name='emails',
                in_="formData",
                type='string',
                description='email of the user for the operation. Specify multiple of this for apply operation to multiple users at once.',
            ),
            openapi.Parameter(
                name='quota_total',
                in_="formData",
                type='string',
                description='if operation is "set-quota", this will be the quota in MB',
            ),
            openapi.Parameter(
                name='tenant',
                in_="formData",
                type='string',
                description='if operation is "set-tenant", this will be the tenant id',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Operation completed successfully',
                examples={
                    'application/json': {
                        "message": "Operation completed successfully",
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
    def post(self, request):
        # argument check
        emails = request.POST.getlist('emails', None)
        if not emails:
            error_msg = 'email invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        operation = request.POST.get('operation', None)
        if operation not in ('set-quota', 'delete-user', 'set-tenant'):
            error_msg = "operation can only be 'set-quota', 'delete-user', or 'set-tenant'."
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        result = {}
        result['failed'] = []
        result['success'] = []

        existed_users = []
        for email in emails:
            try:
                user = User.objects.get(email=email)
                existed_users.append(user)
            except User.DoesNotExist:
                result['failed'].append({
                    'email': email,
                    'error_msg': 'User %s not found.' % email
                    })
                continue

        if operation == 'set-quota':
            quota_total_mb = request.POST.get('quota_total', None)
            if not quota_total_mb:
                error_msg = 'quota_total invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            try:
                quota_total_mb = int(quota_total_mb)
            except ValueError:
                error_msg = _('must be an integer that is greater than or equal to 0.')
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            if quota_total_mb < 0:
                error_msg = _('Space quota is too low (minimum value is 0)')
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            quota_total_byte = quota_total_mb * get_file_size_unit('MB')

            for user in existed_users:
                email = user.email
                try:
                    syncwerk_api.set_user_quota(email, quota_total_byte)
                except Exception as e:
                    logger.error(e)
                    result['failed'].append({
                        'email': email,
                        'error_msg': 'Internal Server Error'
                        })
                    continue

                result['success'].append({
                    'email': email,
                    'quota_total': syncwerk_api.get_user_quota(email),
                })

        if operation == 'delete-user':
            for user in existed_users:
                email = user.email
                try:
                    user.delete()
                    # Remove link public share from share_fileshare
                    FileShare.objects.filter(username=email).delete()

                    # Remove link public share from share_uploadlinkshare
                    UploadLinkShare.objects.filter(username=email).delete()
                except Exception as e:
                    logger.error(e)
                    result['failed'].append({
                        'email': email,
                        'error_msg': 'Internal Server Error'
                        })
                    continue

                result['success'].append({
                    'email': email,
                })

                # send admin operation log signal
                admin_op_detail = {
                    "email": email,
                }
                admin_operation.send(sender=None, admin_name=request.user.username,
                        operation=USER_DELETE, detail=admin_op_detail)

        if operation == 'set-tenant':
            tenant = request.POST.get('tenant', None)
            if tenant is None:
                error_msg = 'Tenant can not be blank.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            if tenant != '':
                try:
                    obj_insti = Tenant.objects.get(name=tenant)
                except Tenant.DoesNotExist:
                    error_msg = 'Tenant %s does not exist' % tenant
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            for user in existed_users:
                email = user.email
                profile = Profile.objects.get_profile_by_user(email)
                if profile is None:
                    profile = Profile(user=email)
                profile.tenant = tenant
                profile.save()
                result['success'].append({
                    'email': email,
                    'tenant': tenant
                })

        return api_response(msg=_("Operation completed successfully"), data=result)
