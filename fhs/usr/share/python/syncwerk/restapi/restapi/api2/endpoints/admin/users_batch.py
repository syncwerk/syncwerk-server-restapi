# Copyright (c) 2012-2016 Seafile Ltd.

import logging
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from django.utils.translation import ugettext as _

from synserv import syncwerk_api

from restapi.api2.authentication import TokenAuthentication
from restapi.api2.throttling import UserRateThrottle
from restapi.api2.utils import api_error

from restapi.base.accounts import User
from restapi.profile.models import Profile
from restapi.tenants.models import Tenant
from restapi.utils.file_size import get_file_size_unit
from restapi.admin_log.models import USER_DELETE
from restapi.admin_log.signals import admin_operation

logger = logging.getLogger(__name__)


class AdminUsersBatch(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)

    def post(self, request):
        """ Set user quota, set user tenant, delete users, in batch.

        Permission checking:
        1. admin user.
        """

        # argument check
        emails = request.POST.getlist('email', None)
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

        return Response(result)
