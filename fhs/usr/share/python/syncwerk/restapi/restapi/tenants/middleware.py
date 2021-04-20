# Copyright (c) 2012-2016 Seafile Ltd.
from django.conf import settings

from restapi.tenants.models import TenantAdmin


class TenantMiddleware(object):
    def process_request(self, request):
        if not getattr(settings, 'MULTI_INSTITUTION', False):
            return None

        username = request.user.username

        # todo: record to session to avoid database query

        try:
            inst_admin = TenantAdmin.objects.get(user=username)
        except TenantAdmin.DoesNotExist:
            return None

        request.user.tenant = inst_admin.tenant
        request.user.inst_admin = True
        return None
