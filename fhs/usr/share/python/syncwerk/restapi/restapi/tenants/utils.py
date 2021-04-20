# Copyright (c) 2012-2016 Seafile Ltd.
from synserv import syncwerk_api
from restapi.profile.models import Profile
from restapi.tenants.models import TenantQuota


def get_tenant_space_usage(inst):
    # TODO: need to refactor
    usernames = [x.user for x in Profile.objects.filter(tenant=inst.name)]
    total = 0
    for user in usernames:
        total += syncwerk_api.get_user_self_usage(user)
    return total

def get_tenant_available_quota(inst):
    inst_quota = TenantQuota.objects.get_or_none(tenant=inst)
    if inst_quota is None:
        return None

    usernames = [x.user for x in Profile.objects.filter(tenant=inst.name)]
    allocated = 0
    for user in usernames:
        allocated += syncwerk_api.get_user_quota(user)

    return 0 if allocated >= inst_quota else inst_quota - allocated
