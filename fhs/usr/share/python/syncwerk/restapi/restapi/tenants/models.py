# Copyright (c) 2012-2016 Seafile Ltd.
from django.db import models
from django.utils import timezone

from restapi.base.fields import LowerCaseCharField


class Tenant(models.Model):
    name = models.CharField(max_length=200)
    create_time = models.DateTimeField(default=timezone.now)


class TenantAdmin(models.Model):
    tenant = models.ForeignKey(Tenant)
    user = LowerCaseCharField(max_length=255, db_index=True)


class TenantQuotaManager(models.Manager):
    def get_or_none(self, *args, **kwargs):
        try:
            return self.get(*args, **kwargs).quota
        except self.model.DoesNotExist:
            return None


class TenantQuota(models.Model):
    tenant = models.ForeignKey(Tenant)
    quota = models.BigIntegerField()
    objects = TenantQuotaManager()
