from django.db import models
from django.utils import timezone

from restapi.base.fields import LowerCaseCharField

class UserRole(models.Model):
    id = models.AutoField(primary_key=True)
    email = models.CharField(max_length=255)
    role = models.CharField(max_length=255)

    class Meta:
        db_table = "UserRole"
        app_label = 'syncwerk_ccnet_models'
        managed = False