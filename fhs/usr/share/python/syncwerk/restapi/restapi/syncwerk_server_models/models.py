import uuid
import hmac
import datetime
from hashlib import sha1

from django.db import models
from django.utils import timezone

from restapi.base.fields import LowerCaseCharField

DESKTOP_PLATFORMS = ('windows', 'linux', 'mac')
MOBILE_PLATFORMS = ('ios', 'android')

class FolderBranch(models.Model):
    name = models.CharField(max_length=1024)
    repo_id = LowerCaseCharField(max_length=36, primary_key=True)
    commit_id = LowerCaseCharField(max_length=256)

    class Meta:
        db_table = "Branch"
        app_label = 'syncwerk_server_models'

class FileLocks(models.Model):
    id = models.AutoField(primary_key=True)
    repo_id = LowerCaseCharField(max_length=36)
    path = models.CharField(max_length=1024)
    email = models.CharField(max_length=255, db_column='user_name')
    lock_time = models.BigIntegerField()
    expire = models.BigIntegerField(default=0)

    class Meta:
        db_table = "FileLocks"
        app_label = 'syncwerk_server_models'

class FileLockTimestamp(models.Model):
    repo_id = LowerCaseCharField(max_length=36, primary_key=True)
    update_time = models.BigIntegerField()

    class Meta:
        db_table = "FileLockTimestamp"
        app_label = 'syncwerk_server_models'

