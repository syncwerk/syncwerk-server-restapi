# -*- coding: utf-8 -*-
# Generated by Django 1.11.15 on 2020-03-13 08:20
from __future__ import unicode_literals

import datetime
from django.db import migrations, models
import django.utils.timezone
import restapi.base.fields


class Migration(migrations.Migration):

    dependencies = [
        ('api3', '0013_auto_20200313_0650'),
    ]

    operations = [
        
        migrations.AddField(
            model_name='auditlog',
            name='folder_id',
            field=models.TextField(blank=True, null=True),
        ),

    ]