# -*- coding: utf-8 -*-
# Generated by Django 1.11.15 on 2020-07-14 08:08
from __future__ import unicode_literals

import datetime
from django.db import migrations, models
import django.utils.timezone
import restapi.base.fields


class Migration(migrations.Migration):

    dependencies = [
        ('api3', '0027_add_profile_setting_with_max_meetings'),
    ]

    operations = [
        migrations.AddField(
            model_name='meetingroom',
            name='presentation_file',
            field=models.TextField(blank=True, null=True),
        ),
    ]
