# -*- coding: utf-8 -*-
# Generated by Django 1.11.15 on 2020-06-04 09:53
from __future__ import unicode_literals

import datetime
from django.db import migrations, models
import django.utils.timezone
import restapi.base.fields


class Migration(migrations.Migration):

    dependencies = [
        ('api3', '0023_add_share_to_group_columns_to_meeting_private_share'),
    ]

    operations = [
        migrations.AddField(
            model_name='MeetingRoom',
            name='private_setting_id',
            field=models.IntegerField(default=-1)
        ),
    ]