# -*- coding: utf-8 -*-
# Generated by Django 1.11.15 on 2021-02-16 08:05
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api3', '0048_meetingroom_live_stream_active'),
    ]

    operations = [
        migrations.AddField(
            model_name='bbbprivatesetting',
            name='live_stream_token',
            field=models.CharField(default='', max_length=255),
            preserve_default=False,
        ),
    ]