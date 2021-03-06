# -*- coding: utf-8 -*-
# Generated by Django 1.11.11 on 2018-03-21 08:43
from __future__ import unicode_literals

import datetime
from django.db import migrations, models
import restapi.base.fields


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('message', models.CharField(max_length=512)),
                ('primary', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='UserNotification',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('to_user', restapi.base.fields.LowerCaseCharField(db_index=True, max_length=255)),
                ('msg_type', models.CharField(db_index=True, max_length=30)),
                ('detail', models.TextField()),
                ('timestamp', models.DateTimeField(default=datetime.datetime.now)),
                ('seen', models.BooleanField(default=False, verbose_name=b'seen')),
            ],
            options={
                'ordering': ['-timestamp'],
            },
        ),
    ]
