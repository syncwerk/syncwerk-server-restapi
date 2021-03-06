# -*- coding: utf-8 -*-
# Generated by Django 1.11.11 on 2018-03-21 08:42
from __future__ import unicode_literals

from django.db import migrations, models
import restapi.base.fields


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Contact',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_email', restapi.base.fields.LowerCaseCharField(db_index=True, max_length=255)),
                ('contact_email', restapi.base.fields.LowerCaseCharField(max_length=255)),
                ('contact_name', models.CharField(blank=True, default=b'', max_length=255, null=True)),
                ('note', models.CharField(blank=True, default=b'', max_length=255, null=True)),
            ],
        ),
    ]
