# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import restapi.base.fields


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Invitation',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('token', models.CharField(max_length=40)),
                ('inviter', restapi.base.fields.LowerCaseCharField(max_length=255, db_index=True)),
                ('acceptor', restapi.base.fields.LowerCaseCharField(max_length=255)),
                ('invite_time', models.DateTimeField(auto_now_add=True)),
                ('accept_time', models.DateTimeField(null=True, blank=True)),
            ],
        ),
    ]
