# -*- coding: utf-8 -*-
# Generated by Django 1.11.15 on 2020-10-22 14:15
from __future__ import unicode_literals

import datetime
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api3', '0038_auto_20201022_1402'),
    ]

    operations = [
        migrations.CreateModel(
            name='KanbanTask',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('title', models.CharField(db_index=True, max_length=255)),
                ('description', models.TextField(blank=True, max_length=255)),
                ('due_date', models.DateTimeField()),
                ('assignee_id', models.CharField(max_length=255)),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('kanban_board', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api3.KanbanBoard')),
            ],
            options={
                'db_table': 'KanbanTask',
            },
        ),
    ]
