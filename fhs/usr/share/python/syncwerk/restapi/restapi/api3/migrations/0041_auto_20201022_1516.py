# -*- coding: utf-8 -*-
# Generated by Django 1.11.15 on 2020-10-22 15:16
from __future__ import unicode_literals

import datetime
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('api3', '0040_auto_20201022_1427'),
    ]

    operations = [
        migrations.CreateModel(
            name='KanbanAttachment',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('title', models.CharField(db_index=True, max_length=255)),
                ('image', models.ImageField(blank=True, default=b'', upload_to=b'kanban_attach/')),
            ],
            options={
                'db_table': 'KanbanAttachement',
            },
        ),
        migrations.CreateModel(
            name='KanbanColor',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('title', models.CharField(db_index=True, max_length=255)),
                ('color', models.CharField(db_index=True, max_length=255)),
            ],
            options={
                'db_table': 'KanbanColor',
            },
        ),
        migrations.CreateModel(
            name='KanbanComment',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('comment', models.CharField(db_index=True, max_length=255)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('owner_id', models.CharField(max_length=255)),
            ],
            options={
                'db_table': 'KanbanComment',
            },
        ),
        migrations.CreateModel(
            name='KanbanHistory',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('audit', models.CharField(db_index=True, max_length=255)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('owner_id', models.CharField(max_length=255)),
            ],
            options={
                'db_table': 'KanbanHistory',
            },
        ),
        migrations.CreateModel(
            name='KanbanTag',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('title', models.CharField(db_index=True, max_length=255)),
            ],
            options={
                'db_table': 'KanbanTag',
            },
        ),
        migrations.CreateModel(
            name='KanbanUser',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('owner_id', models.CharField(max_length=255)),
            ],
            options={
                'db_table': 'KanbanUser',
            },
        ),
        migrations.AlterField(
            model_name='kanbanproject',
            name='image',
            field=models.ImageField(blank=True, default=b'', upload_to=b'kanban_project/'),
        ),
        migrations.AlterModelTable(
            name='kanbansubtask',
            table='KanbanSubTask',
        ),
        migrations.AddField(
            model_name='kanbanproject',
            name='owners',
            field=models.ManyToManyField(blank=True, related_name='owners', to='api3.KanbanUser'),
        ),
        migrations.AddField(
            model_name='kanbantask',
            name='attachments',
            field=models.ManyToManyField(blank=True, related_name='attachments', to='api3.KanbanAttachment'),
        ),
        migrations.AddField(
            model_name='kanbantask',
            name='color',
            field=models.OneToOneField(blank=True, default='', on_delete=django.db.models.deletion.CASCADE, related_name='colors', to='api3.KanbanColor'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='kanbantask',
            name='comments',
            field=models.ManyToManyField(blank=True, related_name='comments', to='api3.KanbanComment'),
        ),
        migrations.AddField(
            model_name='kanbantask',
            name='history',
            field=models.ManyToManyField(blank=True, related_name='history', to='api3.KanbanHistory'),
        ),
        migrations.AddField(
            model_name='kanbantask',
            name='tags',
            field=models.ManyToManyField(blank=True, related_name='tags', to='api3.KanbanTag'),
        ),
    ]
