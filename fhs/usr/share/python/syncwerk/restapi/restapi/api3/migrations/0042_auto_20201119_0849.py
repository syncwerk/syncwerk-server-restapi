# -*- coding: utf-8 -*-
# Generated by Django 1.11.15 on 2020-11-19 08:49
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import restapi.api3.models
import restapi.base.fields


class Migration(migrations.Migration):

    dependencies = [
        ('api3', '0041_auto_20201022_1516'),
    ]

    operations = [
        migrations.CreateModel(
            name='EmailUser',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('email', restapi.base.fields.LowerCaseCharField(max_length=255)),
                ('passwd', models.CharField(max_length=256)),
                ('is_staff', models.BooleanField()),
                ('is_active', models.BooleanField()),
                ('language', restapi.base.fields.LowerCaseCharField(max_length=255)),
                ('ctime', models.BigIntegerField()),
                ('reference_id', models.CharField(max_length=255)),
            ],
            options={
                'db_table': 'EmailUser',
            },
        ),
        migrations.CreateModel(
            name='FileLocks',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('repo_id', restapi.base.fields.LowerCaseCharField(max_length=36)),
                ('path', models.CharField(max_length=512)),
                ('email', models.CharField(db_column=b'user_name', max_length=255)),
                ('lock_time', models.BigIntegerField()),
                ('expire', models.BigIntegerField(default=0)),
            ],
            options={
                'db_table': 'FileLocks',
            },
        ),
        migrations.CreateModel(
            name='FileLockTimestamp',
            fields=[
                ('repo_id', restapi.base.fields.LowerCaseCharField(max_length=36, primary_key=True, serialize=False)),
                ('update_time', models.BigIntegerField()),
            ],
            options={
                'db_table': 'FileLockTimestamp',
            },
        ),
        migrations.CreateModel(
            name='KanbanAttach',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('title', models.CharField(db_index=True, max_length=255)),
                ('image', models.FileField(blank=True, default=b'', upload_to=b'kanban_attach/')),
            ],
            options={
                'db_table': 'KanbanAttach',
            },
        ),
        migrations.CreateModel(
            name='KanbanMember',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('owner_id', models.CharField(max_length=255)),
                ('kanban_project', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='api3.KanbanProject')),
            ],
            options={
                'db_table': 'KanbanMember',
            },
        ),
        migrations.CreateModel(
            name='LDAPUsers',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('email', restapi.base.fields.LowerCaseCharField(max_length=255)),
                ('password', models.CharField(max_length=255)),
                ('is_staff', models.BooleanField()),
                ('is_active', models.BooleanField()),
                ('language', restapi.base.fields.LowerCaseCharField(max_length=255)),
                ('extra_attrs', models.TextField()),
                ('reference_id', models.CharField(max_length=255)),
            ],
            options={
                'db_table': 'LDAPUsers',
            },
        ),
        migrations.CreateModel(
            name='SharedRepo',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('repo_id', restapi.base.fields.LowerCaseCharField(max_length=36)),
                ('from_email', models.CharField(max_length=255)),
                ('to_email', models.CharField(max_length=255)),
                ('permission', models.CharField(max_length=255)),
                ('allow_view_history', models.BooleanField()),
                ('allow_view_snapshot', models.BooleanField()),
                ('allow_restore_snapshot', models.BooleanField()),
            ],
            options={
                'db_table': 'SharedRepo',
            },
        ),
        migrations.RenameField(
            model_name='kanbanboard',
            old_name='update_at',
            new_name='updated_at',
        ),
        migrations.RemoveField(
            model_name='kanbantask',
            name='attachments',
        ),
        migrations.RemoveField(
            model_name='kanbantask',
            name='color',
        ),
        migrations.RemoveField(
            model_name='kanbantask',
            name='comments',
        ),
        migrations.RemoveField(
            model_name='kanbantask',
            name='history',
        ),
        migrations.RemoveField(
            model_name='kanbantask',
            name='tasks',
        ),
        migrations.RemoveField(
            model_name='monthlyusertraffic',
            name='commit_id',
        ),
        migrations.AddField(
            model_name='kanbancomment',
            name='kanban_task',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='api3.KanbanTask'),
        ),
        migrations.AddField(
            model_name='kanbanhistory',
            name='kanban_task',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='api3.KanbanTask'),
        ),
        migrations.AddField(
            model_name='kanbansubtask',
            name='completed',
            field=models.BooleanField(default=False),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='kanbansubtask',
            name='kanban_task',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='api3.KanbanTask'),
        ),
        migrations.AddField(
            model_name='kanbantask',
            name='completed',
            field=models.BooleanField(default=False),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='kanbantask',
            name='task_color',
            field=models.ManyToManyField(blank=True, related_name='task_color', to='api3.KanbanColor'),
        ),
        migrations.AddField(
            model_name='virusscanninginfectedfile',
            name='commit_id',
            field=models.CharField(default='', max_length=255),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='emailchangingrequest',
            name='request_token',
            field=models.CharField(default='', max_length=64),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='emailchangingrequest',
            name='request_token_expire_time',
            field=models.DateTimeField(default=restapi.api3.models.one_hour_hence),
        ),
        migrations.AlterField(
            model_name='kanbantask',
            name='created_at',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AlterField(
            model_name='kanbantask',
            name='updated_at',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AlterField(
            model_name='monthlyusertraffic',
            name='link_file_download',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='monthlyusertraffic',
            name='link_file_upload',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='monthlyusertraffic',
            name='sync_file_download',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='monthlyusertraffic',
            name='sync_file_upload',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='monthlyusertraffic',
            name='web_file_download',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='monthlyusertraffic',
            name='web_file_upload',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AlterUniqueTogether(
            name='tokenv2',
            unique_together=set([('user', 'platform', 'device_id')]),
        ),
        migrations.AlterModelTable(
            name='token',
            table=None,
        ),
        migrations.AlterModelTable(
            name='tokenv2',
            table=None,
        ),
        migrations.DeleteModel(
            name='KanbanAttachment',
        ),
        migrations.AddField(
            model_name='kanbanattach',
            name='kanban_task',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='api3.KanbanTask'),
        ),
        migrations.AlterUniqueTogether(
            name='filelocks',
            unique_together=set([('repo_id', 'path')]),
        ),
    ]
