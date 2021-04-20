from __future__ import unicode_literals

import datetime
from django.db import migrations, models
from django.utils import timezone
import django.utils.timezone
import restapi.base.fields

class Migration(migrations.Migration):

    dependencies = [
        ('api3', '0005_add_columns_to_virus_scanning_infected_files'),
    ]

    operations = [
        migrations.CreateModel(
            name='EmailChangingRequest',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('user_id', models.CharField(max_length=255)),
                ('new_email', models.CharField(max_length=255)),
                ('request_token', models.CharField(max_length=64)),
                ('request_token_expire_time', models.DateTimeField(default=datetime.datetime(2020, 10, 22, 12, 50, 24, 448897))),
                ('new_email_confirmed', models.BooleanField(default=False)),
                ('request_completed', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={
                'db_table': 'EmailChangingRequest',
                'managed': True,
            },
        ),
    ]
