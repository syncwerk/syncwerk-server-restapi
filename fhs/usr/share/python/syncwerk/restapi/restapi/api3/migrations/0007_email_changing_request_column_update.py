from __future__ import unicode_literals

from django.db import migrations, models
from django.utils import timezone
import restapi.base.fields

class Migration(migrations.Migration):

    dependencies = [
        ('api3', '0006_add_email_changing_request_table'),
    ]

    operations = [
        migrations.AlterField(
            model_name='EmailChangingRequest',
            name='request_token',
            field=models.CharField(max_length=64, blank=True, null=True)
        ),
        migrations.AlterField(
            model_name='EmailChangingRequest',
            name='request_token_expire_time',
            field=models.CharField(max_length=64, blank=True, null=True)
        ),
    ]
