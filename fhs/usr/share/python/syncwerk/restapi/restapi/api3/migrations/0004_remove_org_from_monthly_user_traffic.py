from __future__ import unicode_literals

from django.db import migrations, models
import restapi.base.fields

class Migration(migrations.Migration):

    dependencies = [
        ('api3', '0003_add_virus_scanning_tables'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='monthlyusertraffic',
            name='org_id',
        ),
    ]
