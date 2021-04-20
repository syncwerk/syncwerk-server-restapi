from __future__ import unicode_literals

from django.db import migrations, models
import django.utils.timezone
import restapi.base.fields

class Migration(migrations.Migration):

    dependencies = [
        ('api3', '0004_remove_org_from_monthly_user_traffic'),
    ]

    operations = [
        migrations.AddField(
            model_name='MonthlyUserTraffic',
            name='commit_id',
            field=models.CharField(max_length=256),
        ),
        migrations.AddField(
            model_name='VirusScanningInfectedFile',
            name='detected_at',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
    ]
