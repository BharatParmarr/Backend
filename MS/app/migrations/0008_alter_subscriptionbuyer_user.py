# Generated by Django 5.0.6 on 2024-06-14 19:47

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0007_subscription_code_total_days'),
    ]

    operations = [
        migrations.AlterField(
            model_name='subscriptionbuyer',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
