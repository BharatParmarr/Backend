# Generated by Django 5.0.6 on 2024-06-15 08:40

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0008_alter_subscriptionbuyer_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='subscriptionbuyer',
            name='subscription_start_time',
            field=models.DateTimeField(default=datetime.datetime(2024, 6, 15, 14, 10, 29, 835323)),
        ),
    ]