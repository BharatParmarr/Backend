# Generated by Django 5.0.6 on 2024-06-14 18:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0006_alter_subscriptionbuyer_subscription_time'),
    ]

    operations = [
        migrations.AddField(
            model_name='subscription_code',
            name='total_days',
            field=models.IntegerField(default=28),
            preserve_default=False,
        ),
    ]
