# Generated by Django 5.0.6 on 2024-06-06 10:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0024_payment_payment_for'),
    ]

    operations = [
        migrations.AlterField(
            model_name='meal',
            name='price',
            field=models.FloatField(blank=True, null=True),
        ),
    ]
