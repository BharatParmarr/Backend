# Generated by Django 5.0.6 on 2024-06-18 19:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0013_alter_servicetable_ocupied'),
    ]

    operations = [
        migrations.AddField(
            model_name='service',
            name='aprox_time_max',
            field=models.IntegerField(default=30),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='service',
            name='aprox_time_min',
            field=models.IntegerField(default=30),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='service',
            name='discount',
            field=models.FloatField(default=0),
        ),
        migrations.AddField(
            model_name='service',
            name='rattings',
            field=models.FloatField(default=0),
        ),
        migrations.AddField(
            model_name='service',
            name='speciality',
            field=models.BooleanField(default=False),
        ),
    ]
