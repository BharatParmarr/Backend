# Generated by Django 5.0.6 on 2024-06-24 17:32

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0016_restorant_close_time_restorant_open_time_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='RestorantOpenClose',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('day', models.CharField(max_length=20)),
                ('is_open', models.BooleanField(default=True)),
                ('open_time', models.TimeField()),
                ('close_time', models.TimeField()),
                ('status', models.BooleanField(default=True)),
                ('updated_time', models.DateTimeField(auto_now=True)),
                ('restorant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.restorant')),
            ],
        ),
    ]