# Generated by Django 5.0.6 on 2024-05-23 19:47

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0012_table_numebr'),
    ]

    operations = [
        migrations.AddField(
            model_name='category',
            name='restorant',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='app.restorant'),
            preserve_default=False,
        ),
    ]