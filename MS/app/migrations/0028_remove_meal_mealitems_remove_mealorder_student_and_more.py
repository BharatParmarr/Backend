# Generated by Django 5.0.6 on 2024-06-06 12:44

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0027_meal_mealitems'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='meal',
            name='mealItems',
        ),
        migrations.RemoveField(
            model_name='mealorder',
            name='student',
        ),
        migrations.AddField(
            model_name='mealorder',
            name='hostel',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='app.hostel'),
            preserve_default=False,
        ),
    ]