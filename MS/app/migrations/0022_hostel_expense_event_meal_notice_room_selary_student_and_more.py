# Generated by Django 5.0.6 on 2024-06-04 11:19

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0021_product_quantity_product_updated_time_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Hostel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('address', models.CharField(max_length=200)),
                ('phone', models.CharField(max_length=200)),
                ('email', models.EmailField(max_length=254)),
                ('website', models.URLField(blank=True, null=True)),
                ('logo', models.ImageField(blank=True, null=True, upload_to='hostel_logo/')),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='hostel_created_by', to=settings.AUTH_USER_MODEL)),
                ('manager_hostel', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='manager_hostel', to=settings.AUTH_USER_MODEL)),
                ('staffs', models.ManyToManyField(blank=True, related_name='hostel_staffs', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Expense',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('description', models.TextField()),
                ('amount', models.FloatField()),
                ('created_time', models.DateTimeField(auto_now_add=True)),
                ('updated_time', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='expense_created_by', to=settings.AUTH_USER_MODEL)),
                ('hostel', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.hostel')),
            ],
        ),
        migrations.CreateModel(
            name='Event',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('description', models.TextField()),
                ('date', models.DateField()),
                ('time', models.TimeField()),
                ('created_time', models.DateTimeField(auto_now_add=True)),
                ('updated_time', models.DateTimeField(auto_now=True)),
                ('hostel', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.hostel')),
            ],
        ),
        migrations.CreateModel(
            name='Meal',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('price', models.FloatField()),
                ('description', models.TextField(blank=True, null=True)),
                ('updated_time', models.DateTimeField(auto_now=True)),
                ('hostel', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.hostel')),
            ],
        ),
        migrations.CreateModel(
            name='Notice',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('description', models.TextField()),
                ('created_time', models.DateTimeField(auto_now_add=True)),
                ('updated_time', models.DateTimeField(auto_now=True)),
                ('hostel', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.hostel')),
            ],
        ),
        migrations.CreateModel(
            name='Room',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('number', models.IntegerField()),
                ('capacity', models.IntegerField()),
                ('status', models.BooleanField(default=True)),
                ('hostel', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.hostel')),
            ],
        ),
        migrations.CreateModel(
            name='Selary',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('amount', models.FloatField()),
                ('created_time', models.DateTimeField(auto_now_add=True)),
                ('updated_time', models.DateTimeField(auto_now=True)),
                ('hostel', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.hostel')),
                ('staff', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='staff', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Student',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('roll', models.CharField(max_length=200)),
                ('image', models.ImageField(blank=True, null=True, upload_to='student_image/')),
                ('created_time', models.DateTimeField(auto_now_add=True)),
                ('updated_time', models.DateTimeField(auto_now=True)),
                ('hostel', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.hostel')),
                ('room', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.room')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='student', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Payment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('total', models.FloatField()),
                ('payment_method', models.CharField(max_length=200)),
                ('paid', models.FloatField()),
                ('due', models.FloatField()),
                ('created_time', models.DateTimeField(auto_now_add=True)),
                ('updated_time', models.DateTimeField(auto_now=True)),
                ('student', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.student')),
            ],
        ),
        migrations.CreateModel(
            name='MealOrder',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('quantity', models.IntegerField()),
                ('total', models.FloatField()),
                ('created_time', models.DateTimeField(auto_now_add=True)),
                ('updated_time', models.DateTimeField(auto_now=True)),
                ('meal', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.meal')),
                ('student', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.student')),
            ],
        ),
        migrations.CreateModel(
            name='Complaint',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('description', models.TextField()),
                ('created_time', models.DateTimeField(auto_now_add=True)),
                ('updated_time', models.DateTimeField(auto_now=True)),
                ('student', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.student')),
            ],
        ),
        migrations.CreateModel(
            name='Visitor',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('phone', models.CharField(max_length=200)),
                ('address', models.CharField(max_length=200)),
                ('purpose', models.TextField()),
                ('in_time', models.DateTimeField(auto_now_add=True)),
                ('out_time', models.DateTimeField(auto_now=True)),
                ('hostel', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.hostel')),
            ],
        ),
    ]