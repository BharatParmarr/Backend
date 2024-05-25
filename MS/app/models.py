import os
import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.utils.translation import gettext_lazy as _
# Create your models here.
# user
from django.contrib.auth.models import User as AuthUser


def Profile_image_name(instance, filename):
    extension = os.path.splitext(filename)[1]  # Get the file extension
    random_string = str(uuid.uuid4())
    return 'user_image/' + random_string + extension


class User(AbstractUser):
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=200)
    address = models.CharField(max_length=200)
    image = models.ImageField(
        upload_to=Profile_image_name, null=True, blank=True)
    # profile = models.OneToOneField(
    #     Profile, on_delete=models.CASCADE, null=True, blank=True, related_name='user')
    groups = models.ManyToManyField(
        Group,
        verbose_name=_('groups'),
        blank=True,
        help_text=_(
            'The groups this user belongs to. A user will get all permissions '
            'granted to each of their groups.'
        ),
        related_name="custom_user_set",
        related_query_name="user",
    )

    user_permissions = models.ManyToManyField(
        Permission,
        verbose_name=_('user permissions'),
        blank=True,
        help_text=_('Specific permissions for this user.'),
        related_name="custom_user_set",
        related_query_name="user",
    )

    def __str__(self):
        return self.username

# restorant management system


class Profile(models.Model):
    user = models.OneToOneField(
        AuthUser, on_delete=models.CASCADE, related_name='profile')
    otp = models.IntegerField()
    otp_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username


def restorant_logo_name(instance, filename):
    random_string = str(uuid.uuid4())
    extension = os.path.splitext(filename)[1]  # Get the file extension
    return 'restorant_logo/' + random_string + extension


class Restorant(models.Model):
    name = models.CharField(max_length=200)
    address = models.CharField(max_length=200)
    phone = models.CharField(max_length=200)
    email = models.EmailField()
    website = models.URLField(null=True, blank=True)
    logo = models.ImageField(
        upload_to='restorant_logo/', null=True, blank=True)
    created_by = models.ForeignKey(
        AuthUser, on_delete=models.CASCADE, related_name='created_by')
    manager_restorant = models.ForeignKey(
        AuthUser, on_delete=models.CASCADE, related_name='manager_restorant', null=True, blank=True)
    staffs = models.ManyToManyField(
        AuthUser, related_name='staffs', blank=True)

    def __str__(self):
        return self.name


class Table(models.Model):
    restorant = models.ForeignKey(Restorant, on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    numebr = models.IntegerField()
    capacity = models.IntegerField()
    status = models.BooleanField(default=True)

    def __str__(self):
        return self.name


class Category(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField()
    restorant = models.ForeignKey(Restorant, on_delete=models.CASCADE)

    def __str__(self):
        return self.name


def Item_image_name(instance, filename):
    extension = os.path.splitext(filename)[1]  # Get the file extension
    random_string = str(uuid.uuid4())
    return 'item_image/' + random_string + extension


class Item(models.Model):
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    description = models.TextField()
    price = models.FloatField()
    image = models.ImageField(upload_to='item_image/')

    def __str__(self):
        return self.name


class Order(models.Model):
    table = models.ForeignKey(Table, on_delete=models.CASCADE)
    status = models.BooleanField(default=False)
    order_time = models.DateTimeField(auto_now_add=True)
    order_number = models.IntegerField()

    def __str__(self):
        return self.table.name


class OrderDetail(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    quantity = models.IntegerField()
    price = models.FloatField()
    total = models.FloatField()
    is_completed = models.BooleanField(default=False)

    def __str__(self):
        return self.item.name
