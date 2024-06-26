from datetime import datetime
import os
import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.utils.translation import gettext_lazy as _
# Create your models here.
# user


def Profile_image_name(instance, filename):
    extension = os.path.splitext(filename)[1]  # Get the file extension
    random_string = str(uuid.uuid4())
    return 'user_image/' + random_string + extension


class User(AbstractUser):
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=200, null=True, blank=True)
    address = models.CharField(max_length=200, null=True, blank=True)
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


class SubscriptionBuyer(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    options = (
        ('free', 'Free'),
        ('premium', 'Premium'),
        ('enterprise', 'Enterprise'),
    )
    type = models.CharField(max_length=20, choices=options, default='free')
    subscription = models.BooleanField(default=False)
    created_time = models.DateTimeField(auto_now_add=True)
    subscription_start_time = models.DateTimeField()
    subscription_time = models.DateTimeField()

    def __str__(self):
        return self.user.username


class Subscription_code(models.Model):
    code = models.CharField(max_length=20, unique=True)
    options = (
        ('free', 'Free'),
        ('premium', 'Premium'),
        ('enterprise', 'Enterprise'),
    )
    type_of_subscription = models.CharField(
        max_length=20, choices=options, default='free')
    created_time = models.DateTimeField(auto_now_add=True)
    subscription_time = models.DateTimeField(null=True, blank=True)
    total_days = models.IntegerField()
    useg_limit = models.IntegerField(default=1)

    def __str__(self):
        return self.code


class Subscribers(models.Model):
    email = models.EmailField(unique=True)
    created_time = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.email

# restorant management system


class Profile(models.Model):
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='profile')
    otp = models.IntegerField()
    otp_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username


def restorant_logo_name(instance, filename):
    random_string = str(uuid.uuid4())
    extension = os.path.splitext(filename)[1]  # Get the file extension
    return 'restorant_logo/' + random_string + extension


class Restorant(models.Model):
    name = models.CharField(max_length=200, unique=True)
    address = models.CharField(max_length=200)
    phone = models.CharField(max_length=200)
    email = models.EmailField()
    website = models.URLField(null=True, blank=True)
    logo = models.ImageField(
        upload_to='restorant_logo/', null=True, blank=True)
    created_by = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='created_by')
    manager_restorant = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='manager_restorant', null=True, blank=True)
    staffs = models.ManyToManyField(
        User, related_name='staffs', blank=True)
    active = models.BooleanField(default=True)
    open_time = models.TimeField(null=True, blank=True)
    close_time = models.TimeField(null=True, blank=True)

    def __str__(self):
        return self.name


class RestorantOpenClose(models.Model):
    restorant = models.ForeignKey(Restorant, on_delete=models.CASCADE)
    day = models.CharField(max_length=20)
    is_open = models.BooleanField(default=True)
    open_time = models.TimeField()
    close_time = models.TimeField()
    status = models.BooleanField(default=True)
    updated_time = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.restorant.name


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
    active = models.BooleanField(default=False)

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
    image = models.ImageField(upload_to='item_image/', null=True, blank=True)
    veg = models.BooleanField(default=True)
    active = models.BooleanField(default=False)

    def __str__(self):
        return self.name


class Order(models.Model):
    table = models.ForeignKey(Table, on_delete=models.CASCADE)
    status = models.BooleanField(default=False)
    order_time = models.DateTimeField(auto_now_add=True)
    order_number = models.IntegerField()
    completed_time = models.DateTimeField(auto_now=True)
    order_ip_address = models.GenericIPAddressField(null=True, blank=True)
    order_key = models.CharField(max_length=200, null=True, blank=True)
    order_by = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='order_by', null=True, blank=True)

    def __str__(self):
        return self.table.name


class OrderDetail(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    quantity = models.IntegerField()
    price = models.FloatField()
    total = models.FloatField()
    is_completed = models.BooleanField(default=False)
    created_time = models.DateTimeField(auto_now_add=True)
    completed_time = models.DateTimeField(
        auto_now=True)

    def __str__(self):
        return self.item.name


# class Payment(models.Model):
#     order = models.ForeignKey(Order, on_delete=models.CASCADE)
#     total = models.FloatField()
#     payment_method = models.CharField(max_length=200)
#     paid = models.FloatField()
#     due = models.FloatField()
#     created_time = models.DateTimeField(auto_now_add=True)
#     completed_time = models.DateTimeField(auto_now=True)

#     def __str__(self):
#         return self.order.table.name'
def product_image_name(instance, filename):
    extension = os.path.splitext(filename)[1]  # Get the file extension
    random_string = str(uuid.uuid4())
    return 'product_image/' + random_string + extension


class Product(models.Model):
    restorant = models.ForeignKey(Restorant, on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    price = models.FloatField()
    description = models.TextField(null=True, blank=True)
    quantity = models.IntegerField(default=0)
    image = models.ImageField(
        upload_to=product_image_name, null=True, blank=True)
    updated_time = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class Inventory(models.Model):
    restorant = models.ForeignKey(Restorant, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.IntegerField()
    created_time = models.DateTimeField(auto_now_add=True)
    updated_time = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.item.name

#
#
#
# models for Hostel + Mess Management System


class Hostel(models.Model):
    name = models.CharField(max_length=200, unique=True)
    address = models.CharField(max_length=200)
    phone = models.CharField(max_length=200)
    email = models.EmailField()
    website = models.URLField(null=True, blank=True)
    logo = models.ImageField(
        upload_to='hostel_logo/', null=True, blank=True)
    created_by = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='hostel_created_by')
    manager_hostel = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='manager_hostel', null=True, blank=True)
    staffs = models.ManyToManyField(
        User, related_name='hostel_staffs', blank=True)

    def __str__(self):
        return self.name


class Room(models.Model):
    hostel = models.ForeignKey(Hostel, on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    number = models.IntegerField()
    capacity = models.IntegerField()
    status = models.BooleanField(default=True)

    def __str__(self):
        return self.name


def student_image_name(instance, filename):
    extension = os.path.splitext(filename)[1]  # Get the file extension
    random_string = str(uuid.uuid4())
    return 'student_image/' + random_string + extension


class Student(models.Model):
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='student')
    roll = models.CharField(max_length=200)
    room = models.ForeignKey(Room, on_delete=models.CASCADE)
    hostel = models.ForeignKey(Hostel, on_delete=models.CASCADE)
    image = models.ImageField(
        upload_to=student_image_name, null=True, blank=True)
    created_time = models.DateTimeField(auto_now_add=True)
    updated_time = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user.username


class Meal(models.Model):
    hostel = models.ForeignKey(Hostel, on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    price = models.FloatField(null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    MealTime = models.CharField(max_length=200)
    updated_time = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class MealItem(models.Model):
    hostel = models.ForeignKey(Hostel, on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    price = models.FloatField()
    description = models.TextField(null=True, blank=True)
    updated_time = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class MealOrder(models.Model):
    # student = models.ForeignKey(Student, on_delete=models.CASCADE)
    hostel = models.ForeignKey(Hostel, on_delete=models.CASCADE)
    meal = models.ForeignKey(Meal, on_delete=models.CASCADE)
    meal_item = models.ForeignKey(MealItem, on_delete=models.CASCADE)
    unlimited = models.BooleanField(default=True)
    quantity = models.IntegerField()
    # total = models.FloatField()
    created_time = models.DateTimeField(auto_now_add=True)
    updated_time = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.student.user.username


class Payment(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    total = models.FloatField()
    payment_method = models.CharField(max_length=200)
    paid = models.FloatField()
    due = models.FloatField()
    created_time = models.DateTimeField(auto_now_add=True)
    updated_time = models.DateTimeField(auto_now=True)
    payment_for = models.DateField(blank=True, null=True)

    def __str__(self):
        return self.student.user.username


class Visitor(models.Model):
    name = models.CharField(max_length=200)
    phone = models.CharField(max_length=200)
    address = models.CharField(max_length=200)
    hostel = models.ForeignKey(Hostel, on_delete=models.CASCADE)
    purpose = models.TextField()
    in_time = models.DateTimeField(auto_now_add=True)
    out_time = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class Complaint(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    description = models.TextField()
    created_time = models.DateTimeField(auto_now_add=True)
    updated_time = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class Notice(models.Model):
    hostel = models.ForeignKey(Hostel, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    description = models.TextField()
    created_time = models.DateTimeField(auto_now_add=True)
    updated_time = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class Event(models.Model):
    hostel = models.ForeignKey(Hostel, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    description = models.TextField()
    date = models.DateField()
    time = models.TimeField()
    created_time = models.DateTimeField(auto_now_add=True)
    updated_time = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class Expense(models.Model):
    hostel = models.ForeignKey(Hostel, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    description = models.TextField()
    amount = models.FloatField()
    created_by = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='expense_created_by')
    created_time = models.DateTimeField(auto_now_add=True)
    updated_time = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class Selary(models.Model):
    hostel = models.ForeignKey(Hostel, on_delete=models.CASCADE)
    staff = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='staff')
    amount = models.FloatField()
    created_time = models.DateTimeField(auto_now_add=True)
    updated_time = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.staff.username


# block ip address
class BlockIP(models.Model):
    ip = models.GenericIPAddressField(blank=True, null=True)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, null=True, blank=True)
    key = models.CharField(max_length=200, null=True, blank=True)
    reason = models.TextField()
    restorant = models.ForeignKey(
        Restorant, on_delete=models.CASCADE, null=True, blank=True)
    hostel = models.ForeignKey(
        Hostel, on_delete=models.CASCADE, null=True, blank=True)
    created_time = models.DateTimeField(auto_now_add=True)
    updated_time = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.ip


# service management system models ########################################
def Service_shop_logo_name(instance, filename):
    extension = os.path.splitext(filename)[1]  # Get the file extension
    random_string = str(uuid.uuid4())
    return 'service_shop_logo/' + random_string + extension


class ServiceShop(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField(null=True, blank=True)
    address = models.CharField(max_length=200, null=True, blank=True)
    phone = models.CharField(max_length=200, null=True, blank=True)
    email = models.EmailField(null=True, blank=True)
    website = models.URLField(null=True, blank=True)
    created_by = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='service_created_by')
    staffs = models.ManyToManyField(
        User, related_name='service_staffs', blank=True)
    manager_service = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='manager_service', null=True, blank=True)
    active = models.BooleanField(default=True)
    logo = models.ImageField(
        upload_to=Service_shop_logo_name, null=True, blank=True)
    open_time = models.TimeField(null=True, blank=True)
    close_time = models.TimeField(null=True, blank=True)

    def __str__(self):
        return self.name


class ServiceTable(models.Model):
    service_shop = models.ForeignKey(ServiceShop, on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    capacity = models.IntegerField()
    ocupied = models.IntegerField(default=0)
    status = models.BooleanField(default=True)
    active = models.BooleanField(default=True)

    def __str__(self):
        return self.name


class Service(models.Model):
    service_table = models.ForeignKey(ServiceTable, on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    description = models.TextField(
        null=True, blank=True)  # service description
    # service price (in future we will add multiple prices for different time and days)
    price = models.FloatField()
    image = models.ImageField(
        upload_to='service_image/', null=True, blank=True)  # service image( in future we will add multiple images)
    # only active services will be shown in the shop
    active = models.BooleanField(default=True)
    aprox_time_min = models.IntegerField()  # in minutes
    aprox_time_max = models.IntegerField()  # in minutes
    discount = models.FloatField(default=0)  # 0 to 100 discount in percentage
    rattings = models.FloatField(default=0)  # 0 to 5 service rating
    # in views we will manualy allow only 3 services to be speciality
    speciality = models.BooleanField(default=False)

    def __str__(self):
        return self.name


class ServiceOrder(models.Model):
    table = models.ForeignKey(ServiceTable, on_delete=models.CASCADE)
    status = models.BooleanField(default=False)
    order_time = models.DateTimeField(auto_now_add=True)
    order_number = models.IntegerField()
    completed_time = models.DateTimeField(auto_now=True)
    order_ip_address = models.GenericIPAddressField(null=True, blank=True)
    order_key = models.CharField(max_length=200, null=True, blank=True)
    order_by = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='service_order_by', null=True, blank=True)

    def __str__(self):
        return self.table.name


class ServiceOrderDetail(models.Model):
    order = models.ForeignKey(ServiceOrder, on_delete=models.CASCADE)
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
    quantity = models.IntegerField()
    price = models.FloatField()
    total = models.FloatField()
    is_completed = models.BooleanField(default=False)
    created_time = models.DateTimeField(auto_now_add=True)
    completed_time = models.DateTimeField(
        auto_now=True)

    def __str__(self):
        return self.service.name


class ShopAnouncement(models.Model):
    service_shop = models.ForeignKey(ServiceShop, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    description = models.TextField()
    created_time = models.DateTimeField(auto_now_add=True)
    updated_time = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class ShopReview(models.Model):
    service_shop = models.ForeignKey(ServiceShop, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    rating = models.IntegerField()
    review = models.TextField(null=True, blank=True)
    created_time = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.username
