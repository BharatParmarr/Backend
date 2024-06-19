# Adjust the import path as necessary
from app.models import Category, Item, Order, OrderDetail, Restorant, Table, User
import os
import django
import random
from faker import Faker

# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MS.settings')
# django.setup()


fake = Faker()


def create_restorants(n):
    restorants = []
    for _ in range(n):
        name = fake.company()
        address = fake.address()
        phone = fake.phone_number()
        email = fake.email()
        website = fake.url()
        created_by = User.objects.first()
        restorants.append(Restorant(name=name, address=address, phone=phone,
                                    email=email, website=website, created_by=created_by))
    Restorant.objects.bulk_create(restorants)


def create_categories(n):
    categories = []
    for _ in range(n):
        name = fake.word()
        description = fake.text()
        restorant = random.choice(Restorant.objects.all())
        active = True
        categories.append(
            Category(name=name, description=description, restorant=restorant, active=active))
    Category.objects.bulk_create(categories)


def create_items(n):
    items = []
    for _ in range(n):
        category = random.choice(Category.objects.all())
        name = fake.word()
        description = fake.text()
        price = round(random.uniform(5.0, 50.0), 2)
        items.append(Item(category=category, name=name,
                     description=description, price=price))
    Item.objects.bulk_create(items)


def create_orders(n):
    orders = []
    for _ in range(n):
        table = random.choice(Table.objects.all())
        order_number = random.randint(100, 999)
        orders.append(Order(table=table, order_number=order_number))
    Order.objects.bulk_create(orders)


def Create_orders_details(n):
    orders_details = []
    for _ in range(n):
        order = random.choice(Order.objects.all())
        # item shoul belong to the same restorant as the order
        item = random.choice(Item.objects.filter(
            category__restorant=order.table.restorant))
        quantity = random.randint(1, 10)
        price = item.price
        total = quantity * price
        orders_details.append(OrderDetail(
            order=order, item=item, quantity=quantity, price=price, total=total))
    OrderDetail.objects.bulk_create(orders_details)


# Adjust the number of fake records you want to create for each model
create_restorants(10)
create_categories(50)
create_items(200)
create_orders(100)

print("Fake data insertion completed.")
