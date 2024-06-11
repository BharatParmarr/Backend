from rest_framework import serializers

from .models import BlockIP, Meal, MealItem, MealOrder, Notice, Payment, Product, Restorant, Table, Category, Item, Order, OrderDetail, Hostel, Room, Student, User


class AuthUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']


class UserSerializer(serializers.ModelSerializer):
    image = serializers.ImageField(
        max_length=None, use_url=True, required=False)

    class Meta:
        model = User
        fields = ['username', 'email', 'image', 'phone', 'address']


class RestorantSerializer(serializers.ModelSerializer):
    logo = serializers.ImageField(
        max_length=None, use_url=True, required=False)

    class Meta:
        model = Restorant
        fields = '__all__'


class TableSerializer(serializers.ModelSerializer):
    class Meta:
        model = Table
        fields = '__all__'


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = '__all__'


class ItemSerializer(serializers.ModelSerializer):
    image = serializers.ImageField(
        max_length=None, use_url=True, required=False)

    class Meta:
        model = Item
        fields = '__all__'


class OrderDetailSerializer(serializers.ModelSerializer):
    item_name = serializers.CharField(source='item.name', read_only=True)

    class Meta:
        model = OrderDetail
        fields = ['item', 'quantity', 'price',
                  'total', 'item_name', 'is_completed', 'id']


class OrderSerializer(serializers.ModelSerializer):
    order_details = OrderDetailSerializer(source='orderdetail_set', many=True)
    table_name = serializers.CharField(source='table.name', read_only=True)
    table_id = serializers.IntegerField(source='table.id', read_only=True)

    class Meta:
        model = Order
        fields = ['table', 'status', 'order_time',
                  'order_number', 'order_details', 'id', 'table_name', 'table_id']

    def create(self, validated_data):
        order_details_data = validated_data.pop('order_details')
        order = Order.objects.create(**validated_data)
        for order_detail_data in order_details_data:
            OrderDetail.objects.create(order=order, **order_detail_data)
        return order


class ProductSerializer(serializers.ModelSerializer):
    image = serializers.ImageField(
        max_length=None, use_url=True, required=False)

    class Meta:
        model = Product
        fields = '__all__'

# hostel serializers ===========


class HostelSerializer(serializers.ModelSerializer):
    logo = serializers.ImageField(
        max_length=None, use_url=True, required=False)

    class Meta:
        model = Hostel
        fields = '__all__'


class RoomSerializer(serializers.ModelSerializer):
    students = serializers.SerializerMethodField()

    class Meta:
        model = Room
        fields = ['hostel', 'number', 'name', 'students', 'id', 'capacity']

    def get_students(self, obj):
        students = Student.objects.filter(room=obj.id)
        return StudentSerializer(students, many=True).data


class StudentSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    image = serializers.ImageField(
        max_length=None, use_url=True, required=False)
    room_number = serializers.CharField(source='room.number', read_only=True)

    class Meta:
        model = Student
        fields = ['user', 'room', 'username', 'id',
                  'roll', 'image', 'hostel', 'room_number']


class MealSerializer(serializers.ModelSerializer):
    MealItems = serializers.SerializerMethodField()

    class Meta:
        model = Meal
        fields = '__all__'

    def get_MealItems(self, obj):
        MealItems = MealOrder.objects.filter(meal=obj.id)
        return MealOrderSerializer(MealItems, many=True).data


class PaymentSerializer(serializers.ModelSerializer):
    student_name = serializers.CharField(
        source='student.user.username', read_only=True)

    class Meta:
        model = Payment
        fields = ['id', 'student', 'paid', 'due', 'payment_method',
                  'payment_for', 'updated_time', 'student_name', 'total']


class MealItemSerializer(serializers.ModelSerializer):

    class Meta:
        model = MealItem
        fields = '__all__'


class MealOrderSerializer(serializers.ModelSerializer):
    name = serializers.CharField(source='meal_item.name', read_only=True)

    class Meta:
        model = MealOrder
        fields = '__all__'


class NoticeSerializer(serializers.ModelSerializer):

    class Meta:
        model = Notice
        fields = '__all__'


class BlockIpSerializer(serializers.Serializer):

    class Meta:
        model = BlockIP
        fields = '__all__'
