from django.shortcuts import render
from rest_framework import viewsets
from django.db.models import Q
from .models import Profile, Restorant, Table, Category, Item, Order, OrderDetail
from .serializers import RestorantSerializer, TableSerializer, CategorySerializer, ItemSerializer, OrderSerializer, OrderDetailSerializer

# user
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from django.core.mail import send_mail
from django.contrib.auth import authenticate, login
import random
# authentication token
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
# models for order
from django.db import transaction
from django.core.exceptions import ObjectDoesNotExist
# changel websocket
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
# Create your views here.
# data anlyses
from django.db.models import Count, Sum, Avg
from django.db.models import F, ExpressionWrapper, fields
from django.db.models.functions import Cast


def Home(request):
    return render(request, 'home.html')


# user login, sing up, logout, profile, password change, password reset, password reset done, password reset confirm, password reset complete
User = get_user_model()


class SignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            username = request.data.get('username')
            email = request.data.get('email')
            password = request.data.get('password')

            if not username or not email or not password:
                return Response({"error": "Username, email, and password are required"}, status=status.HTTP_400_BAD_REQUEST)

            if User.objects.filter(username=username).exists() or User.objects.filter(email=email).exists():
                return Response({"error": "Username or email already exists"}, status=status.HTTP_400_BAD_REQUEST)

            user = User.objects.create_user(
                username=username, email=email, password=password)
            user.save()

            otp = random.randint(100000, 999999)
            profile = Profile.objects.create(user=user, otp=otp)
            profile.save()

            send_mail(
                'Your OTP',
                f'Your OTP is {otp}',
                'from@example.com',
                [email],
                fail_silently=False,
            )

            return Response({"message": "OTP sent to email"}, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        otp = request.data.get('otp')
        email = request.data.get('email')
        user = User.objects.get(email=email)
        profile = Profile.objects.get(user=user)
        print('1', type(profile.otp), otp)
        if int(otp) == profile.otp:
            print("OTP verified")
            profile.otp_verified = True
            profile.save()
            token, created = Token.objects.get_or_create(user=user)
            return Response({"message": "OTP verified", "token": token.key}, status=status.HTTP_200_OK)
        else:
            return Response({"message": "OTP incorrect"}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(request, username=email, password=password)
        print(user, email, password)
        if user is not None:
            login(request, user)
            token, created = Token.objects.get_or_create(user=user)
            return Response({"token": token.key}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Wrong Credentials"}, status=status.HTTP_400_BAD_REQUEST)


class Userdata(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({"username": user.username, "email": user.email}, status=status.HTTP_200_OK)


class RestorantViewSet(viewsets.ModelViewSet):
    authentication_classes = [TokenAuthentication]
    serializer_class = RestorantSerializer
    queryset = Restorant.objects.all()

    def list(self, request, *args, **kwargs):
        user = self.request.user
        if user.is_authenticated:
            manager_restorant = Restorant.objects.filter(
                manager_restorant=user)
            staffs = Restorant.objects.filter(staffs=user)
            created_by = Restorant.objects.filter(created_by=user)
            return Response({
                'manager_restorant': RestorantSerializer(manager_restorant, many=True).data,
                'staffs': RestorantSerializer(staffs, many=True).data,
                'created_by': RestorantSerializer(created_by, many=True).data,
            })
        else:
            return Response({})

    def get_queryset(self):
        user = self.request.user
        return Restorant.objects.filter(Q(manager_restorant=user) | Q(staffs=user) | Q(created_by=user))

    def create(self, request, *args, **kwargs):
        data = request.data
        data['created_by'] = request.user.id
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class TableViewSet(viewsets.ModelViewSet):
    queryset = Table.objects.all()
    serializer_class = TableSerializer

    def get_queryset(self):
        user = self.request.user
        restorant_id = self.request.query_params.get('restorant_id')
        if user.is_authenticated and restorant_id:
            restorant = Restorant.objects.get(id=restorant_id)
            if restorant.created_by == user or restorant.manager_restorant == user or user in restorant.staffs.all():
                return Table.objects.filter(restorant=restorant_id)
        # else return zero table
        return Table.objects.none()

    def create(self, request, *args, **kwargs):
        data = request.data
        restorant = Restorant.objects.get(id=data['restorant'])
        if restorant.created_by == request.user or restorant.manager_restorant == request.user:
            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
        else:
            return Response({"error": "You are not authorized to create table for this restorant"}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, *args, **kwargs):
        data = request.data
        table = Table.objects.get(id=data['table_id'])
        restorant = table.restorant
        if restorant.created_by == request.user:
            table.delete()
            return Response({"message": "Table deleted"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to delete this table"}, status=status.HTTP_403_FORBIDDEN)


class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer

    def get_queryset(self):
        user = self.request.user
        restorant_id = self.request.query_params.get('restorant_id')
        if user.is_authenticated and restorant_id:
            restorant = Restorant.objects.get(id=restorant_id)
            if restorant.created_by == user or restorant.manager_restorant == user or user in restorant.staffs.all():
                return Category.objects.filter(restorant=restorant_id)
        # else return zero category
        return Category.objects.none()

    def create(self, request, *args, **kwargs):
        data = request.data
        restorant = Restorant.objects.get(id=data['restorant'])
        if restorant.created_by == request.user or restorant.manager_restorant == request.user:
            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
        else:
            return Response({"error": "You are not authorized to create category for this restorant"}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, *args, **kwargs):
        data = request.data
        category = Category.objects.get(id=data['category_id'])
        restorant = category.restorant
        if restorant.created_by == request.user:
            category.delete()
            return Response({"message": "Category deleted"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to delete this category"}, status=status.HTTP_403_FORBIDDEN)


class ItemViewSet(viewsets.ModelViewSet):
    queryset = Item.objects.all()
    serializer_class = ItemSerializer

    def get_queryset(self):
        user = self.request.user
        category_id = self.request.query_params.get('category_id')
        if user.is_authenticated and category_id:
            category = Category.objects.get(id=category_id)
            if category.restorant.created_by == user or category.restorant.manager_restorant == user or user in category.restorant.staffs.all():
                return Item.objects.filter(category=category_id)
        # else return zero item
        return Item.objects.none()

    def create(self, request, *args, **kwargs):
        data = request.data
        category = Category.objects.get(id=data['category'])
        if category.restorant.created_by == request.user or category.restorant.manager_restorant == request.user:
            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
        else:
            return Response({"error": "You are not authorized to create item for this category"}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, *args, **kwargs):
        data = request.data
        item = Item.objects.get(id=data['item_id'])
        category = item.category
        if category.restorant.created_by == request.user:
            item.delete()
            return Response({"message": "Item deleted"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to delete this item"}, status=status.HTTP_403_FORBIDDEN)


class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer

    def get_queryset(self):
        user = self.request.user
        restorant_id = self.request.query_params.get('restorant_id')
        if user.is_authenticated and restorant_id:
            restorant = Restorant.objects.get(id=restorant_id)
            if restorant.created_by == user or restorant.manager_restorant == user or user in restorant.staffs.all():
                return Order.objects.filter(table__restorant=restorant_id, status=False)
        # else return zero order
        return Order.objects.none()

    def create(self, request, *args, **kwargs):
        data = request.data
        table = Table.objects.get(id=data['table'])
        if table.restorant.created_by == request.user or table.restorant.manager_restorant == request.user:
            order_number = Order.objects.filter(
                table=table, status=False).count()
            order = Order.objects.create(
                table=table, order_number=order_number + 1)
            return Response({"order_id": order.id}, status=status.HTTP_201_CREATED)
        else:
            return Response({"error": "You are not authorized to create order for this table"}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, *args, **kwargs):
        data = request.data
        order = Order.objects.get(id=data['order_id'])
        table = order.table
        if table.restorant.created_by == request.user:
            order.delete()
            return Response({"message": "Order deleted"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to delete this order"}, status=status.HTTP_403_FORBIDDEN)

    def update(self, request, *args, **kwargs):
        data = request.data
        order = Order.objects.get(id=data['order_id'])
        table = order.table
        if table.restorant.created_by == request.user:
            order.status = True
            order.save()
            return Response({"message": "Order closed"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to close this order"}, status=status.HTTP_403_FORBIDDEN)


class OrderDetailViewSet(viewsets.ModelViewSet):
    queryset = OrderDetail.objects.all()
    serializer_class = OrderDetailSerializer


class OrderCreateView(APIView):
    def post(self, request, format=None):
        data = request.data
        if not data['items']:
            return Response({'error': 'No items in order'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            with transaction.atomic():
                table = Table.objects.get(id=data['table'])
                order_number = Order.objects.filter(
                    table=table, status=False).count()
                order = Order.objects.create(
                    table=table, order_number=order_number + 1)

                for item_data in data['items']:
                    item = Item.objects.get(id=item_data['item'])
                    OrderDetail.objects.create(
                        order=order,
                        item=item,
                        quantity=item_data['quantity'],
                        price=item.price,
                        total=item.price * item_data['quantity']
                    )

                # Send message to WebSocket group
                channel_layer = get_channel_layer()
                async_to_sync(channel_layer.group_send)(
                    'orders_group',
                    {
                        'type': 'order_update',
                        'message': 'New order created'
                    }
                )

            return Response({'status': 'success'}, status=status.HTTP_201_CREATED)
        except ObjectDoesNotExist as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# class OrderCreateView(APIView):
#     def post(self, request, format=None):
#         data = request.data
#         # if there are no items then return
#         if not data['items']:
#             return Response({'error': 'No items in order'}, status=status.HTTP_400_BAD_REQUEST)
#         try:
#             with transaction.atomic():
#                 table = Table.objects.get(id=data['table'])
#                 # find current active order in the order table
#                 order_number = Order.objects.filter(
#                     table=table, status=False).count()
#                 order = Order.objects.create(
#                     table=table, order_number=order_number + 1)

#                 for item_data in data['items']:
#                     item = Item.objects.get(id=item_data['item'])
#                     OrderDetail.objects.create(
#                         order=order,
#                         item=item,
#                         quantity=item_data['quantity'],
#                         price=item.price,
#                         total=item.price * item_data['quantity']
#                     )

#             return Response({'status': 'success'}, status=status.HTTP_201_CREATED)
#         except ObjectDoesNotExist as e:
#             return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
#         except Exception as e:
#             return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# change is_completed of order detail to True
class OrderCompleteView(APIView):
    authentication_classes = [TokenAuthentication]

    def get(self, request, order_detail_pk, format=None):
        if not request.user.is_authenticated:
            return Response({'error': 'User not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
        # request.user is not None and request.user not in ['manager_restorant', 'staffs'] of Restorant.objects.get(id=OrderDetail.objects.get(id=order_detail_pk).order.table.restorant):
        restaurant = Restorant.objects.get(id=OrderDetail.objects.get(
            id=order_detail_pk).order.table.restorant.id)
        user = request.user

        if not restaurant.staffs.filter(id=user.id).exists() and \
                restaurant.created_by != user and \
                restaurant.manager_restorant != user:
            return Response({'error': 'User not authorized'}, status=status.HTTP_403_FORBIDDEN)
        if OrderDetail.objects.get(id=order_detail_pk).is_completed:
            return Response({'error': 'Order already completed'}, status=status.HTTP_200_OK)
        try:
            order_detail = OrderDetail.objects.get(id=order_detail_pk)
            order_detail.is_completed = True
            order_detail.save()
            return Response({'status': 'success'}, status=status.HTTP_200_OK)
        except ObjectDoesNotExist as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# record payment of order
class Record_payment(APIView):
    authentication_classes = [TokenAuthentication]

    def get(self, request, order_pk, format=None):
        if not request.user.is_authenticated:
            return Response({'error': 'User not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
        # request.user is not None and request.user not in ['manager_restorant', 'staffs'] of Restorant.objects.get(id=Order.objects.get(id=order_pk).table.restorant):
        restaurant = Restorant.objects.get(id=Order.objects.get(
            id=order_pk).table.restorant.id)
        user = request.user

        if not restaurant.staffs.filter(id=user.id).exists() and \
                restaurant.created_by != user and \
                restaurant.manager_restorant != user:
            return Response({'error': 'User not authorized'}, status=status.HTTP_403_FORBIDDEN)
        if Order.objects.get(id=order_pk).status:
            return Response({'error': 'Order already completed'}, status=status.HTTP_200_OK)
        try:
            order = Order.objects.get(id=order_pk)
            order.status = True
            order.save()
            return Response({'status': 'success'}, status=status.HTTP_200_OK)
        except ObjectDoesNotExist as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DataAnalysis(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        restorant_id = request.query_params.get('restorant_id')
        if restorant_id:
            restorant = Restorant.objects.get(id=restorant_id)
            if restorant.created_by == user or restorant.manager_restorant == user or user in restorant.staffs.all():
                items_sold = OrderDetail.objects.filter(
                    order__table__restorant=restorant).aggregate(total=Sum('quantity'))['total']

                # How much money has each item made
                item_revenue = OrderDetail.objects.filter(order__table__restorant=restorant).values(
                    'item__name').annotate(revenue=Sum('total'))

                # Which category has received the highest amount of orders and money
                category_data = OrderDetail.objects.filter(order__table__restorant=restorant).values('item__category__name').annotate(
                    total_orders=Sum('quantity'), total_revenue=Sum('total')).order_by('-total_orders', '-total_revenue')

                # Convert 'created_time' to Unix timestamp (seconds since 1970-01-01)
                item_creation_time = OrderDetail.objects.filter(order__table__restorant=restorant).annotate(
                    created_time_unix=Cast(ExpressionWrapper(
                        F('created_time'), output_field=fields.DateTimeField()), output_field=fields.FloatField())
                ).values('item__name').annotate(avg_creation_time=Avg('created_time_unix'))

                # Convert 'completed_time' to Unix timestamp
                avg_order_completion_time = Order.objects.filter(
                    table__restorant=restorant).annotate(
                    completed_time_unix=Cast(ExpressionWrapper(
                        F('completed_time'), output_field=fields.DateTimeField()), output_field=fields.FloatField())
                ).aggregate(avg_completion_time=Avg('completed_time_unix'))

                data = {
                    'items_sold': items_sold,
                    'item_revenue': list(item_revenue),
                    'category_data': list(category_data),
                    'item_creation_time': list(item_creation_time),
                    'avg_order_completion_time': avg_order_completion_time,
                }
                return Response(data, status=status.HTTP_200_OK)
        return Response({"error": "You are not authorized to view this data"}, status=status.HTTP_403_FORBIDDEN)
