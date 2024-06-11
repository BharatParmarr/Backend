from django.forms import ValidationError
from django.utils import timezone
from datetime import timedelta
import json
from django.shortcuts import render
from rest_framework import viewsets
from django.db.models import Q
from .models import BlockIP, Hostel, Inventory, Meal, MealItem, Notice, Payment, Product, Profile, Restorant, Room, Student, Table, Category, Item, Order, OrderDetail
from .serializers import AuthUserSerializer, BlockIpSerializer, HostelSerializer, MealItemSerializer, MealOrderSerializer, MealSerializer, NoticeSerializer, PaymentSerializer, ProductSerializer, RestorantSerializer, RoomSerializer, StudentSerializer, TableSerializer, CategorySerializer, ItemSerializer, OrderSerializer, OrderDetailSerializer, UserSerializer

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
from django.db import IntegrityError, transaction
from django.core.exceptions import ObjectDoesNotExist
# changel websocket
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
# Create your views here.
# data anlyses
from django.db.models import Count, Sum, Avg
from django.db.models import F, ExpressionWrapper, fields
from django.db.models.functions import Cast
from django.db.models.functions import ExtractHour
# google auth
from social_django.utils import psa
from social_core.backends.oauth import BaseOAuth2
from social_core.exceptions import AuthTokenError
from social_django.utils import load_strategy, load_backend
from rest_framework.exceptions import AuthenticationFailed

User = get_user_model()


def Home(request):
    return render(request, 'home.html')


class GoogleLogin(APIView):

    def post(self, request):
        try:
            token = request.data.get('token')
            backend = load_backend(
                strategy=load_strategy(request),
                name='google-oauth2',
                redirect_uri=None
            )
            user = backend.do_auth(token)
            if user is None:
                raise AuthenticationFailed('Authentication failed.')

            if User.objects.filter(email=user.email).exists():
                # Check if user can be saved
                try:
                    user.full_clean()
                except ValidationError as e:
                    # Handle the validation error
                    return Response({'error': str(e)})

                login(request, user)
                user.save()
                user_instance = User.objects.get(email=user.email)
                print(user, 'user', user_instance)

                # Ensure atomicity of the token retrieval/creation process
                if user is None or not user.pk:
                    raise ValueError(
                        'User instance does not exist or is not saved in the database.')

                # Ensure atomicity of the token retrieval/creation process
                try:
                    with transaction.atomic():
                        token, created = Token.objects.get_or_create(
                            user=user_instance)
                except IntegrityError:
                    raise ValueError(
                        'FOREIGN KEY constraint failed. User instance does not exist.')
                if token is None:
                    raise Exception('Token creation failed.')

                return Response({'token': token.key})
            else:
                return Response({'error': 'Invalid Token or create user'}, status=status.HTTP_400_BAD_REQUEST)
        except IntegrityError as e:
            print(e, 'error')
            return Response({'error': str(e)})
            # print(user, 'user')
            # if user:
            #     if User.objects.filter(email=user.email).exists():
            #         user.backend = 'django.contrib.auth.backends.ModelBackend'
            #         login(request, user)
            #         print(user)
            #         token, created = Token.objects.get_or_create(user=user)
            #         return Response({'token': token.key})
            #     else:
            #         new_user = User.objects.create_user(
            #             username=user.email, email=user.email)
            #         new_user.save()
            #         new_user.backend = 'django.contrib.auth.backends.ModelBackend'
            #         login(request, new_user)
            #         token, created = Token.objects.get_or_create(
            #             user=new_user)
            #         return Response({'token': token.key})
            # else:
            #     return Response({'error': 'Invalid Token'}, status=status.HTTP_400_BAD_REQUEST)
        except AuthTokenError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


# user login, sing up, logout, profile, password change, password reset, password reset done, password reset confirm, password reset complete
# User = get_user_model()


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

    # def post(self, request):
    #     email = request.data.get('email')
    #     password = request.data.get('password')
    #     user = User.objects.filter(username=email).first()
    #     if user is not None and user.check_password(password):
    #         login(request, user)
    #         token, created = Token.objects.get_or_create(user=user)
    #         return Response({"token": token.key}, status=status.HTTP_200_OK)
    #     else:
    #         return Response({"error": "Wrong Credentials"}, status=status.HTTP_400_BAD_REQUEST)
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = User.objects.filter(Q(username=email) | Q(email=email)).first()
        print(user, email, password)
        if user is not None:
            user.backend = 'django.contrib.auth.backends.ModelBackend'
            login(request, user)
            token, created = Token.objects.get_or_create(user=user)
            return Response({"token": token.key}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Wrong Credentials"}, status=status.HTTP_400_BAD_REQUEST)


class Userdata(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # print ip
        ip = request.META.get('REMOTE_ADDR')
        print(ip)
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data)

    def post(self, request):
        data = request.data
        user = request.user
        serializer = UserSerializer(user, data=data, partial=True)
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "User data updated"}, status=status.HTTP_200_OK)


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
        try:
            data = request.data
            data['created_by'] = request.user.id
            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
        except Exception as e:
            if 'name' in str(e):
                return Response({"error": "Restorant name already exists."}, status=status.HTTP_409_CONFLICT)
            elif 'website' in str(e):
                return Response({"error": "Website name not appropriate."}, status=status.HTTP_409_CONFLICT)
            return Response({"error": 'Something went wrong.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def delete(self, request, *args, **kwargs):
        data = request.data
        restorant = Restorant.objects.get(id=data['restorant_id'])
        if restorant.created_by == request.user:
            restorant.delete()
            return Response({"message": "Restorant deleted"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to delete this restorant"}, status=status.HTTP_403_FORBIDDEN)

    def update(self, request, *args, **kwargs):
        data = request.data.copy()
        restorant = Restorant.objects.get(id=data['restorant_id'])
        data['created_by'] = request.user.id
        if restorant.created_by == request.user:
            try:
                serializer = self.get_serializer(
                    restorant, data=data, partial=True)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Exception as e:
                if 'name' in str(e):
                    return Response({"error": "Hostel name already exists"}, status=status.HTTP_409_CONFLICT)
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"error": "You are not authorized to update this restorant"}, status=status.HTTP_403_FORBIDDEN)


class RestorantDetails(APIView):
    authentication_classes = [TokenAuthentication]

    def get(self, request):
        user = request.user
        restorant_id = request.query_params.get('restorant_id')
        if restorant_id:
            restorant = Restorant.objects.get(id=restorant_id)
            if restorant.created_by == user or restorant.manager_restorant == user or user in restorant.staffs.all():
                return Response(RestorantSerializer(restorant).data, status=status.HTTP_200_OK)
        return Response({"error": "You are not authorized to view this data"}, status=status.HTTP_403_FORBIDDEN)

    def put(self, request):
        data = request.data
        restorant = Restorant.objects.get(id=data['restorant_id'])
        # data['created_by'] = request.user.id
        if restorant.created_by == request.user:
            try:
                serializer = RestorantSerializer(
                    restorant, data=data, partial=True)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Exception as e:
                if 'name' in str(e):
                    return Response({"error": "Hostel name already exists"}, status=status.HTTP_409_CONFLICT)
        else:
            return Response({"error": "You are not authorized to update this restorant"}, status=status.HTTP_403_FORBIDDEN)


class SetManagerRestorant(APIView):
    authentication_classes = [TokenAuthentication]

    def get(self, request):
        user = request.user
        restorant_id = request.query_params.get('restorant_id')
        if restorant_id:
            restorant = Restorant.objects.get(id=restorant_id)
            if restorant.created_by == user:
                manager = restorant.manager_restorant
                staffs = restorant.staffs.all()
                return Response({
                    'manager': manager.username if manager else None,
                    'staffs': [staff.username for staff in staffs]
                }, status=status.HTTP_200_OK)
        return Response({"error": "You are not authorized to view this data"}, status=status.HTTP_403_FORBIDDEN)

    def post(self, request):
        data = request.data
        restorant = Restorant.objects.get(id=data['restorant_id'])
        if restorant.created_by == request.user:
            try:
                manager = User.objects.get(username=data['username'])
            except ObjectDoesNotExist:
                return Response({"error": "User not found"}, status=status.HTTP_409_CONFLICT)
            restorant.staffs.add(manager)
            restorant.save()
            return Response({"message": "Manager set"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to set manager for this restorant"}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request):
        restorant = request.query_params.get('restorant_id')
        restorant = Restorant.objects.get(id=data['restorant_id'])
        user = request.query_params.get('manager_name')
        try:
            user = User.objects.get(username=user)
        except ObjectDoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_409_CONFLICT)
        is_manager = request.query_params.get('is_manager')
        if is_manager == '1':
            restorant.manager_restorant = None
            restorant.save()
            return Response({"message": "Manager removed"}, status=status.HTTP_200_OK)
        if restorant.created_by == request.user:
            restorant.staffs.remove(user)
            restorant.save()
            return Response({"message": "Staff removed"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to remove manager for this restorant"}, status=status.HTTP_403_FORBIDDEN)

    def put(self, request):
        data = request.data
        restorant = Restorant.objects.get(id=data['restorant_id'])
        if restorant.created_by == request.user:
            try:
                manager = User.objects.get(username=data['username'])
            except ObjectDoesNotExist:
                return Response({"error": "User not found"}, status=status.HTTP_409_CONFLICT)
            restorant.manager_restorant = manager
            restorant.save()
            return Response({"message": "Manager set"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to set manager for this restorant"}, status=status.HTTP_403_FORBIDDEN)


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


class TableDetail(APIView):

    def get(self, request):
        table_id = request.query_params.get('table_id')
        if table_id:
            table = Table.objects.get(id=table_id)
            data = {
                'table_name': table.name,
                'restorant_name': table.restorant.name,
            }
            return Response(data, status=status.HTTP_200_OK)
        return Response({"error": "You are not authorized to view this data"}, status=status.HTTP_403_FORBIDDEN)


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
        elif restorant_id:
            restorant = Restorant.objects.get(id=restorant_id)
            return Category.objects.filter(restorant=restorant_id, active=True)
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


class CategoryActive(APIView):
    authentication_classes = [TokenAuthentication]

    def put(self, request):
        data = request.data
        category = Category.objects.get(id=data['category_id'])
        if category.restorant.created_by == request.user:
            category.active = not category.active
            category.save()
            return Response({"message": "Category updated"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to update this category"}, status=status.HTTP_403_FORBIDDEN)


class ItemActive(APIView):
    authentication_classes = [TokenAuthentication]

    def put(self, request):
        data = request.data
        item = Item.objects.get(id=data['item_id'])
        if item.category.restorant.created_by == request.user:
            item.active = not item.active
            item.save()
            return Response({"message": "Item updated"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to update this item"}, status=status.HTTP_403_FORBIDDEN)


class ItemViewSet(viewsets.ModelViewSet):
    queryset = Item.objects.all()
    serializer_class = ItemSerializer

    def get_queryset(self):
        user = self.request.user
        category_id = self.request.query_params.get('category_id')
        if category_id:
            category = Category.objects.get(id=category_id)
            if category.restorant.created_by == user or category.restorant.manager_restorant == user or user in category.restorant.staffs.all():
                return Item.objects.filter(category=category_id)
            else:
                return Item.objects.filter(category=category_id, active=True)
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
        ip_address = request.META.get('REMOTE_ADDR')

        if not data['items']:
            return Response({'error': 'No items in order'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            with transaction.atomic():
                table = Table.objects.get(id=data['table'])
                if BlockIP.objects.filter(ip=ip_address, restorant=table.restorant.id).exists():
                    return Response({'error': 'Invalid data from user.'}, status=status.HTTP_403_FORBIDDEN)
                order_number = Order.objects.filter(
                    table=table, status=False).count()
                order = Order.objects.create(
                    table=table, order_number=order_number + 1, order_ip_address=ip_address)

                for item_data in data['items']:
                    item = Item.objects.get(id=item_data['item'])
                    OrderDetail.objects.create(
                        order=order,
                        item=item,
                        quantity=item_data['quantity'],
                        price=item.price,
                        total=item.price * item_data['quantity'],
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


class ModifyOrder(APIView):
    authentication_classes = [TokenAuthentication]

    def post(self, request, pk, format=None):
        if not request.user.is_authenticated:
            return Response({'error': 'User not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
        # request.user is not None and request.user not in ['manager_restorant', 'staffs'] of Restorant.objects.get(id=OrderDetail.objects.get(id=order_detail_pk).order.table.restorant):
        restaurant = Restorant.objects.get(id=OrderDetail.objects.get(
            id=pk).order.table.restorant.id)
        user = request.user

        if not restaurant.staffs.filter(id=user.id).exists() and \
                restaurant.created_by != user and \
                restaurant.manager_restorant != user:
            return Response({'error': 'User not authorized'}, status=status.HTTP_403_FORBIDDEN)
        try:
            order_detail = OrderDetail.objects.filter(order=pk)
            for item in order_detail:
                item.delete()
            data = request.data
            for item_data in data['items']:
                item = Item.objects.get(id=item_data['item'])
                OrderDetail.objects.create(
                    order=Order.objects.get(id=pk),
                    item=item,
                    quantity=item_data['quantity'],
                    price=item.price,
                    total=item.price * item_data['quantity']
                )
            return Response({'status': 'success'}, status=status.HTTP_200_OK)
        except ObjectDoesNotExist as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


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

                # time of order according hour of day
                order_time = Order.objects.filter(
                    table__restorant=restorant).annotate(
                    order_hour=ExtractHour('order_time')
                ).values('order_hour').annotate(total_orders=Count('id'))

                data = {
                    'items_sold': items_sold,
                    'item_revenue': list(item_revenue),
                    'category_data': list(category_data),
                    'item_creation_time': list(item_creation_time),
                    'avg_order_completion_time': avg_order_completion_time,
                    'order_time': list(order_time),
                }
                return Response(data, status=status.HTTP_200_OK)
        return Response({"error": "You are not authorized to view this data"}, status=status.HTTP_403_FORBIDDEN)


class OrderHistory(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        restorant_id = request.query_params.get('restorant_id')
        if restorant_id:
            page = request.query_params.get('page')
            restorant = Restorant.objects.get(id=restorant_id)
            if restorant.created_by == user or restorant.manager_restorant == user or user in restorant.staffs.all():
                orders = Order.objects.filter(
                    table__restorant=restorant, status=True).order_by('-completed_time')
                if page:
                    orders = orders[int(page) * 10 - 10:int(page) * 10]
                else:
                    orders = orders[:10]
                serializer = OrderSerializer(orders, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"error": "You are not authorized to view this data"}, status=status.HTTP_403_FORBIDDEN)


class ProductViewSet(APIView):
    authentication_classes = [TokenAuthentication]

    def get(self, request):
        user = request.user
        restorant_id = request.query_params.get('restorant_id')
        if restorant_id:
            restorant = Restorant.objects.get(id=restorant_id)
            if restorant.created_by == user or restorant.manager_restorant == user or user in restorant.staffs.all():
                products = Product.objects.filter(restorant=restorant_id)
                serializer = ProductSerializer(products, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"error": "You are not authorized to view this data"}, status=status.HTTP_403_FORBIDDEN)

    def post(self, request):
        user = request.user
        restorant_id = request.query_params.get('restorant_id')
        if restorant_id:
            restorant = Restorant.objects.get(id=restorant_id)
            if restorant.created_by == user or restorant.manager_restorant == user:
                data = request.data
                serializer = ProductSerializer(data=data)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response({"error": "You are not authorized to add product"}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, *args, **kwargs):
        data = request.data
        product = Product.objects.get(id=data['product_id'])
        restorant = product.restorant
        if restorant.created_by == request.user:
            product.delete()
            return Response({"message": "Product deleted"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to delete this product"}, status=status.HTTP_403_FORBIDDEN)


class ProductquantityViewSet(APIView):
    authentication_classes = [TokenAuthentication]

    def post(self, request, pk):
        user = request.user
        restorant_id = request.query_params.get('restorant_id')
        if restorant_id:
            restorant = Restorant.objects.get(id=restorant_id)
            if restorant.created_by == user or restorant.manager_restorant == user:
                product = Product.objects.get(id=pk)
                data = request.data
                product.quantity = data['quantity']
                product.save()
                return Response({"status": "success"}, status=status.HTTP_200_OK)
        return Response({"error": "You are not authorized to update product quantity"}, status=status.HTTP_403_FORBIDDEN)


class InventoryViewSet(APIView):
    authentication_classes = [TokenAuthentication]

    def get(self, request):
        user = request.user
        restorant_id = request.query_params.get('restorant_id')
        if restorant_id:
            restorant = Restorant.objects.get(id=restorant_id)
            if restorant.created_by == user or restorant.manager_restorant == user or user in restorant.staffs.all():
                products = Inventory.objects.filter(
                    restorant=restorant_id).values('product__name').annotate(total_quantity=Sum('quantity'))
                return Response(list(products), status=status.HTTP_200_OK)
        return Response({"error": "You are not authorized to view this data"}, status=status.HTTP_403_FORBIDDEN)

    def post(self, request):
        user = request.user
        restorant_id = request.query_params.get('restorant_id')
        if restorant_id:
            restorant = Restorant.objects.get(id=restorant_id)
            if restorant.created_by == user or restorant.manager_restorant == user or user in restorant.staffs.all():
                data = request.data
                product = Product.objects.get(id=data['product'])
                Inventory.objects.update_or_create(
                    restorant=restorant,
                    product=product,
                    defaults={'quantity': data['quantity']}
                )
                return Response({"status": "success"}, status=status.HTTP_201_CREATED)
        return Response({"error": "You are not authorized to add inventory"}, status=status.HTTP_403_FORBIDDEN)


# hostel views ==================================================


class HostelViewSet(APIView):
    authentication_classes = [TokenAuthentication]

    def get(self, request):
        if request.user.is_authenticated:
            user = request.user
            hostel_id = request.query_params.get('hostel_id')
            if hostel_id:
                hostel = Hostel.objects.get(id=hostel_id)
                if hostel.created_by == user or hostel.manager_hostel == user or user in hostel.staffs.all():
                    serializer = HostelSerializer(hostel)
                    return Response(serializer.data, status=status.HTTP_200_OK)
            hostels = Hostel.objects.filter(created_by=user)
            serializer = HostelSerializer(hostels, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        # user = request.user
        # hostels = Hostel.objects.filter(created_by=user)
        # serializer = HostelSerializer(hostels, many=True)
        # return Response(serializer.data)

    def post(self, request):
        user = request.user
        data = request.data.copy()
        data['created_by'] = user.id
        serializer = HostelSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def delete(self, request, *args, **kwargs):
        data = request.data
        hostel = Hostel.objects.get(id=data['hostel_id'])
        if hostel.created_by == request.user:
            hostel.delete()
            return Response({"message": "Hostel deleted"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to delete this hostel"}, status=status.HTTP_403_FORBIDDEN)

    def put(self, request, *args, **kwargs):
        data = request.data.copy()
        hostel = Hostel.objects.get(id=data['hostel_id'])
        data['created_by'] = request.user.id
        if hostel.created_by == request.user:
            try:
                serializer = HostelSerializer(hostel, data=data)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                return Response({"message": "Hostel updated"}, status=status.HTTP_200_OK)
            except Exception as e:
                if 'name' in str(e):
                    return Response({"error": "Hostel name already exists"}, status=status.HTTP_409_CONFLICT)

        else:
            return Response({"error": "You are not authorized to update this hostel"}, status=status.HTTP_403_FORBIDDEN)


class SetManagerHostel(APIView):
    authentication_classes = [TokenAuthentication]

    def get(self, request):
        user = request.user
        hostel_id = request.query_params.get('hostel_id')
        if hostel_id:
            hostel = Hostel.objects.get(id=hostel_id)
            if hostel.created_by == user:
                manager = hostel.manager_hostel
                staffs = hostel.staffs.all()
                staffs_json = []
                for staff in staffs:
                    staffs_json.append(staff.username)
                return Response({"manager": manager.username, "staffs": staffs_json}, status=status.HTTP_200_OK)
        return Response({"error": "You are not authorized to view this data"}, status=status.HTTP_403_FORBIDDEN)

    def post(self, request):
        data = request.data
        hostel = Hostel.objects.get(id=data['hostel_id'])
        try:
            user = User.objects.get(username=data['username'])
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_409_CONFLICT)
        if hostel.created_by == request.user:
            hostel.staffs.add(user)
            hostel.save()
            return Response({"message": "Manager set"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to set manager for this hostel"}, status=status.HTTP_403_FORBIDDEN)

    def put(self, request):
        data = request.data
        hostel = Hostel.objects.get(id=data['hostel_id'])
        try:
            user = User.objects.get(username=data['username'])
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_409_CONFLICT)
        if hostel.created_by == request.user:
            hostel.manager_hostel = user
            hostel.save()
            return Response({"message": "Manager set"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to set manager for this hostel"}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request):
        hostel = request.query_params.get('hostel_id')
        hostel = Hostel.objects.get(id=hostel)
        user = request.query_params.get('manager_name')
        try:
            user = User.objects.get(username=user).id
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_409_CONFLICT)
        is_manager = request.query_params.get('manager')
        if is_manager == '1':
            hostel.manager_hostel = None
            hostel.save()
            return Response({"message": "Manager removed"}, status=status.HTTP_200_OK)
        if hostel.created_by == request.user:
            hostel.staffs.remove(user)
            hostel.save()
            return Response({"message": "Staff removed"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to remove manager for this hostel"}, status=status.HTTP_403_FORBIDDEN)


class RoomViewSet(APIView):
    authentication_classes = [TokenAuthentication]

    def get(self, request):
        user = request.user
        hostel_id = request.query_params.get('hostel_id')
        room_id = request.query_params.get('room_id')
        if hostel_id:
            if room_id:
                room = Room.objects.get(id=room_id)
                if room.hostel.created_by == user or room.hostel.manager_hostel == user or user in room.hostel.staffs.all():
                    serializer = RoomSerializer(room)
                    return Response(serializer.data, status=status.HTTP_200_OK)
            hostel = Hostel.objects.get(id=hostel_id)
            if hostel.created_by == user or hostel.manager_hostel == user or user in hostel.staffs.all():
                rooms = Room.objects.filter(hostel=hostel_id)
                serializer = RoomSerializer(rooms, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"error": "You are not authorized to view this data"}, status=status.HTTP_403_FORBIDDEN)

    def post(self, request):
        user = request.user
        data = request.data
        hostel = Hostel.objects.get(id=data['hostel'])
        if hostel.created_by == user:
            serializer = RoomSerializer(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response({"error": "You are not authorized to create room for this hostel"}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, *args, **kwargs):
        data = request.data
        room = Room.objects.get(id=data['room_id'])
        hostel = room.hostel
        if hostel.created_by == request.user:
            room.delete()
            return Response({"message": "Room deleted"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to delete this room"}, status=status.HTTP_403_FORBIDDEN)

    def put(self, request, *args, **kwargs):
        data = request.data
        room = Room.objects.get(id=data['room_id'])
        hostel = room.hostel
        if hostel.created_by == request.user or hostel.manager_hostel == request.user:
            room.capacity = data['capacity']
            room.save()
            return Response({"message": "Room capacity updated"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to update this room"}, status=status.HTTP_403_FORBIDDEN)


class StudentViewSet(APIView):
    authentication_classes = [TokenAuthentication]

    def get(self, request):
        user = request.user
        hostel_id = request.query_params.get('hostel_id')
        room_id = request.query_params.get('room_id')
        if int(room_id) == 0:
            if hostel_id:
                hostel = Hostel.objects.get(id=hostel_id)
                if hostel.created_by == user or hostel.manager_hostel == user or user in hostel.staffs.all():
                    students = Student.objects.filter(hostel=hostel_id)
                    serializer = StudentSerializer(students, many=True)
                    return Response(serializer.data, status=status.HTTP_200_OK)
        elif room_id:
            try:
                room = Room.objects.get(id=room_id)
                print(room.hostel.created_by, user)
                if room.hostel.created_by == user or room.hostel.manager_hostel == user or user in room.hostel.staffs.all():
                    students = Student.objects.filter(room=room_id)
                    serializer = StudentSerializer(students, many=True)
                    return Response(serializer.data, status=status.HTTP_200_OK)
            except Room.DoesNotExist:
                return Response({"error": "Room not found"}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response({"error": "You are not authorized to view this data"}, status=status.HTTP_403_FORBIDDEN)

    def post(self, request):
        user = request.user
        data = request.data
        hostel = Hostel.objects.get(id=data['hostel'])
        if User.objects.get(username=data['user']) and hostel.created_by == user:
            data['user'] = User.objects.get(username=data['user']).id
            if Student.objects.filter(user=data['user'], hostel=hostel).exists():
                return Response({"error": "Student already exists"}, status=status.HTTP_409_CONFLICT)
        else:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        if hostel.created_by == user:
            try:
                serializer = StudentSerializer(data=data)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except Exception as e:
                # print(e)
                return Response({"error": str(e)}, status=status.HTTP_412_PRECONDITION_FAILED)
        else:
            print("You are not authorized to create student for this hostel")
            return Response({"error": "You are not authorized to create student for this hostel"}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, pk, format=None):
        # data = request.data
        student = Student.objects.get(id=pk)
        hostel = student.hostel
        if hostel.created_by == request.user:
            student.delete()
            return Response({"message": "Student deleted"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to delete this student"}, status=status.HTTP_403_FORBIDDEN)

    def put(self, request, pk, format=None):
        data = request.data
        student = Student.objects.get(id=pk)
        hostel = student.hostel
        if hostel.created_by == request.user or hostel.manager_hostel == request.user:
            student.room = Room.objects.get(id=int(data['room']))
            student.save()
            return Response({"message": "Student room updated"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to update this student"}, status=status.HTTP_403_FORBIDDEN)


# Payment views ==================================================

class PaymentViewSet(APIView):
    authentication_classes = [TokenAuthentication]

    def get(self, request):
        user = request.user
        hostel_id = request.query_params.get('hostel_id')
        if hostel_id:
            hostel = Hostel.objects.get(id=hostel_id)
            if hostel.created_by == user or hostel.manager_hostel == user or user in hostel.staffs.all():
                payments = Payment.objects.filter(student__hostel=hostel_id)
                serializer = PaymentSerializer(payments, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"error": "You are not authorized to view this data"}, status=status.HTTP_403_FORBIDDEN)

    def post(self, request):
        user = request.user
        data = request.data.copy()
        hostel = Hostel.objects.get(id=data['hostel'])
        print(hostel.created_by, user, data)
        if hostel.created_by == user or hostel.manager_hostel == user or user in hostel.staffs.all():
            try:
                total = int(data['total'])
                paid = int(data['paid'])
                due = total - paid
                data['due'] = due
                serializer = PaymentSerializer(data=data)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except Exception as e:
                print(e)
                return Response({"error": str(e)}, status=status.HTTP_412_PRECONDITION_FAILED)
        else:
            return Response({"error": "You are not authorized to add payment"}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, *args, **kwargs):
        data = request.data
        payment = Payment.objects.get(id=data['payment_id'])
        hostel = payment.student.hostel
        if hostel.created_by == request.user:
            payment.delete()
            return Response({"message": "Payment deleted"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to delete this payment"}, status=status.HTTP_403_FORBIDDEN)

    def put(self, request, *args, **kwargs):
        data = request.data
        payment = Payment.objects.get(id=data['payment_id'])
        hostel = payment.student.hostel
        if hostel.created_by == request.user:
            payment.paid = data['paid']
            payment.due = payment.total - data['paid']
            payment.save()
            return Response({"message": "Payment updated"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to update this payment"}, status=status.HTTP_403_FORBIDDEN)


# meal views ==================================================

class MealViewSet(APIView):
    authentication_classes = [TokenAuthentication]

    def get(self, request):
        user = request.user
        hostel_id = request.query_params.get('hostel_id')
        if hostel_id:
            hostel = Hostel.objects.get(id=hostel_id)
            if hostel.created_by == user or hostel.manager_hostel == user or user in hostel.staffs.all():
                meals = Meal.objects.filter(hostel=hostel_id)
                serializer = MealSerializer(meals, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"error": "You are not authorized to view this data"}, status=status.HTTP_403_FORBIDDEN)

    def post(self, request):
        user = request.user
        data = request.data
        hostel_id = request.query_params.get('hostel_id')
        new_data = {
            'hostel': hostel_id,
            'name': data['name'],
            'MealTime': data['time'],
        }
        MealOrderData = []

        # print(data)
        hostel = Hostel.objects.get(id=hostel_id)
        if hostel.created_by == user:
            serializer = MealSerializer(data=new_data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            # create mealOrder
            for i in data['mealItems']:
                MealOrderData.append({
                    'meal': serializer.data['id'],
                    'meal_item': i['meal'],
                    'quantity': i['quantity'],
                    'unlimited': i['unlimited'],
                    'hostel': hostel_id,
                })
            serializer_mealOrder = MealOrderSerializer(
                data=MealOrderData, many=True)
            serializer_mealOrder.is_valid(raise_exception=True)
            serializer_mealOrder.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response({"error": "You are not authorized to add meal"}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, *args, **kwargs):
        data = request.data
        meal = Meal.objects.get(id=data['meal_id'])
        hostel = meal.hostel
        if hostel.created_by == request.user:
            meal.delete()
            return Response({"message": "Meal deleted"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to delete this meal"}, status=status.HTTP_403_FORBIDDEN)

    def put(self, request, *args, **kwargs):
        data = request.data
        meal = Meal.objects.get(id=data['meal_id'])
        hostel = meal.hostel
        if hostel.created_by == request.user or hostel.manager_hostel == request.user:
            meal.price = data['price']
            meal.save()
            return Response({"message": "Meal price updated"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to update this meal"}, status=status.HTTP_403_FORBIDDEN)


class MealItemView(APIView):
    authentication_classes = [TokenAuthentication]

    def get(self, request):
        user = request.user
        hostel_id = request.query_params.get('hostel_id')
        if hostel_id:
            hostel = Hostel.objects.get(id=hostel_id)
            if hostel.created_by == user or hostel.manager_hostel == user or user in hostel.staffs.all():
                meal_items = MealItem.objects.filter(hostel=hostel_id)
                serializer = MealItemSerializer(meal_items, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"error": "You are not authorized to view this data"}, status=status.HTTP_403_FORBIDDEN)

    def post(self, request):
        user = request.user
        data = request.data
        hostel = Hostel.objects.get(id=data['hostel'])
        if hostel.created_by == user:
            serializer = MealItemSerializer(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response({"error": "You are not authorized to add meal item"}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, *args, **kwargs):
        data = request.data
        meal_item = MealItem.objects.get(id=data['meal_item_id'])
        hostel = meal_item.hostel
        if hostel.created_by == request.user:
            meal_item.delete()
            return Response({"message": "Meal item deleted"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to delete this meal item"}, status=status.HTTP_403_FORBIDDEN)


# class Notice(models.Model):
#     hostel = models.ForeignKey(Hostel, on_delete=models.CASCADE)
#     title = models.CharField(max_length=200)
#     description = models.TextField()
#     created_time = models.DateTimeField(auto_now_add=True)
#     updated_time = models.DateTimeField(auto_now=True)

#     def __str__(self):
#         return self.title

class NoticeViewSet(APIView):
    authentication_classes = [TokenAuthentication]

    def get(self, request):
        user = request.user
        hostel_id = request.query_params.get('hostel_id')
        if hostel_id:
            hostel = Hostel.objects.get(id=hostel_id)
            if hostel.created_by == user or hostel.manager_hostel == user or user in hostel.staffs.all():
                notices = Notice.objects.filter(hostel=hostel_id)[::-1]
                serializer = NoticeSerializer(notices, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"error": "You are not authorized to view this data"}, status=status.HTTP_403_FORBIDDEN)

    def post(self, request):
        user = request.user
        data = request.data
        hostel = Hostel.objects.get(id=data['hostel'])
        if hostel.created_by == user:
            serializer = NoticeSerializer(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response({"error": "You are not authorized to add notice"}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, *args, **kwargs):
        data = request.data
        notice = Notice.objects.get(id=data['notice_id'])
        hostel = notice.hostel
        if hostel.created_by == request.user:
            notice.delete()
            return Response({"message": "Notice deleted"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You are not authorized to delete this notice"}, status=status.HTTP_403_FORBIDDEN)


# block Ip address
# class BlockIP(models.Model):
#     ip = models.GenericIPAddressField()
#     reason = models.TextField()
#     restorant = models.ForeignKey(
#         Restorant, on_delete=models.CASCADE, null=True, blank=True)
#     hostel = models.ForeignKey(
#         Hostel, on_delete=models.CASCADE, null=True, blank=True)
#     created_time = models.DateTimeField(auto_now_add=True)
#     updated_time = models.DateTimeField(auto_now=True)

#     def __str__(self):
#         return self.ip

class BlockIp(APIView):
    authentication_classes = [TokenAuthentication]

    def post(self, request):
        data = request.data
        order = data['order_id']
        if order:
            order = Order.objects.get(id=order)
            ip = order.order_ip_address
        else:
            return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)
        user = request.user
        if data['for'] == 'restorant':
            restorant = request.query_params.get('restorant_id')
            restoro = Restorant.objects.get(id=restorant)
            if restoro.created_by == user or restoro.manager_restorant == user or user in restoro.staffs.all():
                BlockIP.objects.create(
                    ip=ip, reason=data['reason'], restorant=restoro)
                return Response({"message": "IP blocked"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "You are not authorized to block IP for this restorant"}, status=status.HTTP_403_FORBIDDEN)
        elif data['for'] == 'hostel':
            hostel = request.query_params.get('hostel_id')
            host = Hostel.objects.get(id=hostel)
            if host.created_by == user or host.manager_hostel == user or user in host.staffs.all():
                BlockIP.objects.create(
                    ip=ip, reason=data['reason'], hostel=host)
                return Response({"message": "IP blocked"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "You are not authorized to block IP for this hostel"}, status=status.HTTP_403_FORBIDDEN)
        else:
            return Response({"error": "Invalid block for"}, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        user = request.user
        block_for = request.query_params.get('for')
        if block_for == 'restorant':
            restorant = request.query_params.get('restorant_id')
            restoro = Restorant.objects.get(id=restorant)
            if restoro.created_by == user or restoro.manager_restorant == user or user in restoro.staffs.all():
                block_ips = BlockIP.objects.filter(restorant=restoro)
                serializer = BlockIpSerializer(block_ips, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response({"error": "You are not authorized to view blocked IPs for this restorant"}, status=status.HTTP_403_FORBIDDEN)
        elif block_for == 'hostel':
            hostel = request.query_params.get('hostel_id')
            host = Hostel.objects.get(id=hostel)
            if host.created_by == user or host.manager_hostel == user or user in host.staffs.all():
                block_ips = BlockIP.objects.filter(hostel=host)
                serializer = BlockIpSerializer(block_ips, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response({"error": "You are not authorized to view blocked IPs for this hostel"}, status=status.HTTP_403_FORBIDDEN)
        else:
            return Response({"error": "Invalid block for"}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        data = request.data
        block_ip = BlockIP.objects.get(id=data['block_ip_id'])
        user = request.user
        if block_ip.restorant:
            if block_ip.restorant.created_by == user:
                block_ip.delete()
                return Response({"message": "IP unblocked"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "You are not authorized to unblock this IP"}, status=status.HTTP_403_FORBIDDEN)
        elif block_ip.hostel:
            if block_ip.hostel.created_by == user:
                block_ip.delete()
                return Response({"message": "IP unblocked"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "You are not authorized to unblock this IP"}, status=status.HTTP_403_FORBIDDEN)
        else:
            return Response({"error": "Invalid block for"}, status=status.HTTP_400_BAD_REQUEST)
