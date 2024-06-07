from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import HostelViewSet, InventoryViewSet, LoginView, MealItemView, MealViewSet, ModifyOrder, NoticeViewSet, OrderCompleteView, OrderCreateView, OrderHistory, PaymentViewSet, ProductViewSet, ProductquantityViewSet, Record_payment, RestorantViewSet, RoomViewSet, SignupView, StudentViewSet, TableViewSet, CategoryViewSet, ItemViewSet, OrderViewSet, OrderDetailViewSet, Userdata, VerifyOTPView, DataAnalysis
from django.conf import settings
from django.conf.urls.static import static


router = DefaultRouter()
router.register(r'restorants', RestorantViewSet)
router.register(r'tables', TableViewSet)
router.register(r'categories', CategoryViewSet)
router.register(r'items', ItemViewSet)
router.register(r'orders', OrderViewSet)
router.register(r'orderdetails', OrderDetailViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('signup/', SignupView.as_view(), name='signup'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('login/', LoginView.as_view(), name='login'),
    path('api/user', Userdata.as_view(), name='userdata'),
    path('order/', OrderCreateView.as_view(), name='order-create'),
    path('order_complete/order_details/<int:order_detail_pk>/',
         OrderCompleteView.as_view(), name='order-complete'),
    path('order_complete/record_payment/<int:order_pk>/',
         Record_payment.as_view(), name='order-complete'),
    path('api/Analysis', DataAnalysis.as_view(), name='Analysis'),
    path('ModifyOrder/<int:pk>/', ModifyOrder.as_view(), name='ModifyOrder'),
    path('api/orderHistory', OrderHistory.as_view(), name='orderHistory'),
    path('api/product', ProductViewSet.as_view(), name='product'),
    path('api/product/<int:pk>', ProductquantityViewSet.as_view(), name='product'),
    path('api/Inventory', InventoryViewSet.as_view(), name='Inventory'),
    path('api/hostel/hostels/', HostelViewSet.as_view(), name='hostel'),
    path('api/hostels', RoomViewSet.as_view(), name='room'),
    path('api/hostel/rooms', RoomViewSet.as_view(), name='room'),
    path('api/hostel/students', StudentViewSet.as_view(), name='student'),
    path('api/hostel/students/<int:pk>',
         StudentViewSet.as_view(), name='student'),
    path('api/hostel/meals', MealViewSet.as_view(), name='student'),
    path('api/hostel/mealsitem', MealItemView.as_view(), name='student'),
    path('api/hostel/payments', PaymentViewSet.as_view(), name='student'),
    path('api/hostel/notice', NoticeViewSet.as_view(), name='student'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL,
                          document_root=settings.MEDIA_ROOT)
