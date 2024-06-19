from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ActivateService, BlockIp, CategoryActive, DataAnalysisForMonth, GoogleLogin, HostelViewSet, InventoryViewSet, ItemActive, LoginView, MealItemView, MealViewSet, ModifyOrder, NoticeViewSet, OrderCompleteView, OrderCreateView, OrderHistory, PaymentViewSet, ProductViewSet, ProductquantityViewSet, Record_payment, RestorantDetails, RestorantViewSet, RoomViewSet, Run, ServiceShopViewSet, ServiceTableViewSet, ServiceViewSet, SetManagerHostel, SetManagerRestorant, ShopAnouncementViewSet, ShopReviewViewSet, SignupView, StudentViewSet, Subscription_buy, Subscription_codeViewSet, TableDetail, TableViewSet, CategoryViewSet, ItemViewSet, OrderViewSet, OrderDetailViewSet, TimeInqueCalculate, Userdata, VerifyOTPView, DataAnalysis
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
    path('api/subscription', Subscription_buy.as_view(), name='subscription'),
    path('api/subscriptionCode', Subscription_codeViewSet.as_view(),
         name='subscriptionCode'),
    path('order/', OrderCreateView.as_view(), name='order-create'),
    path('order_complete/order_details/<int:order_detail_pk>/',
         OrderCompleteView.as_view(), name='order-complete'),
    path('order_complete/record_payment/<int:order_pk>/',
         Record_payment.as_view(), name='order-complete'),
    path('api/Analysis', DataAnalysis.as_view(), name='Analysis'),
    path('api/AnalysisMonth', DataAnalysisForMonth.as_view(), name='AnalysisMonth'),
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
    path('api/hostel/hostels/SetManager',
         SetManagerHostel.as_view(), name='student'),
    #    # Service shop
    path('api/service-shop/', ServiceShopViewSet.as_view(), name='service'),
    path('api/service-shop/Table', ServiceTableViewSet.as_view(), name='service'),
    path('api/service-shop/services', ServiceViewSet.as_view(), name='service'),
    path('api/service-shop/Announcement',
         ShopAnouncementViewSet.as_view(), name='service'),
    path('api/service-shop/Rating', ShopReviewViewSet.as_view(), name='service'),
    path('api/service-shop/service/activate',
         ActivateService.as_view(), name='service'),
    path('api/service-shop/tables/time',
         TimeInqueCalculate.as_view(), name='service'),
    #     restorent
    path('api/restorant/restorant', RestorantDetails.as_view(), name='restorant'),
    path('api/restorant/restorant/SetManager',
         SetManagerRestorant.as_view(), name='restorant'),
    path('api/restorant/tabledetails', TableDetail.as_view(), name='restorant'),
    # activate category
    path('api/restorant/activate_category/',
         CategoryActive.as_view(), name='restorant'),
    path('api/restorant/activate_item/',
         ItemActive.as_view(), name='restorant'),
    path('api/block_ip', BlockIp.as_view(), name='blockIp'),
    path('auth2/', GoogleLogin.as_view(), name='google-login'),
    path('auth/', include('social_django.urls', namespace='social')),
    path('run', Run, name='run'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL,
                          document_root=settings.MEDIA_ROOT)
