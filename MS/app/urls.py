from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import LoginView, OrderCompleteView, OrderCreateView, Record_payment, RestorantViewSet, SignupView, TableViewSet, CategoryViewSet, ItemViewSet, OrderViewSet, OrderDetailViewSet, Userdata, VerifyOTPView, DataAnalysis
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
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL,
                          document_root=settings.MEDIA_ROOT)
