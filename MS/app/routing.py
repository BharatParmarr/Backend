from channels.routing import ProtocolTypeRouter, URLRouter
from django.urls import re_path
from app import consumers

websocket_urlpatterns = [
    re_path(r'ws/orders/(?P<restorant_id>\d+)/$',
            consumers.OrderConsumer.as_asgi()),
]
