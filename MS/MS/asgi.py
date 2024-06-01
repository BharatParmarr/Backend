import os
from django.core.asgi import get_asgi_application
import app.routing
from channels.routing import ProtocolTypeRouter, URLRouter

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MS.settings')


application = ProtocolTypeRouter({
    "http":  get_asgi_application(),
    "websocket": URLRouter(
        app.routing.websocket_urlpatterns
    ),
})
