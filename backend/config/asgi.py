"""
ASGI config for BlockVote India.

Mounts Django Channels ProtocolTypeRouter so that:
  - HTTP requests  → handled by the standard Django ASGI application
  - WebSocket upgrades → routed by URLRouter through api.routing
"""

import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from django.core.asgi import get_asgi_application
from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler
from django.conf import settings
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
import api.routing

http_app = get_asgi_application()
if settings.DEBUG:
    http_app = ASGIStaticFilesHandler(http_app)

application = ProtocolTypeRouter({
    # Standard Django HTTP handler
    "http": http_app,

    # WebSocket handler — sessions are available inside consumers via self.scope["session"]
    "websocket": AuthMiddlewareStack(
        URLRouter(
            api.routing.websocket_urlpatterns
        )
    ),
})

