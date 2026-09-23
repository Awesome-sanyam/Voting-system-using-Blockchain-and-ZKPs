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
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
import api.routing

application = ProtocolTypeRouter({
    # Standard Django HTTP handler
    "http": get_asgi_application(),

    # WebSocket handler — sessions are available inside consumers via self.scope["session"]
    "websocket": AuthMiddlewareStack(
        URLRouter(
            api.routing.websocket_urlpatterns
        )
    ),
})
