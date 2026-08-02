from django.urls import re_path
from . import consumers

# This is the WebSocket equivalent of urls.py
websocket_urlpatterns = [
    # When Flutter connects to ws://localhost:8000/ws/qr-session/
    # it triggers the QRTokenConsumer we just wrote.
    re_path(r'ws/qr-session/$', consumers.QRTokenConsumer.as_asgi()),
]