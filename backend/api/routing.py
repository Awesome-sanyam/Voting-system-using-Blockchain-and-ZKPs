from django.urls import re_path
from . import consumers

# WebSocket URL patterns — equivalent of urls.py for WebSocket connections
websocket_urlpatterns = [
    # Voter QR session — streams HMAC-signed tokens every 3 minutes
    re_path(r'ws/qr-session/$', consumers.QRTokenConsumer.as_asgi()),

    # Admin telemetry — real-time AI threat event feed for the admin dashboard
    re_path(r'ws/telemetry/$', consumers.TelemetryConsumer.as_asgi()),
]