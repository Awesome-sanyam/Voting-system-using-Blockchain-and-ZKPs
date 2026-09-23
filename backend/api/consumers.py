import json
import time
import asyncio
import hmac
import hashlib
import secrets
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.exceptions import StopConsumer
from django.conf import settings


class QRTokenConsumer(AsyncWebsocketConsumer):
    """
    Streams HMAC-signed, 3-minute QR tokens to the authenticated voter's browser.
    Voter identity is read from the Django session (set by voter_auth_view).
    Unauthenticated connections are rejected with close code 4001.
    """

    async def connect(self):
        # Read voter identity from the authenticated Django session
        session = self.scope.get('session', {})
        self.voter_hash = session.get('voter_hash')

        if not self.voter_hash:
            # Reject unauthenticated WebSocket connections
            await self.close(code=4001)
            return

        self.session_active = True
        await self.accept()

        # Start the 3-minute refresh loop as a background task
        self.loop_task = asyncio.create_task(self.send_qr_loop())

    async def disconnect(self, close_code):
        self.session_active = False
        if hasattr(self, 'loop_task') and not self.loop_task.done():
            self.loop_task.cancel()
            try:
                await self.loop_task
            except asyncio.CancelledError:
                pass

    async def send_qr_loop(self):
        """
        Pushes a fresh HMAC-SHA256 signed token every 180 seconds.
        Handles client disconnection and cancellation gracefully.
        """
        SERVER_SECRET = getattr(settings, 'SECRET_KEY', 'blockvote-dev-secret').encode('utf-8')

        while self.session_active:
            current_time = int(time.time())
            expiry_time = current_time + 180  # Valid for 3 minutes

            payload = {
                "voter_hash": self.voter_hash,
                "issued_at": current_time,
                "expires_at": expiry_time,
                "session_nonce": secrets.token_hex(8)  # Replay attack prevention
            }

            # Deterministic signature over sorted keys
            payload_string = json.dumps(payload, sort_keys=True)
            signature = hmac.new(
                SERVER_SECRET,
                payload_string.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()

            secure_token = {
                "payload": payload,
                "signature": signature
            }

            try:
                await self.send(text_data=json.dumps({
                    "type": "qr_refresh",
                    "token": secure_token
                }))
            except (StopConsumer, Exception):
                # Client disconnected mid-send — terminate the loop cleanly
                self.session_active = False
                break

            try:
                await asyncio.sleep(180)
            except asyncio.CancelledError:
                break


class TelemetryConsumer(AsyncWebsocketConsumer):
    """
    Admin telemetry WebSocket consumer.
    Subscribes to the 'admin_telemetry' channel group so that
    server-side threat detection events (from submit_vote_relayer)
    can be pushed to all connected admin dashboards in real time.
    """
    GROUP_NAME = "admin_telemetry"

    async def connect(self):
        # Only allow authenticated staff/superusers
        user = self.scope.get('user')
        if not user or not user.is_authenticated or not (user.is_staff or user.is_superuser):
            await self.close(code=4003)
            return

        await self.channel_layer.group_add(self.GROUP_NAME, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        try:
            await self.channel_layer.group_discard(self.GROUP_NAME, self.channel_name)
        except Exception:
            pass

    # Receive message from channel layer group (sent by submit_vote_relayer view)
    async def threat_event(self, event):
        """Forwards threat events from the Django view layer to all admin browsers."""
        try:
            await self.send(text_data=json.dumps(event))
        except Exception:
            pass