import json
import time
import asyncio
import hmac
import hashlib
import secrets
from channels.generic.websocket import AsyncWebsocketConsumer
from django.conf import settings

class QRTokenConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # 1. Accept the WebSocket connection from Flutter
        await self.accept()

        # 2. In a real scenario, we verify the JWT token here to get the Voter Hash.
        # For now, we simulate a verified voter's unique hash.
        self.voter_hash = f"0x{secrets.token_hex(16)}"
        self.session_active = True

        # 3. Start the continuous 3-minute loop in the background
        self.loop_task = asyncio.create_task(self.send_qr_loop())

    async def disconnect(self, close_code):
        # Kill the background loop when the user closes the app or navigates away
        self.session_active = False
        if hasattr(self, 'loop_task'):
            self.loop_task.cancel()

    async def send_qr_loop(self):
        """
        This background task pushes a fresh cryptographic token exactly every 3 minutes.
        """
        # A secret key used to sign the QR code (keep this safe in .env in production)
        # Using a dummy secret for development
        SERVER_SECRET = getattr(settings, 'SECRET_KEY', 'super-secret-voting-key').encode('utf-8')

        while self.session_active:
            current_time = int(time.time())
            expiry_time = current_time + 180  # Valid for exactly 3 minutes

            # The raw data we want to embed in the QR code
            payload = {
                "voter_hash": self.voter_hash,
                "issued_at": current_time,
                "expires_at": expiry_time,
                "session_nonce": secrets.token_hex(8) # Prevents replay attacks
            }

            # Cryptographically sign the payload so hackers cannot forge their own QR codes
            payload_string = json.dumps(payload, sort_keys=True)
            signature = hmac.new(SERVER_SECRET, payload_string.encode('utf-8'), hashlib.sha256).hexdigest()

            # The final data sent to Flutter
            secure_token = {
                "payload": payload,
                "signature": signature
            }

            # Push the data down the open WebSocket to the frontend
            await self.send(text_data=json.dumps({
                "type": "qr_refresh",
                "token": secure_token
            }))

            # Sleep for exactly 180 seconds without blocking the rest of the server
            await asyncio.sleep(180)