import os
import json
import requests
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from web3 import Web3
from django.conf import settings

# In a real production environment, these would be in your .env file
POLYGON_RPC_URL = os.getenv("POLYGON_RPC_URL", "https://rpc-amoy.polygon.technology")
SERVER_PRIVATE_KEY = os.getenv("SERVER_PRIVATE_KEY", "YOUR_DUMMY_PRIVATE_KEY_HERE")
VOTING_CONTRACT_ADDRESS = os.getenv("VOTING_CONTRACT_ADDRESS", "0xYourDeployedContractAddress")

# A simplified ABI just for the castVote function to keep the file clean
VOTING_ABI = json.loads("""
[
    {
        "inputs": [
            {"internalType": "uint256[2]", "name": "a", "type": "uint256[2]"},
            {"internalType": "uint256[2][2]", "name": "b", "type": "uint256[2][2]"},
            {"internalType": "uint256[2]", "name": "c", "type": "uint256[2]"},
            {"internalType": "uint256", "name": "nullifier", "type": "uint256"},
            {"internalType": "uint256", "name": "candidateId", "type": "uint256"}
        ],
        "name": "castVote",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]
""")

@api_view(['POST'])
def submit_vote_relayer(request):
    """
    Receives the ZK-Proof from Flutter, validates the traffic, 
    and relays it to the Polygon blockchain gas-free.
    """
    try:
        data = request.data
        
        # 1. AI Threat Detection Hook (Scikit-Learn)
        # ---------------------------------------------------------
        client_ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
        payload_size = len(request.body)
        
        # In production, you would calculate real-time velocity using Redis. 
        # We use a safe baseline here for development.
        request_velocity = 2.5 

        try:
            ai_response = requests.post(
                "http://127.0.0.1:8001/api/v1/analyze-threat/",
                json={
                    "ip_address": client_ip,
                    "payload_size": payload_size,
                    "request_velocity": request_velocity
                },
                timeout=2 # Strict 2-second timeout so voting isn't delayed
            )
            
            if ai_response.status_code == 200:
                threat_data = ai_response.json()
                if threat_data.get("is_anomalous"):
                    return Response({
                        "error": "Security Threat Detected",
                        "details": "Active Sentinel blocked this request due to anomalous network behavior.",
                        "threat_score": threat_data.get("threat_score")
                    }, status=status.HTTP_403_FORBIDDEN)
        except requests.exceptions.RequestException:
            print("WARNING: Active Sentinel ML Service is offline. Bypassing threat detection.")
        # ---------------------------------------------------------

        # 2. Extract ZK Proof Data sent by Flutter's SnarkJS WASM
        a = data.get('a')
        b = data.get('b')
        c = data.get('c')
        nullifier = data.get('nullifier')
        candidate_id = data.get('candidateId')

        if not all([a, b, c, nullifier, candidate_id]):
            return Response({"error": "Missing cryptographic proof parameters"}, status=status.HTTP_400_BAD_REQUEST)

        # 3. Connect to Polygon Blockchain
        w3 = Web3(Web3.HTTPProvider(POLYGON_RPC_URL))
        if not w3.is_connected():
            return Response({"error": "Failed to connect to Polygon network"}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        # 4. Prepare the Smart Contract Transaction
        server_account = w3.eth.account.from_key(SERVER_PRIVATE_KEY)
        voting_contract = w3.eth.contract(address=VOTING_CONTRACT_ADDRESS, abi=VOTING_ABI)

        # Build the transaction dictionary
        tx = voting_contract.functions.castVote(
            a, b, c, int(nullifier), int(candidate_id)
        ).build_transaction({
            'from': server_account.address,
            'nonce': w3.eth.get_transaction_count(server_account.address),
            'gas': 500000, # Estimated gas limit for ZK verification
            'maxFeePerGas': w3.to_wei('30', 'gwei'),
            'maxPriorityFeePerGas': w3.to_wei('30', 'gwei'),
            'chainId': 80002 # Polygon Amoy Chain ID
        })

        # 5. Sign with the Server's Wallet (The Gasless Magic)
        signed_tx = w3.eth.account.sign_transaction(tx, private_key=SERVER_PRIVATE_KEY)

        # 6. Broadcast to the Blockchain
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)

        # Return the transaction hash to the voter immediately
        return Response({
            "status": "success",
            "message": "Vote cryptographically secured on Polygon.",
            "transaction_hash": w3.to_hex(tx_hash)
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)








import hashlib
from .models import VoterIdentity

@api_view(['POST'])
def verify_epic_and_register(request):
    """
    Simulates the Indian Government API Setu Sandbox.
    Accepts an EPIC number, validates age/citizenship, and saves ONLY a cryptographic hash.
    """
    try:
        epic_number = request.data.get('epic_number')
        phone_number = request.data.get('phone_number')

        if not epic_number or not phone_number:
            return Response({"error": "EPIC number and phone number are required."}, status=status.HTTP_400_BAD_REQUEST)

        # ---------------------------------------------------------
        # SIMULATING GOVERNMENT API SETU RESPONSE
        # ---------------------------------------------------------
        # In the real world: response = requests.post("https://apisetu.gov.in/kyc...", data)
        # Here, we simulate a failure if the EPIC number starts with 'FAIL'
        if epic_number.upper().startswith('FAIL'):
             return Response({
                 "error": "Verification Failed", 
                 "details": "The provided EPIC number is invalid or the citizen is under 18."
             }, status=status.HTTP_403_FORBIDDEN)
        
        # ---------------------------------------------------------
        # CRYPTOGRAPHIC IDENTITY HASHING (Privacy Preservation)
        # ---------------------------------------------------------
        # We mathematically hash the EPIC number with a server salt.
        # This ensures the raw Voter ID NEVER touches our PostgreSQL database.
        secret_salt = getattr(settings, 'SECRET_KEY', 'default-salt').encode('utf-8')
        raw_identity = f"{epic_number}:{phone_number}".encode('utf-8')
        
        voter_hash = "0x" + hashlib.sha256(raw_identity + secret_salt).hexdigest()

        # Check if this citizen is already registered
        if VoterIdentity.objects.filter(voter_hash=voter_hash).exists():
            return Response({"error": "Citizen is already registered for this election."}, status=status.HTTP_409_CONFLICT)

        # Save the anonymous hash to the whitelist
        VoterIdentity.objects.create(
            voter_hash=voter_hash,
            is_verified=True,
            has_voted=False
        )

        return Response({
            "status": "success",
            "message": "Citizen successfully verified and whitelisted.",
            "voter_hash": voter_hash # We return this so the Flutter app can store it locally
        }, status=status.HTTP_201_CREATED)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
