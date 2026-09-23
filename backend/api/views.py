import os
import json
import hashlib
from functools import wraps
import requests
from asgiref.sync import async_to_sync
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from web3 import Web3
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from .models import Election, Candidate, VoterIdentity, ThreatLog, AuditorProfile

# Institutional invite secret for gated auditor access
AUDITOR_TRUST_SECRET = os.getenv("AUDITOR_TRUST_SECRET", "ECI-AUDIT-2026-SECURE")

# In a real production environment, these would be in your .env file
POLYGON_RPC_URL = os.getenv("POLYGON_RPC_URL", "https://polygon-amoy-bor-rpc.publicnode.com")
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
    Gasless ZK-proof relayer: validates traffic with Active Sentinel ML,
    then relays the Groth16 proof to the Polygon Amoy smart contract.

    The body MUST be read (cached) before request.data is accessed —
    DRF's request.data consumes the raw stream; subsequent len(request.body)
    calls raise 'You cannot access body after reading from request.data stream'.
    """
    try:
        # 0. Cache raw body FIRST to avoid DRF stream double-read bug
        # ---------------------------------------------------------
        raw_body_bytes = request.body  # This caches body into request._body
        payload_size = len(raw_body_bytes)

        # Now it is safe to access request.data (parsed JSON via DRF)
        data = request.data

        # 1. AI Threat Detection Hook (Scikit-Learn Active Sentinel)
        # ---------------------------------------------------------
        client_ip = request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip() \
                    or request.META.get('REMOTE_ADDR', '127.0.0.1')

        # Accept velocity from the X-Request-Velocity header (set by DDoS simulator)
        # or fall back to a safe dev-mode baseline of 2.5 req/sec.
        try:
            request_velocity = float(request.META.get('HTTP_X_REQUEST_VELOCITY', '2.5'))
        except (ValueError, TypeError):
            request_velocity = 2.5

        try:
            ai_response = requests.post(
                "http://127.0.0.1:8001/api/v1/analyze-threat/",
                json={
                    "ip_address": client_ip,
                    "payload_size": payload_size,
                    "request_velocity": request_velocity
                },
                timeout=2  # Strict 2-second timeout so voting isn't delayed
            )

            if ai_response.status_code == 200:
                threat_data = ai_response.json()
                if threat_data.get("is_anomalous"):
                    # Broadcast threat event to admin telemetry WebSocket group
                    try:
                        from channels.layers import get_channel_layer
                        channel_layer = get_channel_layer()
                        async_to_sync(channel_layer.group_send)("admin_telemetry", {
                            "type": "threat_event",
                            "event": {
                                "type": "BLOCKED",
                                "ip": client_ip,
                                "score": threat_data.get("threat_score", 0),
                                "msg": "Active Sentinel blocked anomalous vote relay",
                                "timestamp": __import__('datetime').datetime.now().strftime('%H:%M:%S'),
                                "id": f"EVT-{__import__('random').randint(10000, 99999)}"
                            }
                        })
                    except Exception:
                        pass  # Channel layer may not be available in all environments

                    # Log to DB
                    ThreatLog.objects.create(
                        ip_address=client_ip,
                        threat_score=threat_data.get("threat_score", 0),
                        payload_size=payload_size
                    )
                    return Response({
                        "error": "Security Threat Detected",
                        "details": "Active Sentinel blocked this request due to anomalous network behavior.",
                        "threat_score": threat_data.get("threat_score")
                    }, status=status.HTTP_403_FORBIDDEN)
        except requests.exceptions.RequestException:
            print("WARNING: Active Sentinel ML Service is offline. Bypassing threat detection.")
        # ---------------------------------------------------------

        # 2. Extract ZK Proof Data sent by the browser's SnarkJS WASM (via zkp_prover.js)
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
        tx_hex = w3.to_hex(tx_hash)

        # 7. Update has_voted flag in database
        voter_hash_session = request.session.get('voter_hash')
        if voter_hash_session:
            VoterIdentity.objects.filter(voter_hash=voter_hash_session).update(has_voted=True)

        return Response({
            "status": "success",
            "message": "Vote cryptographically secured on Polygon.",
            "transaction_hash": tx_hex
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)






@api_view(['POST'])
def lock_merkle_root(request):
    """
    Admin-only endpoint to lock the Merkle root for the active election.
    Persists the root to the Django DB (Election.merkle_root) and sets is_root_locked=True.
    The admin dashboard calls this via admin_telemetry.js when the Electoral Roll is sealed.

    NOTE: In production, this should also call ElectionRegistration.lockMerkleRoot()
    via Web3 to update the on-chain state. That call requires a funded admin wallet.
    """
    if not request.user.is_authenticated or not (request.user.is_staff or request.user.is_superuser):
        return Response({"error": "Unauthorized — Admin credentials required."}, status=403)

    merkle_root = request.data.get('merkle_root', '').strip()
    if not merkle_root:
        return Response({"error": "merkle_root is required."}, status=400)

    election = Election.objects.order_by('-created_at').first()
    if not election:
        return Response({"error": "No active election found in database."}, status=404)

    if election.is_root_locked:
        return Response({"error": "Merkle root is already locked for this election."}, status=409)

    election.merkle_root = merkle_root
    election.is_root_locked = True
    election.save()

    return Response({
        "status": "locked",
        "merkle_root": merkle_root,
        "election_id": election.pk,
        "message": "Electoral roll has been sealed. Voting is now open."
    })


@api_view(['GET'])
def get_election_state(request):
    """
    Public endpoint returning the current election state.
    Used by zkp_prover.js to fetch the real on-chain Merkle root
    for inclusion proof generation before calling snarkjs.groth16.fullProve().
    """
    election = Election.objects.order_by('-created_at').first()
    if not election:
        return Response({"error": "No active election found."}, status=404)

    return Response({
        "election_id":   election.pk,
        "election_name": election.name,
        "merkle_root":   election.merkle_root or "0x0",
        "is_locked":     election.is_root_locked,
    })


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


def derive_voter_identity_hash(epic_number: str, phone_number: str) -> str:
    """
    Deterministically hashes EPIC number + salt to maintain zero raw identifier storage.
    """
    secret_salt = getattr(settings, 'SECRET_KEY', 'default-salt').encode('utf-8')
    raw_identity = f"{epic_number.strip().upper()}:{phone_number.strip()}".encode('utf-8')
    return "0x" + hashlib.sha256(raw_identity + secret_salt).hexdigest()


# ═══════════════════════════════════════════════════════════════════════════════
#  ROLE PROTECTION DECORATORS (RBAC)
# ═══════════════════════════════════════════════════════════════════════════════

def voter_required(view_func):
    """
    Restricts access strictly to citizens with an active, verified session voter_hash.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        voter_hash = request.session.get('voter_hash')
        if not voter_hash:
            messages.warning(request, "Voter authentication required. Please register or verify with your EPIC/OTP.")
            return redirect(f"/auth/voter/?next={request.path}")
        if not VoterIdentity.objects.filter(voter_hash=voter_hash, is_verified=True).exists():
            request.session.pop('voter_hash', None)
            messages.error(request, "Voter identity not found on the registry. Please register via API Setu.")
            return redirect(f"/auth/voter/?next={request.path}")
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def admin_required(view_func):
    """
    Restricts access strictly to authenticated users with staff/superuser privileges.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated or not (request.user.is_staff or request.user.is_superuser):
            messages.warning(request, "Administrative authentication required. Access restricted to authorized election authority personnel.")
            return redirect(f"/auth/admin/?next={request.path}")
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def auditor_required(view_func):
    """
    Restricts access strictly to certified institutional auditors or election staff.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            messages.warning(request, "Auditor authentication required. Access restricted to verified institutional observers.")
            return redirect(f"/auth/auditor/?next={request.path}")
        if request.user.is_staff or request.user.is_superuser:
            return view_func(request, *args, **kwargs)
        profile = getattr(request.user, 'auditor_profile', None)
        if not profile or not profile.is_approved:
            messages.error(request, "Access Denied: Your institutional auditor account is awaiting election authority verification.")
            return redirect(f"/auth/auditor/?next={request.path}")
        return view_func(request, *args, **kwargs)
    return _wrapped_view


# ═══════════════════════════════════════════════════════════════════════════════
#  MULTI-ROLE AUTHENTICATION VIEWS
# ═══════════════════════════════════════════════════════════════════════════════

def portal_select(request):
    """
    Enterprise Hub for selecting between Voter Portal, Admin Console, and Public Auditor.
    """
    has_voter_session = bool(request.session.get('voter_hash'))
    is_admin = bool(request.user.is_authenticated and (request.user.is_staff or request.user.is_superuser))
    is_auditor = bool(
        request.user.is_authenticated and (
            (hasattr(request.user, 'auditor_profile') and request.user.auditor_profile.is_approved) or
            request.user.is_staff or request.user.is_superuser
        )
    )

    context = {
        'has_voter_session': has_voter_session,
        'voter_hash': request.session.get('voter_hash'),
        'voter_epic': request.session.get('voter_epic'),
        'is_admin': is_admin,
        'is_auditor': is_auditor,
    }
    return render(request, 'api/portal_select.html', context)


def voter_auth_view(request):
    """
    Dual-mode Voter Authentication portal:
      1. Register Voter Identity (API Setu Sandbox simulation)
      2. Voter OTP Login
    """
    next_url = request.POST.get('next') or request.GET.get('next') or '/voter/'

    if request.method == 'POST':
        action = request.POST.get('action', 'login')

        if action == 'register':
            epic_number = request.POST.get('epic_number', '').strip().upper()
            phone_number = request.POST.get('phone_number', '').strip()

            if not epic_number or not phone_number:
                messages.error(request, "Both EPIC Voter ID and Registered Mobile Number are required.")
                return render(request, 'api/auth_voter.html', {'active_tab': 'register', 'next': next_url})

            if len(epic_number) < 7:
                messages.error(request, "Invalid EPIC format. Must contain standard prefix and identifier (e.g., IND1234567).")
                return render(request, 'api/auth_voter.html', {'active_tab': 'register', 'next': next_url})

            if epic_number.startswith('FAIL'):
                messages.error(request, "API Setu KYC Verification Failed: Citizen record is inactive or under 18 years old.")
                return render(request, 'api/auth_voter.html', {'active_tab': 'register', 'next': next_url}, status=403)

            voter_hash = derive_voter_identity_hash(epic_number, phone_number)
            voter, created = VoterIdentity.objects.get_or_create(voter_hash=voter_hash)
            voter.is_verified = True
            voter.save()

            request.session['voter_hash'] = voter_hash
            request.session['voter_epic'] = epic_number
            messages.success(request, f"Citizen Identity whitelisted via API Setu Sandbox. Voter Hash: {voter_hash[:16]}...")
            return redirect(next_url)

        elif action == 'login':
            epic_number = request.POST.get('epic_number', '').strip().upper()
            phone_number = request.POST.get('phone_number', '').strip()
            otp = request.POST.get('otp', '').strip()

            if not epic_number or not phone_number:
                messages.error(request, "EPIC Voter ID and Registered Mobile Number are required.")
                return render(request, 'api/auth_voter.html', {'active_tab': 'login', 'next': next_url})

            SANDBOX_OTP = "749201"
            if not otp or otp != SANDBOX_OTP:
                messages.error(request, "Invalid Security OTP. Use sandbox code: 749201")
                return render(request, 'api/auth_voter.html', {'active_tab': 'login', 'next': next_url})

            voter_hash = derive_voter_identity_hash(epic_number, phone_number)
            if not VoterIdentity.objects.filter(voter_hash=voter_hash, is_verified=True).exists():
                messages.error(request, f"No verified voter record found for EPIC {epic_number}. Please register first.")
                return render(request, 'api/auth_voter.html', {'active_tab': 'register', 'next': next_url})

            request.session['voter_hash'] = voter_hash
            request.session['voter_epic'] = epic_number
            messages.success(request, "Authentication verified. Single-use voting session authorized.")
            return redirect(next_url)

    context = {
        'next': next_url,
        'active_tab': request.GET.get('tab', 'login'),
        'has_voter_session': bool(request.session.get('voter_hash')),
    }
    return render(request, 'api/auth_voter.html', context)


def admin_auth_view(request):
    """
    Standard credential-based login strictly for users with is_staff=True.
    """
    next_url = request.POST.get('next') or request.GET.get('next') or '/admin-panel/'

    if request.user.is_authenticated and (request.user.is_staff or request.user.is_superuser):
        return redirect(next_url)

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()

        user = authenticate(request, username=username, password=password)
        if user is not None:
            if user.is_staff or user.is_superuser:
                login(request, user)
                messages.success(request, f"Welcome, Administrator {user.username}. Security terminal activated.")
                return redirect(next_url)
            else:
                messages.error(request, "Access Denied: Staff/Superuser administrative privileges required.")
        else:
            messages.error(request, "Authentication Failed: Invalid username or password.")

    return render(request, 'api/auth_admin.html', {'next': next_url})


def auditor_auth_view(request):
    """
    Gated authentication portal for Certified Institutional Observers.
    Registration requires a valid AUDITOR_TRUST_SECRET invite token.
    """
    next_url = request.POST.get('next') or request.GET.get('next') or '/auditor/'

    if request.method == 'POST':
        action = request.POST.get('action', 'login')

        if action == 'login':
            username = request.POST.get('username', '').strip()
            password = request.POST.get('password', '').strip()

            user = authenticate(request, username=username, password=password)
            if user is not None:
                profile = getattr(user, 'auditor_profile', None)
                if (profile and profile.is_approved) or user.is_staff or user.is_superuser:
                    login(request, user)
                    messages.success(request, f"Auditor session authorized for institutional observer: {user.username}.")
                    return redirect(next_url)
                else:
                    messages.error(request, "Account Pending Verification: Your institutional auditor account requires Election Authority approval.")
                    return render(request, 'api/auth_auditor.html', {'active_tab': 'login', 'next': next_url})
            else:
                messages.error(request, "Invalid auditor credentials.")
                return render(request, 'api/auth_auditor.html', {'active_tab': 'login', 'next': next_url})

        elif action == 'register':
            username = request.POST.get('username', '').strip()
            password = request.POST.get('password', '').strip()
            organization = request.POST.get('organization', '').strip()
            trust_invite_code = request.POST.get('trust_invite_code', '').strip()

            if not username or not password or not organization:
                messages.error(request, "Username, Password, and Organization are mandatory.")
                return render(request, 'api/auth_auditor.html', {'active_tab': 'register', 'next': next_url})

            # Gatekeeper Logic: Validate Trust Invite Code
            if trust_invite_code != AUDITOR_TRUST_SECRET:
                messages.error(request, "Access restricted to verified institutional sources only. Invalid Trust Invite Token.")
                return render(request, 'api/auth_auditor.html', {'active_tab': 'register', 'next': next_url}, status=403)

            if User.objects.filter(username=username).exists():
                messages.error(request, f"Username '{username}' already exists. Please choose a different handle.")
                return render(request, 'api/auth_auditor.html', {'active_tab': 'register', 'next': next_url})

            user = User.objects.create_user(username=username, password=password)
            token_hash = hashlib.sha256(trust_invite_code.encode('utf-8')).hexdigest()
            AuditorProfile.objects.create(
                user=user,
                organization=organization,
                access_token_hash=token_hash,
                is_approved=True
            )
            login(request, user)
            messages.success(request, f"Institutional Observer identity registered and verified for {organization}. Access granted to Public Auditor Portal.")
            return redirect(next_url)

    context = {
        'next': next_url,
        'active_tab': request.GET.get('tab', 'login'),
    }
    return render(request, 'api/auth_auditor.html', context)


def logout_view(request):
    """
    Terminates all active sessions (Voter session, Admin session, Auditor session)
    and redirects to the portal selection landing page.
    """
    request.session.flush()
    logout(request)
    messages.info(request, "All active sessions have been securely terminated.")
    return redirect('/')


# ═══════════════════════════════════════════════════════════════════════════════
#  PROTECTED SSR PORTAL VIEWS (RBAC ENFORCED)
# ═══════════════════════════════════════════════════════════════════════════════

@voter_required
def voter_portal(request):
    """
    Renders the voter dashboard. Protected by @voter_required.
    """
    active_election = Election.objects.order_by('-created_at').first()
    candidates = []
    if active_election:
        candidates = Candidate.objects.filter(election=active_election).order_by('candidate_id')

    context = {
        'candidates':        candidates,
        'active_election':   active_election,
        'voter_hash':        request.session.get('voter_hash'),
        'voter_epic':        request.session.get('voter_epic'),
        'security_features': [
            'SHA-256 Hashed Identity',
            'Zero-Knowledge Proof',
            'HMAC-Signed QR Token',
            'Gas-Free Relayer',
            'Polygon Blockchain',
            'Nullifier Anti-Replay',
        ],
    }
    return render(request, 'api/voter_dashboard.html', context)


@admin_required
def admin_portal(request):
    """
    Renders the admin dashboard. Protected by @admin_required.
    """
    active_election = Election.objects.order_by('-created_at').first()
    candidates      = Candidate.objects.select_related('election').all().order_by('candidate_id')
    voters          = VoterIdentity.objects.all().order_by('-registered_at')[:50]
    threats         = ThreatLog.objects.filter(resolved=False).order_by('-timestamp')[:20]

    total_voters  = voters.count()
    voted_count   = VoterIdentity.objects.filter(has_voted=True).count()
    turnout_pct   = round((voted_count / total_voters * 100), 1) if total_voters > 0 else 0

    context = {
        'active_election': active_election,
        'candidates':      candidates,
        'voters':          voters,
        'threats':         threats,
        'voter_stats': {
            'total':       total_voters,
            'voted':       voted_count,
            'turnout':     f'{turnout_pct}%',
            'turnout_pct': turnout_pct,
        },
        'stats': [
            {'icon': '🗳️', 'label': 'Total Requests',  'value': '—'},
            {'icon': '🚫', 'label': 'IPs Blocked',     'value': threats.count()},
            {'icon': '✅', 'label': 'Votes Cast',       'value': voted_count},
            {'icon': '🧠', 'label': 'ML Model',         'value': 'Active'},
        ],
        'nav_items': [
            {'icon': '🏠', 'label': 'Overview',     'anchor': 'overview'},
            {'icon': '🗳️', 'label': 'Elections',    'anchor': 'elections'},
            {'icon': '👥', 'label': 'Voters',        'anchor': 'voters'},
            {'icon': '🛡️', 'label': 'Threat AI',    'anchor': 'threat-ai'},
            {'icon': '🌳', 'label': 'Merkle Root',   'anchor': 'merkle'},
            {'icon': '📊', 'label': 'Candidates',    'anchor': 'candidates'},
        ],
        'table_headers': ['ID', 'Name', 'Election', 'Status'],
    }
    return render(request, 'api/admin_dashboard.html', context)


@auditor_required
def auditor_portal(request):
    """
    Renders the public auditor dashboard. Protected by @auditor_required.
    """
    active_election = Election.objects.order_by('-created_at').first()
    candidates      = Candidate.objects.filter(
        election=active_election
    ).order_by('candidate_id') if active_election else []

    total_votes = VoterIdentity.objects.filter(has_voted=True).count()

    # Attempt to fetch real on-chain tallies via Web3
    w3 = None
    voting_contract = None
    try:
        w3 = Web3(Web3.HTTPProvider(POLYGON_RPC_URL))
        if w3.is_connected() and VOTING_CONTRACT_ADDRESS != '0xYourDeployedContractAddress':
            voting_contract = w3.eth.contract(address=VOTING_CONTRACT_ADDRESS, abi=VOTING_ABI)
    except Exception:
        pass

    candidate_data = []
    for c in candidates:
        real_count = 0
        if voting_contract:
            try:
                real_count = voting_contract.functions.getTally(c.candidate_id).call()
            except Exception:
                real_count = 0
        pct = round(real_count / total_votes * 100, 1) if total_votes > 0 else 0
        candidate_data.append({
            'candidate_id': c.candidate_id,
            'name':         c.name,
            'vote_count':   real_count,
            'vote_pct':     pct,
        })

    context = {
        'active_election':   active_election,
        'candidates':        candidate_data,
        'voter_count':       VoterIdentity.objects.count(),
        'spent_nullifiers':  total_votes,
        'merkle_root':       active_election.merkle_root if active_election else None,
        'is_root_locked':    active_election.is_root_locked if active_election else False,
        'nullifiers':        [],
        'trust_badges': [
            {'icon': '🔒', 'label': 'End-to-End Encrypted'},
            {'icon': '🌐', 'label': 'Public & Open'},
            {'icon': '⬡',  'label': 'Polygon Verified'},
            {'icon': '🧮', 'label': 'Mathematically Auditable'},
            {'icon': '🕵️', 'label': 'Anonymous Ballots'},
        ],
    }
    return render(request, 'api/auditor_dashboard.html', context)

