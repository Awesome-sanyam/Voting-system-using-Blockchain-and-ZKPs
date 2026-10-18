from django.urls import path
from . import views

# ── REST API Endpoints (all prefixed at /api/ from config/urls.py) ────────────
# SSR portal routes (/, /voter/, /admin-panel/, /auditor/, /auth/*) are
# defined ONLY in config/urls.py to avoid duplicate name conflicts.
urlpatterns = [
    # Gasless ZK-proof relayer — broadcasts Groth16 proof to Polygon
    path('v1/cast-vote/',          views.submit_vote_relayer,      name='submit_vote_relayer'),
    path('v1/relayer/submit-vote/', views.submit_vote_relayer,     name='submit_vote_relayer_alias'),

    # API Setu KYC voter registration — returns voter_hash
    path('v1/register/',           views.verify_epic_and_register, name='verify_epic_and_register'),

    # Dynamic OTP generation — generates random OTP, stores in session (sandbox: returns it)
    path('v1/send-otp/',           views.generate_voter_otp,       name='generate_voter_otp'),

    # Admin: lock the Merkle root on-chain and in the Django DB
    path('v1/lock-merkle-root/',   views.lock_merkle_root,         name='lock_merkle_root'),

    # Public: returns the active election state (merkle_root, is_locked, election_id)
    # Used by zkp_prover.js to fetch the real Merkle root for proof generation
    path('v1/election-state/',     views.get_election_state,       name='get_election_state'),

    # Independent Cryptographic Audit Engine — performs 6-point mathematical validation
    path('v1/audit/verify/',       views.execute_audit_verification, name='execute_audit_verification'),

    # Public Mempool — returns live confirmed on-chain ballot transactions
    path('v1/auditor/mempool/',    views.get_auditor_mempool,       name='get_auditor_mempool'),

    # Blockchain Status — returns RPC connection, latest block height, and contract addresses
    path('v1/blockchain/status/',  views.get_blockchain_status,    name='get_blockchain_status'),
]

