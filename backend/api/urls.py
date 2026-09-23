from django.urls import path
from . import views

# ── REST API Endpoints (all prefixed at /api/ from config/urls.py) ────────────
# SSR portal routes (/, /voter/, /admin-panel/, /auditor/, /auth/*) are
# defined ONLY in config/urls.py to avoid duplicate name conflicts.
urlpatterns = [
    # Gasless ZK-proof relayer — broadcasts Groth16 proof to Polygon
    path('v1/cast-vote/',          views.submit_vote_relayer,      name='submit_vote_relayer'),

    # API Setu KYC voter registration — returns voter_hash
    path('v1/register/',           views.verify_epic_and_register, name='verify_epic_and_register'),

    # Admin: lock the Merkle root on-chain and in the Django DB
    path('v1/lock-merkle-root/',   views.lock_merkle_root,         name='lock_merkle_root'),

    # Public: returns the active election state (merkle_root, is_locked, election_id)
    # Used by zkp_prover.js to fetch the real Merkle root for proof generation
    path('v1/election-state/',     views.get_election_state,       name='get_election_state'),
]
