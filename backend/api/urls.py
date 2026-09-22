from django.urls import path
from . import views

urlpatterns = [
    # ── REST API Endpoints (untouched) ────────────────────────────────────────
    # The gasless ZK-proof relayer that broadcasts to Polygon
    path('v1/cast-vote/', views.submit_vote_relayer, name='submit_vote_relayer'),

    # API Setu KYC voter registration — returns voter_hash
    path('v1/register/', views.verify_epic_and_register, name='verify_epic_and_register'),

    # ── SSR Portal Views ──────────────────────────────────────────────────────
    # Voter dashboard: /voter/
    path('voter/', views.voter_portal, name='voter_portal'),

    # Admin dashboard: /admin-panel/
    path('admin-panel/', views.admin_portal, name='admin_portal'),

    # Public auditor portal: /auditor/
    path('auditor/', views.auditor_portal, name='auditor_portal'),
]
