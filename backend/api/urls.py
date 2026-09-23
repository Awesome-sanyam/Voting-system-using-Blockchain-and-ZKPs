from django.urls import path
from . import views

urlpatterns = [
    # ── REST API Endpoints ────────────────────────────────────────────────────
    # The gasless ZK-proof relayer that broadcasts to Polygon
    path('v1/cast-vote/', views.submit_vote_relayer, name='submit_vote_relayer'),

    # API Setu KYC voter registration — returns voter_hash
    path('v1/register/', views.verify_epic_and_register, name='verify_epic_and_register'),

    # ── Portal Selection & Multi-Role Authentication ──────────────────────────
    path('',              views.portal_select,      name='portal_select_api'),
    path('auth/voter/',   views.voter_auth_view,    name='voter_auth_api'),
    path('auth/admin/',   views.admin_auth_view,    name='admin_auth_api'),
    path('auth/auditor/', views.auditor_auth_view,  name='auditor_auth_api'),
    path('logout/',       views.logout_view,        name='logout_api'),

    # ── Protected SSR Portal Views ────────────────────────────────────────────
    path('voter/',       views.voter_portal,       name='voter_portal'),
    path('admin-panel/', views.admin_portal,       name='admin_portal'),
    path('auditor/',     views.auditor_portal,      name='auditor_portal'),
]
