"""
URL configuration for BlockVote India.
"""
from django.contrib import admin
from django.urls import path, include
from api import views as api_views

urlpatterns = [
    # ── Django Admin ──────────────────────────────────────────────────────────
    path('admin/', admin.site.urls),

    # ── REST API Endpoints (accessed by JS fetch()) ───────────────────────────
    path('api/', include('api.urls')),

    # ── Portal Selection Hub (Landing Page) ──────────────────────────────────
    path('', api_views.portal_select, name='portal_select'),

    # ── Multi-Role Authentication Endpoints ──────────────────────────────────
    path('auth/voter/',   api_views.voter_auth_view,   name='voter_auth'),
    path('auth/admin/',   api_views.admin_auth_view,   name='admin_auth'),
    path('auth/auditor/', api_views.auditor_auth_view, name='auditor_auth'),
    path('logout/',       api_views.logout_view,       name='logout'),

    # ── Protected SSR Portal Views ───────────────────────────────────────────
    path('voter/',       api_views.voter_portal,   name='voter_portal'),
    path('admin-panel/', api_views.admin_portal,   name='admin_portal'),
    path('auditor/',     api_views.auditor_portal,  name='auditor_portal'),
]