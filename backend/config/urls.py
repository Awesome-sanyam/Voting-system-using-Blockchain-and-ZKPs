"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
"""
from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView
from api import views as api_views

urlpatterns = [
    # ── Django Admin ──────────────────────────────────────────────────────────
    path('admin/', admin.site.urls),

    # ── REST API Endpoints (accessed by JS fetch()) ───────────────────────────
    path('api/', include('api.urls')),

    # ── SSR Portal Views ──────────────────────────────────────────────────────
    # These are rendered by Django directly — no separate frontend server needed
    path('voter/',       api_views.voter_portal,   name='voter_portal'),
    path('admin-panel/', api_views.admin_portal,   name='admin_portal'),
    path('auditor/',     api_views.auditor_portal,  name='auditor_portal'),

    # ── Homepage redirect → Voter Portal ─────────────────────────────────────
    path('', RedirectView.as_view(url='/voter/', permanent=False), name='home'),
]