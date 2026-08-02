from django.urls import path
from . import views

urlpatterns = [
    # Endpoint 1: The Gasless Relayer
    path('v1/cast-vote/', views.submit_vote_relayer, name='submit_vote_relayer'),
    
    # Endpoint 2: API Setu KYC Registration
    path('v1/register/', views.verify_epic_and_register, name='verify_epic_and_register'),
]
