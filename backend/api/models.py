from django.db import models
from django.utils import timezone

class Election(models.Model):
    """
    Stores the configuration for the election lifecycle.
    Managed exclusively by the Administrator.
    """
    title = models.CharField(max_length=255, default="GLS University Capstone Election")
    start_timestamp = models.BigIntegerField(help_text="Unix timestamp for election start")
    end_timestamp = models.BigIntegerField(help_text="Unix timestamp for election end")
    
    # The cryptographic lock
    merkle_root = models.CharField(max_length=66, blank=True, null=True, help_text="0x-prefixed 32-byte hash")
    is_root_locked = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} (Locked: {self.is_root_locked})"


class Candidate(models.Model):
    """
    Stores the candidates available for selection in the Flutter UI.
    """
    election = models.ForeignKey(Election, on_delete=models.CASCADE, related_name='candidates')
    candidate_id = models.PositiveIntegerField(unique=True, help_text="Matches the ID on the smart contract")
    name = models.CharField(max_length=150)
    party_symbol_url = models.URLField(blank=True, null=True)
    
    def __str__(self):
        return f"[{self.candidate_id}] {self.name}"


class VoterIdentity(models.Model):
    """
    The whitelist registry. 
    Notice what is MISSING: Name, EPIC Number, Address, Phone Number.
    """
    # We only store the SHA-256 hash of (EPIC + Salt)
    voter_hash = models.CharField(max_length=66, unique=True, primary_key=True)
    
    # Status flags
    is_verified = models.BooleanField(default=False, help_text="Cleared by API Setu")
    has_voted = models.BooleanField(default=False, help_text="Flipped to True when smart contract emits event")
    
    registered_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Voter: {self.voter_hash[:10]}... | Voted: {self.has_voted}"


class ThreatLog(models.Model):
    """
    Used by the Admin Dashboard to visualize attacks blocked by the AI microservice.
    """
    ip_address = models.GenericIPAddressField()
    threat_score = models.FloatField(help_text="Anomaly confidence score from Scikit-Learn")
    payload_size = models.IntegerField(help_text="Size of the rejected payload in bytes")
    timestamp = models.DateTimeField(default=timezone.now)
    resolved = models.BooleanField(default=False)

    def __str__(self):
        return f"Threat from {self.ip_address} at {self.timestamp}"


from django.contrib.auth.models import User

class AuditorProfile(models.Model):
    """
    Manages gated access for certified electoral observers and public auditors.
    Requires an authorized RSA/SHA-256 trusted invite token or administrator approval.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='auditor_profile')
    organization = models.CharField(max_length=255, help_text="Observer institution, NGO, or Electoral agency")
    access_token_hash = models.CharField(max_length=66, blank=True, help_text="SHA-256 hash of the trusted invite token")
    is_approved = models.BooleanField(default=False, help_text="Requires manual admin approval or valid trusted token")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Auditor: {self.user.username} ({self.organization}) | Approved: {self.is_approved}"