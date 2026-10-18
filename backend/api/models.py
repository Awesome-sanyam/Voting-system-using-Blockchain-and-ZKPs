from django.db import models
from django.utils import timezone
import time


class Election(models.Model):
    """
    Stores the full lifecycle configuration for an election.
    Managed exclusively by the Administrator.

    Lifecycle:
        DRAFT   → Admin creates election, adds voters and candidates.
                  Voter list can be modified freely.
        ACTIVE  → Admin starts the election. Voter list is permanently locked.
                  Voter Portal becomes accessible to whitelisted citizens.
        CLOSED  → Election end_timestamp has passed. Voting is no longer possible.

    The 'status' field is the authoritative gate for voter portal access.
    The is_root_locked flag seals the Merkle Tree cryptographically when ACTIVE.
    """

    # ── Lifecycle Status ─────────────────────────────────────────────────────
    STATUS_DRAFT  = 'DRAFT'
    STATUS_ACTIVE = 'ACTIVE'
    STATUS_CLOSED = 'CLOSED'
    STATUS_CHOICES = [
        (STATUS_DRAFT,  'Draft — Registration Open'),
        (STATUS_ACTIVE, 'Active — Voting Open'),
        (STATUS_CLOSED, 'Closed — Election Ended'),
    ]

    # ── Core Fields ──────────────────────────────────────────────────────────
    title       = models.CharField(max_length=255, default="GLS University Capstone Election")
    description = models.TextField(blank=True, help_text="Official election description / mandate")
    status      = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default=STATUS_DRAFT,
        db_index=True,
        help_text="Authoritative lifecycle state. Set to ACTIVE by admin to start voting."
    )

    # ── Schedule ─────────────────────────────────────────────────────────────
    # Stored as Unix timestamps (UTC seconds) for precision and timezone safety.
    # The admin form converts local IST datetimes → UTC Unix before saving.
    start_timestamp = models.BigIntegerField(
        help_text="Unix timestamp (UTC) for election start — Voting opens from this moment."
    )
    end_timestamp = models.BigIntegerField(
        help_text="Unix timestamp (UTC) for election end — Voting closes after this moment."
    )

    # ── Cryptographic Lock ───────────────────────────────────────────────────
    # Computed from the voter whitelist Merkle tree. Set when Admin starts election.
    merkle_root   = models.CharField(max_length=66, blank=True, null=True,
                                     help_text="0x-prefixed 32-byte Merkle root hash")
    is_root_locked = models.BooleanField(
        default=False,
        help_text="True once the electoral roll is sealed and voter list is immutable."
    )

    # ── Metadata ─────────────────────────────────────────────────────────────
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(
        null=True, blank=True,
        help_text="Timestamp when admin activated the election."
    )

    # ── Computed Properties ───────────────────────────────────────────────────
    @property
    def is_active(self):
        """
        True only when:
          - status == ACTIVE AND
          - current UTC time is within [start_timestamp, end_timestamp]
        """
        if self.status != self.STATUS_ACTIVE:
            return False
        now = time.time()
        return self.start_timestamp <= now <= self.end_timestamp

    @property
    def is_closed(self):
        """True if election has ended (past end_timestamp) OR status is CLOSED."""
        if self.status == self.STATUS_CLOSED:
            return True
        return time.time() > self.end_timestamp

    @property
    def is_voter_list_locked(self):
        """
        Voter list is locked whenever the election is NOT in DRAFT state.
        Once started (ACTIVE or CLOSED), neither admin nor anyone else can modify it.
        """
        return self.status in (self.STATUS_ACTIVE, self.STATUS_CLOSED)

    @property
    def time_remaining_seconds(self):
        """Seconds remaining until election closes. Negative if already closed."""
        return int(self.end_timestamp - time.time())

    @property
    def time_to_start_seconds(self):
        """Seconds until election opens. Negative if already started or past start."""
        return int(self.start_timestamp - time.time())

    def __str__(self):
        return f"{self.title} [{self.status}]"

    class Meta:
        ordering = ['-created_at']


class Candidate(models.Model):
    """
    Stores the candidates available for selection in the Voter Portal.
    """
    election       = models.ForeignKey(Election, on_delete=models.CASCADE, related_name='candidates')
    candidate_id   = models.PositiveIntegerField(unique=True, help_text="Matches the ID on the smart contract")
    name           = models.CharField(max_length=150)
    party          = models.CharField(max_length=150, blank=True, default='Independent',
                                      help_text="Party or coalition name")
    party_symbol_url = models.URLField(blank=True, null=True)

    def __str__(self):
        return f"[{self.candidate_id}] {self.name} ({self.party})"


class ElectionVoterRoll(models.Model):
    """
    Admin-managed whitelist of eligible voters for a specific election.

    This is SEPARATE from VoterIdentity (which is a citizen's KYC self-registration).
    The ElectionVoterRoll is the official pre-approved voter list that the Election
    Authority adds BEFORE starting the election.

    Flow:
      1. Admin adds EPIC numbers to the ElectionVoterRoll (DRAFT phase).
      2. On election start, the server hashes all EPICs and creates/updates
         VoterIdentity records for each whitelisted EPIC.
      3. Voter list is LOCKED — no adds or removes allowed once election is ACTIVE.

    Privacy Design:
      We store the raw EPIC temporarily (only in DRAFT state). Once the election
      starts, the EPIC is hashed server-side (SHA-256 + salt) and the hash is
      stored in VoterIdentity. The raw EPIC is then cleared from this model.
    """
    election   = models.ForeignKey(Election, on_delete=models.CASCADE, related_name='voter_roll')
    epic_number = models.CharField(
        max_length=20,
        help_text="Raw EPIC Voter ID number (cleared after election starts)"
    )
    phone_number = models.CharField(
        max_length=20,
        blank=True,
        help_text="Registered mobile number for OTP dispatch"
    )
    voter_name   = models.CharField(max_length=150, blank=True, help_text="Full name for display only")
    voter_hash   = models.CharField(
        max_length=66, blank=True,
        help_text="SHA-256 hash computed on election start (populated from VoterIdentity)"
    )
    is_hashed    = models.BooleanField(
        default=False,
        help_text="True once EPIC has been hashed and VoterIdentity created"
    )
    added_by     = models.CharField(max_length=50, default='admin')
    added_at     = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('election', 'epic_number')
        ordering = ['added_at']

    def __str__(self):
        display = self.voter_name or self.epic_number
        return f"Roll[{self.election.title}] — {display}"


class VoterIdentity(models.Model):
    """
    The whitelist registry.
    Notice what is MISSING: Name, EPIC Number, Address, Phone Number.
    """
    # We only store the SHA-256 hash of (EPIC + Salt)
    voter_hash   = models.CharField(max_length=66, unique=True, primary_key=True)

    # Status flags
    is_verified  = models.BooleanField(default=False, help_text="Cleared by API Setu")
    has_voted    = models.BooleanField(default=False, help_text="Flipped to True when smart contract emits event")

    registered_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Voter: {self.voter_hash[:10]}... | Voted: {self.has_voted}"


class ThreatLog(models.Model):
    """
    Used by the Admin Dashboard to visualize attacks blocked by the AI microservice.
    """
    ip_address   = models.GenericIPAddressField()
    threat_score = models.FloatField(help_text="Anomaly confidence score from Scikit-Learn")
    payload_size = models.IntegerField(help_text="Size of the rejected payload in bytes")
    timestamp    = models.DateTimeField(default=timezone.now)
    resolved     = models.BooleanField(default=False)

    def __str__(self):
        return f"Threat from {self.ip_address} at {self.timestamp}"


class BallotRecord(models.Model):
    """
    Cryptographic on-chain ballot record for public audit and verification.
    Stores NO voter identity (zero names, zero phones, zero EPIC, zero IP).
    Only records the anonymous mathematical nullifier and on-chain transaction receipt.
    """
    candidate        = models.ForeignKey(Candidate, on_delete=models.CASCADE, related_name='ballots')
    nullifier        = models.CharField(max_length=100, unique=True, help_text="Poseidon cryptographic nullifier hash")
    transaction_hash = models.CharField(max_length=66, unique=True, help_text="0x-prefixed transaction hash")
    block_number     = models.PositiveIntegerField(default=1)
    gas_used         = models.PositiveIntegerField(default=284520)
    timestamp        = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Ballot {self.nullifier[:12]}... -> {self.candidate.name} (Tx: {self.transaction_hash[:10]}...)"


from django.contrib.auth.models import User

class AuditorProfile(models.Model):
    """
    Manages gated access for certified electoral observers and public auditors.
    Requires an authorized RSA/SHA-256 trusted invite token or administrator approval.
    """
    user             = models.OneToOneField(User, on_delete=models.CASCADE, related_name='auditor_profile')
    organization     = models.CharField(max_length=255, help_text="Observer institution, NGO, or Electoral agency")
    trust_token_hash = models.CharField(max_length=66, blank=True, help_text="SHA-256 hash of the trusted institutional invite token")
    is_approved      = models.BooleanField(default=False, help_text="Requires manual admin approval or valid trusted token")
    created_at       = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Auditor: {self.user.username} ({self.organization}) | Approved: {self.is_approved}"