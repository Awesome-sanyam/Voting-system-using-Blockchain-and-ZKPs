from django.contrib import admin
from .models import Election, Candidate, VoterIdentity, ThreatLog, BallotRecord, AuditorProfile, AuditorInviteToken, ElectionVoterRoll

@admin.register(Election)
class ElectionAdmin(admin.ModelAdmin):
    list_display = ('title', 'start_timestamp', 'end_timestamp', 'is_root_locked')
    readonly_fields = ('created_at',)
    list_filter = ('is_root_locked',)

@admin.register(Candidate)
class CandidateAdmin(admin.ModelAdmin):
    list_display = ('candidate_id', 'name', 'party', 'election')
    search_fields = ('name', 'party')

@admin.register(VoterIdentity)
class VoterIdentityAdmin(admin.ModelAdmin):
    list_display = ('voter_hash_display', 'is_verified', 'has_voted', 'registered_at')
    readonly_fields = ('voter_hash', 'has_voted', 'registered_at') 
    list_filter = ('is_verified', 'has_voted')
    
    def voter_hash_display(self, obj):
        if obj.voter_hash and len(obj.voter_hash) > 16:
            return f"{obj.voter_hash[:10]}...{obj.voter_hash[-6:]}"
        return obj.voter_hash
    voter_hash_display.short_description = 'Voter Identity Hash'

@admin.register(ThreatLog)
class ThreatLogAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'threat_score', 'payload_size', 'timestamp', 'resolved')
    list_filter = ('resolved',)
    search_fields = ('ip_address',)

@admin.register(BallotRecord)
class BallotRecordAdmin(admin.ModelAdmin):
    list_display = ('transaction_hash_display', 'candidate', 'nullifier_display', 'block_number', 'timestamp')
    readonly_fields = ('transaction_hash', 'nullifier', 'candidate', 'block_number', 'gas_used', 'timestamp')
    
    def transaction_hash_display(self, obj):
        return f"{obj.transaction_hash[:12]}...{obj.transaction_hash[-6:]}"
    transaction_hash_display.short_description = 'Tx Hash'

    def nullifier_display(self, obj):
        return f"{obj.nullifier[:12]}...{obj.nullifier[-6:]}"
    nullifier_display.short_description = 'Nullifier'

@admin.register(AuditorProfile)
class AuditorProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'organization', 'is_approved', 'created_at')
    list_filter = ('is_approved',)
    search_fields = ('organization', 'user__username')

@admin.register(AuditorInviteToken)
class AuditorInviteTokenAdmin(admin.ModelAdmin):
    list_display = ('token_code', 'organization', 'is_active', 'used_count', 'max_uses', 'created_at', 'expires_at')
    list_filter = ('is_active',)
    search_fields = ('token_code', 'organization')