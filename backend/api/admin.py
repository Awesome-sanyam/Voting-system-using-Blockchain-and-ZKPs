from django.contrib import admin
from .models import Election, Candidate, VoterIdentity, ThreatLog

@admin.register(Election)
class ElectionAdmin(admin.ModelAdmin):
    list_display = ('title', 'start_timestamp', 'end_timestamp', 'is_root_locked')
    readonly_fields = ('created_at',)
    list_filter = ('is_root_locked',)

@admin.register(Candidate)
class CandidateAdmin(admin.ModelAdmin):
    list_display = ('candidate_id', 'name', 'election')
    search_fields = ('name',)

@admin.register(VoterIdentity)
class VoterIdentityAdmin(admin.ModelAdmin):
    list_display = ('voter_hash_display', 'is_verified', 'has_voted', 'registered_at')
    
    # Critical Security Measure: The Admin cannot manually edit a voter's hash or voting status
    readonly_fields = ('voter_hash', 'has_voted', 'registered_at') 
    list_filter = ('is_verified', 'has_voted')
    
    def voter_hash_display(self, obj):
        # Only show the first and last few characters of the hash for visual cleanliness
        if obj.voter_hash and len(obj.voter_hash) > 16:
            return f"{obj.voter_hash[:10]}...{obj.voter_hash[-6:]}"
        return obj.voter_hash
    voter_hash_display.short_description = 'Voter Identity Hash'

@admin.register(ThreatLog)
class ThreatLogAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'threat_score', 'timestamp', 'resolved')
    list_filter = ('resolved',)
    search_fields = ('ip_address',)