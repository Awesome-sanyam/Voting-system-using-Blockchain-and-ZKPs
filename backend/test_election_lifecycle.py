"""
End-to-end unit and lifecycle test for Election Lifecycle and Voter Roll Locking:
- Election Creation (DRAFT)
- Voter Roll management (Add/Remove in DRAFT)
- Gatekeeping: Voter portal blocked during DRAFT or before start
- Election Activation (DRAFT -> ACTIVE)
- Complete voter roll locking: Admin CANNOT add or remove voters once started
- Identity hashing into VoterIdentity whitelist
- Election Closure (ACTIVE -> CLOSED)
"""
import os
import sys
import django
import time

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from django.test import Client
from django.contrib.auth.models import User
from api.models import Election, ElectionVoterRoll, VoterIdentity, Candidate
import json

def run_election_lifecycle_tests():
    print("=" * 70)
    print("▶ RUNNING ELECTION LIFECYCLE & IMMUTABLE VOTER ROLL TESTS")
    print("=" * 70)

    # Setup admin user
    admin_user, _ = User.objects.get_or_create(username='admin_tester', defaults={'is_staff': True, 'is_superuser': True})
    admin_user.set_password('AdminTest@2026')
    admin_user.save()

    client = Client()
    # Log in admin
    login_res = client.post('/auth/admin/', {'username': 'admin_tester', 'password': 'AdminTest@2026'})
    assert login_res.status_code == 302, f"Admin login failed: {login_res.status_code}"
    print("✅ [PASS] 1. Admin authenticated successfully")

    # Clean existing test elections and any active/draft elections
    Election.objects.filter(status__in=[Election.STATUS_DRAFT, Election.STATUS_ACTIVE]).delete()

    now = int(time.time())
    start_ts = now + 10      # 10s in future
    end_ts = start_ts + 3600  # 1 hour duration

    # 1. Create Election in DRAFT
    create_payload = {
        'title': 'Test Automated Election 2026',
        'description': 'Automated lifecycle validation election',
        'start_timestamp': start_ts,
        'end_timestamp': end_ts
    }
    res = client.post('/api/v1/elections/create/', json.dumps(create_payload), content_type='application/json')
    assert res.status_code == 201, f"Expected 201 Created, got {res.status_code}: {res.content}"
    data = res.json()
    election_id = data['election_id']
    election = Election.objects.get(pk=election_id)
    assert election.status == Election.STATUS_DRAFT
    assert election.is_voter_list_locked is False
    print(f"✅ [PASS] 2. Election created in DRAFT state (ID={election_id}, Locked=False)")

    # 2. Add Voters to Roll while in DRAFT
    voter1 = {'epic_number': 'TESTVOTER001', 'phone_number': '9876543210', 'voter_name': 'Alpha Tester'}
    voter2 = {'epic_number': 'TESTVOTER002', 'phone_number': '9876543211', 'voter_name': 'Beta Tester'}

    res_add1 = client.post(f'/api/v1/elections/{election_id}/voters/add/', json.dumps(voter1), content_type='application/json')
    assert res_add1.status_code == 201, f"Failed to add voter 1: {res_add1.content}"
    voter1_entry_id = res_add1.json()['roll_entry_id']

    res_add2 = client.post(f'/api/v1/elections/{election_id}/voters/add/', json.dumps(voter2), content_type='application/json')
    assert res_add2.status_code == 201, f"Failed to add voter 2: {res_add2.content}"
    voter2_entry_id = res_add2.json()['roll_entry_id']
    assert ElectionVoterRoll.objects.filter(election=election).count() == 2
    print(f"✅ [PASS] 3. Voters added to DRAFT roll (Total on roll: 2)")

    # 3. Test Duplicate Prevention
    res_dup = client.post(f'/api/v1/elections/{election_id}/voters/add/', json.dumps(voter1), content_type='application/json')
    assert res_dup.status_code == 409, f"Duplicate voter was not rejected with 409! Got {res_dup.status_code}"
    print(f"✅ [PASS] 4. Duplicate EPIC correctly rejected (HTTP 409 Conflict)")

    # 4. Test Removing Voter from DRAFT roll
    res_del = client.delete(f'/api/v1/elections/{election_id}/voters/{voter2_entry_id}/remove/')
    assert res_del.status_code == 200, f"Failed to delete voter 2: {res_del.content}"
    assert ElectionVoterRoll.objects.filter(election=election).count() == 1
    print(f"✅ [PASS] 5. Voter removed from DRAFT roll (Remaining: 1)")

    # Re-add voter 2
    res_readd = client.post(f'/api/v1/elections/{election_id}/voters/add/', json.dumps(voter2), content_type='application/json')
    assert res_readd.status_code == 201
    print(f"✅ [PASS] 6. Voter re-added to roll (Total on roll: 2)")

    # 5. Verify Voter Portal is blocked when election is not ACTIVE
    voter_client = Client()
    # Try voter auth page - should show alert or redirect when no active election
    res_vauth = voter_client.get('/voter/')
    assert res_vauth.status_code == 302, "Voter was able to access /voter/ during DRAFT!"
    print(f"✅ [PASS] 7. Voter portal access prevented during DRAFT status (HTTP 302 redirect)")

    # Add candidates to election so it can be started
    Candidate.objects.create(election=election, candidate_id=1, name="Candidate One", party="Democratic Front")
    Candidate.objects.create(election=election, candidate_id=2, name="Candidate Two", party="Progressive Alliance")

    # 6. Start Election (DRAFT -> ACTIVE)
    res_start = client.post(f'/api/v1/elections/{election_id}/start/')
    assert res_start.status_code == 200, f"Failed to start election: {res_start.content}"
    election.refresh_from_db()
    assert election.status == Election.STATUS_ACTIVE
    assert election.is_voter_list_locked is True
    print(f"✅ [PASS] 8. Election successfully started (Status: ACTIVE, Voter List: LOCKED)")

    # Check that entries in ElectionVoterRoll are now hashed into VoterIdentity
    roll_entries = ElectionVoterRoll.objects.filter(election=election)
    for entry in roll_entries:
        assert entry.is_hashed is True, f"Entry {entry.epic_number} not marked as hashed!"
        assert entry.voter_hash != "", f"Entry {entry.epic_number} has empty voter_hash!"
        assert VoterIdentity.objects.filter(voter_hash=entry.voter_hash).exists(), f"VoterIdentity not found for {entry.voter_hash}"
    print(f"✅ [PASS] 9. All voter roll entries hashed and whitelisted into VoterIdentity")

    # 7. CRITICAL TEST: Admin CANNOT add voters once election is started
    voter3 = {'epic_number': 'TESTVOTER003', 'phone_number': '9876543212', 'voter_name': 'Late Voter'}
    res_locked_add = client.post(f'/api/v1/elections/{election_id}/voters/add/', json.dumps(voter3), content_type='application/json')
    assert res_locked_add.status_code == 403, f"Admin was able to add voter after election started! Got {res_locked_add.status_code}"
    print(f"✅ [PASS] 10. STRICT IMMUTABILITY: Adding voter blocked when election is ACTIVE (HTTP 403 Forbidden)")

    # 8. CRITICAL TEST: Admin CANNOT remove voters once election is started
    res_locked_del = client.delete(f'/api/v1/elections/{election_id}/voters/{voter1_entry_id}/remove/')
    assert res_locked_del.status_code == 403, f"Admin was able to remove voter after election started! Got {res_locked_del.status_code}"
    print(f"✅ [PASS] 11. STRICT IMMUTABILITY: Removing voter blocked when election is ACTIVE (HTTP 403 Forbidden)")

    # 9. Whitelisted voter can authenticate and access Voter Portal now that election is ACTIVE
    otp_res = voter_client.post('/api/v1/send-otp/', json.dumps({
        'epic_number': 'TESTVOTER001',
        'phone_number': '9876543210'
    }), content_type='application/json')
    assert otp_res.status_code == 200, f"Failed to send OTP: {otp_res.content}"
    otp_code = voter_client.session.get('voter_otp')
    assert otp_code is not None, "OTP was not saved in session!"

    login_post = voter_client.post('/auth/voter/', {
        'action': 'login',
        'epic_number': 'TESTVOTER001',
        'phone_number': '9876543210',
        'otp': otp_code,
        'next': '/voter/'
    }, follow=True)
    assert login_post.status_code == 200
    res_dash = voter_client.get('/voter/')
    assert res_dash.status_code == 200
    print(f"✅ [PASS] 12. Whitelisted voter authenticated and accessed Voter Portal (HTTP 200)")

    # 10. Close Election
    res_close = client.post(f'/api/v1/elections/{election_id}/close/')
    assert res_close.status_code == 200, f"Failed to close election: {res_close.content}"
    election.refresh_from_db()
    assert election.status == Election.STATUS_CLOSED
    print(f"✅ [PASS] 13. Election closed successfully (Status: CLOSED)")

    # 11. Attempting to add voter to CLOSED election is also blocked
    res_closed_add = client.post(f'/api/v1/elections/{election_id}/voters/add/', json.dumps(voter3), content_type='application/json')
    assert res_closed_add.status_code == 403
    print(f"✅ [PASS] 14. Adding voter blocked on CLOSED election (HTTP 403 Forbidden)")

    # Cleanup
    election.delete()
    print("=" * 70)
    print("🎉 ALL 14 ELECTION LIFECYCLE & VOTER ROLL TESTS PASSED PERFECTLY!")
    print("=" * 70)

if __name__ == '__main__':
    run_election_lifecycle_tests()
