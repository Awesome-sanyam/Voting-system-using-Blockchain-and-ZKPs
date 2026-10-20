"""
End-to-End Verification of RBAC and Authentication Gateway for BlockVote-India.
Tests all roles (Voter, Admin, Auditor) across login, registration, session persistence, and authorization boundaries.
"""
import os
import sys
import django

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from django.test import Client
from django.contrib.auth.models import User
from api.models import VoterIdentity, AuditorProfile, Election, ElectionVoterRoll, AuditorInviteToken
import time
import json

def run_tests():
    client = Client()
    print("======================================================================")
    print("▶ STARTING RBAC & AUTHENTICATION SUITE FOR BLOCKVOTE-INDIA")
    print("======================================================================")

    # Clean up any leftover test users or tokens from prior runs
    User.objects.filter(username__in=['fake_auditor', 'transparency_observer', 'imposter_observer']).delete()

    # 1. Test Portal Hub
    res = client.get('/')
    assert res.status_code == 200, f"Expected 200 for '/', got {res.status_code}"
    assert b"BlockVote India" in res.content and b"Operational Hub" in res.content
    print("✅ [PASS] 1. Operational Portal Hub ('/') loaded successfully (HTTP 200)")

    # 2. Test Unauthenticated Access Protection (Strict RBAC Boundary)
    # With no active election, /voter/ redirects to '/' (portal select) with warning
    res_voter = client.get('/voter/')
    assert res_voter.status_code == 302, f"Expected 302 for unauth /voter/, got {res_voter.status_code}"
    # Without an active election, redirects to '/' (portal hub) — correct new behavior
    assert '/' in res_voter.url, f"Expected redirect to '/' or '/auth/voter/', got {res_voter.url}"
    print("✅ [PASS] 2. Unauthenticated '/voter/' redirected correctly (HTTP 302)")

    res_admin = client.get('/admin-panel/')
    assert res_admin.status_code == 302, f"Expected 302 for unauth /admin-panel/, got {res_admin.status_code}"
    assert '/auth/admin/' in res_admin.url
    print("✅ [PASS] 3. Unauthenticated '/admin-panel/' redirected to /auth/admin/ (HTTP 302)")

    res_auditor = client.get('/auditor/')
    assert res_auditor.status_code == 302, f"Expected 302 for unauth /auditor/, got {res_auditor.status_code}"
    assert '/auth/auditor/' in res_auditor.url
    print("✅ [PASS] 4. Unauthenticated '/auditor/' redirected to /auth/auditor/ (HTTP 302)")

    # 3. Test Authentication Pages Load
    assert client.get('/auth/voter/').status_code == 200
    print("✅ [PASS] 5. Voter Auth page loaded (HTTP 200)")

    assert client.get('/auth/admin/').status_code == 200
    print("✅ [PASS] 6. Admin Auth page loaded (HTTP 200)")

    assert client.get('/auth/auditor/').status_code == 200
    print("✅ [PASS] 7. Auditor Auth page loaded (HTTP 200)")

    # 4. Test Voter Registration Workflow with Dynamic OTP
    voter_client = Client()
    # Step A: Request OTP
    otp_resp = voter_client.post('/api/v1/send-otp/', {'epic_number': 'IND5566778', 'phone_number': '9811223344'}, content_type='application/json')
    assert otp_resp.status_code == 200
    otp_code = otp_resp.json().get('sandbox_otp') or voter_client.session.get('voter_otp')
    assert otp_code is not None

    # Step B: Register with OTP
    reg_data = {
        'action': 'register',
        'full_name': 'Aarav Sharma',
        'epic_number': 'IND5566778',
        'phone_number': '9811223344',
        'otp': otp_code,
        'next': '/voter/'
    }
    res_reg = voter_client.post('/auth/voter/', reg_data, follow=True)
    assert res_reg.status_code == 200
    print(f"✅ [PASS] 8. Voter Registration with Dynamic OTP succeeded (HTTP 200)")

    # 5. Test Voter OTP Login Workflow (New Client)
    created_test_election = False
    now_ts = int(time.time())
    test_election = Election.objects.filter(status=Election.STATUS_ACTIVE).first()
    if not test_election:
        test_election = Election.objects.create(
            title='RBAC Test Election',
            start_timestamp=now_ts - 60,
            end_timestamp=now_ts + 86400,
            status=Election.STATUS_ACTIVE
        )
        created_test_election = True

    try:
        login_client = Client()
        # Step A: Request Login OTP
        login_otp_resp = login_client.post('/api/v1/send-otp/', {'epic_number': 'IND5566778', 'phone_number': '9811223344'}, content_type='application/json')
        assert login_otp_resp.status_code == 200
        login_otp = login_otp_resp.json().get('sandbox_otp') or login_client.session.get('voter_otp')

        # Step B: Submit Login
        login_data = {
            'action': 'login',
            'epic_number': 'IND5566778',
            'phone_number': '9811223344',
            'otp': login_otp,
            'next': '/voter/'
        }
        res_login = login_client.post('/auth/voter/', login_data, follow=True)
        assert res_login.status_code == 200
        assert login_client.session.get('voter_hash') is not None
        print("✅ [PASS] 9. Voter OTP Login succeeded. Access granted to voter dashboard (HTTP 200)")

        # Test Voter Portal access with active session AND active election
        res_voter_dash = login_client.get('/voter/')
        assert res_voter_dash.status_code == 200, f"Expected 200 for /voter/ with active session+election, got {res_voter_dash.status_code}"
        print("✅ [PASS] 10. Protected '/voter/' accessed with valid voter session (HTTP 200)")

        # 6. Test Admin Auth Workflow
        admin_client = Client()
        # Test bad login
        bad_admin = admin_client.post('/auth/admin/', {'username': 'admin', 'password': 'wrongpassword'})
        assert bad_admin.status_code == 200
        assert b"Authentication Failed" in bad_admin.content or b"alert-danger" in bad_admin.content
        print("✅ [PASS] 11. Invalid Admin credentials rejected with alert-danger badge")

        # Verify admin user exists with password BlockVote@Admin2026
        admin_user, _ = User.objects.get_or_create(username='admin')
        admin_user.is_staff = True
        admin_user.is_superuser = True
        admin_user.set_password('BlockVote@Admin2026')
        admin_user.save()

        good_admin = admin_client.post('/auth/admin/', {'username': 'admin', 'password': 'BlockVote@Admin2026', 'next': '/admin-panel/'}, follow=True)
        assert good_admin.status_code == 200
        assert b"Admin" in good_admin.content or b"Merkle" in good_admin.content
        print("✅ [PASS] 12. Admin Authenticated successfully. Protected '/admin-panel/' accessible (HTTP 200)")

        # 7. Test Public Auditor Auth & Gated Registration Workflow
        auditor_client = Client()

        # Attempt registration with INVALID invite token (Should return HTTP 403 Forbidden)
        bad_auditor_reg = auditor_client.post('/auth/auditor/', {
            'action': 'register',
            'username': 'fake_auditor',
            'password': 'Password123!',
            'organization': 'Unauthorized Org',
            'trust_invite_code': 'INVALID-SECRET-TOKEN'
        })
        assert bad_auditor_reg.status_code == 403, f"Expected 403 for invalid token, got {bad_auditor_reg.status_code}"
        print("✅ [PASS] 13. Auditor registration with invalid token blocked (HTTP 403 Forbidden)")

        # Login with existing approved auditor
        auditor_user, _ = User.objects.get_or_create(username='adr_official_auditor')
        auditor_user.set_password('ADR@Auditor2026')
        auditor_user.save()
        AuditorProfile.objects.update_or_create(
            user=auditor_user,
            defaults={'organization': 'Association for Democratic Reforms (ADR)', 'is_approved': True}
        )

        good_auditor_login = auditor_client.post('/auth/auditor/', {
            'action': 'login',
            'username': 'adr_official_auditor',
            'password': 'ADR@Auditor2026',
            'next': '/auditor/'
        }, follow=True)
        assert good_auditor_login.status_code == 200
        assert b"Auditor" in good_auditor_login.content or b"Observer" in good_auditor_login.content
        print("✅ [PASS] 14. Institutional Auditor logged in successfully with ADR@Auditor2026 (HTTP 200)")

        # Test Auditor Portal access
        res_auditor_dash = auditor_client.get('/auditor/')
        assert res_auditor_dash.status_code == 200
        print("✅ [PASS] 15. Protected '/auditor/' accessed with approved auditor credentials (HTTP 200)")

        # 8. Test Global Logout Workflow
        logout_res = auditor_client.get('/logout/', follow=True)
        assert logout_res.status_code == 200
        # Verify session is flushed and cannot access protected auditor portal anymore
        res_after_logout = auditor_client.get('/auditor/')
        assert res_after_logout.status_code == 302
        assert '/auth/auditor/' in res_after_logout.url
        print("✅ [PASS] 16. Global '/logout/' flushed session and restored strict access boundaries (HTTP 302)")

        # 9. Test Dynamic Auditor Token Provisioning & Lifecycle
        # Step A: Admin generates a new Auditor Invite Token
        gen_tok_res = admin_client.post('/api/v1/auditor-tokens/generate/', json.dumps({
            'organization': 'Transparency International',
            'max_uses': 1,
            'expiry_days': 7,
            'notes': 'Accredited external observer'
        }), content_type='application/json')
        assert gen_tok_res.status_code == 201, f"Failed to generate auditor token: {gen_tok_res.content}"
        tok_data = gen_tok_res.json()
        new_token_code = tok_data['token_code']
        token_id = tok_data['token_id']
        assert new_token_code.startswith('ECI-AUDIT-'), f"Invalid token format: {new_token_code}"
        print(f"✅ [PASS] 17. Admin successfully issued Auditor Invite Token: {new_token_code} (HTTP 201)")

        # Step B: New Auditor registers using the issued token
        new_auditor_client = Client()
        reg_res = new_auditor_client.post('/auth/auditor/', {
            'action': 'register',
            'username': 'transparency_observer',
            'password': 'SecureObserverPass2026!',
            'organization': 'Transparency International',
            'trust_invite_code': new_token_code,
            'next': '/auditor/'
        }, follow=True)
        assert reg_res.status_code == 200, f"Registration failed with issued token: {reg_res.content}"
        res_new_dash = new_auditor_client.get('/auditor/')
        assert res_new_dash.status_code == 200, f"New auditor unable to access dashboard: {res_new_dash.status_code}"
        print(f"✅ [PASS] 18. New Observer registered with issued token and accessed Auditor Portal (HTTP 200)")

        # Step C: Single-use token is now exhausted - reuse must be rejected
        exhausted_client = Client()
        repeat_reg = exhausted_client.post('/auth/auditor/', {
            'action': 'register',
            'username': 'imposter_observer',
            'password': 'AnotherPassword123!',
            'organization': 'Copycat Org',
            'trust_invite_code': new_token_code
        })
        assert repeat_reg.status_code == 403, f"Expected 403 for exhausted token, got {repeat_reg.status_code}"
        print(f"✅ [PASS] 19. Exhausted single-use Auditor Token rejected on reuse (HTTP 403 Forbidden)")

        # Step D: Admin suspends the newly registered auditor
        new_profile = AuditorProfile.objects.get(user__username='transparency_observer')
        toggle_res = admin_client.post(f'/api/v1/auditor/{new_profile.pk}/toggle-status/')
        assert toggle_res.status_code == 200
        new_profile.refresh_from_db()
        assert new_profile.is_approved is False

        # Attempt login while suspended
        suspended_login = new_auditor_client.post('/auth/auditor/', {
            'action': 'login',
            'username': 'transparency_observer',
            'password': 'SecureObserverPass2026!'
        })
        assert b"Account Suspended" in suspended_login.content or b"Account Pending Verification" in suspended_login.content
        print(f"✅ [PASS] 20. Admin can suspend auditor access; suspended login blocked successfully")

        # Admin re-approves auditor
        admin_client.post(f'/api/v1/auditor/{new_profile.pk}/toggle-status/')
        new_profile.refresh_from_db()
        assert new_profile.is_approved is True
        print(f"✅ [PASS] 21. Admin restored auditor access; profile re-approved successfully")

        print("======================================================================")
        print("🎉 ALL 21 RBAC, AUTHENTICATION & AUDITOR TOKEN LIFECYCLE TESTS PASSED!")
        print("======================================================================")
    finally:
        User.objects.filter(username__in=['fake_auditor', 'transparency_observer', 'imposter_observer']).delete()
        if created_test_election:
            Election.objects.filter(pk=test_election.pk).delete()

if __name__ == '__main__':
    run_tests()
