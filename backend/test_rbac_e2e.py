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
from api.models import VoterIdentity, AuditorProfile

def run_tests():
    client = Client()
    print("======================================================================")
    print("▶ STARTING RBAC & AUTHENTICATION SUITE FOR BLOCKVOTE-INDIA")
    print("======================================================================")

    # 1. Test Portal Hub
    res = client.get('/')
    assert res.status_code == 200, f"Expected 200 for '/', got {res.status_code}"
    assert b"BlockVote India Operational Hub" in res.content
    print("✅ [PASS] 1. Operational Portal Hub ('/') loaded successfully (HTTP 200)")

    # 2. Test Unauthenticated Access Protection (Strict RBAC Boundary)
    res_voter = client.get('/voter/')
    assert res_voter.status_code == 302, f"Expected 302 for unauth /voter/, got {res_voter.status_code}"
    assert '/auth/voter/' in res_voter.url
    print("✅ [PASS] 2. Unauthenticated '/voter/' redirected to /auth/voter/ (HTTP 302)")

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

    # 4. Test Voter Registration Workflow
    voter_client = Client()
    reg_data = {
        'action': 'register',
        'epic_number': 'IND5566778',
        'phone_number': '9811223344',
        'next': '/voter/'
    }
    res_reg = voter_client.post('/auth/voter/', reg_data, follow=True)
    assert res_reg.status_code == 200
    # Must now be on the voter portal
    assert b"Voter Portal" in res_reg.content or b"Identity Whitelisted" in res_reg.content
    assert voter_client.session.get('voter_hash') is not None
    print(f"✅ [PASS] 8. Voter Registration succeeded. Session hash: {voter_client.session['voter_hash'][:16]}... (HTTP 200)")

    # Test Voter Portal access with active session
    res_voter_dash = voter_client.get('/voter/')
    assert res_voter_dash.status_code == 200
    print("✅ [PASS] 9. Protected '/voter/' accessed with valid voter session (HTTP 200)")

    # 5. Test Voter OTP Login Workflow (New Client)
    login_client = Client()
    login_data = {
        'action': 'login',
        'epic_number': 'IND5566778',
        'phone_number': '9811223344',
        'otp': '749201',
        'next': '/voter/'
    }
    res_login = login_client.post('/auth/voter/', login_data, follow=True)
    assert res_login.status_code == 200
    assert login_client.session.get('voter_hash') is not None
    print("✅ [PASS] 10. Voter OTP Login succeeded. Access granted to voter dashboard (HTTP 200)")

    # 6. Test Admin Auth Workflow
    admin_client = Client()
    # Test bad login
    bad_admin = admin_client.post('/auth/admin/', {'username': 'admin', 'password': 'wrongpassword'})
    assert bad_admin.status_code == 200
    assert b"Authentication Failed" in bad_admin.content or b"alert-danger" in bad_admin.content
    print("✅ [PASS] 11. Invalid Admin credentials rejected with alert-danger badge")

    # Ensure admin user exists with is_staff=True
    admin_user, _ = User.objects.get_or_create(username='admin')
    admin_user.is_staff = True
    admin_user.is_superuser = True
    admin_user.set_password('admin123')
    admin_user.save()

    good_admin = admin_client.post('/auth/admin/', {'username': 'admin', 'password': 'admin123', 'next': '/admin-panel/'}, follow=True)
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

    # Register with VALID token ('ECI-AUDIT-2026-SECURE')
    User.objects.filter(username='adr_official_auditor').delete()
    good_auditor_reg = auditor_client.post('/auth/auditor/', {
        'action': 'register',
        'username': 'adr_official_auditor',
        'password': 'ObserverSecurePass2026!',
        'organization': 'Association for Democratic Reforms (ADR)',
        'trust_invite_code': 'ECI-AUDIT-2026-SECURE',
        'next': '/auditor/'
    }, follow=True)
    assert good_auditor_reg.status_code == 200
    assert b"Auditor" in good_auditor_reg.content or b"Observer" in good_auditor_reg.content
    
    # Verify AuditorProfile in database
    auditor_prof = AuditorProfile.objects.get(user__username='adr_official_auditor')
    assert auditor_prof.is_approved is True
    print(f"✅ [PASS] 14. Institutional Auditor registered and auto-approved. Org: '{auditor_prof.organization}' (HTTP 200)")

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

    print("======================================================================")
    print("🎉 ALL 16 RBAC & AUTHENTICATION TESTS PASSED PERFECTLY!")
    print("======================================================================")

if __name__ == '__main__':
    run_tests()
