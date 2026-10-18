#!/usr/bin/env python3
"""
Seed script for BlockVote India.
Initializes active Election, Candidate roster, Admin superuser, Auditor profile,
and sample verified voter identities.
"""
import os
import sys
import time
import django
from django.utils import timezone

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from django.contrib.auth.models import User
from api.models import Election, Candidate, VoterIdentity, ThreatLog, AuditorProfile, BallotRecord, ElectionVoterRoll
from api.views import derive_voter_identity_hash


def seed():
    print("▶ Seeding BlockVote India test data...")

    # 1. Admin Superuser
    admin, created = User.objects.get_or_create(username='admin')
    admin.is_staff = True
    admin.is_superuser = True
    admin.email = 'admin@eci.gov.in'
    admin.set_password('BlockVote@Admin2026')
    admin.save()
    print(f"  [+] Superuser: admin (password: BlockVote@Admin2026)")

    # 2. Institutional Auditor
    auditor_user, created = User.objects.get_or_create(username='adr_official_auditor')
    auditor_user.is_staff = False
    auditor_user.is_superuser = False
    auditor_user.email = 'audit@adrindia.org'
    auditor_user.set_password('ADR@Auditor2026')
    auditor_user.save()

    auditor_profile, _ = AuditorProfile.objects.get_or_create(
        user=auditor_user,
        defaults={
            'organization': 'Association for Democratic Reforms (ADR)',
            'trust_token_hash': 'demo_token_hash',
            'is_approved': True
        }
    )
    auditor_profile.is_approved = True
    auditor_profile.save()
    print(f"  [+] Certified Auditor: adr_official_auditor (password: ADR@Auditor2026)")

    # 3. Active Election
    now = int(time.time())
    merkle_root = "0x1e8555e1a1795efcd8cae9842bf9ecafcff7e0faeef7faad36e1c27806f1cc0a"
    election, _ = Election.objects.get_or_create(
        id=1,
        defaults={
            'title': 'General Parliamentary Elections 2026 — New Delhi Central (AC-047)',
            'status': Election.STATUS_ACTIVE,
            'start_timestamp': now - 86400,
            'end_timestamp': now + (86400 * 7),
            'merkle_root': merkle_root,
            'is_root_locked': True
        }
    )
    election.title = 'General Parliamentary Elections 2026 — New Delhi Central (AC-047)'
    election.status = Election.STATUS_ACTIVE
    election.merkle_root = merkle_root
    election.is_root_locked = True
    election.save()
    print(f"  [+] Active Election: '{election.title}' (Status: {election.status}, Root Locked: {election.is_root_locked})")

    # 4. Candidates Roster
    candidates_data = [
        (1, "Aarav Sharma", "National Democratic Front", "https://img.icons8.com/color/96/lotus.png"),
        (2, "Priya Patel", "United Progressive Alliance", "https://img.icons8.com/color/96/hand.png"),
        (3, "Rajesh Kumar", "Federal People's Party", "https://img.icons8.com/color/96/broom.png"),
        (4, "Meera Deshmukh", "Green Democratic Coalition", "https://img.icons8.com/color/96/sun.png"),
        (5, "None of the Above (NOTA)", "Independent", "https://img.icons8.com/color/96/ballot.png"),
    ]

    for cid, name, party, icon in candidates_data:
        cand, _ = Candidate.objects.update_or_create(
            candidate_id=cid,
            defaults={
                'election': election,
                'name': name,
                'party': party,
                'party_symbol_url': icon
            }
        )
    print(f"  [+] Configured {len(candidates_data)} electoral candidates with verified party affiliations")

    # 5. Seed Test Voter (EPIC: IND5566778, Phone: 9811223344)
    primary_hash = derive_voter_identity_hash('IND5566778', '9811223344')
    primary_voter, _ = VoterIdentity.objects.get_or_create(
        voter_hash=primary_hash,
        defaults={'is_verified': True, 'has_voted': False}
    )
    primary_voter.is_verified = True
    primary_voter.has_voted = False
    primary_voter.save()
    # Also populate ElectionVoterRoll
    ElectionVoterRoll.objects.update_or_create(
        election=election,
        epic_number='IND5566778',
        defaults={
            'phone_number': '9811223344',
            'voter_name': 'Aarav Sharma (Primary Test)',
            'voter_hash': primary_hash,
            'is_hashed': True
        }
    )
    print(f"  [+] Primary test voter: EPIC IND5566778 (Phone: 9811223344, Ready to vote)")

    # Additional sample voters
    sample_voters = [
        ("IND1234567", "9876543210", "Priya Patel", False),
        ("IND9876543", "9876543210", "Rajesh Kumar", False),
        ("IND1002001", "9800000001", "Vikram Singh", True),
        ("IND1002002", "9800000002", "Sunita Rao", True),
        ("IND1002003", "9800000003", "Ananya Sen", False),
        ("IND1002004", "9800000004", "Kavita Nair", False),
        ("IND1002005", "9800000005", "Rohan Mehta", False),
    ]
    for epic, phone, v_name, voted in sample_voters:
        v_hash = derive_voter_identity_hash(epic, phone)
        v, _ = VoterIdentity.objects.get_or_create(
            voter_hash=v_hash,
            defaults={'is_verified': True, 'has_voted': voted}
        )
        v.is_verified = True
        v.has_voted = voted
        v.save()

        ElectionVoterRoll.objects.update_or_create(
            election=election,
            epic_number=epic,
            defaults={
                'phone_number': phone,
                'voter_name': v_name,
                'voter_hash': v_hash,
                'is_hashed': True
            }
        )
    print(f"  [+] Seeded {len(sample_voters) + 1} voters into ElectionVoterRoll")

    # 6. Seed Sample Threat Logs
    if ThreatLog.objects.count() == 0:
        ThreatLog.objects.create(
            ip_address="192.168.1.105",
            threat_score=0.94,
            payload_size=204800,
            timestamp=timezone.now(),
            resolved=False
        )
        ThreatLog.objects.create(
            ip_address="45.33.32.156",
            threat_score=0.88,
            payload_size=102400,
            timestamp=timezone.now(),
            resolved=False
        )
        print("  [+] Initialized sample ThreatLog security telemetry")

    # 7. Seed Initial Verified Ballots
    if BallotRecord.objects.count() == 0:
        c1 = Candidate.objects.get(candidate_id=1)
        c2 = Candidate.objects.get(candidate_id=2)
        c3 = Candidate.objects.get(candidate_id=3)

        now = timezone.now()
        BallotRecord.objects.create(
            candidate=c1,
            nullifier="0x3f98a1c7e92b04f1283c74902187319a",
            transaction_hash="0x4b78a2f192b004c38219ef294821a8c39174b219083c27189a0129bcfe841290",
            block_number=1492038,
            gas_used=284520,
            timestamp=now - timezone.timedelta(minutes=14)
        )
        BallotRecord.objects.create(
            candidate=c2,
            nullifier="0x78ab12cf9012384a9218209384719283",
            transaction_hash="0x9182371928371928371928371928371928371928371928371928371928371928",
            block_number=1492039,
            gas_used=286100,
            timestamp=now - timezone.timedelta(minutes=8)
        )
        BallotRecord.objects.create(
            candidate=c1,
            nullifier="0x55bc8129048120384719283719284719",
            transaction_hash="0x1238471928371928371928371928371928371928371928371928371928371928",
            block_number=1492040,
            gas_used=283990,
            timestamp=now - timezone.timedelta(minutes=2)
        )
        print("  [+] Initialized 3 verified on-chain ballot records")

    print("✅ Seeding complete!")

if __name__ == '__main__':
    seed()

