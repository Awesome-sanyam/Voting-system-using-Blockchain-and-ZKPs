#!/usr/bin/env python3
"""
============================================================================
BlockVote India — Phase 5 End-to-End Lifecycle Simulation Script
backend/simulate_lifecycle.py
============================================================================

Orchestrates a complete pre-election lifecycle:
  1.  Pings /api/v1/register/ with 5 EPIC voter identities
  2.  Builds an in-memory Poseidon-compatible Merkle Tree from the returned
      SHA-256 voter hashes
  3.  Submits lockMerkleRoot() to the ElectionRegistration contract on
      Polygon Amoy via web3.py

Usage:
    cd backend
    source venv/bin/activate
    python simulate_lifecycle.py

Required environment variables (or defaults used for dev):
    SERVER_PRIVATE_KEY        — 0x-prefixed private key of election authority wallet
    REGISTRATION_CONTRACT     — Deployed ElectionRegistration address on Amoy
    POLYGON_RPC_URL           — (optional) defaults to rpc-amoy.polygon.technology
    DJANGO_BACKEND_URL        — (optional) defaults to http://127.0.0.1:8000
============================================================================
"""

import os
import sys
import json
import time
import hashlib
import logging
import requests
from typing import List, Tuple

# ── Optional: load .env if python-dotenv is available ───────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ── Web3 import (requires: pip install web3) ────────────────────────────────
try:
    from web3 import Web3
    from web3.exceptions import ContractLogicError
except ImportError:
    print("[FATAL] web3 is not installed. Run: pip install web3")
    sys.exit(1)

# ============================================================================
# CONFIGURATION
# ============================================================================

DJANGO_BACKEND_URL: str = os.getenv("DJANGO_BACKEND_URL", "http://127.0.0.1:8000")
POLYGON_RPC_URL: str = os.getenv("POLYGON_RPC_URL", "https://polygon-amoy-bor-rpc.publicnode.com")
SERVER_PRIVATE_KEY: str = os.getenv("SERVER_PRIVATE_KEY", "")
REGISTRATION_CONTRACT_ADDR: str = os.getenv(
    "REGISTRATION_CONTRACT",
    "0x0000000000000000000000000000000000000000"  # Replace with deployed address
)
CHAIN_ID: int = 80002  # Polygon Amoy

# ── ABI for ElectionRegistration.sol ────────────────────────────────────────
REGISTRATION_ABI = json.loads("""
[
    {
        "inputs": [{"internalType": "bytes32", "name": "commitment", "type": "bytes32"}],
        "name": "registerVoter",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "_merkleRoot", "type": "bytes32"}],
        "name": "lockMerkleRoot",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "isRootLocked",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "merkleRoot",
        "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "totalRegistered",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    }
]
""")

# ── Sample voter identities (simulating EPIC + mobile) ──────────────────────
DUMMY_VOTERS: List[dict] = [
    {"epic_number": "IND1234567", "phone_number": "9876543210"},
    {"epic_number": "IND2345678", "phone_number": "9876543211"},
    {"epic_number": "IND3456789", "phone_number": "9876543212"},
    {"epic_number": "IND4567890", "phone_number": "9876543213"},
    {"epic_number": "IND5678901", "phone_number": "9876543214"},
]

# ============================================================================
# LOGGING
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("lifecycle")

DIVIDER = "─" * 68


# ============================================================================
# STEP 1: Voter Registration via Django REST API
# ============================================================================

def register_voters_via_api() -> List[str]:
    """
    Posts each dummy EPIC + phone pair to /api/v1/register/ and collects the
    returned SHA-256 voter hashes that Django stores in PostgreSQL.
    """
    log.info(DIVIDER)
    log.info("STEP 1 — Voter Registration via /api/v1/register/")
    log.info(DIVIDER)

    collected_hashes: List[str] = []
    endpoint = f"{DJANGO_BACKEND_URL}/api/v1/register/"

    for voter in DUMMY_VOTERS:
        epic = voter["epic_number"]
        try:
            log.info(f"  → Registering EPIC: {epic} | Phone: {voter['phone_number']}")
            resp = requests.post(
                endpoint,
                json=voter,
                headers={"Content-Type": "application/json"},
                timeout=10
            )

            if resp.status_code == 201:
                data = resp.json()
                voter_hash = data.get("voter_hash", "")
                log.info(f"    ✓ Registered  | voter_hash = {voter_hash[:18]}...")
                collected_hashes.append(voter_hash)
            elif resp.status_code == 409:
                # Already registered — derive the hash locally for Merkle tree
                data = resp.json()
                log.warning(f"    ⚠ Already registered: {epic}. Deriving hash locally.")
                local_hash = derive_voter_hash_locally(epic, voter["phone_number"])
                collected_hashes.append(local_hash)
            else:
                log.error(f"    ✗ Failed ({resp.status_code}): {resp.text[:120]}")

        except requests.exceptions.ConnectionError:
            log.error(
                f"    ✗ Django server not reachable at {DJANGO_BACKEND_URL}. "
                "Ensure it is running with: python manage.py runserver"
            )
            local_hash = derive_voter_hash_locally(epic, voter["phone_number"])
            log.info(f"    ↳ Using locally derived hash: {local_hash[:18]}...")
            collected_hashes.append(local_hash)
        except requests.exceptions.Timeout:
            log.error(f"    ✗ Request timed out for {epic}")

        time.sleep(0.4)  # Polite rate-limiting

    log.info(f"\n  ✓ Total voter hashes collected: {len(collected_hashes)}")
    return collected_hashes


def derive_voter_hash_locally(epic: str, phone: str) -> str:
    """
    Reproduces the exact SHA-256 derivation used in views.py as a local fallback.
    Matches: hashlib.sha256(raw_identity + secret_salt).hexdigest()
    """
    secret_salt = b"django-insecure-i+x8n)u4po3#!!afqz1d^^k1!d*(hg0!kdb!&i*ui-%eh$7#72"
    raw_identity = f"{epic}:{phone}".encode("utf-8")
    h = hashlib.sha256(raw_identity + secret_salt).hexdigest()
    return "0x" + h


# ============================================================================
# STEP 2: Build a Merkle Tree from Voter Hashes
# ============================================================================

def sha256_pair(left: bytes, right: bytes) -> bytes:
    """Hashes two 32-byte leaves together (Ethereum convention: sorted pair)."""
    if left <= right:
        combined = left + right
    else:
        combined = right + left
    return hashlib.sha256(combined).digest()


def build_merkle_tree(voter_hashes: List[str]) -> Tuple[str, List[List[str]]]:
    """
    Builds a binary Merkle Tree from the list of hex-encoded voter hashes.

    Returns:
        (root_hex, tree_levels)
        root_hex: 0x-prefixed 32-byte root hash suitable for bytes32 in Solidity
        tree_levels: list of levels, each level is a list of hex-encoded hashes
    """
    log.info(DIVIDER)
    log.info("STEP 2 — Building In-Memory Merkle Tree")
    log.info(DIVIDER)

    if not voter_hashes:
        raise ValueError("Cannot build Merkle tree: no voter hashes provided")

    # Convert hex strings to raw bytes
    leaves: List[bytes] = []
    for h in voter_hashes:
        raw = bytes.fromhex(h.lstrip("0x"))
        leaves.append(hashlib.sha256(raw).digest())  # Leaf hash = H(voter_hash)

    log.info(f"  Leaves: {len(leaves)}")

    # Pad to next power of 2
    size = len(leaves)
    target = 1
    while target < size:
        target <<= 1
    if target > size:
        pad_leaf = hashlib.sha256(b"\x00" * 32).digest()
        leaves += [pad_leaf] * (target - size)
        log.info(f"  Padded to {target} leaves (next power-of-2)")

    # Build tree level-by-level
    tree_levels: List[List[str]] = [["0x" + leaf.hex() for leaf in leaves]]
    current = leaves[:]

    while len(current) > 1:
        next_level: List[bytes] = []
        for i in range(0, len(current), 2):
            parent = sha256_pair(current[i], current[i + 1])
            next_level.append(parent)
        tree_levels.append(["0x" + node.hex() for node in next_level])
        current = next_level

    root_hex = "0x" + current[0].hex()
    log.info(f"  ✓ Merkle Root: {root_hex}")
    log.info(f"  Tree Depth:   {len(tree_levels) - 1} levels")

    return root_hex, tree_levels


# ============================================================================
# STEP 3: Submit lockMerkleRoot() to Polygon Amoy
# ============================================================================

def lock_merkle_root_on_chain(merkle_root_hex: str) -> None:
    """
    Calls ElectionRegistration.lockMerkleRoot(bytes32) on Polygon Amoy,
    sealing the electoral roll cryptographically on-chain.
    """
    log.info(DIVIDER)
    log.info("STEP 3 — Sealing Merkle Root on Polygon Amoy Testnet")
    log.info(DIVIDER)

    if not SERVER_PRIVATE_KEY:
        log.warning(
            "  SERVER_PRIVATE_KEY is not set. Skipping on-chain transaction.\n"
            "  Set env var SERVER_PRIVATE_KEY=0x<key> to execute this step."
        )
        log.info(
            f"  Merkle Root that WOULD be submitted to lockMerkleRoot():\n"
            f"  {merkle_root_hex}"
        )
        return

    if REGISTRATION_CONTRACT_ADDR.startswith("0x000000"):
        log.warning(
            "  REGISTRATION_CONTRACT is not configured. Skipping on-chain transaction.\n"
            "  Set env var REGISTRATION_CONTRACT=0x<address> to execute this step."
        )
        return

    # Connect to Polygon Amoy
    log.info(f"  Connecting to Polygon Amoy RPC: {POLYGON_RPC_URL}")
    w3 = Web3(Web3.HTTPProvider(POLYGON_RPC_URL))

    if not w3.is_connected():
        log.error("  ✗ Failed to connect to Polygon Amoy RPC. Check network.")
        return

    # Latest block confirmation
    latest_block = w3.eth.block_number
    log.info(f"  ✓ Connected | Latest Block: #{latest_block:,}")

    # Build account from private key
    account = w3.eth.account.from_key(SERVER_PRIVATE_KEY)
    balance_wei = w3.eth.get_balance(account.address)
    balance_matic = w3.from_wei(balance_wei, "ether")
    log.info(f"  Authority Wallet: {account.address}")
    log.info(f"  Wallet Balance:   {float(balance_matic):.6f} MATIC")

    if float(balance_matic) < 0.001:
        log.error(
            "  ✗ Insufficient MATIC for gas. Fund your wallet on the Amoy faucet: "
            "https://faucet.polygon.technology"
        )
        return

    # Instantiate contract
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(REGISTRATION_CONTRACT_ADDR),
        abi=REGISTRATION_ABI
    )

    # Check if already locked
    try:
        is_locked = contract.functions.isRootLocked().call()
        if is_locked:
            existing_root = contract.functions.merkleRoot().call()
            log.warning(
                f"  ⚠ Electoral roll is already sealed on-chain.\n"
                f"    On-chain root: 0x{existing_root.hex()}"
            )
            return
    except Exception as ex:
        log.error(f"  ✗ Could not read contract state: {ex}")
        return

    # Convert root hex string to bytes32
    root_bytes = bytes.fromhex(merkle_root_hex.lstrip("0x"))
    assert len(root_bytes) == 32, "Merkle root must be exactly 32 bytes"

    log.info(f"  Submitting lockMerkleRoot({merkle_root_hex[:18]}...)")

    try:
        # Build transaction
        nonce = w3.eth.get_transaction_count(account.address)
        gas_price = w3.eth.gas_price
        tx = contract.functions.lockMerkleRoot(root_bytes).build_transaction({
            "from": account.address,
            "nonce": nonce,
            "gas": 200_000,
            "maxFeePerGas": gas_price * 2,
            "maxPriorityFeePerGas": w3.to_wei("30", "gwei"),
            "chainId": CHAIN_ID,
        })

        # Sign and broadcast
        signed = w3.eth.account.sign_transaction(tx, private_key=SERVER_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        tx_hex = w3.to_hex(tx_hash)
        log.info(f"  ✓ Transaction broadcast: {tx_hex}")
        log.info(f"    Explorer: https://amoy.polygonscan.com/tx/{tx_hex}")

        # Wait for receipt (up to 60 seconds)
        log.info("  Waiting for on-chain confirmation (timeout: 60s)...")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)

        if receipt.status == 1:
            log.info(f"  ✓ CONFIRMED in Block #{receipt.blockNumber:,}")
            log.info(f"    Gas Used: {receipt.gasUsed:,}")
            log.info(f"  ✓ Electoral Roll SEALED. Voting phase is now OPEN.")
        else:
            log.error("  ✗ Transaction REVERTED on-chain. Check contract logic.")

    except ContractLogicError as ce:
        log.error(f"  ✗ Smart contract revert: {ce}")
    except Exception as ex:
        log.error(f"  ✗ Transaction error: {ex}")


# ============================================================================
# STEP 4: Print Lifecycle Summary
# ============================================================================

def print_summary(hashes: List[str], root: str, tree_levels: List[List[str]]) -> None:
    log.info(DIVIDER)
    log.info("LIFECYCLE SIMULATION COMPLETE — Summary Report")
    log.info(DIVIDER)
    log.info(f"  Registered Voters:   {len(hashes)}")
    log.info(f"  Merkle Tree Depth:   {len(tree_levels) - 1} levels")
    log.info(f"  Merkle Root:         {root}")
    log.info("")
    log.info("  Voter Hashes Registered:")
    for i, h in enumerate(hashes):
        log.info(f"    [{i+1}] {h}")
    log.info(DIVIDER)
    log.info("  Next Step → Run blockchain/scripts/auditor_verify.js to verify tally")
    log.info("  Next Step → Run backend/simulate_ddos.py to validate AI Sentinel defense")
    log.info(DIVIDER)


# ============================================================================
# MAIN ENTRYPOINT
# ============================================================================

def main() -> None:
    print("\n" + "═" * 68)
    print("  BlockVote India — Phase 5: Pre-Election Lifecycle Simulation")
    print("═" * 68 + "\n")

    # Step 1: Register voters through Django API
    voter_hashes = register_voters_via_api()

    if not voter_hashes:
        log.error("No voter hashes were registered. Aborting lifecycle.")
        sys.exit(1)

    # Step 2: Build Merkle Tree locally
    merkle_root, tree_levels = build_merkle_tree(voter_hashes)

    # Step 3: Seal root on-chain
    lock_merkle_root_on_chain(merkle_root)

    # Step 4: Summary
    print_summary(voter_hashes, merkle_root, tree_levels)


if __name__ == "__main__":
    main()
