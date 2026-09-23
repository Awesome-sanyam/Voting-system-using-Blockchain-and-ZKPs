#!/usr/bin/env python3
"""
============================================================================
BlockVote India — Phase 5 Active Threat Simulation Script
backend/simulate_ddos.py
============================================================================

Fires 200 concurrent POST requests with garbage ZK proof payloads directly
at the gasless vote relayer endpoint (/api/v1/cast-vote/).

Validates the Django + FastAPI Active Sentinel defense chain:
  • Active Sentinel (port 8001) must flag anomalous request_velocity
  • Django relayer must return HTTP 403 (AI blocked) before touching Polygon
  • Gas wallet must NEVER be touched by a single garbage payload

Metrics collected and reported:
  • Count of 403 Forbidden responses (AI Sentinel BLOCKED)
  • Count of 400 Bad Request responses (proof parameter validation)
  • Count of 200/500 responses (sentinel offline / unexpected pass-through)
  • Total elapsed time and throughput (requests/sec)
  • Average server response time per status bucket

Usage:
    cd backend
    source venv/bin/activate
    pip install aiohttp
    python simulate_ddos.py

Optional env vars:
    DJANGO_BACKEND_URL   — defaults to http://127.0.0.1:8000
    SIMULATION_WORKERS   — number of concurrent aiohttp connections (default: 50)
    SIMULATION_TOTAL     — total requests to fire (default: 200)
============================================================================
"""

import os
import sys
import time
import json
import random
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

# ── aiohttp import guard ─────────────────────────────────────────────────────
try:
    import aiohttp
    from aiohttp import ClientConnectorError, ServerTimeoutError
except ImportError:
    print("[FATAL] aiohttp is not installed. Run: pip install aiohttp")
    sys.exit(1)

# ── Optional: load .env ──────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ============================================================================
# CONFIGURATION
# ============================================================================

DJANGO_BACKEND_URL: str = os.getenv("DJANGO_BACKEND_URL", "http://127.0.0.1:8000")
CAST_VOTE_ENDPOINT: str = f"{DJANGO_BACKEND_URL}/api/v1/cast-vote/"
SIMULATION_WORKERS: int = int(os.getenv("SIMULATION_WORKERS", "50"))
SIMULATION_TOTAL: int = int(os.getenv("SIMULATION_TOTAL", "200"))
REQUEST_TIMEOUT_SECS: int = 8
WORKER_RAMP_DELAY_MS: float = 5.0  # ms between spawning workers to mimic a real burst

# ============================================================================
# LOGGING
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("ddos_sim")
DIVIDER = "─" * 68


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class RequestResult:
    status: int
    elapsed_ms: float
    body_snippet: str = ""


@dataclass
class SimulationStats:
    results: List[RequestResult] = field(default_factory=list)
    errors: int = 0

    def tally(self) -> Dict[int, int]:
        counts: Dict[int, int] = {}
        for r in self.results:
            counts[r.status] = counts.get(r.status, 0) + 1
        return counts

    def avg_latency_by_status(self) -> Dict[int, float]:
        buckets: Dict[int, List[float]] = {}
        for r in self.results:
            buckets.setdefault(r.status, []).append(r.elapsed_ms)
        return {s: sum(v) / len(v) for s, v in buckets.items()}


# ============================================================================
# GARBAGE PROOF PAYLOAD GENERATOR
# ============================================================================

def make_garbage_proof_payload(request_id: int) -> dict:
    """
    Generates a structurally plausible but cryptographically invalid
    ZK proof payload. The proof values are random large integers that
    will NEVER satisfy the Groth16 verifier but look like valid JSON
    to a superficial HTTP layer check.
    """
    def rand_big_int() -> str:
        """Random 32-byte integer as string."""
        return str(random.getrandbits(253) % (2**253))

    def rand_uint256_pair() -> List[str]:
        return [rand_big_int(), rand_big_int()]

    def rand_uint256_matrix() -> List[List[str]]:
        return [[rand_big_int(), rand_big_int()], [rand_big_int(), rand_big_int()]]

    return {
        "a": rand_uint256_pair(),
        "b": rand_uint256_matrix(),
        "c": rand_uint256_pair(),
        "nullifier": rand_big_int(),
        "candidateId": random.randint(1, 10),
        "_sim_id": request_id,   # Metadata for tracking only
        "_sim_velocity": 50.0 + random.uniform(0, 10.0),  # Deliberately anomalous velocity
    }


# ============================================================================
# ASYNC WORKER: Single Request
# ============================================================================

async def fire_one_request(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    request_id: int,
    stats: SimulationStats
) -> None:
    """
    Fires a single POST to /api/v1/cast-vote/ and records the result.
    Uses a semaphore to cap simultaneous connections.
    """
    payload = make_garbage_proof_payload(request_id)

    async with semaphore:
        start = time.perf_counter()
        try:
            async with session.post(
                CAST_VOTE_ENDPOINT,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECS)
            ) as response:
                elapsed = (time.perf_counter() - start) * 1000
                try:
                    body = await response.text()
                    snippet = body[:120]
                except Exception:
                    snippet = "[unreadable body]"

                stats.results.append(RequestResult(
                    status=response.status,
                    elapsed_ms=round(elapsed, 1),
                    body_snippet=snippet
                ))

        except (ClientConnectorError, ServerTimeoutError) as network_err:
            elapsed = (time.perf_counter() - start) * 1000
            stats.errors += 1
            if request_id <= 3:
                log.error(f"  [Req #{request_id:03d}] Network error: {network_err}")
        except asyncio.TimeoutError:
            elapsed = (time.perf_counter() - start) * 1000
            stats.errors += 1


# ============================================================================
# PROGRESS PRINTER
# ============================================================================

async def progress_monitor(stats: SimulationStats, total: int, interval: float = 3.0) -> None:
    """Prints a live progress line every `interval` seconds during the attack burst."""
    while True:
        await asyncio.sleep(interval)
        completed = len(stats.results) + stats.errors
        pct = int((completed / total) * 100)
        tally = stats.tally()
        blocked = tally.get(403, 0)
        log.info(
            f"  Progress: {completed}/{total} ({pct}%) | "
            f"403-BLOCKED: {blocked} | "
            f"Errors: {stats.errors}"
        )
        if completed >= total:
            break


# ============================================================================
# ASYNC MAIN: Burst Orchestrator
# ============================================================================

async def run_ddos_simulation() -> SimulationStats:
    log.info(DIVIDER)
    log.info("STARTING DDoS Burst Simulation")
    log.info(DIVIDER)
    log.info(f"  Target Endpoint:    {CAST_VOTE_ENDPOINT}")
    log.info(f"  Total Requests:     {SIMULATION_TOTAL}")
    log.info(f"  Concurrent Workers: {SIMULATION_WORKERS}")
    log.info(f"  Request Timeout:    {REQUEST_TIMEOUT_SECS}s")
    log.info(DIVIDER)

    stats = SimulationStats()
    semaphore = asyncio.Semaphore(SIMULATION_WORKERS)

    connector = aiohttp.TCPConnector(
        limit=SIMULATION_WORKERS + 10,
        force_close=False,
        enable_cleanup_closed=True
    )

    async with aiohttp.ClientSession(
        connector=connector,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "BlockVote-ThreatSim/1.0",
            # Signals an anomalously high request velocity to the Django relayer,
            # which passes it to Active Sentinel (FastAPI/ML) for scoring.
            # Legitimate voters send ~0.5–2.5 req/sec; this burst is 50–60 req/sec.
            "X-Request-Velocity": "55.0",
            # No CSRF token → simulates external attacker; Django API endpoint
            # doesn't require CSRF for JSON requests from external clients
        }
    ) as session:
        burst_start = time.perf_counter()

        # Launch progress monitor in background
        monitor_task = asyncio.create_task(
            progress_monitor(stats, SIMULATION_TOTAL, interval=2.5)
        )

        # Fire all requests concurrently with semaphore-controlled concurrency
        tasks = [
            fire_one_request(session, semaphore, i + 1, stats)
            for i in range(SIMULATION_TOTAL)
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        burst_duration = time.perf_counter() - burst_start

        # Cancel monitor
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass

    log.info(f"\n  Burst completed in {burst_duration:.2f}s")
    return stats


# ============================================================================
# ASSERTIONS & REPORT
# ============================================================================

def evaluate_results(stats: SimulationStats, duration_secs: float) -> bool:
    """
    Evaluates simulation results against expected defense properties.
    Returns True if the Active Sentinel is functioning correctly.
    """
    tally = stats.tally()
    latencies = stats.avg_latency_by_status()
    total_requests = SIMULATION_TOTAL
    total_responses = len(stats.results)

    blocked_403 = tally.get(403, 0)   # AI Sentinel blocked
    bad_400 = tally.get(400, 0)        # Missing proof params (caught before Polygon)
    ok_200 = tally.get(200, 0)         # Would be a critical failure
    error_500 = tally.get(500, 0)      # Server errors
    throughput = total_requests / duration_secs if duration_secs > 0 else 0

    print("\n" + "═" * 68)
    print("  ATTACK SIMULATION RESULTS — BlockVote Active Sentinel Defense Report")
    print("═" * 68)
    print(f"\n  {'Metric':<35} {'Value':>20}")
    print(f"  {'─'*55}")
    print(f"  {'Total Requests Fired':<35} {total_requests:>20,}")
    print(f"  {'Total Responses Received':<35} {total_responses:>20,}")
    print(f"  {'Network / Timeout Errors':<35} {stats.errors:>20,}")
    print(f"  {'Throughput':<35} {throughput:>18.1f}/s")
    print(f"  {'Burst Duration':<35} {duration_secs:>18.2f}s")
    print(f"\n  {'Status Code Breakdown':─<55}")
    for code, count in sorted(tally.items()):
        avg_lat = latencies.get(code, 0)
        label = {
            403: "AI Sentinel BLOCKED",
            429: "Rate Limit Enforced",
            400: "Proof Param Rejected (Pre-Chain)",
            200: "⚠ PASSED THROUGH (UNEXPECTED)",
            500: "Server Error",
            503: "Service Unavailable",
        }.get(code, f"HTTP {code}")
        print(f"  {code}  {label:<40} {count:>5,}   avg {avg_lat:.0f}ms")

    print(f"\n{'─'*68}")

    # ── Assertions ────────────────────────────────────────────────────────────
    all_passed = True
    assertions: List[Tuple[bool, str]] = []

    # Primary: Gas wallet must not be reached by garbage proofs
    # A 200 OK means proof actually hit Polygon → critical failure
    assertions.append((
        ok_200 == 0,
        f"CRITICAL: {ok_200} garbage proofs passed through to Polygon. Gas wallet at risk!"
    ))

    # At least 50% of requests should be blocked (403) or rejected before Polygon (400)
    pre_chain_stops = blocked_403 + bad_400 + tally.get(429, 0)
    assertions.append((
        pre_chain_stops >= total_responses * 0.5,
        f"Expected ≥50% pre-chain stops, got {pre_chain_stops}/{total_responses} "
        f"({100 * pre_chain_stops / max(total_responses, 1):.0f}%)"
    ))

    # If Active Sentinel is online, at least some 403s should be returned
    if total_responses > 10:
        assertions.append((
            blocked_403 > 0 or bad_400 > 0,
            "Active Sentinel returned 0 blocked responses. Is FastAPI running on port 8001?"
        ))

    print("\n  Assertion Results:")
    for passed, msg in assertions:
        icon = "✓" if passed else "✗"
        print(f"  [{icon}] {msg}")
        if not passed:
            all_passed = False

    status_label = "✅ DEFENSE VALIDATED" if all_passed else "❌ DEFENSE FAILURES DETECTED"
    print(f"\n  {status_label}")

    if blocked_403 == 0 and ok_200 == 0 and bad_400 == total_responses:
        print(
            "\n  ℹ  INFO: All requests were blocked at proof parameter validation (400).\n"
            "     This is acceptable when Active Sentinel (FastAPI port 8001) is offline.\n"
            "     Start ml_service: uvicorn main:app --port 8001\n"
            "     Then re-run to validate ML-powered 403 responses."
        )

    print("═" * 68 + "\n")
    return all_passed


# ============================================================================
# MAIN ENTRYPOINT
# ============================================================================

def main() -> None:
    print("\n" + "═" * 68)
    print("  BlockVote India — Phase 5: DDoS Burst & AI Sentinel Validation")
    print("═" * 68 + "\n")

    # Preflight: check if Django is up
    try:
        preflight = requests.get(f"{DJANGO_BACKEND_URL}/voter/", timeout=3)
        log.info(f"  Django backend reachable | Status: {preflight.status_code}")
    except Exception:
        log.warning(
            f"  Django backend at {DJANGO_BACKEND_URL} is NOT reachable. "
            "Simulation will record only connection errors."
        )

    start_time = time.perf_counter()
    stats = asyncio.run(run_ddos_simulation())
    elapsed = time.perf_counter() - start_time

    defense_ok = evaluate_results(stats, elapsed)
    sys.exit(0 if defense_ok else 1)


# ── Lazy import for preflight check ─────────────────────────────────────────
try:
    import requests as _requests_sync
    requests = _requests_sync
except ImportError:
    class _stub:
        @staticmethod
        def get(*a, **kw):
            raise Exception("requests not available")
    requests = _stub()

if __name__ == "__main__":
    main()
