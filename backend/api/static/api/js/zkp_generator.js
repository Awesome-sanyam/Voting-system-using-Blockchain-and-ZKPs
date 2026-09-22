/**
 * BlockVote India — zkp_generator.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Client-side Zero-Knowledge Proof generator.
 *
 * Exposes: window.BlockVoteZKP.generateProof(input) → { proof, publicSignals }
 *
 * Uses snarkjs.groth16.fullProve() with the vote circuit's WASM and ZKey files.
 *
 * Circuit inputs (must match circuits/vote.circom):
 *   - candidateId  : field element — the candidate the voter is choosing
 *   - voterSecret  : field element — voter's private nullifier seed (never sent)
 *   - sessionNonce : field element — prevents replay attacks (from QR token)
 *
 * Public outputs (revealed to the verifier / smart contract):
 *   - nullifier    : H(voterSecret) — proves uniqueness without revealing identity
 *   - candidateId  : the chosen candidate (committed in the proof)
 *
 * SETUP NOTES (Phase 5):
 *   1. Compile vote.circom with circom2:
 *        circom circuits/vote.circom --r1cs --wasm --sym -o circuits/
 *   2. Run Powers of Tau ceremony + Phase 2:
 *        snarkjs powersoftau new bn128 12 pot12_0000.ptau
 *        snarkjs powersoftau contribute ...
 *        snarkjs groth16 setup circuits/vote.r1cs pot12_final.ptau circuits/vote_0000.zkey
 *        snarkjs zkey contribute circuits/vote_0000.zkey circuits/vote_final.zkey
 *        snarkjs zkey export verificationkey circuits/vote_final.zkey circuits/verification_key.json
 *   3. Copy output files to: backend/api/static/api/zkp/
 *        - vote.wasm          (the circuit witness generator)
 *        - vote_final.zkey    (the proving key)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 */

(function (global) {
  'use strict';

  // ── Circuit asset paths (served by Django staticfiles) ──────────────────────
  const WASM_PATH = '/static/api/zkp/vote.wasm';
  const ZKEY_PATH = '/static/api/zkp/vote_final.zkey';

  // ── Internal helpers ─────────────────────────────────────────────────────────

  /**
   * Converts a hex string (0x-prefixed or not) to a BigInt field element.
   * snarkjs expects numeric strings or BigInts for circuit inputs.
   */
  function hexToField(hexStr) {
    const clean = hexStr.replace(/^0x/, '');
    return BigInt('0x' + clean).toString();
  }

  /**
   * Derives a deterministic voter secret from the voter_hash using SHA-256.
   * In a real deployment this would come from the voter's locally-stored
   * cryptographic key material — never transmitted to the server.
   *
   * ⚠️  This is a SIMPLIFIED demo derivation. Production should use a proper
   *      key derivation function (e.g. PBKDF2 / Argon2) over a user-chosen PIN.
   */
  async function deriveVoterSecret(voterHash) {
    const encoder  = new TextEncoder();
    const data     = encoder.encode('blockvote_secret_v1:' + voterHash);
    const hashBuf  = await crypto.subtle.digest('SHA-256', data);
    const hashHex  = Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    // Reduce modulo BN128 field order to ensure it's a valid field element
    const BN128_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    return (BigInt('0x' + hashHex) % BN128_ORDER).toString();
  }

  /**
   * Derives the nullifier from the voter secret.
   * nullifier = H(voterSecret || 'nullifier')
   * This is what gets published on-chain — proves uniqueness, reveals nothing.
   */
  async function deriveNullifier(voterSecret) {
    const encoder  = new TextEncoder();
    const data     = encoder.encode('nullifier:' + voterSecret);
    const hashBuf  = await crypto.subtle.digest('SHA-256', data);
    const hashHex  = Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    const BN128_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    return (BigInt('0x' + hashHex) % BN128_ORDER).toString();
  }

  // ── Core proof generation ────────────────────────────────────────────────────

  /**
   * generateProof(input) → Promise<{ proof, publicSignals }>
   *
   * @param {Object} input
   * @param {number} input.candidateId   - The on-chain candidate ID (1-based)
   * @param {string} input.voterHash     - The anonymous voter hash (0x…)
   * @param {string} input.sessionNonce  - 8-byte hex nonce from QR token
   *
   * @returns {Promise<{proof: Object, publicSignals: string[]}>}
   */
  async function generateProof(input) {
    // 1. Validate inputs
    if (!input || !input.candidateId) {
      throw new Error('[BlockVoteZKP] candidateId is required');
    }

    // 2. Check snarkjs is loaded
    if (typeof snarkjs === 'undefined') {
      throw new Error('[BlockVoteZKP] snarkjs is not loaded. Ensure the CDN script is included in base.html.');
    }

    console.log('[BlockVoteZKP] Starting proof generation for candidate:', input.candidateId);

    // 3. Derive the voter secret (client-only, never leaves the browser)
    const voterSecret  = await deriveVoterSecret(input.voterHash || '0xmock');
    const nullifier    = await deriveNullifier(voterSecret);
    const sessionField = hexToField(
      input.sessionNonce
        ? input.sessionNonce.padEnd(16, '0')
        : '0000000000000001'
    );

    // 4. Prepare circuit inputs — must match the circom signal declarations
    const circuitInputs = {
      candidateId:  input.candidateId.toString(),
      voterSecret:  voterSecret,
      sessionNonce: sessionField,
    };

    console.log('[BlockVoteZKP] Circuit inputs prepared (voterSecret is private — not logged)');

    // 5. Check if WASM file is accessible (gives a clear error if not deployed yet)
    let wasmExists = false;
    try {
      const probe = await fetch(WASM_PATH, { method: 'HEAD' });
      wasmExists  = probe.ok;
    } catch (_) { /* offline or file missing */ }

    if (!wasmExists) {
      // ── DEV FALLBACK: mock proof ────────────────────────────────────────────
      console.warn('[BlockVoteZKP] Circuit WASM not found at', WASM_PATH);
      console.warn('[BlockVoteZKP] Using MOCK proof for development. See setup instructions in zkp_generator.js.');

      await new Promise(r => setTimeout(r, 1200)); // Simulate computation

      const mockProof = {
        pi_a: [
          '0x' + Array(64).fill(0).map(() => Math.floor(Math.random()*16).toString(16)).join(''),
          '0x' + Array(64).fill(0).map(() => Math.floor(Math.random()*16).toString(16)).join(''),
          '1'
        ],
        pi_b: [
          ['0x' + Array(64).fill(0).map(()=>Math.floor(Math.random()*16).toString(16)).join(''),
           '0x' + Array(64).fill(0).map(()=>Math.floor(Math.random()*16).toString(16)).join('')],
          ['0x' + Array(64).fill(0).map(()=>Math.floor(Math.random()*16).toString(16)).join(''),
           '0x' + Array(64).fill(0).map(()=>Math.floor(Math.random()*16).toString(16)).join('')],
          ['1', '0'],
        ],
        pi_c: [
          '0x' + Array(64).fill(0).map(() => Math.floor(Math.random()*16).toString(16)).join(''),
          '0x' + Array(64).fill(0).map(() => Math.floor(Math.random()*16).toString(16)).join(''),
          '1'
        ],
        protocol: 'groth16',
        curve:    'bn128',
      };

      return {
        proof:         mockProof,
        publicSignals: [nullifier, input.candidateId.toString()],
        _isMock:       true,
      };
    }

    // ── PRODUCTION PATH: real SnarkJS fullProve ─────────────────────────────
    console.log('[BlockVoteZKP] Running snarkjs.groth16.fullProve()…');
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInputs,
      WASM_PATH,
      ZKEY_PATH
    );

    console.log('[BlockVoteZKP] ✓ Proof generated. Public signals:', publicSignals);

    return { proof, publicSignals, _isMock: false };
  }

  // ── Public API ────────────────────────────────────────────────────────────────
  global.BlockVoteZKP = {
    generateProof,
    /** Exposed for testing in the browser console */
    _deriveVoterSecret: deriveVoterSecret,
    _deriveNullifier:   deriveNullifier,
    WASM_PATH,
    ZKEY_PATH,
  };

  console.log('[BlockVoteZKP] Module loaded. Call window.BlockVoteZKP.generateProof(input) to generate a proof.');

})(window);
