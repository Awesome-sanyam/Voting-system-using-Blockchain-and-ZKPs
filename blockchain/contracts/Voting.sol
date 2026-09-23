// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/metatx/ERC2771Context.sol";
import "./ElectionRegistration.sol";

// ── Interface matches SnarkJS-generated Groth16Verifier.sol exactly ──────────
// Verifier.sol signature: verifyProof(uint[2] calldata, uint[2][2] calldata, uint[2] calldata, uint[4] calldata)
interface IZKVerifier {
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[4] calldata _pubSignals
    ) external view returns (bool);
}

contract Voting is ERC2771Context {
    ElectionRegistration public immutable registrationContract;
    IZKVerifier public immutable zkVerifier;

    mapping(uint256 => bool) public usedNullifiers;
    mapping(uint256 => uint256) public candidateVotes;

    event VoteCast(uint256 indexed candidateId, uint256 indexed nullifier);

    constructor(
        address _trustedForwarder,
        address _registrationContract,
        address _zkVerifier
    ) ERC2771Context(_trustedForwarder) {
        registrationContract = ElectionRegistration(_registrationContract);
        zkVerifier = IZKVerifier(_zkVerifier);
    }

    /// @notice Casts an anonymous vote using a zk-SNARK proof.
    /// @dev Public signals order MUST match Circom circuit's public output order:
    ///      [0] nullifier   — output of Poseidon(voterSecret, electionId)
    ///      [1] merkleRoot  — from ElectionRegistration.merkleRoot()
    ///      [2] electionId  — from ElectionRegistration.electionId()
    ///      [3] candidateId — candidate chosen by voter
    function castVote(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint256 nullifier,
        uint256 candidateId
    ) external {
        require(registrationContract.isRootLocked(), "Election has not started");
        require(!usedNullifiers[nullifier], "Double Voting Error: Nullifier already spent");

        // Build public signal array in Circom output order: [nullifier, root, electionId, candidateId]
        uint[4] memory publicInputs = [
            nullifier,
            uint256(registrationContract.merkleRoot()),
            registrationContract.electionId(),
            candidateId
        ];

        // Verify the Groth16 proof against the on-chain verification key
        require(
            zkVerifier.verifyProof(_pA, _pB, _pC, publicInputs),
            "Invalid Zero-Knowledge Proof"
        );

        // Mark nullifier as spent BEFORE state change (CEI pattern)
        usedNullifiers[nullifier] = true;
        candidateVotes[candidateId] += 1;

        emit VoteCast(candidateId, nullifier);
    }

    /// @notice Returns the on-chain vote tally for a candidate.
    function getTally(uint256 candidateId) external view returns (uint256) {
        return candidateVotes[candidateId];
    }
}