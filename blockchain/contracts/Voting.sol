// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/metatx/ERC2771Context.sol";
import "./ElectionRegistration.sol";

interface IZKVerifier {
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[3] memory input
    ) external view returns (bool r);
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

    /// @notice Casts an anonymous vote using a zk-SNARK proof
    function castVote(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256 nullifier,
        uint256 candidateId
    ) external {
        require(registrationContract.isRootLocked(), "Election has not started");
        require(!usedNullifiers[nullifier], "Double Voting Error: Nullifier already spent");

        // Prepare public input array expected by Circom Verifier: [nullifier, root, electionId, candidateId]
        uint256[3] memory publicInputs = [
            nullifier,
            uint256(registrationContract.merkleRoot()),
            candidateId
        ];

        // Verify ZK Proof
        require(
            zkVerifier.verifyProof(a, b, c, publicInputs),
            "Invalid Zero-Knowledge Proof"
        );

        // Mark nullifier as spent to prevent reentrancy and double-voting
        usedNullifiers[nullifier] = true;
        candidateVotes[candidateId] += 1;

        emit VoteCast(candidateId, nullifier);
    }

    function getTally(uint256 candidateId) external view returns (uint256) {
        return candidateVotes[candidateId];
    }
}