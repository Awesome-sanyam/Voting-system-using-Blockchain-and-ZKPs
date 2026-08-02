// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

contract ElectionRegistration is Ownable {
    bytes32 public merkleRoot;
    bool public isRootLocked;
    uint256 public immutable electionId;
    
    mapping(bytes32 => bool) public registeredCommitments;
    uint256 public totalRegistered;

    event VoterRegistered(bytes32 indexed commitment, uint256 total);
    event MerkleRootLocked(bytes32 indexed root, uint256 timestamp);

    constructor(uint256 _electionId) Ownable(msg.sender) {
        electionId = _electionId;
    }

    /// @notice Registers a voter's public commitment hash (Pre-Election)
    function registerVoter(bytes32 commitment) external onlyOwner {
        require(!isRootLocked, "Registration is closed and root is locked");
        require(!registeredCommitments[commitment], "Commitment already registered");

        registeredCommitments[commitment] = true;
        totalRegistered++;

        emit VoterRegistered(commitment, totalRegistered);
    }

    /// @notice Freezes the voter roll and locks the Merkle Root on-chain
    function lockMerkleRoot(bytes32 _merkleRoot) external onlyOwner {
        require(!isRootLocked, "Merkle Root is already locked");
        require(_merkleRoot != bytes32(0), "Invalid Merkle Root");

        merkleRoot = _merkleRoot;
        isRootLocked = true;

        emit MerkleRootLocked(_merkleRoot, block.timestamp);
    }
}