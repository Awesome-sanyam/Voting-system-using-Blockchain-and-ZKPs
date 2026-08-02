/* STREAMING_CHUNK: Defining the Voter Eligibility ZK Circuit... */
pragma circom 2.1.6;

// Fixed import paths: Looking one level up into the blockchain/node_modules folder
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

template MerkleTreeVerifier(levels) {
signal input leaf;
signal input root;
signal input pathElements[levels];
signal input pathIndices[levels];

component selectors[levels];
component hashers[levels];

signal currentHash[levels + 1];
currentHash[0] <== leaf;

for (var i = 0; i < levels; i++) {
    pathIndices[i] * (1 - pathIndices[i]) === 0;

    selectors[i] = Mux1();
    selectors[i].c[0] <== currentHash[i];
    selectors[i].c[1] <== pathElements[i];
    selectors[i].s <== pathIndices[i];

    hashers[i] = Poseidon(2);
    hashers[i].inputs[0] <== selectors[i].out;
    hashers[i].inputs[1] <== currentHash[i] + pathElements[i] - selectors[i].out;

    currentHash[i + 1] <== hashers[i].out;
}
root === currentHash[levels];


}

template VoterEligibility(levels) {
// Private Inputs
signal input voterSecret;
signal input salt;
signal input pathElements[levels];
signal input pathIndices[levels];

// Public Inputs
signal input root;
signal input electionId;
signal input candidateId;

// Public Output
signal output nullifier;

// 1. Calculate Leaf
component leafHasher = Poseidon(2);
leafHasher.inputs[0] <== voterSecret;
leafHasher.inputs[1] <== salt;

// 2. Verify Merkle Tree Inclusion
component merkleVerifier = MerkleTreeVerifier(levels);
merkleVerifier.leaf <== leafHasher.out;
merkleVerifier.root <== root;
for (var i = 0; i < levels; i++) {
    merkleVerifier.pathElements[i] <== pathElements[i];
    merkleVerifier.pathIndices[i] <== pathIndices[i];
}

// 3. Generate Deterministic Nullifier
component nullifierHasher = Poseidon(2);
nullifierHasher.inputs[0] <== voterSecret;
nullifierHasher.inputs[1] <== electionId;

nullifier <== nullifierHasher.out;


}

// 20 levels allows for over 1 million voters
component main {public [root, electionId, candidateId]} = VoterEligibility(20);