#!/bin/bash

# STREAMING_CHUNK: Stripping comments and updating compilation script...

mkdir -p circuits/build
mkdir -p contracts

echo "1. Compiling the Circom Circuit..."
circom circuits/voter_eligibility.circom --wasm --r1cs -l node_modules -o circuits/build

cd circuits/build || exit

echo "2. Starting Trusted Setup..."
npx snarkjs powersoftau new bn128 14 pot14_0000.ptau -v
npx snarkjs powersoftau contribute pot14_0000.ptau pot14_0001.ptau --name="BlockVote1" -v -e="entropy1"
npx snarkjs powersoftau prepare phase2 pot14_0001.ptau pot14_final.ptau -v

echo "3. Generating Proving Keys..."
npx snarkjs groth16 setup voter_eligibility.r1cs pot14_final.ptau voter_eligibility_0000.zkey
npx snarkjs zkey contribute voter_eligibility_0000.zkey voter_eligibility_final.zkey --name="BlockVote2" -v -e="entropy2"
npx snarkjs zkey export verificationkey voter_eligibility_final.zkey verification_key.json

echo "4. Exporting Solidity Verifier..."
npx snarkjs zkey export solidityverifier voter_eligibility_final.zkey ../../contracts/Verifier.sol

echo "✅ Success! Math compiled and Smart Contract generated."