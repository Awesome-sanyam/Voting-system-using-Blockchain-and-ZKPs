import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { ethers } from 'ethers';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
    console.log("▶ Deploying BlockVote-India Smart Contracts...");

    const rpcUrl = process.env.RPC_URL || "http://127.0.0.1:8545";
    const privateKey = process.env.PRIVATE_KEY || "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    const provider = new ethers.JsonRpcProvider(rpcUrl);
    const signer = new ethers.Wallet(privateKey, provider);
    const deployerAddress = await signer.getAddress();
    const balance = await provider.getBalance(deployerAddress);

    console.log(`  [+] Deployer Address: ${deployerAddress} (${ethers.formatEther(balance)} ETH)`);

    const rootDir = path.resolve(__dirname, '..');
    const regArtifact = JSON.parse(fs.readFileSync(path.join(rootDir, 'artifacts/contracts/ElectionRegistration.sol/ElectionRegistration.json')));
    const verArtifact = JSON.parse(fs.readFileSync(path.join(rootDir, 'artifacts/contracts/Verifier.sol/Groth16Verifier.json')));
    const votArtifact = JSON.parse(fs.readFileSync(path.join(rootDir, 'artifacts/contracts/Voting.sol/Voting.json')));

    // 1. Deploy ElectionRegistration
    const electionId = 2026;
    const RegFactory = new ethers.ContractFactory(regArtifact.abi, regArtifact.bytecode, signer);
    const registration = await RegFactory.deploy(electionId);
    await registration.waitForDeployment();
    const registrationAddress = await registration.getAddress();
    console.log(`  [+] ElectionRegistration deployed: ${registrationAddress}`);

    // Small delay for clean provider sync
    await new Promise(r => setTimeout(r, 300));

    // 2. Deploy Groth16Verifier
    const VerFactory = new ethers.ContractFactory(verArtifact.abi, verArtifact.bytecode, signer);
    const verifier = await VerFactory.deploy();
    await verifier.waitForDeployment();
    const verifierAddress = await verifier.getAddress();
    console.log(`  [+] Groth16Verifier deployed: ${verifierAddress}`);

    await new Promise(r => setTimeout(r, 300));

    // 3. Deploy Voting (ERC2771 Forwarder)
    const trustedForwarder = ethers.getAddress("0x7a0d94f55792c484505244ec82250da7ca1b228f");
    const VotFactory = new ethers.ContractFactory(votArtifact.abi, votArtifact.bytecode, signer);
    const voting = await VotFactory.deploy(trustedForwarder, registrationAddress, verifierAddress);
    await voting.waitForDeployment();
    const votingAddress = await voting.getAddress();
    console.log(`  [+] Voting deployed: ${votingAddress}`);

    await new Promise(r => setTimeout(r, 300));

    // 4. Lock Merkle Root on ElectionRegistration
    const merkleRoot = "0x1e8555e1a1795efcd8cae9842bf9ecafcff7e0faeef7faad36e1c27806f1cc0a";
    const lockTx = await registration.lockMerkleRoot(merkleRoot);
    await lockTx.wait();
    console.log(`  [+] Sealed Merkle Root on-chain: ${merkleRoot}`);

    // 5. Update backend/.env file
    const envPath = path.resolve(__dirname, '../../backend/.env');
    if (fs.existsSync(envPath)) {
        let envContent = fs.readFileSync(envPath, 'utf8');
        envContent = envContent.replace(/POLYGON_RPC_URL=.*/, `POLYGON_RPC_URL=${rpcUrl}`);
        if (!envContent.includes('SERVER_PRIVATE_KEY=')) {
            envContent += `\nSERVER_PRIVATE_KEY=${privateKey}`;
        } else {
            envContent = envContent.replace(/SERVER_PRIVATE_KEY=.*/, `SERVER_PRIVATE_KEY=${privateKey}`);
        }
        if (!envContent.includes('VOTING_CONTRACT_ADDRESS=')) {
            envContent += `\nVOTING_CONTRACT_ADDRESS=${votingAddress}`;
        } else {
            envContent = envContent.replace(/VOTING_CONTRACT_ADDRESS=.*/, `VOTING_CONTRACT_ADDRESS=${votingAddress}`);
        }
        fs.writeFileSync(envPath, envContent);
        console.log(`  [+] Updated backend/.env with live deployed addresses!`);
    }

    console.log("✅ Smart Contracts successfully deployed and configured!");
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
