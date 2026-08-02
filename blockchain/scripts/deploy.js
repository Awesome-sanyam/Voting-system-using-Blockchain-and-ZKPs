const hre = require("hardhat");

async function main() {
    console.log("Starting BlockVote-India Smart Contract Deployment...");

    // 1. Deploy ElectionRegistration Contract
    const electionId = 2026;
    const Registration = await hre.ethers.getContractFactory("ElectionRegistration");
    const registration = await Registration.deploy(electionId);
    await registration.waitForDeployment();
    console.log(`ElectionRegistration deployed to: ${await registration.getAddress()}`);

    // 2. Deploy Auto-Generated SnarkJS Verifier Contract
    const Verifier = await hre.ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();
    console.log(`Groth16Verifier deployed to: ${await verifier.getAddress()}`);

    // 3. Deploy Voting Contract (EIP-2771 Enabled with OpenZeppelin Trusted Forwarder)
    const trustedForwarder = "0x7A0D94F55792c484505244ec82250da7CA1b228f"; // Polygon Amoy Forwarder
    const Voting = await hre.ethers.getContractFactory("Voting");
    const voting = await Voting.deploy(
        trustedForwarder,
        await registration.getAddress(),
        await verifier.getAddress()
    );
    await voting.waitForDeployment();
    console.log(`Voting Contract deployed to: ${await voting.getAddress()}`);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});

