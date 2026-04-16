const { ethers } = require("hardhat");
const hre = require("hardhat");

// Networks and their deployed Vault contract addresses
// You can add multiple addresses per network if needed
const DEPLOYED_CONTRACTS = {
  "mega_eth": [
    "0x5f02ED27A20BbDbB90EEf98670fA36c36fc02D12"
  ],
  "arb_sepolia": [
    "0x5f02ED27A20BbDbB90EEf98670fA36c36fc02D12"
  ],
  "op_sepolia": [
    "0x91BC4bd9Ced9cD9C35467a0797a0724A3FA7ff9b"
  ],
  "sepolia": [
    "0xA7458040272226378397C3036eda862D60C3b307"
  ],
  "base_sepolia": [
    "0x4152FAFe480013F2a33d1aE4d7322fCDD5393395"
  ],
  "monad_testnet": [
    "0x10B69f0E3c21C1187526940A615959E9ee6012F9"
  ],
  "citrea_testnet": [
    "0xc22C0D6Be68b3068b21E563Cd24A598a4f209771"
  ]
};

// Role to grant
const SETTLEMENT_VERIFIER_ROLE = ethers.keccak256(ethers.toUtf8Bytes("SETTLEMENT_VERIFIER_ROLE"));

async function grantRoleOnNetwork(networkName, addressCalled) {
  console.log(`\n${"=".repeat(60)}`);
  console.log(`Processing network: ${networkName}...`);
  console.log(`${"=".repeat(60)}`);

  const contracts = DEPLOYED_CONTRACTS[networkName];
  if (!contracts || contracts.length === 0) {
    console.log(`⚠️ No contracts found for ${networkName}. Skipping.`);
    return;
  }

  try {
    // Get network config from hardhat
    const networkConfig = hre.config.networks[networkName];
    if (!networkConfig || !networkConfig.url) {
      throw new Error(`Network ${networkName} not found in hardhat.config.ts`);
    }

    const provider = new ethers.JsonRpcProvider(networkConfig.url);
    const wallet = new ethers.Wallet(networkConfig.accounts[0], provider);

    console.log(`Network: ${networkName}`);
    console.log(`Signer: ${wallet.address}`);
    console.log(`Target Address (to be granted role): ${addressCalled}`);
    console.log(`Role Hash: ${SETTLEMENT_VERIFIER_ROLE}`);

    const VaultFactory = await ethers.getContractFactory("Vault");

    for (const contractAddress of contracts) {
      console.log(`\nTarget Contract: ${contractAddress}`);
      
      const vault = VaultFactory.attach(contractAddress).connect(wallet);

      // Check if already has role
      const hasRole = await vault.hasRole(SETTLEMENT_VERIFIER_ROLE, addressCalled);
      if (hasRole) {
        console.log(`ℹ️ Address ${addressCalled} already has SETTLEMENT_VERIFIER_ROLE on ${contractAddress}`);
        continue;
      }

      console.log(`Granting SETTLEMENT_VERIFIER_ROLE...`);
      const tx = await vault.grantRole(SETTLEMENT_VERIFIER_ROLE, addressCalled);
      console.log(`Transaction sent: ${tx.hash}`);
      
      await tx.wait();
      console.log(`✅ Role granted successfully on ${contractAddress}`);
    }

  } catch (error) {
    console.error(`❌ Failed on ${networkName}:`, error.message);
  }
}

async function main() {
  console.log("🚀 Starting Multi-Network Role Grant Script...");

  // Helper to find address in args if index is shifted
  const findAddress = (args) => {
    for (let i = 2; i < args.length; i++) {
      if (ethers.isAddress(args[i])) return args[i];
    }
    return null;
  };

  // Get address to grant role to
  // Priority: 1. Env Var, 2. Argv[2], 3. Find in Argv
  let addressCalled = process.env.GRANT_ROLE_TO || process.argv[2];
  
  if (!addressCalled || !ethers.isAddress(addressCalled)) {
    // Try to find it in other arguments
    addressCalled = findAddress(process.argv);
  }

  if (!addressCalled || !ethers.isAddress(addressCalled)) {
    console.error(`❌ Error: Please provide a valid address.`);
    console.error(`   You can pass it as an argument or set GRANT_ROLE_TO environment variable.`);
    console.error(`   Received at argv[2]: "${process.argv[2]}"`);
    console.error("Usage: npx hardhat run scripts/grant-settlement-role-multi-network.js -- <address> [network1,network2]");
    console.error("   OR: GRANT_ROLE_TO=<address> npx hardhat run scripts/grant-settlement-role-multi-network.js");
    process.exit(1);
  }

  // Get networks from command line or use all defined in DEPLOYED_CONTRACTS
  let networksArg = process.env.NETWORKS || process.argv[3];

  // If we had to search for the address, look for networks after it
  const addressIndex = process.argv.indexOf(addressCalled);
  if (addressIndex > -1 && process.argv[addressIndex + 1]) {
     // Check if the next arg is a network list (comma separated or just a string that is not an address)
     const nextArg = process.argv[addressIndex + 1];
     if (!ethers.isAddress(nextArg)) {
        networksArg = nextArg;
     }
  }

  const networksToProcess = networksArg
    ? networksArg.split(",").map((n) => n.trim())
    : Object.keys(DEPLOYED_CONTRACTS);

  console.log(`Address to Grant Role: ${addressCalled}`);
  console.log(`Networks: ${networksToProcess.join(", ")}\n`);

  for (const networkName of networksToProcess) {
    await grantRoleOnNetwork(networkName, addressCalled);
  }

  console.log("\n✨ Operation complete!");
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
