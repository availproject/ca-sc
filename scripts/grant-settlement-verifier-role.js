// Script to grant SETTLEMENT_VERIFIER_ROLE to a list of MPC addresses
// Usage: VAULT_ADDRESS=0x... npx hardhat run scripts/grant-settlement-verifier-role.js --network <network-name>

const { ethers } = require("hardhat");

// List of MPC addresses to grant the role to
const MPC_ADDRESSES = [
    "0xDA1BA5813F8d87fbf55b11383A7a435150B952b9"
];

async function main() {
    // Get vault address from environment variable
    const VAULT_ADDRESS = process.env.VAULT_ADDRESS;
    
    if (!VAULT_ADDRESS) {
        throw new Error(
            "Vault address not provided.\n" +
            "Usage: VAULT_ADDRESS=0x... npx hardhat run scripts/grant-settlement-verifier-role.js --network <network-name>"
        );
    }
    
    // Validate vault address format
    if (!ethers.isAddress(VAULT_ADDRESS)) {
        throw new Error(`Invalid vault address: ${VAULT_ADDRESS}`);
    }

    console.log("Starting role grant process...");
    console.log("Vault Address:", VAULT_ADDRESS);
    console.log("Network:", network.name);
    console.log("Number of MPC addresses:", MPC_ADDRESSES.length);
    console.log("---");

    // Get the signer
    const [signer] = await ethers.getSigners();
    console.log("Signer address:", signer.address);

    // Get the Vault contract instance
    const Vault = await ethers.getContractFactory("Vault");
    const vault = Vault.attach(VAULT_ADDRESS);

    // Calculate the role hash (same as in the contract)
    const SETTLEMENT_VERIFIER_ROLE = ethers.keccak256(
        ethers.toUtf8Bytes("SETTLEMENT_VERIFIER_ROLE")
    );
    console.log("SETTLEMENT_VERIFIER_ROLE hash:", SETTLEMENT_VERIFIER_ROLE);
    console.log("---");

    // Check if signer has admin role
    const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;
    const hasAdminRole = await vault.hasRole(DEFAULT_ADMIN_ROLE, signer.address);
    if (!hasAdminRole) {
        throw new Error(`Signer ${signer.address} does not have DEFAULT_ADMIN_ROLE. Cannot grant roles.`);
    }
    console.log("✓ Signer has admin privileges");
    console.log("---");

    // Grant role to each MPC address
    let successCount = 0;
    let skipCount = 0;
    let errorCount = 0;

    for (let i = 0; i < MPC_ADDRESSES.length; i++) {
        const mpcAddress = MPC_ADDRESSES[i];
        console.log(`[${i + 1}/${MPC_ADDRESSES.length}] Processing: ${mpcAddress}`);

        try {
            // Check if address already has the role
            const hasRole = await vault.hasRole(SETTLEMENT_VERIFIER_ROLE, mpcAddress);
            
            if (hasRole) {
                console.log(`  ⊙ Address already has SETTLEMENT_VERIFIER_ROLE. Skipping.`);
                skipCount++;
                continue;
            }

            // Grant the role
            console.log(`  → Granting role...`);
            const tx = await vault.grantRole(SETTLEMENT_VERIFIER_ROLE, mpcAddress);
            console.log(`  → Transaction sent: ${tx.hash}`);
            
            const receipt = await tx.wait();
            console.log(`  ✓ Role granted successfully (Block: ${receipt.blockNumber})`);
            successCount++;

        } catch (error) {
            console.error(`  ✗ Error granting role: ${error.message}`);
            errorCount++;
        }
        
        console.log("---");
    }

    // Summary
    console.log("=== SUMMARY ===");
    console.log(`Total addresses processed: ${MPC_ADDRESSES.length}`);
    console.log(`Successfully granted: ${successCount}`);
    console.log(`Already had role (skipped): ${skipCount}`);
    console.log(`Errors: ${errorCount}`);
    
    if (errorCount > 0) {
        console.log("\n⚠️  Some addresses failed. Please review the errors above.");
    } else {
        console.log("\n✓ All addresses processed successfully!");
    }
}

// Execute the script
main()
    .then(() => {
        console.log("\nScript completed!");
        process.exit(0);
    })
    .catch((error) => {
        console.error("\n✗ Script failed:");
        console.error(error);
        process.exit(1);
    });
