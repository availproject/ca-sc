const { ethers } = require("hardhat");
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

// Networks to deploy to
const NETWORKS_TO_DEPLOY = [
  // "polygon_mainnet",
  // "optimism_mainnet",
  // "base_mainnet",
  // "scroll_mainnet",
  // "linea_mainnet",
  "avalanche_c_chain",
  "hyperliquid",
  "kaia_mainnet",
  // "bnb_smart_chain_mainnet",
  "monad_mainnet",
  "ethereum",
];

// Native token names for each network
const NATIVE_TOKENS = {
  ethereum: "ETH",
  polygon_mainnet: "MATIC",
  arbitrum_one: "ETH",
  optimism_mainnet: "ETH",
  base_mainnet: "ETH",
  scroll_mainnet: "ETH",
  linea_mainnet: "ETH",
  avalanche_c_chain: "AVAX",
  hyperliquid: "HYPE",
  kaia_mainnet: "KAI",
  bnb_smart_chain_mainnet: "BNB",
  monad_mainnet: "MONAD",
  sepolia: "ETH",
  "arb_sepolia": "ETH",
  "op_sepolia": "ETH",
  "base_sepolia": "ETH",
  "polygon_amony": "MATIC",
};

// Deployment results storage
const deploymentResults = {
  timestamp: new Date().toISOString(),
  deployments: {},
  summary: {
    successful: 0,
    failed: 0,
  },
};

async function deployToNetwork(networkName, adminAddress) {
  console.log(`\n${"=".repeat(60)}`);
  console.log(`Deploying to ${networkName}...`);
  console.log(`${"=".repeat(60)}`);

  try {
    // Get network config from hardhat
    const networkConfig = hre.config.networks[networkName];
    if (!networkConfig || !networkConfig.url) {
      throw new Error(`Network ${networkName} not found in hardhat.config.ts`);
    }

    const provider = new ethers.JsonRpcProvider(networkConfig.url);
    const network = await provider.getNetwork();
    const feeData = await provider.getFeeData();

    const wallet = new ethers.Wallet(networkConfig.accounts[0], provider);

    console.log(`Chain ID: ${network.chainId}`);
    console.log(`Deployer: ${wallet.address}`);
    console.log(
      `Gas Price: ${ethers.formatUnits(feeData.gasPrice || 0n, "gwei")} gwei`
    );

    const balance = await provider.getBalance(wallet.address);
    console.log(
      `Balance: ${ethers.formatEther(balance)} ${
        NATIVE_TOKENS[networkName] || "ETH"
      }`
    );

    const admin = adminAddress || wallet.address;
    console.log(`Admin: ${admin}`);

    console.log("Deploying Vault implementation...");

    const Vault = await ethers.getContractFactory("Vault");
    let tx = await Vault.getDeployTransaction();
    let gasEstimate = await provider.estimateGas({
      from: wallet.address,
      data: tx.data,
    });
    console.log(`Gas estimate: ${gasEstimate.toString()}`);

    const vault = await Vault.connect(wallet).deploy({
      gasLimit: gasEstimate,
    });

    const implementationAddress = await vault.getAddress();
    console.log(`Implementation deployed to: ${implementationAddress}`);

    // Wait for deployment
    await vault.waitForDeployment();

    // Verify deployment
    const code = await provider.getCode(implementationAddress);
    if (code === "0x") {
      throw new Error("Contract deployment failed - no code at address");
    }

    const deployTx = vault.deploymentTransaction();
    let receipt = null;
    if (deployTx) {
      receipt = await deployTx.wait();
    }

    const gasUsed = receipt ? receipt.gasUsed : null;
    const actualCost =
      receipt && feeData.gasPrice ? receipt.gasUsed * feeData.gasPrice : null;

    deploymentResults.deployments[networkName] = {
      chainId: network.chainId.toString(),
      implementationAddress,
      admin,
      deployer: wallet.address,
      gasUsed: gasUsed ? gasUsed.toString() : "N/A",
      gasPrice: feeData.gasPrice
        ? ethers.formatUnits(feeData.gasPrice, "gwei")
        : "N/A",
      actualCost: actualCost ? ethers.formatEther(actualCost) : "N/A",
      nativeToken: NATIVE_TOKENS[networkName] || "ETH",
      txHash: receipt ? receipt.hash : "N/A",
      blockNumber: receipt ? receipt.blockNumber.toString() : "N/A",
      timestamp: new Date().toISOString(),
    };

    console.log(`✅ Successfully deployed to ${networkName}`);
    if (gasUsed) {
      console.log(`   Gas Used: ${gasUsed.toString()}`);
    }
    if (actualCost) {
      console.log(
        `   Cost: ${ethers.formatEther(actualCost)} ${
          NATIVE_TOKENS[networkName] || "ETH"
        }`
      );
    }
    if (receipt) {
      console.log(`   Transaction: ${receipt.hash}`);
      console.log(`   Block: ${receipt.blockNumber}`);
    }

    return {
      success: true,
      network: networkName,
      implementationAddress,
      chainId: network.chainId.toString(),
      gasUsed: gasUsed ? gasUsed.toString() : null,
      cost: actualCost ? ethers.formatEther(actualCost) : null,
    };
  } catch (error) {
    console.error(`❌ Failed to deploy to ${networkName}:`, error.message);
    deploymentResults.deployments[networkName] = {
      error: error.message,
      timestamp: new Date().toISOString(),
    };
    return {
      success: false,
      network: networkName,
      error: error.message,
    };
  }
}

function printReport() {
  console.log("\n" + "=".repeat(100));
  console.log("DEPLOYMENT REPORT - MULTI-NETWORK");
  console.log("=".repeat(100));

  console.log("\n📊 Network Results:\n");

  // Define column widths
  const colNetwork = 22;
  const colChainId = 10;
  const colAddress = 45;
  const colGas = 15;
  const colCost = 25;

  // Header
  const header =
    "Network".padEnd(colNetwork) +
    "Chain ID".padEnd(colChainId) +
    "Implementation Address".padEnd(colAddress) +
    "Gas Used".padEnd(colGas) +
    "Cost".padEnd(colCost);
  console.log(header);
  console.log("-".repeat(120));

  // Data rows
  Object.entries(deploymentResults.deployments).forEach(([network, data]) => {
    if (data.error) {
      console.log(`${network.padEnd(colNetwork)} ❌ ${data.error}`);
    } else {
      const address = data.implementationAddress || "N/A";
      const gas = data.gasUsed || "N/A";
      const cost = data.actualCost || "N/A";
      const nativeToken = data.nativeToken || "ETH";
      const costFormatted = cost !== "N/A" ? `${cost} ${nativeToken}` : "N/A";

      const row =
        network.padEnd(colNetwork) +
        data.chainId.padEnd(colChainId) +
        address.padEnd(colAddress) +
        gas.padEnd(colGas) +
        costFormatted.padEnd(colCost);
      console.log(row);
    }
  });

  console.log("-".repeat(120));

  // Summary
  const successful = Object.values(deploymentResults.deployments).filter(
    (d) => d.implementationAddress && !d.error
  );
  const failed = Object.values(deploymentResults.deployments).filter(
    (d) => d.error
  );

  console.log("\n📈 Summary:");
  console.log(`   ✅ Successful deployments: ${successful.length}`);
  console.log(`   ❌ Failed deployments: ${failed.length}`);
  console.log(
    `   📝 Total networks: ${Object.keys(deploymentResults.deployments).length}`
  );

  console.log("\n" + "=".repeat(100));
}

async function main() {
  console.log("🚀 Starting multi-network deployment (Implementation only)...");
  console.log(`Networks: ${NETWORKS_TO_DEPLOY.join(", ")}\n`);

  // Get admin address from command line or use first signer
  const adminAddress = process.argv[2] || null;

  // Get networks from command line or use default list
  const networksArg = process.argv[3];
  const networksToDeploy = networksArg
    ? networksArg.split(",").map((n) => n.trim())
    : NETWORKS_TO_DEPLOY;

  console.log(`Networks to deploy: ${networksToDeploy.join(", ")}`);
  if (adminAddress) {
    console.log(`Admin address: ${adminAddress}`);
  } else {
    console.log("Admin: Will use deployer address for each network");
  }

  const results = [];

  // Deploy to each network sequentially
  for (const networkName of networksToDeploy) {
    const result = await deployToNetwork(networkName, adminAddress);
    results.push(result);

    // Small delay between deployments
    if (networksToDeploy.indexOf(networkName) < networksToDeploy.length - 1) {
      console.log("\nWaiting 3 seconds before next deployment...");
      await new Promise((resolve) => setTimeout(resolve, 3000));
    }
  }

  // Update summary
  deploymentResults.summary.successful = results.filter(
    (r) => r.success
  ).length;
  deploymentResults.summary.failed = results.filter((r) => !r.success).length;

  // Save deployment results to file
  const resultsPath = path.join(__dirname, "..", "deployments.json");
  fs.writeFileSync(resultsPath, JSON.stringify(deploymentResults, null, 2));
  console.log(`\n📝 Deployment results saved to: ${resultsPath}`);

  // Print formatted report
  printReport();
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .then(() => {
    console.log("\n✨ Deployment complete!");
  });
