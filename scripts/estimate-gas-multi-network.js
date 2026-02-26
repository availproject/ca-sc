const { ethers, upgrades } = require("hardhat");
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

// Select 10 networks for gas estimation
const NETWORKS_TO_ESTIMATE = [
  "ethereum",
  "polygon_mainnet",
  "arbitrum_one",
  "optimism_mainnet",
  "base_mainnet",
  "scroll_mainnet",
  "linea_mainnet",
  "avalanche_c_chain",
  "hyperliquid",
  "kaia_mainnet",
  "bnb_smart_chain_mainnet",
  "monad_mainnet",
  //   "arb_sepolia",
  //   "op_sepolia",
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
  //   arb_sepolia: "ETH",
  //   op_sepolia: "ETH",
};

const gasReport = {
  timestamp: new Date().toISOString(),
  networks: {},
  summary: {
    minGas: null,
    maxGas: null,
    avgGas: null,
    minCost: null,
    maxCost: null,
    avgCost: null,
  },
};

async function estimateGasForNetwork(networkName) {
  console.log(`\n${"=".repeat(60)}`);
  console.log(`Estimating gas for ${networkName}...`);
  console.log(`${"=".repeat(60)}`);

  try {
    // Get network config from hardhat
    const networkConfig = hre.config.networks[networkName];
    if (!networkConfig || !networkConfig.url) {
      throw new Error(`Network ${networkName} not found in hardhat.config.ts`);
    }

    // Create a new provider for this network
    const provider = new ethers.JsonRpcProvider(networkConfig.url);
    const network = await provider.getNetwork();
    const feeData = await provider.getFeeData();

    // Create a signer for this network
    const wallet = new ethers.Wallet(networkConfig.accounts[0], provider);

    console.log(`Chain ID: ${network.chainId}`);
    console.log(`Deployer: ${wallet.address}`);
    console.log(
      `Gas Price: ${ethers.formatUnits(feeData.gasPrice || 0n, "gwei")} gwei`
    );

    let gasEstimate = null;
    let estimatedCost = null;
    let error = null;

    try {
      console.log("   Estimating (simulation only, no broadcast)...");

      const implFactory = await ethers.getContractFactory("Vault");
      const implDeployTx = await implFactory.getDeployTransaction();

      const implGasEstimate = await provider.estimateGas({
        from: wallet.address,
        data: implDeployTx.data,
      });

      console.log(`   Implementation gas: ${implGasEstimate.toString()}`);

      // For UUPS proxy deployment, we need to account for:
      // 1. Implementation deployment: ~implGasEstimate
      // 2. Proxy contract deployment: ~50k-100k
      // 3. Initialization call: ~50k-100k
      // Total overhead: ~150k-200k

      const proxyOverhead = 175000n;
      gasEstimate = implGasEstimate + proxyOverhead;

      if (feeData.gasPrice) {
        estimatedCost = gasEstimate * feeData.gasPrice;
      } else if (feeData.maxFeePerGas) {
        estimatedCost = gasEstimate * feeData.maxFeePerGas;
      }

      console.log(`   Proxy overhead: ${proxyOverhead.toString()}`);
      console.log(`   Total estimated: ${gasEstimate.toString()}`);
    } catch (estError) {
      error = `Estimation failed: ${estError.message}`;
      console.error(`   Error: ${error}`);
    }

    if (gasEstimate) {
      const result = {
        chainId: network.chainId.toString(),
        gasEstimate: gasEstimate.toString(),
        gasPrice: feeData.gasPrice
          ? ethers.formatUnits(feeData.gasPrice, "gwei")
          : "N/A",
        maxFeePerGas: feeData.maxFeePerGas
          ? ethers.formatUnits(feeData.maxFeePerGas, "gwei")
          : "N/A",
        estimatedCostETH: estimatedCost
          ? ethers.formatEther(estimatedCost)
          : "N/A",
        nativeToken: NATIVE_TOKENS[networkName] || "ETH",
        estimatedCostWei: estimatedCost ? estimatedCost.toString() : "N/A",
        timestamp: new Date().toISOString(),
      };

      gasReport.networks[networkName] = result;

      const nativeToken = NATIVE_TOKENS[networkName] || "ETH";
      console.log(`✅ Gas Estimate: ${gasEstimate.toString()}`);
      console.log(
        `   Cost: ${estimatedCost ? ethers.formatEther(estimatedCost) : "N/A"
        } ${nativeToken}`
      );

      return result;
    } else {
      throw new Error(error || "Could not estimate gas");
    }
  } catch (error) {
    console.error(`❌ Failed: ${error.message}`);
    gasReport.networks[networkName] = {
      error: error.message,
      timestamp: new Date().toISOString(),
    };
    return null;
  }
}

function calculateSummary() {
  const successful = Object.values(gasReport.networks).filter(
    (n) => n.gasEstimate && !n.error
  );

  if (successful.length === 0) return;

  const gasValues = successful.map((n) => BigInt(n.gasEstimate));
  const costValues = successful
    .filter((n) => n.estimatedCostWei && n.estimatedCostWei !== "N/A")
    .map((n) => BigInt(n.estimatedCostWei));

  if (gasValues.length > 0) {
    gasReport.summary.minGas = gasValues
      .reduce((a, b) => (a < b ? a : b))
      .toString();
    gasReport.summary.maxGas = gasValues
      .reduce((a, b) => (a > b ? a : b))
      .toString();
    const sum = gasValues.reduce((a, b) => a + b, 0n);
    gasReport.summary.avgGas = (sum / BigInt(gasValues.length)).toString();
  }

  if (costValues.length > 0) {
    gasReport.summary.minCost = costValues
      .reduce((a, b) => (a < b ? a : b))
      .toString();
    gasReport.summary.maxCost = costValues
      .reduce((a, b) => (a > b ? a : b))
      .toString();
    const sum = costValues.reduce((a, b) => a + b, 0n);
    gasReport.summary.avgCost = (sum / BigInt(costValues.length)).toString();
  }
}

function printReport() {
  console.log("\n" + "=".repeat(100));
  console.log("GAS ESTIMATION REPORT - MULTI-NETWORK");
  console.log("=".repeat(100));

  console.log("\n📊 Network Results:\n");

  // Define column widths
  const colNetwork = 22;
  const colChainId = 10;
  const colGas = 15;
  const colCost = 25;
  const colGasPrice = 18;

  // Header
  const header =
    "Network".padEnd(colNetwork) +
    "Chain ID".padEnd(colChainId) +
    "Gas".padEnd(colGas) +
    "Cost".padEnd(colCost) +
    "Gas Price (gwei)".padEnd(colGasPrice);
  console.log(header);
  console.log("-".repeat(100));

  // Data rows
  Object.entries(gasReport.networks).forEach(([network, data]) => {
    if (data.error) {
      console.log(`${network.padEnd(colNetwork)} ❌ ${data.error}`);
    } else {
      const gas = data.gasEstimate || "N/A";
      const cost = data.estimatedCostETH || "N/A";
      const nativeToken = NATIVE_TOKENS[network] || "ETH";

      let costFormatted = "N/A";
      if (cost !== "N/A") {
        const costNum = parseFloat(cost);
        if (costNum < 0.000001) {
          costFormatted = `${costNum.toExponential(4)} ${nativeToken}`;
        } else if (costNum < 1) {
          costFormatted = `${costNum.toFixed(8)} ${nativeToken}`;
        } else {
          costFormatted = `${costNum.toFixed(4)} ${nativeToken}`;
        }
      }

      const gasPrice = data.gasPrice || "N/A";
      const gasPriceFormatted =
        gasPrice !== "N/A" ? parseFloat(gasPrice).toFixed(6) : "N/A";

      const row =
        network.padEnd(colNetwork) +
        data.chainId.padEnd(colChainId) +
        gas.padEnd(colGas) +
        costFormatted.padEnd(colCost) +
        gasPriceFormatted.padEnd(colGasPrice);
      console.log(row);
    }
  });

  console.log("-".repeat(100));

  if (gasReport.summary.minGas) {
    console.log("\n📈 Summary Statistics:");
    console.log(`   Min Gas: ${gasReport.summary.minGas}`);
    console.log(`   Max Gas: ${gasReport.summary.maxGas}`);
    console.log(`   Avg Gas: ${gasReport.summary.avgGas}`);
  }

  if (gasReport.summary.minCost) {
    const minCost = ethers.formatEther(gasReport.summary.minCost);
    const maxCost = ethers.formatEther(gasReport.summary.maxCost);
    const avgCost = ethers.formatEther(gasReport.summary.avgCost);

    console.log("\n💰 Cost Summary (in native tokens):");
    console.log(`   Min Cost: ${minCost}`);
    console.log(`   Max Cost: ${maxCost}`);
    console.log(`   Avg Cost: ${avgCost}`);
    console.log(
      "   Note: Costs are in each network's native token (ETH, MATIC, AVAX, etc.)"
    );
  }

  console.log("\n" + "=".repeat(100));
}

async function main() {
  console.log("🚀 Starting multi-network gas estimation...");
  console.log(`Networks: ${NETWORKS_TO_ESTIMATE.join(", ")}\n`);

  // Estimate gas for each network sequentially
  for (const networkName of NETWORKS_TO_ESTIMATE) {
    await estimateGasForNetwork(networkName);

    // Small delay between networks
    if (
      NETWORKS_TO_ESTIMATE.indexOf(networkName) <
      NETWORKS_TO_ESTIMATE.length - 1
    ) {
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  }

  calculateSummary();

  const reportPath = path.join(__dirname, "..", "gas-report.json");
  fs.writeFileSync(reportPath, JSON.stringify(gasReport, null, 2));
  console.log(`\n📝 Full report saved to: ${reportPath}`);

  printReport();
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .then(() => {
    console.log("\n✨ Estimation complete!");
  });
