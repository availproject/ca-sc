const { ethers, upgrades } = require("hardhat");
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

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
  arb_sepolia: "ETH",
  op_sepolia: "ETH",
  base_sepolia: "ETH",
  citrea_testnet: "cBTC",
  monad_testnet: "MONAD"
};

const NETWORKS_TO_DEPLOY = [
  // "avalanche_c_chain",
  // "hyperliquid",
  // "kaia_mainnet",
  // "bnb_smart_chain_mainnet",
  // "monad_mainnet",
  // "ethereum",
  // "base_sepolia",
  // "arb_sepolia",
  // "op_sepolia",
  // "polygon_amony",
  // "sepolia"
  // "monad_testnet",
  "citrea_testnet"
];

async function deploySingleNetwork(adminAddress) {
  const networkName = hre.network.name;
  console.log(`\n${"=".repeat(60)}`);
  console.log(`Deploying UUPS Proxy to ${networkName}...`);
  console.log(`${"=".repeat(60)}`);

  const [deployer] = await ethers.getSigners();
  const provider = deployer.provider;
  const network = await provider.getNetwork();
  const feeData = await provider.getFeeData();

  console.log(`Chain ID: ${network.chainId}`);
  console.log(`Deployer: ${deployer.address}`);
  console.log(`Gas Price: ${ethers.formatUnits(feeData.gasPrice || 0n, "gwei")} gwei`);

  const balance = await provider.getBalance(deployer.address);
  console.log(`Balance: ${ethers.formatEther(balance)} ${NATIVE_TOKENS[networkName] || "ETH"}`);

  const admin = adminAddress || deployer.address;
  console.log(`Admin: ${admin}`);
  console.log("Deploying Vault proxy (UUPS)...");

  const Vault = await ethers.getContractFactory("Vault");
  const vault = await upgrades.deployProxy(Vault, [admin], {
    kind: "uups",
    timeout: 0,
  });

  const proxyAddress = await vault.getAddress();
  console.log(`Proxy address: ${proxyAddress}`);

  await vault.waitForDeployment();

  const implementationAddress = await upgrades.erc1967.getImplementationAddress(proxyAddress);
  console.log(`Implementation address: ${implementationAddress}`);

  const deployTx = vault.deploymentTransaction();
  let receipt = null;
  if (deployTx) {
    receipt = await deployTx.wait();
  }

  const gasUsed = receipt ? receipt.gasUsed : null;
  const actualCost = receipt && feeData.gasPrice ? receipt.gasUsed * feeData.gasPrice : null;

  const result = {
    chainId: network.chainId.toString(),
    proxyAddress,
    implementationAddress,
    admin,
    deployer: deployer.address,
    gasUsed: gasUsed ? gasUsed.toString() : "N/A",
    gasPrice: feeData.gasPrice ? ethers.formatUnits(feeData.gasPrice, "gwei") : "N/A",
    actualCost: actualCost ? ethers.formatEther(actualCost) : "N/A",
    nativeToken: NATIVE_TOKENS[networkName] || "ETH",
    txHash: receipt ? receipt.hash : "N/A",
    blockNumber: receipt ? receipt.blockNumber.toString() : "N/A",
    timestamp: new Date().toISOString(),
  };

  console.log(`\n✅ Successfully deployed to ${networkName}`);
  console.log(`   Proxy: ${proxyAddress}`);
  console.log(`   Implementation: ${implementationAddress}`);

  console.log(`\n__DEPLOY_RESULT__${JSON.stringify(result)}__END_RESULT__`);
  return result;
}

function runMultiNetwork(adminAddress, networks) {
  console.log("🚀 Starting multi-network UUPS proxy deployment...");
  console.log(`Networks: ${networks.join(", ")}\n`);

  const deploymentResults = {
    timestamp: new Date().toISOString(),
    deployments: {},
    summary: { successful: 0, failed: 0 },
  };

  for (const networkName of networks) {
    console.log(`\n${"=".repeat(60)}`);
    console.log(`Deploying to ${networkName}...`);
    console.log(`${"=".repeat(60)}`);

    try {
      const adminArg = adminAddress ? `--admin ${adminAddress}` : "";
      const cmd = `npx hardhat run scripts/deploy-proxy-multi-network.js --network ${networkName} ${adminArg}`;

      const output = execSync(cmd, {
        encoding: "utf-8",
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env },
      });

      console.log(output);

      const resultMatch = output.match(/__DEPLOY_RESULT__(.+?)__END_RESULT__/);
      if (resultMatch) {
        const result = JSON.parse(resultMatch[1]);
        deploymentResults.deployments[networkName] = result;
        deploymentResults.summary.successful++;
      } else {
        throw new Error("Could not parse deployment result");
      }
    } catch (error) {
      console.error(`❌ Failed to deploy to ${networkName}:`, error.message);
      if (error.stderr) console.error(error.stderr);
      deploymentResults.deployments[networkName] = {
        error: error.message,
        timestamp: new Date().toISOString(),
      };
      deploymentResults.summary.failed++;
    }

    if (networks.indexOf(networkName) < networks.length - 1) {
      console.log("\nWaiting 3 seconds before next deployment...");
      execSync("sleep 3");
    }
  }

  const resultsPath = path.join(__dirname, "..", "proxy-addresses.json");
  fs.writeFileSync(resultsPath, JSON.stringify(deploymentResults, null, 2));
  console.log(`\n📝 Deployment results saved to: ${resultsPath}`);

  printReport(deploymentResults);
}

function printReport(deploymentResults) {
  console.log("\n" + "=".repeat(130));
  console.log("DEPLOYMENT REPORT - MULTI-NETWORK PROXY DEPLOYMENT");
  console.log("=".repeat(130));
  console.log("\n📊 Network Results:\n");

  const colNetwork = 20;
  const colChainId = 10;
  const colProxy = 45;
  const colImpl = 45;
  const colCost = 20;

  const header =
    "Network".padEnd(colNetwork) +
    "Chain ID".padEnd(colChainId) +
    "Proxy Address".padEnd(colProxy) +
    "Implementation".padEnd(colImpl) +
    "Cost".padEnd(colCost);
  console.log(header);
  console.log("-".repeat(140));

  Object.entries(deploymentResults.deployments).forEach(([network, data]) => {
    if (data.error) {
      console.log(`${network.padEnd(colNetwork)} ❌ ${data.error}`);
    } else {
      const proxy = data.proxyAddress || "N/A";
      const impl = data.implementationAddress || "N/A";
      const cost = data.actualCost || "N/A";
      const nativeToken = data.nativeToken || "ETH";
      const costFormatted = cost !== "N/A" ? `${cost} ${nativeToken}` : "N/A";

      const row =
        network.padEnd(colNetwork) +
        data.chainId.padEnd(colChainId) +
        proxy.padEnd(colProxy) +
        impl.padEnd(colImpl) +
        costFormatted.padEnd(colCost);
      console.log(row);
    }
  });

  console.log("-".repeat(140));
  console.log("\n📈 Summary:");
  console.log(`   ✅ Successful: ${deploymentResults.summary.successful}`);
  console.log(`   ❌ Failed: ${deploymentResults.summary.failed}`);
  console.log("=".repeat(130));
}

async function main() {
  const args = process.argv.slice(2);
  // Allow admin address via Env var or CLI arg (CLI takes precedence)
  let adminAddress = process.env.PROXY_ADMIN_ADDRESS || null;

  const adminIdx = args.indexOf("--admin");
  if (adminIdx !== -1 && args[adminIdx + 1]) {
    adminAddress = args[adminIdx + 1];
  }

  if (hre.network.name !== "hardhat") {
    await deploySingleNetwork(adminAddress);
  } else {
    const networksArg = args.find((a) => !a.startsWith("--") && a !== adminAddress);
    const networksToDeploy = networksArg
      ? networksArg.split(",").map((n) => n.trim())
      : NETWORKS_TO_DEPLOY;

    runMultiNetwork(adminAddress, networksToDeploy);
  }
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .then(() => {
    console.log("\n✨ Done!");
  });
