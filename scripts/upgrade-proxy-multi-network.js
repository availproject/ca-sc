const { ethers, upgrades } = require("hardhat");
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

// Networks to upgrade (modify as needed)
const NETWORKS_TO_UPGRADE = [
  "polygon_mainnet",
  "arbitrum_one",
  "base_mainnet",
  "ethereum"
  // "base_sepolia",
  // "arb_sepolia",
  // "op_sepolia",
  // "polygon_amony",
  // "sepolia",
  // "monad_testnet",
  // "citrea_testnet"
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
  tron_mainnet: "TRX",
};

// Upgrade results storage
const upgradeResults = {
  timestamp: new Date().toISOString(),
  upgrades: {},
  summary: {
    successful: 0,
    failed: 0,
  },
};

async function upgradeSingleNetwork(proxyAddress) {
  const networkName = hre.network.name;
  console.log(`\n${"=".repeat(60)}`);
  console.log(`Upgrading proxy on ${networkName}...`);
  console.log(`${"=".repeat(60)}`);

  try {
    const [deployer] = await ethers.getSigners();
    const provider = deployer.provider;
    const network = await provider.getNetwork();
    const feeData = await provider.getFeeData();

    console.log(`Chain ID: ${network.chainId}`);
    console.log(`Deployer: ${deployer.address}`);
    console.log(
      `Gas Price: ${ethers.formatUnits(feeData.gasPrice || 0n, "gwei")} gwei`
    );
    console.log(`Proxy Address: ${proxyAddress}`);

    // Check balance
    const balance = await provider.getBalance(deployer.address);
    console.log(
      `Balance: ${ethers.formatEther(balance)} ${NATIVE_TOKENS[networkName] || "ETH"}`
    );

    // Verify proxy exists and get current implementation
    const proxyCode = await provider.getCode(proxyAddress);
    if (proxyCode === "0x") {
      throw new Error(`No contract found at proxy address ${proxyAddress}`);
    }

    // Get current implementation address using EIP-1967 storage slot
    const IMPLEMENTATION_SLOT =
      "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
    const currentImplStorage = await provider.getStorage(
      proxyAddress,
      IMPLEMENTATION_SLOT
    );
    const currentImplementation = ethers.getAddress(
      "0x" + currentImplStorage.slice(-40)
    );
    console.log(`Current Implementation: ${currentImplementation}`);

    const Vault = await ethers.getContractFactory("Vault");
    const proxy = Vault.attach(proxyAddress);
    const upgraderRole = ethers.keccak256(ethers.toUtf8Bytes("UPGRADER_ROLE"));
    const hasUpgraderRole = await proxy.hasRole(upgraderRole, deployer.address);
    const hasAdminRole = await proxy.hasRole(
      await proxy.DEFAULT_ADMIN_ROLE(),
      deployer.address
    );

    console.log(`Has UPGRADER_ROLE: ${hasUpgraderRole}`);
    console.log(`Has ADMIN_ROLE: ${hasAdminRole}`);

    if (!hasUpgraderRole && !hasAdminRole) {
      throw new Error(
        `Deployer ${deployer.address} does not have UPGRADER_ROLE or ADMIN_ROLE on proxy ${proxyAddress}`
      );
    }

    console.log("Upgrading proxy using Hardhat upgrades plugin...");

    // Use Hardhat upgrades plugin to upgrade the proxy
    // This deploys a new implementation and calls upgradeToAndCall automatically
    const upgradedProxy = await upgrades.upgradeProxy(proxyAddress, Vault, {
      kind: "uups",
      timeout: 0,
    });

    await upgradedProxy.waitForDeployment();

    const newImplementationAddress = await upgrades.erc1967.getImplementationAddress(
      proxyAddress
    );
    console.log(`New implementation deployed at: ${newImplementationAddress}`);

    // Verify the new implementation is set
    if (
      newImplementationAddress.toLowerCase() === currentImplementation.toLowerCase()
    ) {
      throw new Error(
        `Implementation not changed! Still at ${currentImplementation}`
      );
    }

    console.log(`✅ Upgrade confirmed`);

    const deployTx = upgradedProxy.deploymentTransaction();
    let receipt = null;
    if (deployTx) {
      receipt = await deployTx.wait();
    }

    // Get actual gas used
    const gasUsed = receipt ? receipt.gasUsed : null;
    const actualCost =
      receipt && feeData.gasPrice ? receipt.gasUsed * feeData.gasPrice : null;

    const result = {
      success: true,
      chainId: network.chainId.toString(),
      proxyAddress,
      oldImplementation: currentImplementation,
      newImplementation: newImplementationAddress,
      gasUsed: gasUsed ? gasUsed.toString() : "N/A",
      gasPrice: feeData.gasPrice
        ? ethers.formatUnits(feeData.gasPrice, "gwei")
        : "N/A",
      actualCost: actualCost ? ethers.formatEther(actualCost) : "N/A",
      nativeToken: NATIVE_TOKENS[networkName] || "ETH",
      txHash: receipt ? receipt.hash : "N/A",
      blockNumber: receipt ? receipt.blockNumber.toString() : "N/A",
      status: "success",
      timestamp: new Date().toISOString(),
    };

    console.log(`✅ Successfully upgraded proxy on ${networkName}`);
    if (gasUsed) {
      console.log(`   Gas Used: ${gasUsed.toString()}`);
    }
    if (actualCost) {
      console.log(
        `   Cost: ${ethers.formatEther(actualCost)} ${NATIVE_TOKENS[networkName] || "ETH"}`
      );
    }

    console.log(`\n__UPGRADE_RESULT__${JSON.stringify(result)}__END_RESULT__`);
    return result;
  } catch (error) {
    console.error(`❌ Failed to upgrade on ${networkName}:`, error.message);
    const result = {
      success: false,
      network: networkName,
      error: error.message,
      proxyAddress: proxyAddress || "N/A",
      status: "failed",
      timestamp: new Date().toISOString(),
    };
    console.log(`\n__UPGRADE_RESULT__${JSON.stringify(result)}__END_RESULT__`);
    return result;
  }
}

function runMultiNetworkUpgrade(proxyAddresses, networks) {
  console.log("🚀 Starting multi-network proxy upgrade...");
  console.log(
    "   Using Hardhat upgrades plugin (upgrades.upgradeProxy)\n"
  );
  console.log(`Networks: ${networks.join(", ")}\n`);

  const missingAddresses = networks.filter((n) => !proxyAddresses[n]);
  if (missingAddresses.length > 0) {
    console.error(
      `❌ Error: Missing proxy addresses for networks: ${missingAddresses.join(", ")}`
    );
    console.error(
      "Please provide proxy addresses via command line or proxy-addresses.json"
    );
    process.exit(1);
  }

  for (const networkName of networks) {
    console.log(`\n${"=".repeat(60)}`);
    console.log(`Upgrading ${networkName}...`);
    console.log(`${"=".repeat(60)}`);

    const proxyAddress = proxyAddresses[networkName];

    try {
      const cmd = `npx hardhat run scripts/upgrade-proxy-multi-network.js --network ${networkName}`;

      const output = execSync(cmd, {
        encoding: "utf-8",
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, PROXY_ADDRESS: proxyAddress },
      });

      console.log(output);

      const resultMatch = output.match(/__UPGRADE_RESULT__(.+?)__END_RESULT__/);
      if (resultMatch) {
        const result = JSON.parse(resultMatch[1]);
        upgradeResults.upgrades[networkName] = result;
        if (result.success) {
          upgradeResults.summary.successful++;
        } else {
          upgradeResults.summary.failed++;
        }
      } else {
        throw new Error("Could not parse upgrade result");
      }
    } catch (error) {
      console.error(`❌ Failed to upgrade ${networkName}:`, error.message);
      if (error.stderr) console.error(error.stderr);
      upgradeResults.upgrades[networkName] = {
        error: error.message,
        proxyAddress: proxyAddress,
        status: "failed",
        timestamp: new Date().toISOString(),
      };
      upgradeResults.summary.failed++;
    }

    if (networks.indexOf(networkName) < networks.length - 1) {
      console.log("\nWaiting 3 seconds before next upgrade...");
      execSync("sleep 3");
    }
  }

  const resultsPath = path.join(__dirname, "..", "upgrades.json");
  fs.writeFileSync(resultsPath, JSON.stringify(upgradeResults, null, 2));
  console.log(`\n📝 Upgrade results saved to: ${resultsPath}`);

  printReport();
}

function printReport() {
  console.log("\n" + "=".repeat(100));
  console.log("PROXY UPGRADE REPORT - MULTI-NETWORK");
  console.log("=".repeat(100));

  console.log("\n📊 Network Results:\n");

  // Define column widths
  const colNetwork = 22;
  const colChainId = 10;
  const colProxy = 45;
  const colOldImpl = 45;
  const colNewImpl = 45;
  const colStatus = 12;

  // Header
  const header =
    "Network".padEnd(colNetwork) +
    "Chain ID".padEnd(colChainId) +
    "Status".padEnd(colStatus) +
    "Proxy Address".padEnd(colProxy) +
    "Old Impl".padEnd(colOldImpl) +
    "New Impl".padEnd(colNewImpl);
  console.log(header);
  console.log("-".repeat(180));

  // Data rows
  Object.entries(upgradeResults.upgrades).forEach(([network, data]) => {
    if (data.error) {
      console.log(
        `${network.padEnd(colNetwork)}${(data.chainId || "N/A").padEnd(
          colChainId
        )}❌ FAILED${" ".padEnd(colStatus - 7)}${(
          data.proxyAddress || "N/A"
        ).padEnd(colProxy)}`
      );
      console.log(`   Error: ${data.error}`);
    } else if (data.status === "skipped") {
      console.log(
        `${network.padEnd(colNetwork)}${data.chainId.padEnd(
          colChainId
        )}⏭️  SKIPPED${" ".padEnd(colStatus - 8)}${data.proxyAddress.padEnd(
          colProxy
        )}${data.oldImplementation.padEnd(
          colOldImpl
        )}${data.newImplementation.padEnd(colNewImpl)}`
      );
    } else {
      const status = data.status === "success" ? "✅ SUCCESS" : data.status;
      console.log(
        `${network.padEnd(colNetwork)}${data.chainId.padEnd(
          colChainId
        )}${status.padEnd(colStatus)}${data.proxyAddress.padEnd(colProxy)}${(
          data.oldImplementation || "N/A"
        ).padEnd(colOldImpl)}${data.newImplementation.padEnd(colNewImpl)}`
      );
      if (data.gasUsed) {
        console.log(
          `   Gas: ${data.gasUsed} | Cost: ${data.actualCost || "N/A"} ${data.nativeToken || "ETH"
          } | Tx: ${data.txHash || "N/A"}`
        );
      }
    }
  });

  console.log("-".repeat(180));

  // Summary
  const successful = Object.values(upgradeResults.upgrades).filter(
    (d) => d.status === "success"
  );
  const failed = Object.values(upgradeResults.upgrades).filter(
    (d) => d.error || d.status === "failed"
  );
  const skipped = Object.values(upgradeResults.upgrades).filter(
    (d) => d.status === "skipped"
  );

  console.log("\n📈 Summary:");
  console.log(`   ✅ Successful upgrades: ${successful.length}`);
  console.log(`   ❌ Failed upgrades: ${failed.length}`);
  console.log(`   ⏭️  Skipped upgrades: ${skipped.length}`);
  console.log(
    `   📝 Total networks: ${Object.keys(upgradeResults.upgrades).length}`
  );

  console.log("\n" + "=".repeat(100));
}

async function main() {
  const args = process.argv.slice(2);
  
  if (hre.network.name !== "hardhat") {
    const proxyAddress = process.env.PROXY_ADDRESS || args[0];
    if (!proxyAddress) {
      console.error("❌ Error: Proxy address required. Set PROXY_ADDRESS env var or pass as argument");
      console.error("Usage: PROXY_ADDRESS=0x... npx hardhat run scripts/upgrade-proxy-multi-network.js --network <network>");
      console.error("   or: npx hardhat run scripts/upgrade-proxy-multi-network.js --network <network> 0x...");
      process.exit(1);
    }
    await upgradeSingleNetwork(proxyAddress);
  } else {
    const networksArg = args[0];
    const networksToUpgrade = networksArg
      ? networksArg.split(",").map((n) => n.trim())
      : NETWORKS_TO_UPGRADE;

    let proxyAddresses = {};
    const proxyAddressesArg = args[1];

    if (proxyAddressesArg) {
      proxyAddressesArg.split(",").forEach((pair) => {
        const [network, address] = pair.split(":").map((s) => s.trim());
        if (network && address) {
          proxyAddresses[network] = address;
        }
      });
      console.log(
        `📝 Loaded ${Object.keys(proxyAddresses).length} proxy addresses from command line`
      );
    } else {
      const proxyAddressesPath = path.join(__dirname, "..", "proxy-addresses.json");
      if (fs.existsSync(proxyAddressesPath)) {
        try {
          const proxyData = JSON.parse(fs.readFileSync(proxyAddressesPath, "utf8"));
          const deployments = proxyData.proxies || proxyData.deployments || proxyData;
          networksToUpgrade.forEach((network) => {
            if (deployments[network]) {
              const proxyAddr =
                typeof deployments[network] === "string"
                  ? deployments[network]
                  : deployments[network].proxyAddress || deployments[network].address;
              if (proxyAddr) {
                proxyAddresses[network] = proxyAddr;
              }
            }
          });
          console.log(
            `📝 Loaded ${Object.keys(proxyAddresses).length} proxy addresses from proxy-addresses.json`
          );
        } catch (e) {
          console.log(`⚠️  Could not load proxy-addresses.json: ${e.message}`);
        }
      } else {
        console.log(`⚠️  proxy-addresses.json not found. Create it with format:`);
        console.log(`   {`);
        console.log(`     "deployments": {`);
        console.log(`       "polygon_mainnet": { "proxyAddress": "0x..." },`);
        console.log(`       "arbitrum_one": { "proxyAddress": "0x..." }`);
        console.log(`     }`);
        console.log(`   }`);
      }
    }

    await runMultiNetworkUpgrade(proxyAddresses, networksToUpgrade);
  }
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .then(() => {
    console.log("\n✨ Upgrade process complete!");
  });
