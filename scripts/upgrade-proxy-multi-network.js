const { ethers, upgrades } = require("hardhat");
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

// Networks to upgrade (modify as needed)
const NETWORKS_TO_UPGRADE = [
  // "polygon_mainnet",
  // "arbitrum_one",
  // "optimism_mainnet",
  // "base_mainnet",
  // "scroll_mainnet",
  //   "tron_mainnet",
  "base_sepolia",
  "arb_sepolia",
  "op_sepolia",
  // "polygon_amony",
  "sepolia",
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

async function upgradeProxyOnNetwork(networkName, proxyAddress) {
  console.log(`\n${"=".repeat(60)}`);
  console.log(`Upgrading proxy on ${networkName}...`);
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
    console.log(`Proxy Address: ${proxyAddress}`);

    // Check balance
    const balance = await provider.getBalance(wallet.address);
    console.log(
      `Balance: ${ethers.formatEther(balance)} ${NATIVE_TOKENS[networkName] || "ETH"
      }`
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

    // Connect factory to wallet for the upgrade
    const VaultWithSigner = Vault.connect(wallet);
    const proxy = VaultWithSigner.attach(proxyAddress);

    // Get UPGRADER_ROLE hash (keccak256 of UTF-8 bytes)
    const upgraderRole = ethers.keccak256(ethers.toUtf8Bytes("UPGRADER_ROLE"));
    console.log(`Upgrader role: ${upgraderRole}`);
    const checkIfUpgraderRole = await proxy.hasRole(
      upgraderRole,
      wallet.address
    );
    console.log(`Has UPGRADER_ROLE: ${checkIfUpgraderRole}`);

    const hasAdminRole = await proxy.hasRole(
      await proxy.DEFAULT_ADMIN_ROLE(),
      wallet.address
    );
    console.log(`Has ADMIN_ROLE: ${hasAdminRole}`);

    if (!checkIfUpgraderRole) {
      throw new Error(
        `Wallet ${wallet.address} does not have UPGRADER_ROLE or ADMIN_ROLE on proxy ${proxyAddress}`
      );
    }
    console.log("Deploying new implementation...");

    // Deploy the new implementation directly (since proxy is not registered with upgrades tooling)
    const newImplementation = await VaultWithSigner.deploy();
    await newImplementation.waitForDeployment();
    const newImplementationAddress = await newImplementation.getAddress();

    console.log(`New implementation deployed at: ${newImplementationAddress}`);

    // Now manually call upgradeTo on the proxy
    console.log("Upgrading proxy to new implementation...");
    const upgradeTx = await proxy.upgradeToAndCall(
      newImplementationAddress,
      "0x"
    );

    console.log(`Transaction Hash: ${upgradeTx.hash}`);
    console.log("Waiting for confirmation...");

    const receipt = await upgradeTx.wait();
    console.log(`✅ Upgrade confirmed in block ${receipt.blockNumber}`);

    // Verify the new implementation is set
    const verifiedImplAddress = await upgrades.erc1967.getImplementationAddress(
      proxyAddress
    );
    console.log(`Verified implementation address: ${verifiedImplAddress}`);

    if (
      verifiedImplAddress.toLowerCase() !==
      newImplementationAddress.toLowerCase()
    ) {
      throw new Error(
        `Implementation mismatch! Expected ${newImplementationAddress}, got ${verifiedImplAddress}`
      );
    }

    // Get actual gas used
    const gasUsed = receipt.gasUsed;
    const actualCost =
      receipt && feeData.gasPrice ? receipt.gasUsed * feeData.gasPrice : null;

    // Store upgrade info
    upgradeResults.upgrades[networkName] = {
      chainId: network.chainId.toString(),
      proxyAddress,
      oldImplementation: currentImplementation,
      newImplementation: newImplementationAddress,
      gasUsed: gasUsed.toString(),
      gasPrice: feeData.gasPrice
        ? ethers.formatUnits(feeData.gasPrice, "gwei")
        : "N/A",
      actualCost: actualCost ? ethers.formatEther(actualCost) : "N/A",
      nativeToken: NATIVE_TOKENS[networkName] || "ETH",
      txHash: receipt.hash,
      blockNumber: receipt.blockNumber.toString(),
      status: "success",
      timestamp: new Date().toISOString(),
    };

    console.log(`✅ Successfully upgraded proxy on ${networkName}`);
    if (gasUsed) {
      console.log(`   Gas Used: ${gasUsed.toString()}`);
    }
    if (actualCost) {
      console.log(
        `   Cost: ${ethers.formatEther(actualCost)} ${NATIVE_TOKENS[networkName] || "ETH"
        }`
      );
    }

    return {
      success: true,
      network: networkName,
      proxyAddress,
      oldImplementation: currentImplementation,
      newImplementation: newImplementationAddress,
      gasUsed: gasUsed.toString(),
      cost: actualCost ? ethers.formatEther(actualCost) : null,
    };
  } catch (error) {
    console.error(`❌ Failed to upgrade on ${networkName}:`, error.message);
    upgradeResults.upgrades[networkName] = {
      error: error.message,
      proxyAddress: proxyAddress || "N/A",
      status: "failed",
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
  console.log("🚀 Starting multi-network proxy upgrade...");
  console.log(
    "   Note: upgrades.upgradeProxy() will deploy a new implementation from the factory\n"
  );

  // Get networks from command line or use default list
  const networksArg = process.argv[2];
  const networksToUpgrade = networksArg
    ? networksArg.split(",").map((n) => n.trim())
    : NETWORKS_TO_UPGRADE;

  // Get proxy addresses from command line or proxy-addresses.json
  let proxyAddresses = {};
  const proxyAddressesArg = process.argv[3];

  if (proxyAddressesArg) {
    // Parse proxy addresses (format: network1:address1,network2:address2)
    proxyAddressesArg.split(",").forEach((pair) => {
      const [network, address] = pair.split(":").map((s) => s.trim());
      if (network && address) {
        proxyAddresses[network] = address;
      }
    });
    console.log(
      `📝 Loaded ${Object.keys(proxyAddresses).length
      } proxy addresses from command line`
    );
  } else {
    // Try to load from proxy-addresses.json
    const proxyAddressesPath = path.join(
      __dirname,
      "..",
      "proxy-addresses.json"
    );
    if (fs.existsSync(proxyAddressesPath)) {
      try {
        const proxyData = JSON.parse(
          fs.readFileSync(proxyAddressesPath, "utf8")
        );
        // Support both formats: { "network": "address" } or { "proxies": { "network": "address" } }
        const proxies = proxyData.proxies || proxyData.deployments || proxyData;
        networksToUpgrade.forEach((network) => {
          if (proxies[network]) {
            // Support both string address or object with proxyAddress/address field
            const proxyAddr =
              typeof proxies[network] === "string"
                ? proxies[network]
                : proxies[network].proxyAddress ||
                proxies[network].address ||
                proxies[network].implementationAddress;
            if (proxyAddr) {
              proxyAddresses[network] = proxyAddr;
            }
          }
        });
        console.log(
          `📝 Loaded ${Object.keys(proxyAddresses).length
          } proxy addresses from proxy-addresses.json`
        );
      } catch (e) {
        console.log(`⚠️  Could not load proxy-addresses.json: ${e.message}`);
      }
    } else {
      console.log(`⚠️  proxy-addresses.json not found. Create it with format:`);
      console.log(`   {`);
      console.log(`     "polygon_mainnet": "0xProxyAddress",`);
      console.log(`     "arbitrum_one": "0xProxyAddress"`);
      console.log(`   }`);
    }
  }

  console.log(`Networks: ${networksToUpgrade.join(", ")}\n`);

  // Check if we have proxy addresses for all networks
  const missingAddresses = networksToUpgrade.filter((n) => !proxyAddresses[n]);
  if (missingAddresses.length > 0) {
    console.error(
      `❌ Error: Missing proxy addresses for networks: ${missingAddresses.join(
        ", "
      )}`
    );
    console.error(
      "Please provide proxy addresses via command line or proxy-addresses.json"
    );
    process.exit(1);
  }

  const results = [];

  // Upgrade each network sequentially
  for (const networkName of networksToUpgrade) {
    const proxyAddress = proxyAddresses[networkName];
    const result = await upgradeProxyOnNetwork(networkName, proxyAddress);
    results.push(result);

    // Small delay between upgrades
    if (networksToUpgrade.indexOf(networkName) < networksToUpgrade.length - 1) {
      console.log("\nWaiting 3 seconds before next upgrade...");
      await new Promise((resolve) => setTimeout(resolve, 3000));
    }
  }

  // Update summary
  upgradeResults.summary.successful = results.filter((r) => r.success).length;
  upgradeResults.summary.failed = results.filter((r) => !r.success).length;

  // Save upgrade results to file
  const resultsPath = path.join(__dirname, "..", "upgrades.json");
  fs.writeFileSync(resultsPath, JSON.stringify(upgradeResults, null, 2));
  console.log(`\n📝 Upgrade results saved to: ${resultsPath}`);

  // Print formatted report
  printReport();
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .then(() => {
    console.log("\n✨ Upgrade process complete!");
  });
