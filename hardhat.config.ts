
import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@openzeppelin/hardhat-upgrades";
import "hardhat-gas-reporter";
import "dotenv/config";

const PK = process.env.PRIVATE_KEY!;

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.30",
    settings: {
      evmVersion: "prague",
      optimizer: {
        enabled: true,
        runs: 1_000_000,
      },
    },
  },
  networks: {
    ethereum: {
      url: process.env.ETHEREUM_RPC_URL!,
      accounts: [PK],
    },
    polygon_mainnet: {
      url: process.env.POLYGON_RPC_URL!,
      accounts: [PK],
    },
    arb_sepolia: {
      url: process.env.ARB_SEPOLIA_RPC_URL!,
      accounts: [PK],
    },
    op_sepolia: {
      url: process.env.OP_SEPOLIA_RPC_URL!,
      accounts: [PK],
    },
    monad_testnet: {
      url: process.env.MONAD_TESTNET_RPC_URL!,
      accounts: [PK],
    },
    holešky: {
      url: process.env.HOLESKY_RPC_URL!,
      accounts: [PK],
    },
    arbitrum_one: {
      url: process.env.ARBITRUM_RPC_URL!,
      accounts: [PK],
    },
    optimism_mainnet: {
      url: process.env.OPTIMISM_RPC_URL!,
      accounts: [PK],
    },
    base_mainnet: {
      url: process.env.BASE_RPC_URL!,
      accounts: [PK],
    },
    scroll_mainnet: {
      url: process.env.SCROLL_RPC_URL!,
      accounts: [PK],
    },
    linea_mainnet: {
      url: process.env.LINEA_RPC_URL!,
      accounts: [PK],
    },
    sophon_mainnet: {
      url: process.env.SOPHON_RPC_URL!,
      accounts: [PK],
    },
    avalanche_c_chain: {
      url: process.env.AVALANCHE_RPC_URL!,
      accounts: [PK],
    },
    hyperliquid: {
      url: process.env.HYPERLIQUID_RPC_URL!,
      accounts: [PK],
    },
    kaia_mainnet: {
      url: process.env.KAIA_RPC_URL!,
      accounts: [PK],
    },
    bnb_smart_chain_mainnet: {
      url: process.env.BNB_RPC_URL!,
      accounts: [PK],
    },
    citrea_testnet: {
      url: process.env.CITREA_TESTNET_RPC_URL!,
      accounts: [PK]
    },
    monad_mainnet: {
      url: process.env.MONAD_MAINNET_RPC_URL!,
      accounts: [PK],
    },
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL!,
      accounts: [PK],
    },
    base_sepolia: {
      url: process.env.BASE_SEPOLIA_RPC_URL!,
      accounts: [PK],
    },
    polygon_amony: {
      url: process.env.POLYGON_AMOY_RPC_URL!,
      accounts: [PK],
    },
    mega_eth: {
      url: process.env.MEGA_ETH_RPC_URL!,
      accounts: [PK],
    }
  },
  gasReporter: {
    enabled: true,
    currency: "USD",
    coinmarketcap: process.env.COINMARKETCAP_API_KEY!,
    excludeContracts: [],
  },
  paths: {
    sources: "./src",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"

  },
  etherscan: {
    apiKey: {
      'mega-mainnet': 'empty'
    },
    customChains: [
      {
        network: "mega-mainnet",
        chainId: 4326,
        urls: {
          apiURL: "https://megaeth.blockscout.com/api",
          browserURL: "https://megaeth.blockscout.com"
        }
      }
    ]
  }
};

export default config;
