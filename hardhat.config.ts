import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@openzeppelin/hardhat-upgrades";
import "hardhat-gas-reporter";
import "dotenv/config";

// import '@nomicfoundation/hardhat-verify';

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
      url: process.env.POLYGON_MAINNET_RPC_URL!,
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
      url: process.env.ARBITRUM_ONE_RPC_URL!,
      accounts: [PK],
    },
    optimism_mainnet: {
      url: process.env.OPTIMISM_MAINNET_RPC_URL!,
      accounts: [PK],
    },
    base_mainnet: {
      url: process.env.BASE_MAINNET_RPC_URL!,
      accounts: [PK],
    },
    scroll_mainnet: {
      url: process.env.SCROLL_MAINNET_RPC_URL!,
      accounts: [PK],
    },
    linea_mainnet: {
      url: process.env.LINEA_MAINNET_RPC_URL!,
      accounts: [PK],
    },
    sophon_mainnet: {
      url: process.env.SOPHON_MAINNET_RPC_URL!,
      accounts: [PK],
    },
    avalanche_c_chain: {
      url: process.env.AVALANCHE_C_CHAIN_RPC_URL!,
      accounts: [PK],
    },
    hyperliquid: {
      url: process.env.HYPERLIQUID_RPC_URL!,
      accounts: [PK],
    },
    kaia_mainnet: {
      url: process.env.KAIA_MAINNET_RPC_URL!,
      accounts: [PK],
    },
    bnb_smart_chain_mainnet: {
      url: process.env.BNB_SMART_CHAIN_MAINNET_RPC_URL!,
      accounts: [PK],
    },
    citrea_testnet: {
      url: process.env.CITREA_TESTNET_RPC_URL!,
      accounts: [PK],
    },
    monad_mainnet: {
      url: process.env.MONAD_MAINNET_RPC_URL!,
      accounts: [PK],
    },
    citrea_mainnet: {
      url: process.env.CITREA_MAINNET_RPC_URL!,
      accounts: [PK],
    },
    mega_eth: {
      url: process.env.MEGA_ETH_RPC_URL!,
      accounts: [PK],
    },
    base_sepolia: {
      url: process.env.BASE_SEPOLIA_RPC_URL!,
      accounts: [PK],
    },
    polygon_amony: {
      url: process.env.POLYGON_AMONY_RPC_URL!,
      accounts: [PK],
    },
    sepolia: {
      url: process.env.SEPOLIA,
      accounts: [PK],
    },
  },
  gasReporter: {
    enabled: true,
    currency: "USD",
    coinmarketcap: process.env.COINMARKETCAP_API_KEY!,
    excludeContracts: [],
  },
};

export default config;
