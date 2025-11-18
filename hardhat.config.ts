import {HardhatUserConfig} from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@openzeppelin/hardhat-upgrades";
// import '@nomicfoundation/hardhat-verify';

const PK = process.env.PRIVATE_KEY!;

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.30",
    settings: {
      evmVersion: 'prague',
      optimizer: {
        enabled: true,
        runs: 1_000_000,
      },
    },
  },
  networks: {
    ethereum: {
      url: 'https://ethereum-rpc.publicnode.com',
      accounts: [PK]
    },
    polygon_mainnet: {
      url: 'https://polygon-mainnet.g.alchemy.com/v2/PfaswrKq0rjOrfYWHfE9uLQKhiD4JCdq',
      accounts: [PK]
    },
    arb_sepolia: {
      url: 'https://arbitrum-sepolia-rpc.publicnode.com',
      accounts: [PK]
    },
    op_sepolia: {
      url: 'https://optimism-sepolia.api.onfinality.io/public',
      accounts: [PK]
    },
    monad_testnet: {
      url: 'https://testnet-rpc.monad.xyz',
      accounts: [PK]
    },
    holešky: {
      url: 'https://ethereum-holesky-rpc.publicnode.com',
      accounts: [PK]
    },
    arbitrum_one: {
      url: 'https://arbitrum-one-rpc.publicnode.com',
      accounts: [PK]
    },
    optimism_mainnet: {
      url: 'https://optimism-rpc.publicnode.com',
      accounts: [PK]
    },
    base_mainnet: {
      url: 'https://base-rpc.publicnode.com',
      accounts: [PK]
    },
    scroll_mainnet: {
      url: 'https://scroll-rpc.publicnode.com',
      accounts: [PK]
    },
    linea_mainnet: {
      url: 'https://linea-rpc.publicnode.com',
      accounts: [PK]
    },
    sophon_mainnet: {
      url: 'https://rpc.sophon.xyz',
      accounts: [PK]
    },
    avalanche_c_chain: {
      url: 'https://avalanche-c-chain-rpc.publicnode.com',
      accounts: [PK]
    }
  },
  // etherscan: {
  //   apiKey: {
  //     polygon_mainnet: process.env.POLYGONSCAN_API_KEY,
  //     arbitrum_one: process.env.ARBISCAN_API_KEY,
  //     optimism_mainnet: process.env.OPTIMISTIC_ETHERSCAN_API_KEY,
  //   },
  //   customChains: [
  //     {
  //       network: 'polygon_mainnet',
  //       chainId: 137,
  //       urls: {
  //         apiURL: "https://api.polygonscan.com/api",
  //         browserURL: "https://polygonscan.com"
  //       }
  //     },
  //     {
  //       network: "optimism_mainnet",
  //       chainId: 10,
  //       urls: {
  //         apiURL: "https://api-optimistic.etherscan.io/api",
  //         browserURL: "https://optimistic.etherscan.io"
  //       }
  //     },
  //     {
  //       network: "arbitrum_one",
  //       chainId: 42161,
  //       urls: {
  //         apiURL: "https://api.arbiscan.io/api",
  //         browserURL: "https://arbiscan.io"
  //       }
  //     }
  //   ]
  // },
  // sourcify: {
  //   enabled: false
  // }
};

export default config;
