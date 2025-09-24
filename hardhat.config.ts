import {HardhatUserConfig} from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@openzeppelin/hardhat-upgrades";

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
  }
};

export default config;
