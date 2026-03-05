# Nexus Vault

Production-grade upgradeable smart contract vault for the [Avail Nexus](https://availproject.org) cross-chain intent settlement protocol.

## Overview

Nexus Vault enables secure handling of cross-chain intents with support for ERC20 tokens and native assets across multiple blockchain ecosystems (Ethereum, Fuel, Solana, Tron). The vault uses an intent-based architecture where users sign messages off-chain and relayers execute transactions on their behalf.

## Architecture

### Core Components

- **Vault.sol** - Main upgradeable contract handling deposits, fulfillments, and settlements

### Key Features

- **Intent-Based Execution**: Users sign intents off-chain; relayers execute on-chain
- **Gasless User Experience**: Users only pay gas once for token approvals
- **Cross-Chain Support**: Handles intents across Ethereum, Fuel, Solana, and Tron
- **Signature Verification**: EIP-191 compliant message signing
- **Reentrancy Protection**: Transient reentrancy guards for gas efficiency
- **Access Control**: Role-based permissions for upgrades and settlements

### Request Flow

1. **Deposit** - User signs intent, relayer deposits funds into vault
2. **Fulfillment** - Solver fulfills the intent on destination chain
3. **Settlement** - Avail blockchain multisig settles payments to solvers

## Usage

### Prerequisites

```bash
node >= 18.0.0
npm >= 9.0.0
```

### Installation

```shell
npm install
```

### Testing

```shell
# Run full test suite
npx hardhat test

# Run tests with coverage
npx hardhat coverage

# Run tests on local network
npm run test:local
```

### Deployment

```shell
# Compile contracts
npm run compile

# Deploy to multiple networks
npm run deploy:multi

# Upgrade existing proxies
npm run upgrade:multi

# Estimate gas costs
npm run estimate-gas
```

## Contract Addresses

_Mainnet and testnet addresses to be added post-deployment_

## Security

- **Audits**: Contracts are designed following OpenZeppelin best practices
- **Upgradeability**: UUPS proxy pattern with role-based upgrade authorization
- **Reentrancy**: Transient reentrancy guards protect all state-changing functions
- **Signature Replay Protection**: Nonce-based replay protection for all operations

### Access Control Roles

- `DEFAULT_ADMIN_ROLE` - Contract administration
- `UPGRADER_ROLE` - Contract upgrade authorization
- `SETTLEMENT_VERIFIER_ROLE` - Settlement signature verification

## Dependencies

- [@openzeppelin/contracts](https://www.npmjs.com/package/@openzeppelin/contracts) ^5.5.0
- [@openzeppelin/contracts-upgradeable](https://www.npmjs.com/package/@openzeppelin/contracts-upgradeable) ^5.5.0
- [hardhat](https://www.npmjs.com/package/hardhat) ^2.28.0

## License

MIT License - see individual contract files for SPDX identifiers.

---

Built by [Avail](https://availproject.org) - The unification layer of Web3
