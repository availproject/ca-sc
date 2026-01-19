# Deployment Summary

This project uses **Foundry** with the **OpenZeppelin Foundry Upgrades** plugin for secure and upgradeable deployments.

## Prerequisites

- Foundry installed (`forge`)
- Node.js installed (for OpenZeppelin Upgrades validation)
- Environment variables set (see below)

## Contracts

1. **Router.sol**: Main routing contract. Deployed directly (non-upgradeable) to minimize gas costs and complexity for the main entry point.
2. **Vault.sol**: Holds user funds. Deployed as a **UUPS Upgradeable Proxy** to allow future logic updates while preserving state.
3. **MayanRouter.sol**: Specific route implementation for Mayan Swift V2. Deployed directly.

## Deployment Scripts

Scripts are located in `script/`:

- `DeployAll.s.sol`: Deploys the entire system in order: Router -> Vault (Proxy) -> MayanRouter.
- `DeployVault.s.sol`: Deploys only the Vault as a UUPS proxy.
- `DeployRouter.s.sol`: Deploys only the Router.
- `DeployMayanRouter.s.sol`: Deploys only the MayanRouter.

## Deployment Process

### 1. Setup Environment

Create a `.env` file:
```env
PRIVATE_KEY=your_deployer_private_key
ADMIN_ADDRESS=target_admin_address
ROUTER_ADDRESS=deployed_router_address (for partial deployments)
ETHERSCAN_API_KEY=your_key (for verification)
```

### 2. Clean Build (Important)

The OpenZeppelin Upgrades plugin requires a full compilation build info file. Always clean before deploying.

```bash
forge clean && forge build
```

### 3. Deploy

To deploy everything to a network (e.g., Sepolia):

```bash
forge clean && forge script script/DeployAll.s.sol --rpc-url sepolia --broadcast --verify --ffi
```

**Note**: The `--ffi` flag is REQUIRED for the OpenZeppelin Upgrades plugin to perform storage layout validation.

### 4. Admin Access

The scripts are designed to:
1. Use the deployer's key to deploy and configure contracts.
2. If `ADMIN_ADDRESS` in `.env` is different from the deployer:
   - Grant `DEFAULT_ADMIN_ROLE` to the target admin.
   - Renounce `DEFAULT_ADMIN_ROLE` from the deployer.
   - Transfer ownership of `MayanRouter` to the target admin.

This ensures the deployment is fully configured before handing over control.

## Upgrading Vault

To upgrade the Vault contract logic:

1. Create a new script (e.g., `script/UpgradeVault.s.sol`) using `Upgrades.upgradeProxy`.
2. Run validation: `forge clean && forge build`.
3. Execute upgrade script.

```solidity
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
...
Upgrades.upgradeProxy(proxyAddress, "VaultV2.sol", "");
```

## Verification

The deployment scripts include post-deployment verification checks to ensure:
- Roles are correctly assigned.
- Router links are established.
- Ownership is transferred.
