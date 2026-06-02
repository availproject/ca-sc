# AGENTS.md - Arcana Credit Smart Contracts

## Project Overview

Arcana Credit is a cross-chain intent settlement protocol. The Vault contract manages deposits, fulfillments, and settlements. Users sign messages authorizing fund movements; backend servers execute transactions on their behalf.

**Tech Stack:**
- Solidity ^0.8.29/^0.8.30 (EVM contracts)
- Foundry (primary) + Hardhat (secondary) build systems
- OpenZeppelin Contracts v5.x (upgradeable + standard)
- Sway/FuelVM (auxiliary Fuel blockchain implementation)

## Build Commands

### Foundry (Primary)
```bash
# Build
forge build

# Run all tests
forge test

# Run single test file
forge test --match-path test/Vault.t.sol

# Run single test function
forge test --match-test test_Deposit_ERC20Tokens

# Run tests with verbosity
forge test -vvvv

# Run tests with gas report
forge test --gas-report

# Format code
forge fmt

# Check formatting
forge fmt --check
```

### Hardhat (Secondary)
```bash
# Build
npm run compile
# or: npx hardhat compile

# Run tests
npm test
# or: npx hardhat test

# Deploy (multi-network)
npm run deploy:multi

# Upgrade proxies
npm run upgrade:multi

# Estimate gas
npm run estimate-gas
```

### FuelVM (Sway)
```bash
cd fuelVM/vault
forc build
```

## Code Style Guidelines

### File Structure
```
src/
  ├── Vault.sol          # Main upgradeable vault
  ├── Router.sol         # Cross-chain router
  ├── ERC20Sweeper.sol   # Token sweeper utility
  ├── types.sol          # Shared structs/enums
  ├── interfaces/        # Contract interfaces
  └── routes/            # Route implementations (mayan.sol)
test/
  └── *.t.sol            # Foundry tests
script/
  └── Deploy*.s.sol      # Foundry deploy scripts
scripts/
  └── *.js               # Hardhat JS scripts
```

### Solidity Conventions

**License & Pragma:**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;
```

**Imports - Use named imports with curly braces:**
```solidity
// Good
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

// Bad - avoid wildcard imports
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
```

**Formatting (foundry.toml [fmt]):**
- Line length: 100 characters
- Tab width: 4 spaces
- Bracket spacing: enabled
- Int types: `long` (uint256, not uint)
- Multiline function header: `attributes_first`
- Quote style: double quotes
- Number underscore: thousands (1_000_000)

**Naming Conventions:**
- Constants: `SCREAMING_SNAKE_CASE` (e.g., `UPGRADER_ROLE`)
- Private variables: `camelCase` with leading underscore for internal helpers
- Events: `PascalCase` (e.g., `Deposit`, `Fulfilment`, `Settle`)
- Errors: `PascalCase` (e.g., `InvalidRoute`, `ZeroAddress`)
- Functions: `camelCase`
- Structs/Enums: `PascalCase`

**NatSpec Documentation:**
```solidity
/// @title Contract title
/// @author Author name (@handle)
/// @notice User-facing description
/// @dev Technical implementation details
contract Example {
    /// @notice Emitted when X happens
    /// @param param1 Description
    event SomeEvent(uint256 indexed param1);

    /// @notice Function description
    /// @param param Description
    /// @return Description of return value
    function example(uint256 param) external returns (uint256) { }
}
```

### Error Handling

**Prefer custom errors over require strings for gas efficiency:**
```solidity
// Good - custom errors (gas efficient)
error InvalidRoute();
error ZeroAddress();
if (routerAddress == address(0)) revert ZeroAddress();

// Acceptable - require with string (used in existing code)
require(success, "Vault: Invalid signature or from");
```

**Revert message format:** `"ContractName: Error description"`

### Upgradeable Contracts Pattern

```solidity
contract Vault is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardTransient
{
    // Storage gap for future upgrades
    uint256[50] private __gap;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin) public initializer {
        __AccessControl_init();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    { }
}
```

### Test Conventions (Foundry)

```solidity
import { Test } from "forge-std/Test.sol";

contract VaultTest is Test {
    function setUp() public {
        // Setup code
    }

    // Test naming: test_FunctionName_Scenario
    function test_Deposit_ERC20Tokens() public { }
    function test_Deposit_RevertsOnExpiredRequest() public { }

    // Fuzz tests
    function test_SweepERC20_Fuzz(uint256 amount) public {
        vm.assume(amount > 0 && amount < type(uint128).max);
    }
}
```

**Test helpers:**
- `makeAddr("name")` - Create labeled address
- `vm.prank(addr)` - Next call from addr
- `vm.deal(addr, amount)` - Set ETH balance
- `vm.sign(pk, hash)` - Sign message
- `vm.expectRevert("message")` - Expect revert
- `vm.createSelectFork("network")` - Fork mainnet

### Security Patterns

1. **Reentrancy:** Use `nonReentrant` modifier or `ReentrancyGuardTransient`
2. **Safe transfers:** Always use `SafeERC20` for token transfers
3. **Fee-on-transfer tokens:** Verify actual received amount
4. **Signature verification:** Use OpenZeppelin's `ECDSA.recover()`
5. **Nonce management:** Track used nonces to prevent replay attacks
6. **Access control:** Use role-based access (`AccessControl`)

### Key Remappings
```
@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/
@openzeppelin/contracts-upgradeable/=lib/openzeppelin-contracts-upgradeable/contracts/
forge-std/=lib/forge-std/src/
```

### Environment Variables
Required in `.env`:
- `PRIVATE_KEY` - Deployer private key
- `*_RPC_URL` - Network RPC endpoints (ETHEREUM, POLYGON, ARBITRUM, etc.)
- `COINMARKETCAP_API_KEY` - For gas reporting
- `*SCAN_API_KEY` - Block explorer API keys

### Common Patterns in Codebase

**bytes32 to address conversion:**
```solidity
function bytes32ToAddress(bytes32 a) internal pure returns (address) {
    return address(uint160(uint256(a)));
}
```

**EIP-191 signed message verification:**
```solidity
bytes32 signedMessageHash = keccak256(
    abi.encodePacked("\x19Ethereum Signed Message:\n32", _hashRequest(request))
);
address signer = signedMessageHash.recover(signature);
```
