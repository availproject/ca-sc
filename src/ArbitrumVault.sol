// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Vault} from "./Vault.sol";
import {IArbSys} from "./interfaces/IArbSys.sol";

/// @title ArbitrumVault
/// @notice The Vault for Arbitrum Nitro chains
/// @dev Logs on Nitro carry the L2 block number
contract ArbitrumVault is Vault {
    function _blockNumber() internal view override returns (uint256) {
        return IArbSys(address(100)).arbBlockNumber();
    }
}
