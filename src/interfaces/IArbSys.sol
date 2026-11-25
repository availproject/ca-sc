// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/// @title IArbSys
/// @notice The ArbSys precompile at address 100 on Arbitrum Nitro chains
interface IArbSys {
    /// @notice The L2 block number; `block.number` on Nitro is the L1 block number
    function arbBlockNumber() external view returns (uint256);
}
