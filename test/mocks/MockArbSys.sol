// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IArbSys} from "../../src/interfaces/IArbSys.sol";

/// @title MockArbSys
/// @notice ArbSys stand-in for tests; its runtime code is etched at address 100
contract MockArbSys is IArbSys {
    uint256 public constant L2_BLOCK_NUMBER = 777_000_000;

    function arbBlockNumber() external pure returns (uint256) {
        return L2_BLOCK_NUMBER;
    }
}
