// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Request} from "../types.sol";

/// @title IRouter
/// @notice Interface for router contracts that process cross-chain transfers
interface IRouter {
    /// @notice Process a cross-chain transfer
    /// @param request Action struct containing transfer details
    /// @param data Additional route-specific encoded parameters
    function processTransfer(Request calldata request, bytes calldata data) external payable;
}
