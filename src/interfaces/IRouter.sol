// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Request, Route} from "../types.sol";

/// @title IRouter
/// @notice Interface for the main Router contract
interface IRouter {
    /// @notice Process a cross-chain transfer via the specified route
    /// @param request Action struct containing transfer details
    /// @param route Route to use (NATIVE or MAYAN)
    /// @param data Additional route-specific encoded parameters
    function processTransfer(Request calldata request, Route route, bytes calldata data) external payable;

    /// @notice Set or update a router contract address for a specific route
    /// @param route Route identifier
    /// @param routerAddress Address of the router contract
    function setRouter(Route route, address routerAddress) external;

    /// @notice Get the router address for a specific route
    /// @param route Route identifier
    /// @return Router contract address
    function routers(Route route) external view returns (address);
}
