// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";

import { RouterAction, Route } from "./types.sol";
import { ICaRouter } from "./interfaces/ICaRouter.sol";

/// @title Router
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Main routing contract for cross-chain transfers via multiple route providers
/// @dev Non-upgradeable contract with role-based access control
contract Router is AccessControl {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    /// @notice Emitted when a transfer is routed via native protocol
    /// @param requestHash Hash of the action request
    event NativeRoute(bytes32 indexed requestHash);

    /// @notice Emitted when a transfer is routed via Mayan protocol
    /// @param requestHash Hash of the action request
    event MayanRoute(bytes32 indexed requestHash);

    /// @notice Emitted when a router address is updated
    /// @param route Route identifier
    /// @param routerAddress New router contract address
    event RouterSet(Route indexed route, address indexed routerAddress);

    /// @notice Thrown when an invalid or unconfigured route is requested
    error InvalidRoute();

    /// @notice Thrown when a zero address is provided where not allowed
    error ZeroAddress();

    /// @notice Mapping of route identifiers to router contract addresses
    mapping(Route => address) public routers;

    /// @notice Initialize the router contract with admin
    /// @param admin Address to grant DEFAULT_ADMIN_ROLE
    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /// @notice Set or update a router contract address for a specific route
    /// @dev Only callable by admin
    /// @param route Route identifier (NATIVE or MAYAN)
    /// @param routerAddress Address of the router contract implementing ICaRouter
    function setRouter(Route route, address routerAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (routerAddress == address(0)) revert ZeroAddress();
        routers[route] = routerAddress;
        emit RouterSet(route, routerAddress);
    }

    /// @notice Process a cross-chain transfer via the specified route
    /// @dev Delegates to the appropriate router contract
    /// @param request Action struct containing transfer details
    /// @param route Route to use (NATIVE or MAYAN)
    /// @param data Additional route-specific encoded parameters
    function processTransfer(RouterAction calldata request, Route route, bytes calldata data)
        external
        payable
    {
        address routerAddress = routers[route];
        if (routerAddress == address(0)) revert InvalidRoute();

        address tokenAddress = address(uint160(uint256(request.tokenAddress)));
        if (tokenAddress != address(0)) {
            IERC20(tokenAddress).approve(routerAddress, request.amountIn);
        }

        ICaRouter router = ICaRouter(routerAddress);
        if (route == Route.MAYAN) {
            bytes32 requestHash = keccak256(abi.encode(request));
            emit MayanRoute(requestHash);
        } else {
            revert InvalidRoute();
        }

        router.processTransfer{ value: msg.value }(request, data);
    }
}
