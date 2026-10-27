// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {ExternalRequest} from "../types.sol";

/// @title IExternalIntentRouter
/// @notice Interface for the external intent router that verifies and executes signed requests
interface IExternalIntentRouter {
    /// @notice Returns the immutable executor used by the router
    function executor() external view returns (address);

    /// @notice Returns whether a deposit nonce key has been consumed
    /// @param depositKey The key derived from a request nonce and source index
    function depositNonce(uint256 depositKey) external view returns (bool);

    /// @notice Executes one source entry of an external request
    /// @param request The signed external request
    /// @param signature EIP-191 signature over the request
    /// @param sourceIndex Index of the source entry to execute
    /// @param payload ABI-encoded routing payload committed to by the source
    /// @param authorization Optional ERC-20 funding authorization
    function execute(
        ExternalRequest calldata request,
        bytes calldata signature,
        uint256 sourceIndex,
        bytes calldata payload,
        bytes calldata authorization
    ) external payable;
}
