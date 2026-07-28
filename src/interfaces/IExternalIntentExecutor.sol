// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/// @title IExternalIntentExecutor
/// @notice Interface of the immutable ExternalIntentExecutor invoked by the external intent
/// gateway after exact funding has been acquired for one source entry.
interface IExternalIntentExecutor {
    /// @notice Executes the hash-committed routing payload with the funded assets.
    /// @dev Only callable by the immutable gateway. `asset == address(0)` denotes native funding,
    /// in which case `msg.value` must equal `amount`.
    /// @param asset The funded ERC-20 token, or address(0) for the native asset
    /// @param amount The signed source amount funding this execution
    /// @param refundRecipient The signed EVM party receiving leftover funds
    /// @param payload ABI-encoded RoutingPayload committed to by source.payloadHash
    function execute(address asset, uint256 amount, address refundRecipient, bytes calldata payload) external payable;

    /// @notice Permissionlessly transfers the Executor's entire balance of `asset` to `recipient`.
    /// @dev The Executor is not custody; any residual asset is publicly claimable. `recipient`
    /// must be nonzero.
    /// @param asset The ERC-20 to sweep, or address(0) for native currency
    /// @param recipient The receiver of the swept balance
    function sweep(address asset, address recipient) external;
}
