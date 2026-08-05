// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/// @title IExternalIntentExecutor
/// @notice Interface of the immutable ExternalIntentExecutor invoked by the external intent
/// gateway after exact funding has been acquired for one source entry.
interface IExternalIntentExecutor {
    /// @notice Executes the hash-committed routing payload with the funded assets.
    /// @dev Only callable by the immutable gateway. `asset == address(0)` denotes native funding,
    /// in which case `msg.value` must equal `amount`. ERC-20 funding is pulled from the gateway,
    /// which must hold an allowance of at least `amount` for the Executor when it calls.
    /// @param asset The funded ERC-20 token, or address(0) for the native asset
    /// @param amount The signed source amount funding this execution
    /// @param payload ABI-encoded RoutingPayload committed to by source.payloadHash
    function execute(address asset, uint256 amount, address party, bytes calldata payload) external payable;

    /// @notice Transfers the Executor's entire balance of `asset` to the gateway.
    /// @dev Owner-gated recovery for value no execution can attribute to a party: output paid in
    /// a denomination the caller was not funded with, and refunds arriving after `execute`
    /// returns. The destination is fixed, so this cannot redirect value to an arbitrary address.
    /// @param asset The ERC-20 to sweep, or address(0) for native currency
    /// @return amount The balance transferred to the gateway
    function sweep(address asset) external returns (uint256 amount);
}
