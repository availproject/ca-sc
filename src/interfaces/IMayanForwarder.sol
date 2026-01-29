// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/// @title IMayanForwarder
/// @notice Interface for Mayan's forwarder contract that handles token transfers
interface IMayanForwarder {
    /// @notice Permit parameters for gasless ERC20 approvals
    struct PermitParams {
        uint256 value;
        uint256 deadline;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    /// @notice Forward ERC20 tokens to Mayan protocol
    /// @param tokenIn Source token address
    /// @param amountIn Amount to forward
    /// @param permitParams Permit signature parameters
    /// @param mayanProtocol Target Mayan protocol address
    /// @param protocolData Encoded protocol call data
    function forwardERC20(
        address tokenIn,
        uint256 amountIn,
        PermitParams calldata permitParams,
        address mayanProtocol,
        bytes calldata protocolData
    ) external payable;

    /// @notice Forward native ETH to Mayan protocol
    /// @param mayanProtocol Target Mayan protocol address
    /// @param protocolData Encoded protocol call data
    function forwardEth(address mayanProtocol, bytes calldata protocolData) external payable;
}
