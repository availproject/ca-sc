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

    /// @notice Swap tokens and forward native ETH to Mayan protocol
    /// @param amountIn Amount of ETH to swap
    /// @param swapProtocol Address of the swap protocol
    /// @param swapData Encoded swap data for the swap protocol
    /// @param middleToken Address of the expected middle token
    /// @param minMiddleAmount Minimum amount of middle token to receive
    /// @param mayanProtocol Target Mayan protocol address
    /// @param mayanData Encoded protocol call data for Mayan
    function swapAndForwardEth(
        uint256 amountIn,
        address swapProtocol,
        bytes calldata swapData,
        address middleToken,
        uint256 minMiddleAmount,
        address mayanProtocol,
        bytes calldata mayanData
    ) external payable;
}
