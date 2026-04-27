// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/// @title IMayanSwiftV2
/// @notice Interface for Mayan Swift V2 cross-chain swap protocol
interface IMayanSwiftV2 {
    /// @notice Order parameters for cross-chain swap
    struct OrderParams {
        uint8 payloadType;
        bytes32 trader;
        bytes32 destAddr;
        uint16 destChainId;
        bytes32 referrerAddr;
        bytes32 tokenOut;
        uint64 minAmountOut;
        uint64 gasDrop;
        uint64 cancelFee;
        uint64 refundFee;
        uint64 deadline;
        uint8 referrerBps;
        uint8 auctionMode;
        bytes32 random;
    }

    /// @notice Create order with ERC20 token
    /// @param tokenIn Source token address
    /// @param amountIn Amount to swap
    /// @param params Order parameters
    /// @param customPayload Additional payload data
    /// @return orderHash Hash of the created order
    function createOrderWithToken(
        address tokenIn,
        uint256 amountIn,
        OrderParams memory params,
        bytes memory customPayload
    ) external returns (bytes32 orderHash);
}
