// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/// @title IMayanSwiftV1
/// @notice Interface for Mayan Swift V1 cross-chain swap protocol
interface IMayanSwiftV1 {
    /// @notice Order parameters for cross-chain swap
    struct OrderParams {
        bytes32 trader;
        bytes32 tokenOut;
        uint64 minAmountOut;
        uint64 gasDrop;
        uint64 cancelFee;
        uint64 refundFee;
        uint64 deadline;
        bytes32 destAddr;
        uint16 destChainId;
        bytes32 referrerAddr;
        uint8 referrerBps;
        uint8 auctionMode;
        bytes32 random;
    }

    /// @notice Create order with native ETH
    /// @param params Order parameters
    /// @return orderHash Hash of the created order
    function createOrderWithEth(OrderParams memory params) external payable returns (bytes32 orderHash);

    /// @notice Create order with ERC20 token
    /// @param tokenIn Source token address
    /// @param amountIn Amount to swap
    /// @param params Order parameters
    /// @return orderHash Hash of the created order
    function createOrderWithToken(address tokenIn, uint256 amountIn, OrderParams memory params)
        external
        returns (bytes32 orderHash);
}
