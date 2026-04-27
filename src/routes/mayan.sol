//  SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import { Request, Universe, SourcePair } from "../types.sol";
import { ICaRouter } from "../interfaces/ICaRouter.sol";
import { IMayanSwiftV1 } from "../interfaces/IMayanSwiftV1.sol";
import { IMayanForwarder } from "../interfaces/IMayanForwarder.sol";
import { IMayanSwiftV2 } from "../interfaces/IMayanSwiftV2.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

enum SwiftVersion {
    V2,
    V1
}

/// @title MayanRouter
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Router contract for Mayan Swift V2 cross-chain swaps via Wormhole
/// @dev Implements ICaRouter for integration with Arcana Credit protocol
contract MayanRouter is ICaRouter, Ownable {
    address public constant MAYAN_FORWARDER = 0x337685fdaB40D39bd02028545a4FfA7D287cC3E2;

    address public constant SWIFT_V2_PROTOCOL = 0x40fFE85A28DC9993541449464d7529a922142960;

    address public constant SWIFT_V1_PROTOCOL = 0xC38e4e6A15593f908255214653d3D947CA1c2338;

    error InvalidSwiftVersion(uint8 version);

    mapping(bytes32 => mapping(uint256 => uint16)) public caip2ToWormholeChainId;
    mapping(Universe => bytes32) public universeToCaip2Namespace;

    /// @notice Emitted when a Wormhole chain mapping is updated
    /// @param namespaceHash CAIP-2 namespace hash
    /// @param chainId Chain ID within the namespace
    /// @param wormholeChainId Corresponding Wormhole chain ID
    event WormholeChainMappingSet(
        bytes32 indexed namespaceHash, uint256 indexed chainId, uint16 wormholeChainId
    );

    /// @notice Initialize router with default EVM chain mappings
    constructor(address _owner) Ownable(_owner) {
        bytes32 eip155 = keccak256("eip155");
        caip2ToWormholeChainId[eip155][1] = 2;
        caip2ToWormholeChainId[eip155][8453] = 30;
        caip2ToWormholeChainId[eip155][42_161] = 23;
        caip2ToWormholeChainId[eip155][10] = 24;
        caip2ToWormholeChainId[eip155][43_114] = 6;
        caip2ToWormholeChainId[eip155][137] = 5;
        caip2ToWormholeChainId[eip155][56] = 4;

        // Map Universe enum to CAIP-2 namespaces
        universeToCaip2Namespace[Universe.ETHEREUM] = eip155;
    }

    /// @notice Process cross-chain token transfer via Mayan Swift V2 or V1
    /// @dev Only supports ETHEREUM universe sources. Destination chain must be configured.
    /// @param request Action struct containing source, destination, and recipient details
    /// @param data ABI-encoded (SwiftVersion, remaining data)
    function processTransfer(Request calldata request, bytes calldata data)
        external
        payable
        override
    {
        (uint256 chainIndex, uint256 destinationChainIndex, bytes memory actualData) =
            abi.decode(data, (uint256, uint256, bytes));
        address tokenIn = address(uint160(uint256(request.sources[chainIndex].contractAddress)));
        uint256 amountIn = request.sources[chainIndex].value;

        (SwiftVersion version, bytes memory remainingData) = abi.decode(actualData, (SwiftVersion, bytes));

        if (version == SwiftVersion.V2) {
            _processTransferV2(request, destinationChainIndex, tokenIn, amountIn, remainingData);
        } else if (version == SwiftVersion.V1) {
            _processTransferV1(request, tokenIn, amountIn, remainingData);
        } else {
            revert InvalidSwiftVersion(uint8(version));
        }
    }

    /// @notice Process cross-chain transfer via Mayan Swift V2
    /// @param request Action struct containing source, destination, and recipient details
    /// @param tokenIn Source token address (address(0) for ETH)
    /// @param amountIn Amount to transfer
    /// @param data ABI-encoded V2 payload
    function _processTransferV2(
        Request calldata request,
        uint256 destinationChainIndex,
        address tokenIn,
        uint256 amountIn,
        bytes memory data
    ) internal {
        (
            uint64 gasDrop,
            bytes32 destAddr,
            bytes32 referrerAddr,
            uint64 cancelFee,
            uint64 refundFee,
            uint64 deadline,
            uint8 referrerBps,
            uint8 auctionMode,
            bytes32 random,
            uint8 payloadType
        ) = abi.decode(
            data, (uint64, bytes32, bytes32, uint64, uint64, uint64, uint8, uint8, bytes32, uint8)
        );

        uint16 wormholeChainId = caip2ToWormholeChainId[
            universeToCaip2Namespace[request.destinationUniverse]
        ][request.destinationChainID];
        require(wormholeChainId != 0, "Unsupported destination chain");

        IMayanSwiftV2.OrderParams memory orderParams = IMayanSwiftV2.OrderParams({
            payloadType: payloadType,
            trader: request.recipientAddress,
            destAddr: destAddr,
            destChainId: wormholeChainId,
            referrerAddr: referrerAddr,
            tokenOut: request.destinations[destinationChainIndex].contractAddress,
            minAmountOut: uint64(request.destinations[destinationChainIndex].value),
            gasDrop: gasDrop,
            cancelFee: cancelFee,
            refundFee: refundFee,
            deadline: deadline,
            referrerBps: referrerBps,
            auctionMode: auctionMode,
            random: random
        });

        if (tokenIn == address(0)) {
            bytes memory protocolData = abi.encodeWithSelector(
                IMayanSwiftV2.createOrderWithEth.selector, orderParams, bytes("")
            );

            IMayanForwarder(MAYAN_FORWARDER).forwardEth{ value: amountIn }(
                SWIFT_V2_PROTOCOL, protocolData
            );
        } else {
            bytes memory protocolData = abi.encodeWithSelector(
                IMayanSwiftV2.createOrderWithToken.selector,
                tokenIn,
                amountIn,
                orderParams,
                bytes("")
            );
            IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
            IERC20(tokenIn).approve(MAYAN_FORWARDER, amountIn);

            IMayanForwarder.PermitParams memory emptyPermit;
            IMayanForwarder(MAYAN_FORWARDER)
                .forwardERC20(tokenIn, amountIn, emptyPermit, SWIFT_V2_PROTOCOL, protocolData);
        }
    }

    /// @notice Process cross-chain transfer via Mayan Swift V1
    /// @param request Action struct containing source, destination, and recipient details
    /// @param tokenIn Source token address (address(0) for ETH)
    /// @param amountIn Amount to transfer
    /// @param data ABI-encoded V1 payload
    function _processTransferV1(
        Request calldata request,
        address tokenIn,
        uint256 amountIn,
        bytes memory data
    ) internal {
        (
            bytes32 trader,
            bytes32 tokenOut,
            uint64 minAmountOut,
            uint64 gasDrop,
            uint64 cancelFee,
            uint64 refundFee,
            uint64 deadline,
            bytes32 destAddr,
            ,
            bytes32 referrerAddr,
            uint8 referrerBps,
            uint8 auctionMode,
            bytes32 random
        ) = abi.decode(
            data,
            (
                bytes32,
                bytes32,
                uint64,
                uint64,
                uint64,
                uint64,
                uint64,
                bytes32,
                uint16,
                bytes32,
                uint8,
                uint8,
                bytes32
            )
        );

        uint16 wormholeChainId = caip2ToWormholeChainId[
            universeToCaip2Namespace[request.destinationUniverse]
        ][request.destinationChainID];
        require(wormholeChainId != 0, "Unsupported destination chain");

        IMayanSwiftV1.OrderParams memory orderParams = IMayanSwiftV1.OrderParams({
            trader: trader,
            tokenOut: tokenOut,
            minAmountOut: minAmountOut,
            gasDrop: gasDrop,
            cancelFee: cancelFee,
            refundFee: refundFee,
            deadline: deadline,
            destAddr: destAddr,
            destChainId: wormholeChainId,
            referrerAddr: referrerAddr,
            referrerBps: referrerBps,
            auctionMode: auctionMode,
            random: random
        });

        if (tokenIn == address(0)) {
            bytes memory protocolData =
                abi.encodeWithSelector(IMayanSwiftV1.createOrderWithEth.selector, orderParams);

            IMayanForwarder(MAYAN_FORWARDER).forwardEth{ value: amountIn }(
                SWIFT_V1_PROTOCOL, protocolData
            );
        } else {
            bytes memory protocolData = abi.encodeWithSelector(
                IMayanSwiftV1.createOrderWithToken.selector, tokenIn, amountIn, orderParams
            );
            IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
            IERC20(tokenIn).approve(MAYAN_FORWARDER, amountIn);

            IMayanForwarder.PermitParams memory emptyPermit;
            IMayanForwarder(MAYAN_FORWARDER)
                .forwardERC20(tokenIn, amountIn, emptyPermit, SWIFT_V1_PROTOCOL, protocolData);
        }
    }

    /// @notice Set or update CAIP-2 namespace and chain ID to Wormhole chain ID mapping
    /// @dev Only callable by contract owner
    /// @param namespaceHash CAIP-2 namespace hash (e.g., keccak256("eip155") for EVM)
    /// @param chainId Chain ID within the namespace (e.g., 1 for Ethereum, 8453 for Base)
    /// @param wormholeChainId Corresponding Wormhole chain ID
    function setWormholeChainMapping(
        bytes32 namespaceHash,
        uint256 chainId,
        uint16 wormholeChainId
    ) external onlyOwner {
        caip2ToWormholeChainId[namespaceHash][chainId] = wormholeChainId;
        emit WormholeChainMappingSet(namespaceHash, chainId, wormholeChainId);
    }
}
