//  SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Request, Universe, SourcePair, Party} from "../types.sol";
import {ICaRouter} from "../interfaces/ICaRouter.sol";
import {IMayanSwiftV1} from "../interfaces/IMayanSwiftV1.sol";
import {IMayanForwarder} from "../interfaces/IMayanForwarder.sol";
import {IMayanSwiftV2} from "../interfaces/IMayanSwiftV2.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

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
    event WormholeChainMappingSet(bytes32 indexed namespaceHash, uint256 indexed chainId, uint16 wormholeChainId);

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
    function processTransfer(Request calldata request, bytes calldata data) external payable override {
        require(request.sources.length == request.destinations.length, "Invalid RFF");
        (uint256 chainIndex, bytes memory actualData) = abi.decode(data, (uint256, bytes));

        _processTransferV2(request, chainIndex, actualData);
    }

    /// @notice Process cross-chain transfer via Mayan Swift V2
    /// @param request Action struct containing source, destination, and recipient details
    /// @param data ABI-encoded V2 payload
    function _processTransferV2(Request calldata request, uint256 chainIndex, bytes memory data) internal {
        address tokenIn = address(uint160(uint256(request.sources[chainIndex].contractAddress)));
        uint256 amountIn = request.sources[chainIndex].value;

        (
            uint8 tokenOutDecimals,
            uint64 gasDrop,
            bytes32 referrerAddr,
            uint64 cancelFee,
            uint64 refundFee,
            uint64 deadline,
            uint8 referrerBps,
            uint8 auctionMode,
            bytes32 random,
            uint8 payloadType,
            address swapProtocol,
            bytes memory swapData,
            address middleToken,
            uint256 minMiddleAmount
        ) = abi.decode(
            data,
            (
                uint8,
                uint64,
                bytes32,
                uint64,
                uint64,
                uint64,
                uint8,
                uint8,
                bytes32,
                uint8,
                address,
                bytes,
                address,
                uint256
            )
        );

        uint16 wormholeChainId =
            caip2ToWormholeChainId[universeToCaip2Namespace[request.destinationUniverse]][request.destinationChainID];
        require(wormholeChainId != 0, "Unsupported destination chain");

        uint256 normalizedMinAmountOut = request.destinations[chainIndex].value;

        if (tokenOutDecimals > 8) {
            normalizedMinAmountOut = normalizedMinAmountOut / (10 ** (tokenOutDecimals - 8));
        }

        IMayanSwiftV2.OrderParams memory orderParams = IMayanSwiftV2.OrderParams({
            payloadType: payloadType,
            trader: extractAddress(request.parties),
            destAddr: request.recipientAddress,
            destChainId: wormholeChainId,
            referrerAddr: referrerAddr,
            tokenOut: request.destinations[chainIndex].contractAddress,
            minAmountOut: uint64(normalizedMinAmountOut),
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
                IMayanSwiftV2.createOrderWithToken.selector, middleToken, minMiddleAmount, orderParams, bytes("")
            );

            IMayanForwarder(MAYAN_FORWARDER).swapAndForwardEth{value: amountIn}(
                amountIn, swapProtocol, swapData, middleToken, minMiddleAmount, SWIFT_V2_PROTOCOL, protocolData
            );
        } else {
            bytes memory protocolData = abi.encodeWithSelector(
                IMayanSwiftV2.createOrderWithToken.selector, tokenIn, amountIn, orderParams, bytes("")
            );
            IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
            IERC20(tokenIn).approve(MAYAN_FORWARDER, amountIn);

            IMayanForwarder.PermitParams memory emptyPermit;
            IMayanForwarder(MAYAN_FORWARDER)
                .forwardERC20(tokenIn, amountIn, emptyPermit, SWIFT_V2_PROTOCOL, protocolData);
        }
    }

    /// @notice Set or update CAIP-2 namespace and chain ID to Wormhole chain ID mapping
    /// @dev Only callable by contract owner
    /// @param namespaceHash CAIP-2 namespace hash (e.g., keccak256("eip155") for EVM)
    /// @param chainId Chain ID within the namespace (e.g., 1 for Ethereum, 8453 for Base)
    /// @param wormholeChainId Corresponding Wormhole chain ID
    function setWormholeChainMapping(bytes32 namespaceHash, uint256 chainId, uint16 wormholeChainId)
        external
        onlyOwner
    {
        caip2ToWormholeChainId[namespaceHash][chainId] = wormholeChainId;
        emit WormholeChainMappingSet(namespaceHash, chainId, wormholeChainId);
    }

    function extractAddress(Party[] memory parties) internal pure returns (bytes32 user) {
        for (uint256 i = 0; i < parties.length; ++i) {
            if (parties[i].universe == Universe.ETHEREUM) {
                return parties[i].address_;
            }
        }
        revert("Vault: Party not found");
    }
}
