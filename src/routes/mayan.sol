//  SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Request, Action, Universe, SourcePair} from "../types.sol";
import {ICaRouter} from "../interfaces/ICaRouter.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

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
    function forwardEth(
        address mayanProtocol,
        bytes calldata protocolData
    ) external payable;
}

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

    /// @notice Create order with native ETH
    /// @param params Order parameters
    /// @param customPayload Additional payload data
    /// @return orderHash Hash of the created order
    function createOrderWithEth(
        OrderParams memory params,
        bytes memory customPayload
    ) external payable returns (bytes32 orderHash);

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

/// @title MayanRouter
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Router contract for Mayan Swift V2 cross-chain swaps via Wormhole
/// @dev Implements ICaRouter for integration with Arcana Credit protocol
contract MayanRouter is ICaRouter, Ownable {
    address public constant MAYAN_FORWARDER =
        0x337685fdaB40D39bd02028545a4FfA7D287cC3E2;

    address public constant SWIFT_V2_PROTOCOL =
        0xc05fb021704D4709c8C058da691fdf4070574685;

    mapping(bytes32 => mapping(uint256 => uint16))
        public caip2ToWormholeChainId;

    /// @notice Emitted when a Wormhole chain mapping is updated
    /// @param namespaceHash CAIP-2 namespace hash
    /// @param chainId Chain ID within the namespace
    /// @param wormholeChainId Corresponding Wormhole chain ID
    event WormholeChainMappingSet(
        bytes32 indexed namespaceHash,
        uint256 indexed chainId,
        uint16 wormholeChainId
    );

    /// @notice Initialize router with default EVM chain mappings
    constructor() Ownable(msg.sender) {
        bytes32 eip155 = keccak256("eip155");
        caip2ToWormholeChainId[eip155][1] = 2;
        caip2ToWormholeChainId[eip155][8453] = 30;
        caip2ToWormholeChainId[eip155][42161] = 23;
        caip2ToWormholeChainId[eip155][10] = 24;
        caip2ToWormholeChainId[eip155][43114] = 6;
        caip2ToWormholeChainId[eip155][137] = 5;
        caip2ToWormholeChainId[eip155][56] = 4;
    }

    /// @notice Process cross-chain token transfer via Mayan Swift V2
    /// @dev Only supports ETHEREUM universe sources. Destination chain must be configured.
    /// @param request Action struct containing source, destination, and recipient details
    /// @param data ABI-encoded (uint64 gasDrop, uint64 deadline)
    function processTransfer(
        Action calldata request,
        bytes calldata data
    ) external payable override {
        require(request.sources.length > 0, "No sources");

        SourcePair memory source = request.sources[0];
        require(
            source.universe == Universe.ETHEREUM,
            "Only ETHEREUM source supported"
        );

        address tokenIn = address(uint160(uint256(source.contractAddress)));
        uint256 amountIn = source.value;

        (uint64 gasDrop, uint64 deadline) = abi.decode(data, (uint64, uint64));

        uint16 wormholeChainId = caip2ToWormholeChainId[
            request.destinationCaip2namespace
        ][request.destinationCaip2ChainId];
        require(wormholeChainId != 0, "Unsupported destination chain");

        if (deadline == 0) {
            deadline = uint64(block.timestamp + 3600);
        }

        IMayanSwiftV2.OrderParams memory orderParams = IMayanSwiftV2
            .OrderParams({
                payloadType: 0,
                trader: request.recipientAddress,
                destAddr: request.recipientAddress,
                destChainId: wormholeChainId,
                referrerAddr: bytes32(0),
                tokenOut: request.destinationContractAddress,
                minAmountOut: uint64(request.destinationMinTokenAmount),
                gasDrop: gasDrop,
                cancelFee: 0,
                refundFee: 0,
                deadline: deadline,
                referrerBps: 0,
                auctionMode: 0,
                random: keccak256(
                    abi.encodePacked(
                        block.timestamp,
                        msg.sender,
                        amountIn,
                        request.nonce
                    )
                )
            });

        if (tokenIn == address(0)) {
            bytes memory protocolData = abi.encodeWithSelector(
                IMayanSwiftV2.createOrderWithEth.selector,
                orderParams,
                bytes("")
            );

            IMayanForwarder(MAYAN_FORWARDER).forwardEth{value: amountIn}(
                SWIFT_V2_PROTOCOL,
                protocolData
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
            IMayanForwarder(MAYAN_FORWARDER).forwardERC20(
                tokenIn,
                amountIn,
                emptyPermit,
                SWIFT_V2_PROTOCOL,
                protocolData
            );
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
