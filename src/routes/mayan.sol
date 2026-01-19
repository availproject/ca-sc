//  SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Request, Action, Universe, SourcePair} from "../types.sol";
import {ICaRouter} from "../interfaces/ICaRouter.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IMayanForwarder {
    struct PermitParams {
        uint256 value;
        uint256 deadline;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    //
    function forwardERC20(
        address tokenIn,
        uint256 amountIn,
        PermitParams calldata permitParams,
        address mayanProtocol,
        bytes calldata protocolData
    ) external payable;

    function forwardEth(
        address mayanProtocol,
        bytes calldata protocolData
    ) external payable;
}

interface IMayanSwiftV2 {
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

    function createOrderWithEth(
        OrderParams memory params,
        bytes memory customPayload
    ) external payable returns (bytes32 orderHash);

    function createOrderWithToken(
        address tokenIn,
        uint256 amountIn,
        OrderParams memory params,
        bytes memory customPayload
    ) external returns (bytes32 orderHash);
}

contract MayanRouter is ICaRouter {
    address constant MAYAN_FORWARDER =
        0x337685fdaB40D39bd02028545a4FfA7D287cC3E2;

    // Swift V2 protocol contract addresses per chain (EVM chain ID => protocol address)
    mapping(uint256 => address) public swiftV2Protocol;

    // EVM chain ID to Wormhole chain ID mapping
    mapping(uint256 => uint16) public evmToWormholeChainId;

    constructor() {
        // Wormhole chain ID mappings (EVM chain ID => Wormhole chain ID)
        evmToWormholeChainId[1] = 2; // Ethereum
        evmToWormholeChainId[8453] = 30; // Base
        evmToWormholeChainId[42161] = 23; // Arbitrum
        evmToWormholeChainId[10] = 24; // Optimism
        evmToWormholeChainId[43114] = 6; // Avalanche
        evmToWormholeChainId[137] = 5; // Polygon
        evmToWormholeChainId[56] = 4; // BSC
        swiftV2Protocol[1] = 0xc05fb021704D4709c8C058da691fdf4070574685;
    }

    /// @notice Process cross-chain bridge via Mayan Swift V2
    /// @dev Supports any Wormhole-compatible chain (EVM, Solana, Cosmos, etc.)
    /// @param request Transfer request with sources, destinations, and recipient
    /// @param data Encoded: (string destChain, bytes32 destToken, uint256 minAmountOut, uint64 gasDrop, uint64 deadline)
    ///              - destChain: CAIP-2 format string (e.g., "eip155:8453", "solana:mainnet", "cosmos:cosmoshub-4")
    ///              - destToken: bytes32 token address on destination chain (works for any blockchain)
    ///              - minAmountOut: Minimum tokens to receive after fees
    ///              - gasDrop: Native gas amount to airdrop to recipient (0 = none)
    ///              - deadline: Unix timestamp (0 = auto-set to 1 hour)
    function processTransfer(
        Action calldata request,
        bytes calldata data
    ) external payable override {
        // Validate request has at least one source
        require(request.sources.length > 0, "No sources");

        SourcePair memory source = request.sources[0];
        require(
            source.universe == Universe.ETHEREUM,
            "Only ETHEREUM source supported"
        );

        address tokenIn = address(uint160(uint256(source.contractAddress)));
        uint256 amountIn = source.value;

        // Decode additional parameters from data
        (
            string memory destChain, // CAIP-2 string: "eip155:8453", "solana:mainnet", etc.
            bytes32 destToken, // Destination token (bytes32 for cross-chain)
            uint256 minAmountOut, // Minimum output after fees
            uint64 gasDrop, // Optional: native gas to drop to recipient
            uint64 deadline // Deadline timestamp (0 = 1 hour default)
        ) = abi.decode(data, (string, bytes32, uint256, uint64, uint64));

        // Parse CAIP-2 string to get Wormhole chain ID
        // Examples: "eip155:1" → 2, "eip155:8453" → 30, "solana:mainnet" → 1
        uint16 wormholeChainId = _parseCAIP2ToWormhole(destChain);

        // Get Swift V2 protocol address for current chain
        address swiftProtocol = swiftV2Protocol[wormholeChainId];
        require(
            swiftProtocol != address(0),
            "Swift V2 not configured for this chain"
        );

        // Set default deadline if not provided
        if (deadline == 0) {
            deadline = uint64(block.timestamp + 3600); // 1 hour
        }

        // Build OrderParams for Swift V2
        IMayanSwiftV2.OrderParams memory orderParams = IMayanSwiftV2
            .OrderParams({
                payloadType: 0,
                trader: request.recipientAddress,
                destAddr: request.recipientAddress,
                destChainId: wormholeChainId,
                referrerAddr: bytes32(0),
                tokenOut: destToken,
                minAmountOut: uint64(minAmountOut),
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

        // Execute via forwarder
        if (tokenIn == address(0)) {
            bytes memory protocolData = abi.encodeWithSelector(
                IMayanSwiftV2.createOrderWithEth.selector,
                orderParams, // OrderParams struct
                bytes("")
            );

            // Native ETH transfer
            IMayanForwarder(MAYAN_FORWARDER).forwardEth{value: amountIn}(
                swiftProtocol,
                protocolData
            );
        } else {
            // Encode the createOrderWithToken call
            bytes memory protocolData = abi.encodeWithSelector(
                IMayanSwiftV2.createOrderWithToken.selector,
                tokenIn, // tokenIn on source chain
                amountIn, // amountIn
                orderParams, // OrderParams struct
                bytes("")
            );
            IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
            IERC20(tokenIn).approve(MAYAN_FORWARDER, amountIn);

            IMayanForwarder.PermitParams memory emptyPermit;
            IMayanForwarder(MAYAN_FORWARDER).forwardERC20(
                tokenIn,
                amountIn,
                emptyPermit,
                swiftProtocol,
                protocolData
            );
        }
    }

    /// @notice Set Swift V2 protocol address for a specific chain
    /// @param chainId EVM chain ID (for source chain configuration)
    /// @param protocol Swift V2 protocol contract address
    function setSwiftV2Protocol(uint256 chainId, address protocol) external {
        // TODO: Add access control (onlyOwner, etc.)
        swiftV2Protocol[chainId] = protocol;
    }

    /// @notice Add or update EVM chain to Wormhole chain ID mapping
    /// @param evmChainId EVM chain ID (e.g., 1 for Ethereum, 8453 for Base)
    /// @param wormholeChainId Corresponding Wormhole chain ID
    function setWormholeChainMapping(
        uint256 evmChainId,
        uint16 wormholeChainId
    ) external {
        // TODO: Add access control (onlyOwner, etc.)
        evmToWormholeChainId[evmChainId] = wormholeChainId;
    }

    /// @notice Parse CAIP-2 string to Wormhole chain ID
    /// @dev CAIP-2 format: "namespace:chainId"
    ///      Examples:
    ///        - "eip155:1" → Ethereum (Wormhole ID: 2)
    ///        - "eip155:8453" → Base (Wormhole ID: 30)
    ///        - "solana:mainnet" or "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" → Solana (Wormhole ID: 1)
    ///        - "cosmos:cosmoshub-4" → Cosmos Hub (Wormhole ID: 26 if supported)
    ///        - "tron:mainnet" → Tron (Wormhole ID: 3)
    /// @param caip2String CAIP-2 formatted chain identifier
    /// @return wormholeChainId Corresponding Wormhole chain ID
    function _parseCAIP2ToWormhole(
        string memory caip2String
    ) internal view returns (uint16 wormholeChainId) {
        return _parseUint(caip2String);
        // bytes memory caip2Bytes = bytes(caip2String);
        // require(caip2Bytes.length > 0, "Empty CAIP-2 string");
        //
        // // Find the colon separator
        // uint256 colonIndex = 0;
        // for (uint256 i = 0; i < caip2Bytes.length; i++) {
        //     if (caip2Bytes[i] == ":") {
        //         colonIndex = i;
        //         break;
        //     }
        // }
        // require(colonIndex > 0 && colonIndex < caip2Bytes.length - 1, "Invalid CAIP-2 format (missing ':')");
        //
        // // Extract namespace and chainId
        // string memory namespace = _substring(caip2String, 0, colonIndex);
        // uint256 chainId= _parseUint(_substring(caip2String, colonIndex + 1, caip2Bytes.length));
        // // Route based on namespace
        // if (_compareStrings(namespace, "eip155")) {
        // } else if (_compareStrings(namespace, "solana")) {
        // } else if (_compareStrings(namespace, "bsc")) {
        //     // BSC (Binance Smart Chain)
        //     wormholeChainId = 4;
        // } else if (_compareStrings(namespace, "tron")) {
        //     // Tron mainnet
        //     wormholeChainId = 3;
        // } else if (_compareStrings(namespace, "cosmos")) {
        //     // Cosmos chains
        //     // Note: Wormhole support varies by Cosmos chain
        //     if (_compareStrings(chainId, "cosmoshub-4")) {
        //         wormholeChainId = 4000; // Placeholder - verify actual Wormhole ID
        //     } else {
        //         revert("Unsupported Cosmos chain");
        //     }
        // } else if (_compareStrings(namespace, "aptos")) {
        //     // Aptos mainnet
        //     wormholeChainId = 22;
        // } else if (_compareStrings(namespace, "sui")) {
        //     // Sui mainnet
        //     wormholeChainId = 21;
        // } else if (_compareStrings(namespace, "near")) {
        //     // NEAR Protocol
        //     wormholeChainId = 15;
        // } else if (_compareStrings(namespace, "algorand")) {
        //     // Algorand mainnet
        //     wormholeChainId = 8;
        // } else if (_compareStrings(namespace, "terra2")) {
        //     // Terra 2.0
        //     wormholeChainId = 18;
        // } else if (_compareStrings(namespace, "injective")) {
        //     // Injective
        //     wormholeChainId = 19;
        // } else {
        //     revert("Unsupported CAIP-2 namespace");
        // }
    }

    /// @notice Extract substring from string
    /// @param str Source string
    /// @param startIndex Start index (inclusive)
    /// @param endIndex End index (exclusive)
    /// @return result Substring
    function _substring(
        string memory str,
        uint256 startIndex,
        uint256 endIndex
    ) internal pure returns (string memory result) {
        bytes memory strBytes = bytes(str);
        require(
            startIndex < endIndex && endIndex <= strBytes.length,
            "Invalid substring indices"
        );

        bytes memory resultBytes = new bytes(endIndex - startIndex);
        for (uint256 i = 0; i < endIndex - startIndex; i++) {
            resultBytes[i] = strBytes[startIndex + i];
        }
        return string(resultBytes);
    }

    /// @notice Compare two strings for equality
    /// @param a First string
    /// @param b Second string
    /// @return equal True if strings are equal
    function _compareStrings(
        string memory a,
        string memory b
    ) internal pure returns (bool equal) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    /// @notice Parse string to uint16
    /// @param str Numeric string (e.g., "8453")
    /// @return result Parsed uint16
    function _parseUint(
        string memory str
    ) internal pure returns (uint16 result) {
        bytes memory strBytes = bytes(str);
        require(strBytes.length > 0, "Empty string");

        for (uint256 i = 0; i < strBytes.length; i++) {
            uint8 digit = uint8(strBytes[i]);
            require(digit >= 48 && digit <= 57, "Invalid numeric character");

            uint16 newResult = result * 10 + (digit - 48);
            require(newResult >= result, "Numeric overflow");
            result = newResult;
        }
    }
}
