// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IMayanForwarder} from "../interfaces/IMayanForwarder.sol";
import {IMayanSwiftV2} from "../interfaces/IMayanSwiftV2.sol";
import {IRouter} from "../interfaces/IRouter.sol";
import {Party, Request, Universe} from "../types.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title MayanRouter
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Router contract for Mayan Swift V2 cross-chain swaps via Wormhole
/// @dev UUPS upgradeable router for integration with Arcana Credit protocol
contract MayanRouter is Initializable, UUPSUpgradeable, IRouter, OwnableUpgradeable, AccessControlUpgradeable {
    using SafeERC20 for IERC20;

    bytes32 public constant VAULT_ROLE = keccak256("VAULT_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    address public constant MAYAN_FORWARDER = 0x337685fdaB40D39bd02028545a4FfA7D287cC3E2;

    address public constant SWIFT_V2_PROTOCOL = 0x40fFE85A28DC9993541449464d7529a922142960;

    uint16 public constant FEE_BPS_DENOMINATOR = 10_000;

    uint8 public constant PAYLOAD_TYPE = 1;

    bytes32 public referrerAddr;
    uint16 public cancelFeeBps;
    uint16 public refundFeeBps;
    uint8 public referrerBps;
    uint8 public auctionMode;
    mapping(Universe => mapping(uint256 => uint16)) public destinationChainID;
    mapping(uint16 => mapping(address => uint8)) public tokenOutDecimals;

    uint256[50] private __gap;

    /// @notice Emitted when a Wormhole chain mapping is updated
    /// @param universe Destination universe
    /// @param chainId Chain ID within the namespace
    /// @param wormholeChainId Corresponding Wormhole chain ID
    event WormholeChainMappingSet(Universe indexed universe, uint256 indexed chainId, uint16 wormholeChainId);

    /// @notice Emitted when Mayan referrer address is updated
    /// @param referrerAddr Referrer address encoded as bytes32 for Mayan order params
    event ReferrerAddrSet(bytes32 referrerAddr);

    /// @notice Emitted when Mayan cancellation fee percentage is updated
    /// @param cancelFeeBps Fee paid to cancel an order, in basis points of minAmountOut
    event CancelFeeBpsSet(uint16 cancelFeeBps);

    /// @notice Emitted when Mayan refund fee percentage is updated
    /// @param refundFeeBps Fee paid to refund an order, in basis points of minAmountOut
    event RefundFeeBpsSet(uint16 refundFeeBps);

    /// @notice Emitted when Mayan referral settings are updated
    /// @param referrerBps Referrer basis points
    event ReferrerBpsSet(uint8 referrerBps);

    /// @notice Emitted when Mayan auction mode is updated
    /// @param auctionMode Auction mode value used in Mayan order params
    event AuctionModeSet(uint8 auctionMode);

    /// @notice Emitted when destination token decimals are updated
    /// @param wormholeChainId Wormhole destination chain ID
    /// @param token Destination token address
    /// @param decimals Destination token decimals
    event TokenOutDecimalsSet(uint16 indexed wormholeChainId, address indexed token, uint8 decimals);

    error FeeSlippageExceeded(uint64 fee, uint64 maxFee);
    error InvalidFeeBps(uint16 feeBps);
    error InvalidNativeAmount(uint256 expected, uint256 actual);
    error InvalidRFF();
    error InvalidSwiftVersion(uint8 version);
    error MinAmountOutTooLarge(uint256 minAmountOut);
    error PartyNotFound();
    /// @notice Reverts when a token's decimals are not configured for the destination chain
    error TokenOutDecimalsNotConfigured();
    error UnsupportedDestinationChain();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize router with default EVM chain mappings
    /// @param owner_ Address to grant owner, admin, and upgrader permissions
    function initialize(address owner_) public initializer {
        __Ownable_init(owner_);
        __AccessControl_init();

        _grantRole(DEFAULT_ADMIN_ROLE, owner_);
        _grantRole(UPGRADER_ROLE, owner_);

        destinationChainID[Universe.ETHEREUM][1] = 2;
        destinationChainID[Universe.ETHEREUM][8453] = 30;
        destinationChainID[Universe.ETHEREUM][42_161] = 23;
        destinationChainID[Universe.ETHEREUM][10] = 24;
        destinationChainID[Universe.ETHEREUM][43_114] = 6;
        destinationChainID[Universe.ETHEREUM][137] = 5;
        destinationChainID[Universe.ETHEREUM][56] = 4;

        referrerAddr = bytes32(0);
        cancelFeeBps = 150;
        refundFeeBps = 150;
        referrerBps = 0;
        auctionMode = 2;
    }

    /// @notice Process cross-chain token transfer via Mayan Swift V2 or V1
    /// @dev Only supports ETHEREUM universe sources. Destination chain must be configured.
    /// @dev Restricted to callers with VAULT_ROLE.
    /// @param request Action struct containing source, destination, and recipient details
    /// @param data ABI-encoded (SwiftVersion, remaining data)
    function processTransfer(Request calldata request, bytes calldata data)
        external
        payable
        override
        onlyRole(VAULT_ROLE)
    {
        if (request.sources.length != request.destinations.length) revert InvalidRFF();
        (uint256 chainIndex, bytes memory actualData) = abi.decode(data, (uint256, bytes));

        _processTransferV2(request, chainIndex, actualData);
    }

    /// @notice Process cross-chain transfer via Mayan Swift V2
    /// @dev Decodes V2 order params, normalizes amount for token decimals, validates fee slippages,
    /// @dev and forwards the order to MayanForwarder for execution
    /// @param request Action struct containing source, destination, and recipient details
    /// @param chainIndex Index of the source and destination pair to process
    /// @param data ABI-encoded cancelFee, refundFee, gasDrop, random, swapProtocol,
    /// swapData, middleToken, and minMiddleAmount
    function _processTransferV2(Request calldata request, uint256 chainIndex, bytes memory data) internal {
        address tokenIn = address(uint160(uint256(request.sources[chainIndex].contractAddress)));
        uint256 amountIn = request.sources[chainIndex].value;

        (
            uint16 cancelFee,
            uint16 refundFee,
            uint64 gasDrop,
            bytes32 random,
            address swapProtocol,
            bytes memory swapData,
            address middleToken,
            uint256 minMiddleAmount
        ) = abi.decode(data, (uint16, uint16, uint64, bytes32, address, bytes, address, uint256));

        uint16 wormholeChainId = destinationChainID[request.destinationUniverse][request.destinationChainID];
        if (wormholeChainId == 0) revert UnsupportedDestinationChain();

        address tokenOut = address(uint160(uint256(request.destinations[chainIndex].contractAddress)));

        checkFeeSlippages(
            request.sources[chainIndex].value,
            address(uint160(uint256(request.sources[chainIndex].contractAddress))),
            destinationChainID[request.sources[chainIndex].universe][request.sources[chainIndex].chainID],
            cancelFee,
            refundFee
        );

        uint64 normalizedMinAmountOut =
            normaliseAmount(request.destinations[chainIndex].value, tokenOut, wormholeChainId);

        IMayanSwiftV2.OrderParams memory orderParams = IMayanSwiftV2.OrderParams({
            payloadType: PAYLOAD_TYPE,
            trader: extractAddress(request.parties),
            destAddr: request.recipientAddress,
            destChainId: wormholeChainId,
            referrerAddr: referrerAddr,
            tokenOut: request.destinations[chainIndex].contractAddress,
            minAmountOut: normalizedMinAmountOut,
            gasDrop: gasDrop,
            cancelFee: cancelFee,
            refundFee: refundFee,
            deadline: uint64(request.expiry),
            referrerBps: referrerBps,
            auctionMode: auctionMode,
            random: random
        });

        if (tokenIn == address(0)) {
            if (msg.value != amountIn) revert InvalidNativeAmount(amountIn, msg.value);

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
            IERC20(tokenIn).safeTransferFrom(msg.sender, address(this), amountIn);
            IERC20(tokenIn).forceApprove(MAYAN_FORWARDER, amountIn);

            IMayanForwarder.PermitParams memory emptyPermit;
            IMayanForwarder(MAYAN_FORWARDER)
                .forwardERC20(tokenIn, amountIn, emptyPermit, SWIFT_V2_PROTOCOL, protocolData);
        }
    }

    /// @notice Set or update universe and chain ID to Wormhole chain ID mapping
    /// @dev Only callable by contract owner
    /// @param universe Destination universe
    /// @param chainId Chain ID within the namespace (e.g., 1 for Ethereum, 8453 for Base)
    /// @param wormholeChainId Corresponding Wormhole chain ID
    function setWormholeChainMapping(Universe universe, uint256 chainId, uint16 wormholeChainId) external onlyOwner {
        destinationChainID[universe][chainId] = wormholeChainId;
        emit WormholeChainMappingSet(universe, chainId, wormholeChainId);
    }

    /// @notice Set Mayan referrer address
    /// @dev Only callable by contract owner
    /// @param _referrerAddr Referrer address encoded as bytes32 for Mayan order params
    function setReferrerAddr(bytes32 _referrerAddr) external onlyOwner {
        referrerAddr = _referrerAddr;
        emit ReferrerAddrSet(_referrerAddr);
    }

    /// @notice Set Mayan order cancellation fee percentage
    /// @dev Only callable by contract owner
    /// @param _cancelFeeBps Fee paid to cancel an order, in basis points of minAmountOut
    function setCancelFeeBps(uint16 _cancelFeeBps) external onlyOwner {
        if (_cancelFeeBps > FEE_BPS_DENOMINATOR) revert InvalidFeeBps(_cancelFeeBps);
        cancelFeeBps = _cancelFeeBps;
        emit CancelFeeBpsSet(_cancelFeeBps);
    }

    /// @notice Set Mayan order refund fee percentage
    /// @dev Only callable by contract owner
    /// @param _refundFeeBps Fee paid to refund an order, in basis points of minAmountOut
    function setRefundFeeBps(uint16 _refundFeeBps) external onlyOwner {
        if (_refundFeeBps > FEE_BPS_DENOMINATOR) revert InvalidFeeBps(_refundFeeBps);
        refundFeeBps = _refundFeeBps;
        emit RefundFeeBpsSet(_refundFeeBps);
    }

    /// @notice Set Mayan referrer basis points
    /// @dev Only callable by contract owner
    /// @param _referrerBps Referrer basis points
    function setReferrerBps(uint8 _referrerBps) external onlyOwner {
        referrerBps = _referrerBps;
        emit ReferrerBpsSet(_referrerBps);
    }

    /// @notice Set Mayan auction mode
    /// @dev Only callable by contract owner
    /// @param _auctionMode Auction mode value used in Mayan order params
    function setAuctionMode(uint8 _auctionMode) external onlyOwner {
        auctionMode = _auctionMode;
        emit AuctionModeSet(_auctionMode);
    }

    /// @notice Set destination token decimals for Mayan amount normalization
    /// @dev Only callable by contract owner
    /// @param wormholeChainId Wormhole destination chain ID
    /// @param token Destination token address
    /// @param decimals Destination token decimals
    function setTokenOutDecimals(uint16 wormholeChainId, address token, uint8 decimals) external onlyOwner {
        tokenOutDecimals[wormholeChainId][token] = decimals;
        emit TokenOutDecimalsSet(wormholeChainId, token, decimals);
    }

    /// @notice Authorizes a contract upgrade
    /// @dev Ensures only accounts with UPGRADER_ROLE can upgrade the implementation
    /// @param newImplementation Address of the new implementation contract
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}

    /// @notice Calculate fee amount from basis points
    /// @param amount Base amount to calculate fee against
    /// @param feeBps Fee percentage in basis points (e.g., 150 = 1.5%)
    /// @return Fee amount as uint64
    function _feeFromBps(uint256 amount, uint16 feeBps) internal pure returns (uint64) {
        return uint64((amount * feeBps) / FEE_BPS_DENOMINATOR);
    }

    /// @notice Validate that cancel and refund fees do not exceed maximum allowed based on basis points
    /// @dev Uses configured cancelFeeBps and refundFeeBps to calculate max fees from normalizedMinAmountOut
    /// @param cancelFee Actual cancellation fee to validate
    /// @param refundFee Actual refund fee to validate
    function checkFeeSlippages(
        uint256 tokenIn,
        address token,
        uint16 wormholeChainId,
        uint64 cancelFee,
        uint64 refundFee
    ) internal view {
        uint256 normalizedMinAmountOut = normaliseAmount(tokenIn, token, wormholeChainId);
        uint64 maxCancelFee = _feeFromBps(normalizedMinAmountOut, cancelFeeBps);
        uint64 maxRefundFee = _feeFromBps(normalizedMinAmountOut, refundFeeBps);

        if (cancelFee > maxCancelFee) revert FeeSlippageExceeded(cancelFee, maxCancelFee);
        if (refundFee > maxRefundFee) revert FeeSlippageExceeded(refundFee, maxRefundFee);
    }

    /// @notice Extract ETHEREUM universe party address from parties array
    /// @dev Iterates through parties to find first ETHEREUM universe entry
    /// @param parties Array of Party structs to search
    /// @return user The party address cast to bytes32
    function extractAddress(Party[] memory parties) internal pure returns (bytes32 user) {
        for (uint256 i = 0; i < parties.length; ++i) {
            if (parties[i].universe == Universe.ETHEREUM) {
                return parties[i].address_;
            }
        }
        revert PartyNotFound();
    }

    function normaliseAmount(uint256 amount, address token, uint16 wormholeChainId) private view returns (uint64) {
        uint256 normalizedMinAmountOut = amount;
        uint8 decimals = tokenOutDecimals[wormholeChainId][token];

        if (decimals == 0) {
            revert TokenOutDecimalsNotConfigured();
        }

        if (decimals > 8) {
            normalizedMinAmountOut = normalizedMinAmountOut / (10 ** (decimals - 8));
        }

        if (normalizedMinAmountOut > type(uint64).max) {
            revert MinAmountOutTooLarge(normalizedMinAmountOut);
        }

        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(normalizedMinAmountOut);
    }
}
