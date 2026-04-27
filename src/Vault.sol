// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {
    MessageHashUtils
} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";

import {
    AccessControlUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {
    ReentrancyGuardTransient
} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {
    AccessControlUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {
    UUPSUpgradeable
} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {
    Request,
    Party,
    Universe,
    RFFState,
    SettleData,
    Route
} from "./types.sol";
import { IRouter } from "./interfaces/IRouter.sol";

/// @title Vault
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Vault contract for managing deposits, fulfillments, and settlements of cross-chain transfers
/// @dev UUPS upgradeable contract with role-based access control
contract Vault is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardTransient
{
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    mapping(bytes32 => RFFState) public requestState;
    mapping(bytes32 => address) public winningSolver;
    mapping(uint256 => bool) public depositNonce;
    mapping(uint256 => bool) public fillNonce;
    mapping(uint256 => bool) public settleNonce;

    /// @notice Router contract for processing cross-chain transfers
    IRouter public router;

    bytes32 private constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 private constant SETTLEMENT_VERIFIER_ROLE = keccak256("SETTLEMENT_VERIFIER_ROLE");
    string private constant SIGNATURE_PREFIX = "Sign this intent to proceed \n";
    // Storage gap to reserve slots for future use
    uint256[50] private __gap;

    event Deposit(bytes32 indexed requestHash, address from);
    event Fulfilment(bytes32 indexed requestHash, address from, address solver);
    event Settle(uint256 indexed nonce, address[] solver, address[] token, uint256[] amount);
    event RouterSet(address indexed newRouter);
    event DepositAndRoute(bytes32 indexed requestHash, address from, Route route);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin) public initializer {
        __AccessControl_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
    }

    /// @notice Set the router contract address
    /// @param _router Address of the Router contract
    function setRouter(address _router) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_router != address(0), "Vault: Zero address");
        router = IRouter(_router);
        emit RouterSet(_router);
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    { }

    function version() external pure returns (string memory) {
        return "1.0.0";
    }

    function _hashRequest(Request calldata request) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                request.sources,
                request.destinationUniverse,
                request.destinationChainID,
                request.recipientAddress,
                request.destinations,
                request.nonce,
                request.expiry,
                request.parties
            )
        );
    }

    function bytes32ToAddress(bytes32 a) internal pure returns (address) {
        // Cast the last 20 bytes of bytes32 into an address
        return address(uint160(uint256(a)));
    }

    function _verify_request(bytes calldata signature, address from, bytes32 hash)
        private
        pure
        returns (bool, bytes32)
    {
        // Must match EXACT client string: "Sign this intent to proceed \n" + "0x...."
        bytes memory msgBytes = abi.encodePacked(
            SIGNATURE_PREFIX,
            Strings.toHexString(uint256(hash), 32) // 0x + 64 hex chars
        );

        // EIP-191 hash with dynamic decimal length (e.g. 95)
        bytes32 signedMessageHash = MessageHashUtils.toEthSignedMessageHash(msgBytes);

        address signer = signedMessageHash.recover(signature);
        return (signer == from, signedMessageHash);
    }

    function deposit(Request calldata request, bytes calldata signature, uint256 chainIndex)
        external
        payable
        nonReentrant
    {
        address from = extractAddress(request.parties);
        bytes32 request_hash = _hashRequest(request);
        (bool success, bytes32 signedMessageHash) = _verify_request(signature, from, request_hash);
        require(success, "Vault: Invalid signature or from");
        require(request.sources[chainIndex].chainID == block.chainid, "Vault: Chain ID mismatch");
        require(
            request.sources[chainIndex].universe == Universe.ETHEREUM, "Vault: Universe mismatch"
        );
        require(!depositNonce[request.nonce], "Vault: Nonce already used");
        require(request.expiry > block.timestamp, "Vault: Request expired");

        depositNonce[request.nonce] = true;
        requestState[signedMessageHash] = RFFState.DEPOSITED;

        if (request.sources[chainIndex].contractAddress == bytes32(0)) {
            uint256 totalValue = request.sources[chainIndex].value;
            require(msg.value == totalValue, "Vault: Value mismatch");
        } else {
            IERC20 token = IERC20(bytes32ToAddress(request.sources[chainIndex].contractAddress));

            uint256 bal = token.balanceOf(address(this));
            token.safeTransferFrom(from, address(this), request.sources[chainIndex].value);
            // fee on transfer tokens
            if (token.balanceOf(address(this)) - bal != request.sources[chainIndex].value) {
                revert("Vault: failed to transfer the source amount");
            }

            if (request.sources[chainIndex].fee > 0 && msg.sender != from) {
                uint256 solverBal = token.balanceOf(msg.sender);
                token.safeTransferFrom(from, msg.sender, request.sources[chainIndex].fee);
                if (token.balanceOf(msg.sender) - solverBal != request.sources[chainIndex].fee) {
                    revert("Vault: failed to transfer the fee amount");
                }
            } else if (request.sources[chainIndex].fee > 0 && msg.sender == from) {
                revert("Vault: self-fee transfer not allowed");
            }
        }

        emit Deposit(request_hash, from);
    }

    /// @notice Deposit funds and initiate cross-chain transfer via router
    /// @param request Request struct for router containing cross-chain transfer details
    /// @param signature User's signature authorizing the deposit
    /// @param chainIndex Index of the source chain in the request.sources array
    /// @param destinationChainIndex Index of the destination in the request.destinations array
    /// @param route Route to use (NATIVE or MAYAN)
    /// @param routeData Additional route-specific encoded parameters
    function depositRouter(
        Request calldata request,
        bytes calldata signature,
        uint256 chainIndex,
        uint256 destinationChainIndex,
        Route route,
        bytes calldata routeData
    ) external payable nonReentrant {
        require(address(router) != address(0), "Vault: Router not set");
        require(destinationChainIndex < request.destinations.length, "Vault: Invalid destination index");

        address from = extractAddress(request.parties);
        bytes32 request_hash = _hashRequest(request);
        (bool success, bytes32 requestHash) = _verify_request(signature, from, request_hash);
        require(success, "Vault: Invalid signature or from");
        require(request.sources[chainIndex].chainID == block.chainid, "Vault: Chain ID mismatch");
        require(
            request.sources[chainIndex].universe == Universe.ETHEREUM, "Vault: Universe mismatch"
        );
        require(!depositNonce[request.nonce], "Vault: Nonce already used");
        require(request.expiry > block.timestamp, "Vault: Request expired");

        depositNonce[request.nonce] = true;
        requestState[requestHash] = RFFState.DEPOSITED;

        uint256 valueToRoute = 0;

        if (request.sources[chainIndex].contractAddress == bytes32(0)) {
            uint256 totalValue = request.sources[chainIndex].value;
            require(msg.value == totalValue, "Vault: Value mismatch");
            valueToRoute = totalValue;
        } else {
            IERC20 token = IERC20(bytes32ToAddress(request.sources[chainIndex].contractAddress));

            uint256 bal = token.balanceOf(address(this));
            token.safeTransferFrom(from, address(this), request.sources[chainIndex].value);

            if (token.balanceOf(address(this)) - bal != request.sources[chainIndex].value) {
                revert("Vault: failed to transfer the source amount");
            }

            token.safeTransfer(address(router), request.sources[chainIndex].value);

            if (request.sources[chainIndex].fee > 0 && msg.sender != from) {
                uint256 solverBal = token.balanceOf(msg.sender);
                token.safeTransferFrom(from, msg.sender, request.sources[chainIndex].fee);
                if (token.balanceOf(msg.sender) - solverBal != request.sources[chainIndex].fee) {
                    revert("Vault: failed to transfer the fee amount");
                }
            } else if (request.sources[chainIndex].fee > 0 && msg.sender == from) {
                revert("Vault: self-fee transfer not allowed");
            }
        }

        bytes memory encodedRouteData = abi.encode(chainIndex, destinationChainIndex, routeData);
        router.processTransfer{ value: valueToRoute }(request, route, encodedRouteData);

        emit DepositAndRoute(request_hash, from, route);
    }

    function extractAddress(Party[] memory parties) internal pure returns (address user) {
        for (uint256 i = 0; i < parties.length; ++i) {
            if (parties[i].universe == Universe.ETHEREUM) {
                return bytes32ToAddress(parties[i].address_);
            }
        }
        revert("Vault: Party not found");
    }

    function fulfil(Request calldata request, bytes calldata signature)
        external
        payable
        nonReentrant
    {
        address from = extractAddress(request.parties);
        bytes32 request_hash = _hashRequest(request);
        (bool success, bytes32 signedMessageHash) = _verify_request(signature, from, request_hash);
        require(success, "Vault: Invalid signature or from");
        require(uint256(request.destinationChainID) == block.chainid, "Vault: Chain ID mismatch");
        require(request.destinationUniverse == Universe.ETHEREUM, "Vault: Universe mismatch");
        require(!fillNonce[request.nonce], "Vault: Nonce already used");
        require(request.expiry > block.timestamp, "Vault: Request expired");
        address recipient = bytes32ToAddress(request.recipientAddress);

        fillNonce[request.nonce] = true;
        requestState[signedMessageHash] = RFFState.FULFILLED;
        winningSolver[signedMessageHash] = msg.sender;

        uint256 nativeBalance = msg.value;
        for (uint256 i = 0; i < request.destinations.length; ++i) {
            if (request.destinations[i].contractAddress == bytes32(0)) {
                require(nativeBalance >= request.destinations[i].value, "Vault: Value mismatch");
                require(request.destinations[i].value > 0, "Vault: Value mismatch");
                nativeBalance -= request.destinations[i].value;
                (bool sent,) = payable(recipient).call{ value: request.destinations[i].value }("");
                require(sent, "Vault: Transfer failed");
            } else {
                IERC20 token = IERC20(bytes32ToAddress(request.destinations[i].contractAddress));

                uint256 bal = token.balanceOf(recipient);
                token.safeTransferFrom(msg.sender, recipient, request.destinations[i].value);
                // fee on transfer tokens
                if (token.balanceOf(recipient) - bal != request.destinations[i].value) {
                    revert("Vault: failed to transfer the destination amount");
                }
            }
        }
        if (nativeBalance > 0) {
            (bool sent,) = payable(msg.sender).call{ value: nativeBalance }("");
            require(sent, "Vault: Transfer failed");
        }
        emit Fulfilment(request_hash, from, msg.sender);
    }

    function settle(SettleData calldata settleData, bytes calldata signature)
        external
        nonReentrant
    {
        bytes32 structHash = keccak256(
            abi.encode(
                settleData.universe,
                settleData.chainID,
                settleData.vaultAddress,
                settleData.solvers,
                settleData.contractAddresses,
                settleData.amounts,
                settleData.nonce
            )
        );
        bytes32 signatureHash =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        address signer = signatureHash.recover(signature);
        require(hasRole(SETTLEMENT_VERIFIER_ROLE, signer), "Vault: Invalid signature");
        require(
            settleData.solvers.length == settleData.contractAddresses.length,
            "tokens length mismatch"
        );

        require(settleData.solvers.length == settleData.amounts.length, "amounts length mismatch");
        require(!settleNonce[settleData.nonce], "Vault: Nonce already used");
        require(settleData.chainID == block.chainid, "Vault: Chain ID mismatch");
        require(settleData.universe == Universe.ETHEREUM, "Vault: Universe mismatch");
        require(settleData.vaultAddress == address(this), "Vault: Invalid vault address");

        settleNonce[settleData.nonce] = true;
        for (uint256 i = 0; i < settleData.solvers.length; ++i) {
            if (settleData.contractAddresses[i] == address(0)) {
                (bool sent,) = settleData.solvers[i].call{ value: settleData.amounts[i] }("");
                require(sent, "Vault: Transfer failed");
            } else {
                IERC20 token = IERC20(settleData.contractAddresses[i]);
                token.safeTransfer(settleData.solvers[i], settleData.amounts[i]);
            }
        }
        emit Settle(
            settleData.nonce, settleData.solvers, settleData.contractAddresses, settleData.amounts
        );
    }
}
