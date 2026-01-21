// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

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
    Action,
    RouterAction,
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

    function _hashAction(Action calldata action) private pure returns (bytes32) {
        return keccak256(abi.encode(action));
    }

    function _verifyAction(bytes calldata signature, address from, Action calldata action)
        private
        pure
        returns (bool, bytes32)
    {
        bytes32 signedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", _hashAction(action))
        );

        address signer = signedMessageHash.recover(signature);
        return (signer == from, signedMessageHash);
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

    function _verify_request(bytes calldata signature, address from, Request calldata request)
        private
        pure
        returns (bool, bytes32)
    {
        // Prepend the Ethereum signed message prefix
        bytes32 signedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", _hashRequest(request))
        );

        // Recover the signer from the signature
        address signer = signedMessageHash.recover(signature);
        return (signer == from, signedMessageHash);
    }

    function deposit(Request calldata request, bytes calldata signature, uint256 chainIndex)
        external
        payable
        nonReentrant
    {
        address from = extractAddress(request.parties);
        (bool success, bytes32 signedMessageHash) = _verify_request(signature, from, request);
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
        }

        emit Deposit(signedMessageHash, from);
    }

    /// @notice Deposit funds and initiate cross-chain transfer via router
    /// @param action Action struct for router containing cross-chain transfer details
    /// @param signature User's signature authorizing the deposit
    /// @param chainIndex Index of the source chain in the action.sources array
    /// @param route Route to use (NATIVE or MAYAN)
    /// @param routeData Additional route-specific encoded parameters
    function depositRouter(
        Action calldata action,
        bytes calldata signature,
        uint256 chainIndex,
        Route route,
        bytes calldata routeData
    ) external payable nonReentrant {
        require(address(router) != address(0), "Vault: Router not set");

        address from = extractAddress(action.parties);
        (bool success, bytes32 actionHash) = _verifyAction(signature, from, action);
        require(success, "Vault: Invalid signature or from");
        require(action.sources[chainIndex].chainID == block.chainid, "Vault: Chain ID mismatch");
        require(
            action.sources[chainIndex].universe == Universe.ETHEREUM, "Vault: Universe mismatch"
        );
        require(!depositNonce[action.nonce], "Vault: Nonce already used");
        require(action.deadline > block.timestamp, "Vault: Action expired");

        depositNonce[action.nonce] = true;
        requestState[actionHash] = RFFState.DEPOSITED;

        uint256 valueToRoute = 0;

        if (action.sources[chainIndex].contractAddress == bytes32(0)) {
            uint256 totalValue = action.sources[chainIndex].value;
            require(msg.value == totalValue, "Vault: Value mismatch");
            valueToRoute = totalValue;
        } else {
            IERC20 token = IERC20(bytes32ToAddress(action.sources[chainIndex].contractAddress));

            uint256 bal = token.balanceOf(address(this));
            token.safeTransferFrom(from, address(this), action.sources[chainIndex].value);

            if (token.balanceOf(address(this)) - bal != action.sources[chainIndex].value) {
                revert("Vault: failed to transfer the source amount");
            }

            token.safeTransfer(address(router), action.sources[chainIndex].value);
        }

        RouterAction memory routerAction = RouterAction({
            tokenAddress: action.sources[chainIndex].contractAddress,
            recipientAddress: action.recipientAddress,
            destinationCaip2namespace: action.destinationCaip2namespace,
            destinationContractAddress: action.destinationContractAddress,
            destinationMinTokenAmount: action.destinationMinTokenAmount,
            amountIn: action.sources[chainIndex].value,
            destinationCaip2chainId: action.destinationCaip2chainId,
            nonce: action.nonce,
            deadline: action.deadline
        });

        router.processTransfer{ value: valueToRoute }(routerAction, route, routeData);

        emit DepositAndRoute(actionHash, from, route);
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
        (bool success, bytes32 signedMessageHash) = _verify_request(signature, from, request);
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
        emit Fulfilment(signedMessageHash, from, msg.sender);
    }

    function verifyRequestSignature(Request calldata request, bytes calldata signature)
        external
        pure
        returns (bool, bytes32)
    {
        address from = extractAddress(request.parties);
        return _verify_request(signature, from, request);
    }

    function settle(SettleData calldata settleData, bytes calldata signature)
        external
        nonReentrant
    {
        bytes32 structHash = keccak256(
            abi.encode(
                settleData.universe,
                settleData.chainID,
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
