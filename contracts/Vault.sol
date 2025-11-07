// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract Vault is Initializable, UUPSUpgradeable, AccessControlUpgradeable, ReentrancyGuardUpgradeable {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    enum Universe {
        ETHEREUM,
        FUEL,
        SOLANA,
        TRON
    }

    enum RFFState {
        UNPROCESSED,
        DEPOSITED,
        FULFILLED
    }

    mapping(bytes32 => RFFState) public requestState;
    mapping(bytes32 => address) public winningSolver;
    mapping(uint256 => bool) public depositNonce;
    mapping(uint256 => bool) public fillNonce;
    mapping(uint256 => bool) public settleNonce;
    bytes32 private constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // Storage gap to reserve slots for future use
    uint256[50] private __gap;

    struct SourcePair {
        Universe universe;
        uint256 chainID;
        bytes32 contractAddress;
        uint256 value;
    }

    struct DestinationPair {
        bytes32 contractAddress;
        uint256 value;
    }

    struct Party {
        Universe universe;
        bytes32 address_; // address is a reserved keyword
    }

    struct Request {
        SourcePair[] sources;
        Universe destinationUniverse;
        uint256 destinationChainID;
        bytes32 recipientAddress;
        DestinationPair[] destinations;
        uint256 nonce;
        uint256 expiry;
        Party[] parties;
    }

    struct SettleData {
        Universe universe;
        uint256 chainID;
        address[] solvers;
        address[] contractAddresses;
        uint256[] amounts;
        uint256 nonce;
    }

    event Deposit(
        bytes32 indexed requestHash,
        address from
    );
    event Fulfilment(
        bytes32 indexed requestHash,
        address from,
        address solver
    );
    event Settle(uint256 indexed nonce, address[] solver, address[] token, uint256[] amount);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin) initializer public {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        onlyRole(UPGRADER_ROLE)
        override
    {}

    function _hashRequest(
        Request calldata request
    ) private pure returns (bytes32) {
        return
            keccak256(
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

    function _verify_request(
        bytes calldata signature,
        address from,
        Request calldata request
    ) private pure returns (bool, bytes32) {
        // Prepend the Ethereum signed message prefix
        bytes32 signedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", _hashRequest(request))
        );

        // Recover the signer from the signature
        address signer = signedMessageHash.recover(signature);
        return (signer == from, signedMessageHash);
    }

    function deposit(
        Request calldata request,
        bytes calldata signature,
        uint256 chainIndex
    ) external payable nonReentrant {
        address from = extractAddress(request.parties);
        (bool success, bytes32 signedMessageHash) = _verify_request(
            signature,
            from,
            request
        );
        require(success, "Vault: Invalid signature or from");
        require(
            request.sources[chainIndex].chainID == block.chainid,
            "Vault: Chain ID mismatch"
        );
        require(request.sources[chainIndex].universe == Universe.ETHEREUM, "Vault: Universe mismatch");
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
            token.safeTransferFrom(
                from,
                address(this),
                request.sources[chainIndex].value
            );
            // fee on transfer tokens
            if (token.balanceOf(address(this)) - bal != request.sources[chainIndex].value) {
                revert("Vault: failed to transfer the source amount");
            }
        }

        emit Deposit(signedMessageHash, from);
    }

    function extractAddress(Party[] memory parties) internal pure returns (address user) {
        for(uint i = 0; i < parties.length; ++i) {
            if (parties[i].universe == Universe.ETHEREUM) {
                return bytes32ToAddress(parties[i].address_);
            }
        }
        revert("Vault: Party not found");
    }

    function fulfil(
        Request calldata request,
        bytes calldata signature
    ) external payable nonReentrant {
        address from = extractAddress(request.parties);
        (bool success, bytes32 signedMessageHash) = _verify_request(
            signature,
            from,
            request
        );
        require(success, "Vault: Invalid signature or from");
        require(
            uint256(request.destinationChainID) == block.chainid,
            "Vault: Chain ID mismatch"
        );
        require(request.destinationUniverse == Universe.ETHEREUM, "Vault: Universe mismatch");
        require(!fillNonce[request.nonce], "Vault: Nonce already used");
        require(request.expiry > block.timestamp, "Vault: Request expired");
        address recipient = bytes32ToAddress(request.recipientAddress);

        fillNonce[request.nonce] = true;
        requestState[signedMessageHash] = RFFState.FULFILLED;
        winningSolver[signedMessageHash] = msg.sender;

        uint256 nativeBalance = msg.value;
        for (uint i = 0; i < request.destinations.length; ++i) {
            if (request.destinations[i].contractAddress == bytes32(0)) {
                require(
                    nativeBalance >= request.destinations[i].value,
                    "Vault: Value mismatch"
                );
                require(
                    request.destinations[i].value > 0,
                    "Vault: Value mismatch"
                );
                nativeBalance -= request.destinations[i].value;
                (bool sent, ) = payable(recipient).call{
                    value: request.destinations[i].value
                }("");
                require(sent, "Vault: Transfer failed");
            } else {
                IERC20 token = IERC20(bytes32ToAddress(request.destinations[i].contractAddress));
                token.safeTransferFrom(
                    msg.sender,
                    recipient,
                    request.destinations[i].value
                );
            }
        }
        if (nativeBalance > 0) {
            (bool sent, ) = payable(msg.sender).call{
                value: nativeBalance
            }("");
            require(sent, "Vault: Transfer failed");
        }
        emit Fulfilment(signedMessageHash, from, msg.sender);
    }

    function verifyRequestSignature(
        Request calldata request,
        bytes calldata signature
    ) external pure returns (bool, bytes32) {
        address from = extractAddress(request.parties);
        return _verify_request(signature, from, request);
    }

    function settle(
        SettleData calldata settleData,
        bytes calldata signature
    ) external nonReentrant {
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
        bytes32 signatureHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash)
        );
        address signer = signatureHash.recover(signature);
        require(
            hasRole(DEFAULT_ADMIN_ROLE, signer),
            "Vault: Invalid signature"
        );
        require(
            settleData.solvers.length == settleData.contractAddresses.length,
            "tokens length mismatch"
        );

        require(
            settleData.solvers.length == settleData.amounts.length,
            "amounts length mismatch"
        );
        require(!settleNonce[settleData.nonce], "Vault: Nonce already used");
        require(settleData.chainID == block.chainid, "Vault: Chain ID mismatch");
        require(settleData.universe == Universe.ETHEREUM, "Vault: Universe mismatch");

        settleNonce[settleData.nonce] = true;
        for (uint i = 0; i < settleData.solvers.length; ++i) {
            if (settleData.contractAddresses[i] == address(0)) {
                (bool sent, ) = settleData.solvers[i].call{
                    value: settleData.amounts[i]
                }("");
                require(sent, "Vault: Transfer failed");
            } else {
                IERC20 token = IERC20(settleData.contractAddresses[i]);
                token.safeTransfer(
                    settleData.solvers[i],
                    settleData.amounts[i]
                );
            }
        }
        emit Settle(
            settleData.nonce,
            settleData.solvers,
            settleData.contractAddresses,
            settleData.amounts
        );
    }
}
