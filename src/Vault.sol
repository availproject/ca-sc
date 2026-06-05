// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {Request, Party, Universe, RFFState, SettleData} from "./types.sol";
import {IRouter} from "./interfaces/IRouter.sol";

/// @title Vault
/// @author Maharishi, Saurav, Himank, Rachit Anand Srivastava (@privacy_prophet)
/// @notice Vault contract for managing deposits, fulfillments, and settlements of cross-chain transfers
/// @dev UUPS upgradeable contract with role-based access control
contract Vault is Initializable, UUPSUpgradeable, AccessControlUpgradeable, ReentrancyGuardTransient {
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
    uint256[49] private _gap;

    event Deposit(bytes32 indexed requestHash, address from);
    event Fulfilment(bytes32 indexed requestHash, address from, address solver);
    event Settle(uint256 indexed nonce, address[] solver, address[] token, uint256[] amount);
    event RouterSet(address indexed newRouter);
    event DepositMayan(bytes32 indexed requestHash, address from);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the Vault contract with admin roles
    /// @param admin Address to grant DEFAULT_ADMIN_ROLE and UPGRADER_ROLE
    /// @param mpc Address to grant SETTLEMENT_VERIFIER_ROLE
    function initialize(address admin, address mpc) public initializer {
        require(mpc != address(0), "Vault: Zero address");

        __AccessControl_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
        _grantRole(SETTLEMENT_VERIFIER_ROLE, mpc);
    }

    /// @notice Set the router contract address
    /// @param _router Address of the Router contract
    function setRouter(address _router) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_router != address(0), "Vault: Zero address");
        router = IRouter(_router);
        emit RouterSet(_router);
    }

    /// @notice Authorizes a contract upgrade
    /// @dev Ensures only accounts with UPGRADER_ROLE can upgrade the implementation
    /// @param newImplementation Address of the new implementation contract
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}

    /// @notice Returns the contract version
    /// @return Version string semver format
    function version() external pure returns (string memory) {
        return "1.0.0";
    }

    /// @notice Computes the hash of a request struct
    /// @dev Encodes all relevant request fields into a canonical hash
    /// @param request The Request struct to hash
    /// @return Hash of the request struct
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

    /// @notice Converts a bytes32 value to an address
    /// @dev Casts the last 20 bytes of the bytes32 to an address
    /// @param a The bytes32 value to convert
    /// @return The corresponding address
    function bytes32ToAddress(bytes32 a) internal pure returns (address) {
        // Cast the last 20 bytes of bytes32 into an address
        return address(uint160(uint256(a)));
    }

    /// @notice Verifies an EIP-191 signature for a request
    /// @dev Constructs message per EIP-191 and recovers signer via ECDSA
    /// @param signature The signature bytes
    /// @param from Expected signer address
    /// @param hash The hash of the request data
    /// @return success True if signer matches expected address
    /// @return signedMessageHash The computed EIP-191 signed message hash
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

    /// @notice Deposits funds into the vault for a cross-chain intent
    /// @dev Validates signature, chain ID, universe, nonce and expiry before accepting deposit
    /// @param request Request struct containing source chain and amount details
    /// @param signature User's signature authorizing the deposit
    /// @param chainIndex Index of the source chain in request.sources array
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

    /// @notice Deposit funds and initiate cross-chain transfer via mayan
    /// @dev The user signature covers the canonical Request only. routeData is relayer-supplied
    /// and validated by Mayan contracts during execution.
    /// @param request Request struct for router containing cross-chain transfer details
    /// @param signature User's signature authorizing the deposit
    /// @param chainIndex Index of the source chain in the request.sources array
    /// @param routeData Additional route-specific encoded parameters
    function depositMayan(
        Request calldata request,
        bytes calldata signature,
        uint256 chainIndex,
        bytes calldata routeData
    ) external payable nonReentrant {
        require(address(router) != address(0), "Vault: Router not set");
        require(chainIndex < request.destinations.length, "Vault: Invalid destination index");

        address from = extractAddress(request.parties);
        bytes32 request_hash = _hashRequest(request);
        (bool success, bytes32 requestHash) = _verify_request(signature, from, request_hash);
        require(success, "Vault: Invalid signature or from");
        require(request.sources[chainIndex].chainID == block.chainid, "Vault: Chain ID mismatch");
        require(request.sources[chainIndex].universe == Universe.ETHEREUM, "Vault: Universe mismatch");
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

            token.forceApprove(address(router), request.sources[chainIndex].value);

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

        bytes memory encodedRouteData = abi.encode(chainIndex, routeData);
        router.processTransfer{value: valueToRoute}(request, encodedRouteData);

        emit DepositMayan(request_hash, from);
    }

    /// @notice Extracts the Ethereum party address from a parties array
    /// @dev Iterates through parties to find the ETHEREUM universe entry
    /// @param parties Array of Party structs to search
    /// @return user The ETHEREUM party address
    function extractAddress(Party[] memory parties) internal pure returns (address user) {
        for (uint256 i = 0; i < parties.length; ++i) {
            if (parties[i].universe == Universe.ETHEREUM) {
                return bytes32ToAddress(parties[i].address_);
            }
        }
        revert("Vault: Party not found");
    }

    /// @notice Fulfils a cross-chain intent by distributing funds to the recipient
    /// @dev Validates signature, chain ID, universe, nonce and expiry, then transfers tokens/native ETH
    /// @param request Request struct containing destination chain and amount details
    /// @param signature User's signature authorizing the fulfilment
    function fulfil(Request calldata request, bytes calldata signature) external payable nonReentrant {
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
                (bool sent,) = payable(recipient).call{value: request.destinations[i].value}("");
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
            (bool sent,) = payable(msg.sender).call{value: nativeBalance}("");
            require(sent, "Vault: Transfer failed");
        }
        emit Fulfilment(request_hash, from, msg.sender);
    }

    /// @notice Settles outstanding payments to solvers after Avail multisig verification
    /// @dev Verifies signer has SETTLEMENT_VERIFIER_ROLE and processes token/native transfers
    /// @param settleData SettleData struct containing solver addresses, tokens, amounts and nonce
    /// @param signature Avail multisig signature authorizing the settlement
    function settle(SettleData calldata settleData, bytes calldata signature) external nonReentrant {
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
        bytes32 signatureHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        address signer = signatureHash.recover(signature);
        require(hasRole(SETTLEMENT_VERIFIER_ROLE, signer), "Vault: Invalid signature");
        require(settleData.solvers.length == settleData.contractAddresses.length, "tokens length mismatch");

        require(settleData.solvers.length == settleData.amounts.length, "amounts length mismatch");
        require(!settleNonce[settleData.nonce], "Vault: Nonce already used");
        require(settleData.chainID == block.chainid, "Vault: Chain ID mismatch");
        require(settleData.universe == Universe.ETHEREUM, "Vault: Universe mismatch");
        require(settleData.vaultAddress == address(this), "Vault: Invalid vault address");

        settleNonce[settleData.nonce] = true;
        for (uint256 i = 0; i < settleData.solvers.length; ++i) {
            if (settleData.contractAddresses[i] == address(0)) {
                (bool sent,) = settleData.solvers[i].call{value: settleData.amounts[i]}("");
                require(sent, "Vault: Transfer failed");
            } else {
                IERC20 token = IERC20(settleData.contractAddresses[i]);
                token.safeTransfer(settleData.solvers[i], settleData.amounts[i]);
            }
        }
        emit Settle(settleData.nonce, settleData.solvers, settleData.contractAddresses, settleData.amounts);
    }
}
