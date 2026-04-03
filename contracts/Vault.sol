// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// OpenZeppelin Contract Imports
// ═══════════════════════════════════════════════════════════════════════════════════════════════
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// Vault Contract
// ═══════════════════════════════════════════════════════════════════════════════════════════════
// @title Vault
// @author Maharishi, Saurav, Himank, Rachit Anand Srivastava ( @privacy_prophet )
// @notice Secure upgradeable vault for cross-chain intent-based asset settlement
// @dev This contract handles deposits, fulfillments, and settlements using an intent-based
//      architecture. Users sign requests off-chain and relayers execute transactions on-chain.
//      Implements EIP-191 compliant signature verification with nonce-based replay protection.
contract Vault is Initializable, UUPSUpgradeable, AccessControlUpgradeable, ReentrancyGuardTransient {
    // ═══════════════════════════════════════════════════════════════════════════════════════════
    // Type Libraries
    // ═══════════════════════════════════════════════════════════════════════════════════════════
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    // ═══════════════════════════════════════════════════════════════════════════════════════════
    // Enums
    // ═══════════════════════════════════════════════════════════════════════════════════════════
    // @notice Supported blockchain universes for cross-chain operations
    enum Universe {
        ETHEREUM, // Ethereum L1 and EVM-compatible chains
        FUEL, // Fuel Network
        SOLANA, // Solana Network
        TRON // Tron Network
    }

    // @notice Request fulfillment state machine
    enum RFFState {
        UNPROCESSED, // Initial state, request has not been processed
        DEPOSITED, // Funds have been deposited into the vault
        FULFILLED // Intent has been fulfilled and tokens transferred
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════════
    // State Variables
    // ═══════════════════════════════════════════════════════════════════════════════════════════
    // @notice Mapping from signed message hash to fulfillment state
    // @dev Tracks the lifecycle of each request to prevent double processing
    mapping(bytes32 => RFFState) public requestState;

    // @notice Mapping from signed message hash to winning solver address
    // @dev Records which solver successfully fulfilled the intent
    mapping(bytes32 => address) public winningSolver;

    // @notice Mapping tracking used nonces for deposit operations
    // @dev Prevents replay attacks on deposit transactions
    mapping(uint256 => bool) public depositNonce;

    // @notice Mapping tracking used nonces for fill/fulfillment operations
    // @dev Prevents replay attacks on fulfillment transactions
    mapping(uint256 => bool) public fillNonce;

    // @notice Mapping tracking used nonces for settlement operations
    // @dev Prevents replay attacks on settlement transactions
    mapping(uint256 => bool) public settleNonce;

    // @notice Role identifier for contract upgrade authorization
    bytes32 private constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // @notice Role identifier for settlement verification authorization
    bytes32 private constant SETTLEMENT_VERIFIER_ROLE = keccak256("SETTLEMENT_VERIFIER_ROLE");

    // @notice Prefix added to signatures for consistent message formatting
    string private constant SIGNATURE_PREFIX = "Sign this intent to proceed \n";

    // Storage gap to reserve slots for future use
    uint256[50] private __gap;

    // ═══════════════════════════════════════════════════════════════════════════════════════════
    // Structs
    // ═══════════════════════════════════════════════════════════════════════════════════════════
    // @notice Source asset pair for cross-chain transfer origin
    struct SourcePair {
        Universe universe; // Source blockchain universe
        uint256 chainID; // Source chain identifier
        bytes32 contractAddress; // Token contract address (bytes32 for cross-chain compatibility)
        uint256 value; // Amount of tokens/ETH to transfer
        uint256 fee; // Fee amount charged
    }

    // @notice Destination asset pair for cross-chain transfer destination
    struct DestinationPair {
        bytes32 contractAddress; // Destination token contract address
        uint256 value; // Amount of tokens/ETH to receive
    }

    // @notice Party participating in the cross-chain transaction
    struct Party {
        Universe universe; // Blockchain universe of the party
        bytes32 address_; // Party address (bytes32 for cross-chain compatibility)
        // Note: address_ uses underscore suffix because 'address' is a reserved keyword
    }

    // @notice Complete cross-chain transfer request intent
    struct Request {
        SourcePair[] sources; // Source asset pairs
        Universe destinationUniverse; // Target blockchain universe
        uint256 destinationChainID; // Target chain identifier
        bytes32 recipientAddress; // Recipient address
        DestinationPair[] destinations; // Destination asset pairs
        uint256 nonce; // Anti-replay nonce
        uint256 expiry; // Request expiration timestamp
        Party[] parties; // Participating parties
    }

    // @notice Settlement data for solver compensation
    struct SettleData {
        Universe universe; // Universe where settlement occurs
        uint256 chainID; // Chain where settlement occurs
        address vaultAddress; // Vault address to call "settle()" on.
        address[] solvers; // Addresses of solvers to pay
        address[] contractAddresses; // Token contracts (address(0) for ETH)
        uint256[] amounts; // Payment amounts for each solver
        uint256 nonce; // Anti-replay nonce
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════════
    // Events
    // ═══════════════════════════════════════════════════════════════════════════════════════════
    // @notice Emitted when funds are deposited into the vault
    // @param requestHash Hash of the request that was deposited
    // @param from Address that deposited the funds
    event Deposit(bytes32 indexed requestHash, address from);

    // @notice Emitted when an intent is fulfilled
    // @param requestHash Hash of the fulfilled request
    // @param from Address of the original requester
    // @param solver Address of the solver who fulfilled the intent
    event Fulfilment(bytes32 indexed requestHash, address from, address solver);

    // @notice Emitted when solvers are settled/compensated
    // @param nonce Settlement nonce for tracking
    // @param solver Array of solver addresses paid
    // @param token Array of token addresses (address(0) for native ETH)
    // @param amount Array of payment amounts
    event Settle(uint256 indexed nonce, address[] solver, address[] token, uint256[] amount);

    // ═══════════════════════════════════════════════════════════════════════════════════════════
    // Constructor and Initialization
    // ═══════════════════════════════════════════════════════════════════════════════════════════
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // @notice Initializes the vault contract with admin roles
    // @param admin Address to receive DEFAULT_ADMIN_ROLE and UPGRADER_ROLE
    // @dev Must be called once after proxy deployment. Cannot be called again.
    function initialize(address admin) public initializer {
        __AccessControl_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
    }

    // @notice Authorizes contract upgrades to new implementation
    // @param newImplementation Address of the new implementation contract
    // @dev Only callable by accounts with UPGRADER_ROLE
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}

    // @notice Returns the contract version
    // @return string The current implementation version
    // @dev Pure function - version is baked into implementation bytecode
    function version() external pure returns (string memory) {
        return "1.0.0";
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════════
    // Internal Utility Functions
    // ═══════════════════════════════════════════════════════════════════════════════════════════
    // @notice Computes the keccak256 hash of a Request struct
    // @param request The Request struct to hash
    // @return bytes32 The computed hash of all request fields
    // @dev Used for signature verification and request identification
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

    // @notice Converts a bytes32 value to an ethereum address
    // @param a The bytes32 value to convert
    // @return address The address extracted from the last 20 bytes of the bytes32 value
    // @dev Used to handle cross-chain addresses that are stored as bytes32
    function bytes32ToAddress(bytes32 a) internal pure returns (address) {
        // Cast the last 20 bytes of bytes32 into an address
        return address(uint160(uint256(a)));
    }

    // @notice Verifies that a signature was created by the specified address
    // @param signature The EIP-191 compliant signature to verify
    // @param from The expected signer address
    // @param hash The request hash that was signed
    // @return success True if signature is valid and matches 'from'
    // @return signedMessageHash The EIP-191 signed message hash used for recovery
    // @dev Creates a prefixed message matching the client format for verification
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

    // ═══════════════════════════════════════════════════════════════════════════════════════════
    // Core Operations
    // ═══════════════════════════════════════════════════════════════════════════════════════════
    // @notice Deposits assets into the vault for a cross-chain intent
    // @param request The complete request intent with source and destination details
    // @param signature EIP-191 signature from the requester authorizing the deposit
    // @param chainIndex Index of the source pair in the request.sources array to process
    // @dev Validates signature, checks chain/universe compatibility, and transfers assets.
    //      Supports both native ETH (when contractAddress is bytes32(0)) and ERC20 tokens.
    //      Reverts on signature failure, chain mismatches, expired requests, or used nonces.
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
                // fee on transfer tokens
                if (token.balanceOf(msg.sender) - solverBal != request.sources[chainIndex].fee) {
                    revert("Vault: failed to transfer the fee amount");
                }
            } else if (request.sources[chainIndex].fee > 0 && msg.sender == from) {
                revert("Vault: self-fee transfer not allowed");
            }
        }

        emit Deposit(request_hash, from);
    }

    // @notice Extracts the Ethereum address from an array of parties
    // @param parties Array of Party structs to search through
    // @return user The Ethereum address found among the parties
    // @dev Iterates through parties array and returns the first ETHEREUM universe address
    // @custom:reverts Vault: Party not found if no Ethereum party exists in the array
    function extractAddress(Party[] memory parties) internal pure returns (address user) {
        for (uint256 i = 0; i < parties.length; ++i) {
            if (parties[i].universe == Universe.ETHEREUM) {
                return bytes32ToAddress(parties[i].address_);
            }
        }
        revert("Vault: Party not found");
    }

    // @notice Fulfills a cross-chain intent by transferring destination assets
    // @param request The complete request intent to fulfill
    // @param signature EIP-191 signature from the requester authorizing fulfillment
    // @dev Called by solvers to complete the cross-chain transfer. Validates the request,
    //      transfers destination assets (ETH or ERC20) to the recipient, and records the
    //      solver for settlement. Refunds excess ETH to the solver.
    // @custom:reverts Various validation errors on signature/chain/nonce/expiry failures
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

    // ═══════════════════════════════════════════════════════════════════════════════════════════
    // Settlement Function
    // ═══════════════════════════════════════════════════════════════════════════════════════════
    // @notice Settles payments to solvers after successful fulfillment
    // @param settleData Struct containing solver addresses, token addresses, and amounts
    // @param signature EIP-191 signature from an authorized SETTLEMENT_VERIFIER_ROLE holder
    // @dev Called to compensate solvers. Only verifiers with SETTLEMENT_VERIFIER_ROLE can
    //      authorize settlements. Supports both native ETH and ERC20 token payments.
    //      Validates nonce uniqueness, chain/universe compatibility, and signature authority.
    // @custom:reverts Vault: Invalid signature if signer lacks SETTLEMENT_VERIFIER_ROLE
    // @custom:reverts tokens length mismatch if solver and token array lengths differ
    // @custom:reverts amounts length mismatch if solver and amount array lengths differ
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
