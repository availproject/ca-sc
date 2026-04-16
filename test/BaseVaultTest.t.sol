// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

// Imports
import {Test} from "forge-std/Test.sol";
import {Vault} from "../contracts/Vault.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

// BaseVaultTest - Abstract base contract for Vault test suite
// @title BaseVaultTest
// @notice Shared base contract providing common setup and utilities for Vault tests
// @dev All Vault tests should inherit from this contract. Provides:
//      - Proxy deployment with ERC1967Proxy
//      - Common state variables (vault, addresses, tokens)
//      - Helper functions for creating test data structures
//      - Role constants and cheatcode shortcuts
abstract contract BaseVaultTest is Test {
    // State Variables

    /// @notice The vault contract instance (points to proxy)
    Vault public vault;

    /// @notice The vault implementation contract
    Vault public vaultImpl;

    /// @notice The ERC1967 proxy contract
    ERC1967Proxy public proxy;

    /// @notice Admin address with DEFAULT_ADMIN_ROLE and UPGRADER_ROLE
    address public admin;

    /// @notice Regular user address for testing user operations
    address public user;

    /// @notice Solver address that fulfills intents
    address public solver;

    /// @notice Verifier address with SETTLEMENT_VERIFIER_ROLE
    address public verifier;

    /// @notice Mock ERC20 token for testing
    MockERC20 public token;

    /// @notice Secondary mock token for multi-token tests
    MockERC20 public token2;

    // Role Constants

    /// @notice Role identifier for contract upgrade authorization
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @notice Role identifier for settlement verification authorization
    bytes32 public constant SETTLEMENT_VERIFIER_ROLE = keccak256("SETTLEMENT_VERIFIER_ROLE");

    /// @notice Default admin role from OpenZeppelin AccessControl
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    // Setup

    /// @notice Sets up the test environment with proxy deployment
    /// @dev Deploys implementation, proxy, mock tokens, and configures roles
    function setUp() public virtual {
        // Deploy vault implementation
        vaultImpl = new Vault();

        // Create test addresses using makeAddr
        admin = makeAddr("admin");
        user = makeAddr("user");
        solver = makeAddr("solver");
        verifier = makeAddr("verifier");

        // Deploy proxy with initialization data
        bytes memory initData = abi.encodeWithSelector(vaultImpl.initialize.selector, admin);
        proxy = new ERC1967Proxy(address(vaultImpl), initData);
        vault = Vault(address(proxy));

        // Grant SETTLEMENT_VERIFIER_ROLE to verifier
        vm.prank(admin);
        vault.grantRole(SETTLEMENT_VERIFIER_ROLE, verifier);

        // Deploy mock tokens
        token = new MockERC20("Mock Token", "MOCK");
        token2 = new MockERC20("Mock Token 2", "MOCK2");

        // Fund test accounts with tokens
        token.mint(user, 1_000_000 * 10 ** 18);
        token.mint(solver, 1_000_000 * 10 ** 18);
        token2.mint(user, 1_000_000 * 10 ** 18);
        token2.mint(solver, 1_000_000 * 10 ** 18);

        // Fund accounts with ETH
        vm.deal(user, 100 ether);
        vm.deal(solver, 100 ether);
        vm.deal(admin, 100 ether);
        vm.deal(verifier, 100 ether);
    }

    // Helper Functions - Request Data Structures

    /// @notice Creates a SourcePair struct for testing
    /// @param universe The blockchain universe (ETHEREUM, FUEL, SOLANA, TRON)
    /// @param chainId The chain identifier
    /// @param contractAddress The token contract address as bytes32
    /// @param value The amount of tokens/ETH
    /// @param fee The fee amount
    /// @return SourcePair The constructed SourcePair struct
    function _createSourcePair(
        Vault.Universe universe,
        uint256 chainId,
        bytes32 contractAddress,
        uint256 value,
        uint256 fee
    ) internal pure returns (Vault.SourcePair memory) {
        return Vault.SourcePair({
            universe: universe, chainID: chainId, contractAddress: contractAddress, value: value, fee: fee
        });
    }

    /// @notice Creates a DestinationPair struct for testing
    /// @param contractAddress The destination token contract address as bytes32
    /// @param value The amount of tokens/ETH to receive
    /// @return DestinationPair The constructed DestinationPair struct
    function _createDestinationPair(bytes32 contractAddress, uint256 value)
        internal
        pure
        returns (Vault.DestinationPair memory)
    {
        return Vault.DestinationPair({contractAddress: contractAddress, value: value});
    }

    /// @notice Creates a Party struct for testing
    /// @param universe The blockchain universe of the party
    /// @param address_ The party address as bytes32
    /// @return Party The constructed Party struct
    function _createParty(Vault.Universe universe, bytes32 address_) internal pure returns (Vault.Party memory) {
        return Vault.Party({universe: universe, address_: address_});
    }

    /// @notice Creates a complete Request struct for testing
    /// @param sources Array of source asset pairs
    /// @param destinationUniverse Target blockchain universe
    /// @param destinationChainId Target chain identifier
    /// @param recipientAddress Recipient address as bytes32
    /// @param destinations Array of destination asset pairs
    /// @param nonce Anti-replay nonce
    /// @param expiry Request expiration timestamp
    /// @param parties Array of participating parties
    /// @return Request The constructed Request struct
    function _createRequest(
        Vault.SourcePair[] memory sources,
        Vault.Universe destinationUniverse,
        uint256 destinationChainId,
        bytes32 recipientAddress,
        Vault.DestinationPair[] memory destinations,
        uint256 nonce,
        uint256 expiry,
        Vault.Party[] memory parties
    ) internal pure returns (Vault.Request memory) {
        return Vault.Request({
            sources: sources,
            destinationUniverse: destinationUniverse,
            destinationChainID: destinationChainId,
            recipientAddress: recipientAddress,
            destinations: destinations,
            nonce: nonce,
            expiry: expiry,
            parties: parties
        });
    }

    /// @notice Creates a simplified Request with single source and destination
    /// @param sourceToken Source token address (bytes32(0) for ETH)
    /// @param sourceValue Amount to deposit
    /// @param destToken Destination token address (bytes32(0) for ETH)
    /// @param destValue Amount to receive
    /// @param requester Address of the requester (user)
    /// @param recipient Address of the recipient
    /// @param nonce Anti-replay nonce
    /// @param expiry Request expiration timestamp
    /// @return Request The constructed Request struct
    function _createSimpleRequest(
        bytes32 sourceToken,
        uint256 sourceValue,
        bytes32 destToken,
        uint256 destValue,
        address requester,
        address recipient,
        uint256 nonce,
        uint256 expiry
    ) internal view returns (Vault.Request memory) {
        // Create source pair
        Vault.SourcePair[] memory sources = new Vault.SourcePair[](1);
        sources[0] = _createSourcePair(Vault.Universe.ETHEREUM, block.chainid, sourceToken, sourceValue, 0);

        // Create destination pair
        Vault.DestinationPair[] memory destinations = new Vault.DestinationPair[](1);
        destinations[0] = _createDestinationPair(destToken, destValue);

        // Create parties array with requester
        Vault.Party[] memory parties = new Vault.Party[](1);
        parties[0] = _createParty(Vault.Universe.ETHEREUM, bytes32(uint256(uint160(requester))));

        return _createRequest(
            sources,
            Vault.Universe.ETHEREUM,
            block.chainid,
            bytes32(uint256(uint160(recipient))),
            destinations,
            nonce,
            expiry,
            parties
        );
    }

    /// @notice Creates a SettleData struct for testing
    /// @param universe Universe where settlement occurs
    /// @param chainId Chain where settlement occurs
    /// @param vaultAddress Address of the vault contract
    /// @param solvers Array of solver addresses to pay
    /// @param contractAddresses Array of token contract addresses (address(0) for ETH)
    /// @param amounts Array of payment amounts
    /// @param nonce Anti-replay nonce
    /// @return SettleData The constructed SettleData struct
    function _createSettleData(
        Vault.Universe universe,
        uint256 chainId,
        address vaultAddress,
        address[] memory solvers,
        address[] memory contractAddresses,
        uint256[] memory amounts,
        uint256 nonce
    ) internal pure returns (Vault.SettleData memory) {
        return Vault.SettleData({
            universe: universe,
            chainID: chainId,
            vaultAddress: vaultAddress,
            solvers: solvers,
            contractAddresses: contractAddresses,
            amounts: amounts,
            nonce: nonce
        });
    }

    /// @notice Creates a simplified SettleData for single solver payment
    /// @param solver_ Address of solver to pay
    /// @param token_ Token address (address(0) for ETH)
    /// @param amount Amount to pay
    /// @param nonce Anti-replay nonce
    /// @return SettleData The constructed SettleData struct
    function _createSimpleSettleData(address solver_, address token_, uint256 amount, uint256 nonce)
        internal
        view
        returns (Vault.SettleData memory)
    {
        address[] memory solvers = new address[](1);
        solvers[0] = solver_;

        address[] memory contractAddresses = new address[](1);
        contractAddresses[0] = token_;

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = amount;

        return _createSettleData(Vault.Universe.ETHEREUM, block.chainid, address(vault), solvers, contractAddresses, amounts, nonce);
    }

    // Helper Functions - Address Conversion

    /// @notice Converts an address to bytes32
    /// @param addr The address to convert
    /// @return bytes32 The address as bytes32 (padded with zeros)
    function _addrToBytes32(address addr) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(addr)));
    }

    /// @notice Converts bytes32 to address
    /// @param b The bytes32 to convert
    /// @return address The address (last 20 bytes of bytes32)
    function _bytes32ToAddr(bytes32 b) internal pure returns (address) {
        return address(uint160(uint256(b)));
    }

    // Helper Functions - Token Operations

    /// @notice Approves token spending and deals tokens if needed
    /// @param token_ The token to approve
    /// @param owner The token owner
    /// @param spender The address to approve
    /// @param amount The amount to approve
    function _approveToken(MockERC20 token_, address owner, address spender, uint256 amount) internal {
        vm.prank(owner);
        token_.approve(spender, amount);
    }

    /// @notice Mints tokens to an address
    /// @param token_ The token to mint
    /// @param to The address to mint to
    /// @param amount The amount to mint
    function _mintToken(MockERC20 token_, address to, uint256 amount) internal {
        token_.mint(to, amount);
    }

    // Helper Functions - Time Utilities

    /// @notice Returns a timestamp in the future
    /// @param secondsFromNow Seconds from current block timestamp
    /// @return uint256 The future timestamp
    function _futureTimestamp(uint256 secondsFromNow) internal view returns (uint256) {
        return block.timestamp + secondsFromNow;
    }

    /// @notice Returns a timestamp in the past (for expired requests)
    /// @param secondsAgo Seconds before current block timestamp
    /// @return uint256 The past timestamp
    function _pastTimestamp(uint256 secondsAgo) internal view returns (uint256) {
        return block.timestamp - secondsAgo;
    }

    // Helper Functions - Array Builders

    /// @notice Creates a single-element SourcePair array
    /// @param pair The SourcePair to wrap in an array
    /// @return SourcePair[] Array containing the single pair
    function _toSourcePairArray(Vault.SourcePair memory pair) internal pure returns (Vault.SourcePair[] memory) {
        Vault.SourcePair[] memory arr = new Vault.SourcePair[](1);
        arr[0] = pair;
        return arr;
    }

    /// @notice Creates a single-element DestinationPair array
    /// @param pair The DestinationPair to wrap in an array
    /// @return DestinationPair[] Array containing the single pair
    function _toDestinationPairArray(Vault.DestinationPair memory pair)
        internal
        pure
        returns (Vault.DestinationPair[] memory)
    {
        Vault.DestinationPair[] memory arr = new Vault.DestinationPair[](1);
        arr[0] = pair;
        return arr;
    }

    /// @notice Creates a single-element Party array
    /// @param party The Party to wrap in an array
    /// @return Party[] Array containing the single party
    function _toPartyArray(Vault.Party memory party) internal pure returns (Vault.Party[] memory) {
        Vault.Party[] memory arr = new Vault.Party[](1);
        arr[0] = party;
        return arr;
    }
}
