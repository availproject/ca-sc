// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

// Imports
import {BaseVaultTest} from "./BaseVaultTest.t.sol";
import {SignatureHelper} from "./helpers/SignatureHelper.sol";
import {Vault} from "../contracts/Vault.sol";

// VaultFuzzTest - Property-Based Fuzzing Tests for Vault.sol
// @title VaultFuzzTest
// @notice Property-based fuzzing tests for Vault core functions
// @dev Uses Foundry's fuzzing capabilities with vm.assume() and bound() for input constraints
//      Tests invariants for deposit(), fulfil(), and settle() operations
contract VaultFuzzTest is BaseVaultTest {
    // State Variables

    SignatureHelper public sigHelper;

    // Test private keys for signature generation (valid 32-byte private keys)
    uint256 public constant USER_PRIVATE_KEY = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
    uint256 public constant VERIFIER_PRIVATE_KEY = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321;

    // Maximum values for fuzzing bounds
    uint256 public constant MAX_AMOUNT = 1_000_000 * 10 ** 18; // 1M tokens max
    uint256 public constant MAX_ETH = 1000 ether; // 1000 ETH max
    uint256 public constant MAX_EXPIRY_SECONDS = 365 days; // 1 year max expiry
    uint256 public constant MAX_NONCE = 1_000_000; // Reasonable nonce range

    // Setup

    function setUp() public override {
        super.setUp();

        // Deploy signature helper
        sigHelper = new SignatureHelper();

        // Get addresses from private keys
        address requester = vm.addr(USER_PRIVATE_KEY);
        address verifierFromKey = vm.addr(VERIFIER_PRIVATE_KEY);

        // Mint tokens to requester
        token.mint(requester, MAX_AMOUNT * 10);
        token2.mint(requester, MAX_AMOUNT * 10);

        // Fund requester with ETH
        vm.deal(requester, MAX_ETH * 10);

        // Fund solver with enough ETH for deposits and fulfilments
        vm.deal(solver, MAX_ETH * 10);

        // Grant SETTLEMENT_VERIFIER_ROLE to verifier
        vm.prank(admin);
        vault.grantRole(SETTLEMENT_VERIFIER_ROLE, verifierFromKey);

        // Fund verifier
        vm.deal(verifierFromKey, MAX_ETH * 10);
    }

    // Helper Functions

    /// @notice Gets the address derived from a private key
    function _getAddress(uint256 privateKey) internal pure returns (address) {
        return vm.addr(privateKey);
    }

    /// @notice Creates a request for fuzz testing with proper constraints
    function _createFuzzRequest(
        bytes32 sourceToken,
        uint256 sourceValue,
        bytes32 destToken,
        uint256 destValue,
        uint256 nonce,
        uint256 expiry
    ) internal view returns (Vault.Request memory) {
        address requester = _getAddress(USER_PRIVATE_KEY);

        Vault.SourcePair[] memory sources = new Vault.SourcePair[](1);
        sources[0] = _createSourcePair(Vault.Universe.ETHEREUM, block.chainid, sourceToken, sourceValue, 0);

        Vault.DestinationPair[] memory destinations = new Vault.DestinationPair[](1);
        destinations[0] = _createDestinationPair(destToken, destValue);

        Vault.Party[] memory parties = new Vault.Party[](1);
        parties[0] = _createParty(Vault.Universe.ETHEREUM, bytes32(uint256(uint160(requester))));

        return _createRequest(
            sources,
            Vault.Universe.ETHEREUM,
            block.chainid,
            bytes32(uint256(uint160(requester))),
            destinations,
            nonce,
            expiry,
            parties
        );
    }

    // testFuzz_Deposit - Property-Based Tests for deposit()

    /// @notice Fuzz test for ETH deposit with valid parameters
    /// @dev Tests invariant: after successful deposit, nonce is marked used and state is DEPOSITED
    /// @param depositAmount Amount of ETH to deposit (bounded to reasonable range)
    /// @param nonce Unique nonce for the request (must be > 0)
    /// @param expiryOffset Seconds until expiry (bounded to valid future range)
    function testFuzz_Deposit_ETH(uint256 depositAmount, uint256 nonce, uint256 expiryOffset) public {
        // Bound inputs to reasonable ranges
        depositAmount = bound(depositAmount, 0.001 ether, MAX_ETH);
        nonce = bound(nonce, 1, MAX_NONCE);
        expiryOffset = bound(expiryOffset, 1 minutes, MAX_EXPIRY_SECONDS);

        uint256 expiry = block.timestamp + expiryOffset;

        address requester = _getAddress(USER_PRIVATE_KEY);

        // Ensure requester has enough ETH
        vm.assume(requester.balance >= depositAmount);

        // Create request
        Vault.Request memory request = _createFuzzRequest(
            bytes32(0), // ETH
            depositAmount,
            bytes32(0), // ETH destination
            depositAmount,
            nonce,
            expiry
        );

        // Generate signature
        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Get request hash for verification
        bytes32 requestHash = sigHelper.hashRequest(request);

        // Execute deposit
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, signature, 0);

        // Verify invariants
        assertTrue(vault.depositNonce(nonce), "Nonce should be marked as used");

        bytes32 signedMessageHash = sigHelper.getEip191Hash(requestHash);
        assertEq(
            uint256(vault.requestState(signedMessageHash)),
            uint256(Vault.RFFState.DEPOSITED),
            "Request state should be DEPOSITED"
        );
    }

    /// @notice Fuzz test for ERC20 deposit with valid parameters
    /// @dev Tests invariant: after successful deposit, nonce is marked used, state is DEPOSITED, and vault holds tokens
    /// @param depositAmount Amount of tokens to deposit (bounded to reasonable range)
    /// @param nonce Unique nonce for the request
    /// @param expiryOffset Seconds until expiry
    function testFuzz_Deposit_ERC20(uint256 depositAmount, uint256 nonce, uint256 expiryOffset) public {
        // Bound inputs
        depositAmount = bound(depositAmount, 1 * 10 ** 18, MAX_AMOUNT);
        nonce = bound(nonce, 1, MAX_NONCE);
        expiryOffset = bound(expiryOffset, 1 minutes, MAX_EXPIRY_SECONDS);

        uint256 expiry = block.timestamp + expiryOffset;

        address requester = _getAddress(USER_PRIVATE_KEY);

        // Ensure requester has enough tokens and has approved
        vm.assume(token.balanceOf(requester) >= depositAmount);

        // Create request
        Vault.Request memory request = _createFuzzRequest(
            bytes32(uint256(uint160(address(token)))),
            depositAmount,
            bytes32(uint256(uint160(address(token)))),
            depositAmount,
            nonce,
            expiry
        );

        // Generate signature
        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Approve tokens
        vm.prank(requester);
        token.approve(address(vault), depositAmount);

        uint256 vaultBalanceBefore = token.balanceOf(address(vault));

        // Execute deposit
        vm.prank(solver);
        vault.deposit(request, signature, 0);

        // Verify invariants
        assertTrue(vault.depositNonce(nonce), "Nonce should be marked as used");

        bytes32 requestHash = sigHelper.hashRequest(request);
        bytes32 signedMessageHash = sigHelper.getEip191Hash(requestHash);
        assertEq(
            uint256(vault.requestState(signedMessageHash)),
            uint256(Vault.RFFState.DEPOSITED),
            "Request state should be DEPOSITED"
        );

        assertEq(
            token.balanceOf(address(vault)) - vaultBalanceBefore, depositAmount, "Vault should hold deposited tokens"
        );
    }

    // testFuzz_Fulfil - Property-Based Tests for fulfil()

    /// @notice Fuzz test for ETH fulfil with valid parameters
    /// @dev Tests invariant: after successful fulfil, nonce is marked used, state is FULFILLED, solver recorded, recipient receives ETH
    /// @param depositAmount Amount to deposit (bounded)
    /// @param fulfilAmount Amount to fulfil (bounded, must be > 0)
    /// @param nonce Unique nonce
    /// @param expiryOffset Seconds until expiry
    function testFuzz_Fulfil_ETH(uint256 depositAmount, uint256 fulfilAmount, uint256 nonce, uint256 expiryOffset)
        public
    {
        // Bound inputs
        depositAmount = bound(depositAmount, 0.001 ether, MAX_ETH);
        fulfilAmount = bound(fulfilAmount, 0.001 ether, depositAmount); // fulfil <= deposit
        nonce = bound(nonce, 1, MAX_NONCE);
        expiryOffset = bound(expiryOffset, 1 hours, MAX_EXPIRY_SECONDS);

        uint256 expiry = block.timestamp + expiryOffset;

        address requester = _getAddress(USER_PRIVATE_KEY);

        // Create request
        Vault.Request memory request = _createFuzzRequest(
            bytes32(0), // ETH
            depositAmount,
            bytes32(0), // ETH destination
            fulfilAmount,
            nonce,
            expiry
        );

        // Generate signature
        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Deposit first
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, signature, 0);

        uint256 recipientBalanceBefore = requester.balance;

        // Fulfil
        vm.prank(solver);
        vault.fulfil{value: fulfilAmount}(request, signature);

        // Verify invariants
        assertTrue(vault.fillNonce(nonce), "Fill nonce should be marked as used");

        bytes32 requestHash = sigHelper.hashRequest(request);
        bytes32 signedMessageHash = sigHelper.getEip191Hash(requestHash);
        assertEq(
            uint256(vault.requestState(signedMessageHash)),
            uint256(Vault.RFFState.FULFILLED),
            "Request state should be FULFILLED"
        );

        assertEq(vault.winningSolver(signedMessageHash), solver, "Winning solver should be recorded");

        assertEq(requester.balance - recipientBalanceBefore, fulfilAmount, "Recipient should receive ETH");
    }

    /// @notice Fuzz test for ERC20 fulfil with valid parameters
    /// @dev Tests invariant: after successful fulfil, tokens transferred to recipient
    /// @param depositAmount Amount to deposit
    /// @param fulfilAmount Amount to fulfil
    /// @param nonce Unique nonce
    /// @param expiryOffset Seconds until expiry
    function testFuzz_Fulfil_ERC20(uint256 depositAmount, uint256 fulfilAmount, uint256 nonce, uint256 expiryOffset)
        public
    {
        // Bound inputs
        depositAmount = bound(depositAmount, 1 * 10 ** 18, MAX_AMOUNT);
        fulfilAmount = bound(fulfilAmount, 1 * 10 ** 18, MAX_AMOUNT);
        nonce = bound(nonce, 1, MAX_NONCE);
        expiryOffset = bound(expiryOffset, 1 hours, MAX_EXPIRY_SECONDS);

        uint256 expiry = block.timestamp + expiryOffset;

        address requester = _getAddress(USER_PRIVATE_KEY);

        // Create request with token for deposit and fulfil
        Vault.Request memory request = _createFuzzRequest(
            bytes32(uint256(uint160(address(token)))),
            depositAmount,
            bytes32(uint256(uint160(address(token)))),
            fulfilAmount,
            nonce,
            expiry
        );

        // Generate signature
        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Approve and deposit
        vm.prank(requester);
        token.approve(address(vault), depositAmount);

        vm.prank(solver);
        vault.deposit(request, signature, 0);

        // Ensure solver has tokens for fulfilment
        token.mint(solver, fulfilAmount);
        vm.prank(solver);
        token.approve(address(vault), fulfilAmount);

        uint256 recipientBalanceBefore = token.balanceOf(requester);

        // Fulfil
        vm.prank(solver);
        vault.fulfil(request, signature);

        // Verify invariants
        assertTrue(vault.fillNonce(nonce), "Fill nonce should be marked as used");

        bytes32 requestHash = sigHelper.hashRequest(request);
        bytes32 signedMessageHash = sigHelper.getEip191Hash(requestHash);
        assertEq(
            uint256(vault.requestState(signedMessageHash)),
            uint256(Vault.RFFState.FULFILLED),
            "Request state should be FULFILLED"
        );

        assertEq(token.balanceOf(requester) - recipientBalanceBefore, fulfilAmount, "Recipient should receive tokens");
    }

    // testFuzz_Settle - Property-Based Tests for settle()

    /// @notice Fuzz test for ETH settlement with valid parameters
    /// @dev Tests invariant: after successful settle, nonce is marked used, solver receives ETH
    /// @param settleAmount Amount to settle (bounded)
    /// @param nonce Unique nonce
    function testFuzz_Settle_ETH(uint256 settleAmount, uint256 nonce) public {
        // Bound inputs
        settleAmount = bound(settleAmount, 0.001 ether, MAX_ETH);
        nonce = bound(nonce, 1, MAX_NONCE);

        // Fund vault with ETH
        vm.deal(address(vault), settleAmount * 2);

        // Create settle data
        Vault.SettleData memory settleData = _createSimpleSettleData(
            solver,
            address(0), // ETH
            settleAmount,
            nonce
        );

        // Sign with verifier key
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
        bytes32 signatureHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(VERIFIER_PRIVATE_KEY, signatureHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        uint256 solverBalanceBefore = solver.balance;

        // Execute settle
        vm.prank(user);
        vault.settle(settleData, signature);

        // Verify invariants
        assertTrue(vault.settleNonce(nonce), "Settle nonce should be marked as used");
        assertEq(solver.balance - solverBalanceBefore, settleAmount, "Solver should receive ETH");
    }

    /// @notice Fuzz test for ERC20 settlement with valid parameters
    /// @dev Tests invariant: after successful settle, solver receives tokens
    /// @param settleAmount Amount to settle (bounded)
    /// @param nonce Unique nonce
    function testFuzz_Settle_ERC20(uint256 settleAmount, uint256 nonce) public {
        // Bound inputs
        settleAmount = bound(settleAmount, 1 * 10 ** 18, MAX_AMOUNT);
        nonce = bound(nonce, 1, MAX_NONCE);

        // Fund vault with tokens
        token.mint(address(vault), settleAmount * 2);

        // Create settle data
        Vault.SettleData memory settleData = _createSimpleSettleData(solver, address(token), settleAmount, nonce);

        // Sign with verifier key
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
        bytes32 signatureHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(VERIFIER_PRIVATE_KEY, signatureHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        uint256 solverBalanceBefore = token.balanceOf(solver);

        // Execute settle
        vm.prank(user);
        vault.settle(settleData, signature);

        // Verify invariants
        assertTrue(vault.settleNonce(nonce), "Settle nonce should be marked as used");
        assertEq(token.balanceOf(solver) - solverBalanceBefore, settleAmount, "Solver should receive tokens");
    }

    /// @notice Fuzz test for multi-solver settlement
    /// @dev Tests invariant: all solvers receive correct amounts
    /// @param amount1 Amount for first solver
    /// @param amount2 Amount for second solver
    /// @param nonce Unique nonce
    function testFuzz_Settle_MultipleSolvers(uint256 amount1, uint256 amount2, uint256 nonce) public {
        // Bound inputs
        amount1 = bound(amount1, 0.001 ether, MAX_ETH / 2);
        amount2 = bound(amount2, 0.001 ether, MAX_ETH / 2);
        nonce = bound(nonce, 1, MAX_NONCE);

        // Fund vault
        vm.deal(address(vault), amount1 + amount2 + 1 ether);

        address solver2 = makeAddr("solver2");

        // Create settle data with multiple solvers
        address[] memory solvers = new address[](2);
        solvers[0] = solver;
        solvers[1] = solver2;

        address[] memory contractAddresses = new address[](2);
        contractAddresses[0] = address(0); // ETH
        contractAddresses[1] = address(0); // ETH

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = amount1;
        amounts[1] = amount2;

        Vault.SettleData memory settleData =
            _createSettleData(Vault.Universe.ETHEREUM, block.chainid, solvers, contractAddresses, amounts, nonce);

        // Sign with verifier key
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
        bytes32 signatureHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(VERIFIER_PRIVATE_KEY, signatureHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        uint256 solver1BalanceBefore = solver.balance;
        uint256 solver2BalanceBefore = solver2.balance;

        // Execute settle
        vm.prank(user);
        vault.settle(settleData, signature);

        // Verify invariants
        assertTrue(vault.settleNonce(nonce), "Settle nonce should be marked as used");
        assertEq(solver.balance - solver1BalanceBefore, amount1, "Solver 1 should receive correct amount");
        assertEq(solver2.balance - solver2BalanceBefore, amount2, "Solver 2 should receive correct amount");
    }
}
