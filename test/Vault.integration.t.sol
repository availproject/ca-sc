// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

// Imports
import {BaseVaultTest} from "./BaseVaultTest.t.sol";
import {SignatureHelper} from "./helpers/SignatureHelper.sol";
import {Vault} from "../contracts/Vault.sol";

// VaultIntegrationTest - End-to-End Integration Tests for Vault.sol
// @title VaultIntegrationTest
// @notice End-to-end integration tests covering complete user flows
// @dev Tests complete flows: deposit→fulfil→settle, multiple deposits, upgrade with state
contract VaultIntegrationTest is BaseVaultTest {
    // State Variables
    
    SignatureHelper public sigHelper;
    
    // Test private keys for signature generation
    uint256 public constant USER1_PRIVATE_KEY = 0x1111111111111111111111111111111111111111111111111111111111111111;
    uint256 public constant USER2_PRIVATE_KEY = 0x2222222222222222222222222222222222222222222222222222222222222222;
    uint256 public constant USER3_PRIVATE_KEY = 0x3333333333333333333333333333333333333333333333333333333333333333;
    uint256 public constant VERIFIER_PRIVATE_KEY = 0x4444444444444444444444444444444444444444444444444444444444444444;
    
    // Setup
    
    function setUp() public virtual override {
        super.setUp();
        
        // Deploy signature helper
        sigHelper = new SignatureHelper();
        
        // Setup users with tokens and ETH
        _setupUser(USER1_PRIVATE_KEY);
        _setupUser(USER2_PRIVATE_KEY);
        _setupUser(USER3_PRIVATE_KEY);
        
        // Setup verifier with role
        address verifierFromKey = _getAddress(VERIFIER_PRIVATE_KEY);
        vm.prank(admin);
        vault.grantRole(SETTLEMENT_VERIFIER_ROLE, verifierFromKey);
        vm.deal(verifierFromKey, 100 ether);
    }
    
    /// @notice Setup a user with tokens and ETH
    function _setupUser(uint256 privateKey) internal {
        address userAddr = _getAddress(privateKey);
        token.mint(userAddr, 1_000_000 * 10 ** 18);
        token2.mint(userAddr, 1_000_000 * 10 ** 18);
        vm.deal(userAddr, 100 ether);
    }
    
    // Helper Functions
    
    /// @notice Gets the address derived from a private key
    function _getAddress(uint256 privateKey) internal pure returns (address) {
        return vm.addr(privateKey);
    }
    
    /// @notice Creates a request for a specific user
    function _createRequestForUser(
        bytes32 sourceToken,
        uint256 sourceValue,
        bytes32 destToken,
        uint256 destValue,
        uint256 userPrivateKey,
        address recipient,
        uint256 nonce,
        uint256 expiry
    ) internal view returns (Vault.Request memory) {
        address requester = _getAddress(userPrivateKey);
        
        Vault.SourcePair[] memory sources = new Vault.SourcePair[](1);
        sources[0] = _createSourcePair(
            Vault.Universe.ETHEREUM,
            block.chainid,
            sourceToken,
            sourceValue,
            0
        );
        
        Vault.DestinationPair[] memory destinations = new Vault.DestinationPair[](1);
        destinations[0] = _createDestinationPair(destToken, destValue);
        
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
    
    /// @notice Signs settle data with verifier key
    function _signSettleData(Vault.SettleData memory settleData) internal pure returns (bytes memory) {
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
        return abi.encodePacked(r, s, v);
    }

    // Flow 1: Complete Deposit → Fulfil → Settle Flow
    
    /// @notice Test complete flow: deposit ETH → fulfil → settle
    /// @dev Tests the entire lifecycle of a cross-chain intent:
    ///      1. User signs intent off-chain
    ///      2. Relayer deposits ETH into vault
    ///      3. Solver fulfills the intent by sending ETH to recipient
    ///      4. Settlement pays the solver from vault
    function test_CompleteFlow_ETH_DepositFulfilSettle() public {
        // Setup
        uint256 depositAmount = 2 ether;
        uint256 fulfilAmount = 1.8 ether; // Solver takes 0.2 ether as fee
        uint256 settleAmount = 1.9 ether; // Settlement pays solver
        uint256 nonce = 1;
        uint256 expiry = _futureTimestamp(1 hours);
        
        address recipient = makeAddr("recipient");
        
        // Step 1: Deposit - User signs, relayer deposits
        
        Vault.Request memory request = _createRequestForUser(
            bytes32(0), // ETH
            depositAmount,
            bytes32(0), // ETH destination
            fulfilAmount,
            USER1_PRIVATE_KEY,
            recipient,
            nonce,
            expiry
        );
        
        bytes memory signature = sigHelper.signRequest(request, USER1_PRIVATE_KEY);
        bytes32 requestHash = sigHelper.hashRequest(request);
        
        // Record balances before deposit
        uint256 vaultBalanceBefore = address(vault).balance;
        
        // Relayer (solver) executes deposit on behalf of user
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, signature, 0);
        
        // Verify deposit state
        assertTrue(vault.depositNonce(nonce), "Deposit nonce should be marked");
        bytes32 signedMessageHash = sigHelper.getEip191Hash(requestHash);
        assertEq(
            uint256(vault.requestState(signedMessageHash)),
            uint256(Vault.RFFState.DEPOSITED),
            "Request should be DEPOSITED"
        );
        
        // Vault should hold the deposited ETH
        assertEq(
            address(vault).balance - vaultBalanceBefore,
            depositAmount,
            "Vault should hold deposited ETH"
        );
        
        // Step 2: Fulfil - Solver fulfills the intent
        
        uint256 recipientBalanceBefore = recipient.balance;
        uint256 solverBalanceBefore = solver.balance;
        
        // Solver fulfills by sending ETH to recipient
        vm.prank(solver);
        vault.fulfil{value: fulfilAmount}(request, signature);
        
        // Verify fulfilment state
        assertTrue(vault.fillNonce(nonce), "Fill nonce should be marked");
        assertEq(
            uint256(vault.requestState(signedMessageHash)),
            uint256(Vault.RFFState.FULFILLED),
            "Request should be FULFILLED"
        );
        assertEq(vault.winningSolver(signedMessageHash), solver, "Winning solver should be recorded");
        
        // Recipient should receive ETH
        assertEq(
            recipient.balance - recipientBalanceBefore,
            fulfilAmount,
            "Recipient should receive ETH"
        );
        
        // Step 3: Settle - Pay solver from vault
        
        uint256 settleNonce = 100;
        
        Vault.SettleData memory settleData = _createSimpleSettleData(
            solver,
            address(0), // ETH
            settleAmount,
            settleNonce
        );
        
        bytes memory settleSignature = _signSettleData(settleData);
        
        solverBalanceBefore = solver.balance;
        
        // Anyone can call settle with valid signature
        vm.prank(user);
        vault.settle(settleData, settleSignature);
        
        // Verify settlement
        assertTrue(vault.settleNonce(settleNonce), "Settle nonce should be marked");
        assertEq(
            solver.balance - solverBalanceBefore,
            settleAmount,
            "Solver should receive settlement"
        );
    }
    
    /// @notice Test complete flow with ERC20 tokens
    function test_CompleteFlow_ERC20_DepositFulfilSettle() public {
        // Setup
        uint256 depositAmount = 1000 * 10 ** 18;
        uint256 fulfilAmount = 950 * 10 ** 18;
        uint256 settleAmount = 980 * 10 ** 18;
        uint256 nonce = 2;
        uint256 expiry = _futureTimestamp(1 hours);
        
        address user1 = _getAddress(USER1_PRIVATE_KEY);
        address recipient = makeAddr("recipient");
        
        // Step 1: Deposit ERC20
        
        Vault.Request memory request = _createRequestForUser(
            bytes32(uint256(uint160(address(token)))),
            depositAmount,
            bytes32(uint256(uint160(address(token)))),
            fulfilAmount,
            USER1_PRIVATE_KEY,
            recipient,
            nonce,
            expiry
        );
        
        bytes memory signature = sigHelper.signRequest(request, USER1_PRIVATE_KEY);
        
        // Approve vault
        vm.prank(user1);
        token.approve(address(vault), depositAmount);
        
        uint256 vaultBalanceBefore = token.balanceOf(address(vault));
        
        // Deposit
        vm.prank(solver);
        vault.deposit(request, signature, 0);
        
        assertEq(
            token.balanceOf(address(vault)) - vaultBalanceBefore,
            depositAmount,
            "Vault should hold deposited tokens"
        );
        
        // Step 2: Fulfil - Solver sends tokens to recipient
        
        // Mint tokens to solver for fulfilment
        token.mint(solver, fulfilAmount);
        vm.prank(solver);
        token.approve(address(vault), fulfilAmount);
        
        uint256 recipientBalanceBefore = token.balanceOf(recipient);
        
        vm.prank(solver);
        vault.fulfil(request, signature);
        
        assertEq(
            token.balanceOf(recipient) - recipientBalanceBefore,
            fulfilAmount,
            "Recipient should receive tokens"
        );
        
        // Step 3: Settle - Pay solver from vault
        
        uint256 settleNonce = 101;
        
        Vault.SettleData memory settleData = _createSimpleSettleData(
            solver,
            address(token),
            settleAmount,
            settleNonce
        );
        
        bytes memory settleSignature = _signSettleData(settleData);
        
        uint256 solverBalanceBefore = token.balanceOf(solver);
        
        vm.prank(user);
        vault.settle(settleData, settleSignature);
        
        assertEq(
            token.balanceOf(solver) - solverBalanceBefore,
            settleAmount,
            "Solver should receive settlement tokens"
        );
    }

    // Flow 2: Multiple Deposits Flow
    
    /// @notice Test multiple users depositing and fulfilling in sequence
    /// @dev Tests concurrent deposits from different users with different tokens
    function test_MultipleDeposits_ThreeUsers_SequentialFlow() public {
        // Setup - Three users with different intents
        address user2 = _getAddress(USER2_PRIVATE_KEY);
        address user3 = _getAddress(USER3_PRIVATE_KEY);
        
        address recipient1 = makeAddr("recipient1");
        address recipient2 = makeAddr("recipient2");
        address recipient3 = makeAddr("recipient3");
        
        uint256 expiry = _futureTimestamp(1 hours);
        
        // User 1: Deposit ETH
        
        uint256 deposit1 = 1 ether;
        uint256 fulfil1 = 0.9 ether;
        
        Vault.Request memory request1 = _createRequestForUser(
            bytes32(0),
            deposit1,
            bytes32(0),
            fulfil1,
            USER1_PRIVATE_KEY,
            recipient1,
            10,
            expiry
        );
        
        bytes memory sig1 = sigHelper.signRequest(request1, USER1_PRIVATE_KEY);
        
        vm.prank(solver);
        vault.deposit{value: deposit1}(request1, sig1, 0);
        
        // User 2: Deposit ERC20 (token)
        
        uint256 deposit2 = 500 * 10 ** 18;
        uint256 fulfil2 = 480 * 10 ** 18;
        
        Vault.Request memory request2 = _createRequestForUser(
            bytes32(uint256(uint160(address(token)))),
            deposit2,
            bytes32(uint256(uint160(address(token)))),
            fulfil2,
            USER2_PRIVATE_KEY,
            recipient2,
            11,
            expiry
        );
        
        bytes memory sig2 = sigHelper.signRequest(request2, USER2_PRIVATE_KEY);
        
        vm.prank(user2);
        token.approve(address(vault), deposit2);
        
        vm.prank(solver);
        vault.deposit(request2, sig2, 0);
        
        // User 3: Deposit ERC20 (token2)
        
        uint256 deposit3 = 300 * 10 ** 18;
        uint256 fulfil3 = 290 * 10 ** 18;
        
        Vault.Request memory request3 = _createRequestForUser(
            bytes32(uint256(uint160(address(token2)))),
            deposit3,
            bytes32(uint256(uint160(address(token2)))),
            fulfil3,
            USER3_PRIVATE_KEY,
            recipient3,
            12,
            expiry
        );
        
        bytes memory sig3 = sigHelper.signRequest(request3, USER3_PRIVATE_KEY);
        
        vm.prank(user3);
        token2.approve(address(vault), deposit3);
        
        vm.prank(solver);
        vault.deposit(request3, sig3, 0);
        
        // Verify all deposits recorded
        
        assertTrue(vault.depositNonce(10), "User1 deposit nonce should be marked");
        assertTrue(vault.depositNonce(11), "User2 deposit nonce should be marked");
        assertTrue(vault.depositNonce(12), "User3 deposit nonce should be marked");
        
        // Verify vault balances
        assertEq(address(vault).balance, deposit1, "Vault should hold ETH");
        assertEq(token.balanceOf(address(vault)), deposit2, "Vault should hold token");
        assertEq(token2.balanceOf(address(vault)), deposit3, "Vault should hold token2");
        
        // Fulfil all requests
        
        // Fulfil user1's request (ETH)
        vm.prank(solver);
        vault.fulfil{value: fulfil1}(request1, sig1);
        
        // Fulfil user2's request (token)
        token.mint(solver, fulfil2);
        vm.prank(solver);
        token.approve(address(vault), fulfil2);
        vm.prank(solver);
        vault.fulfil(request2, sig2);
        
        // Fulfil user3's request (token2)
        token2.mint(solver, fulfil3);
        vm.prank(solver);
        token2.approve(address(vault), fulfil3);
        vm.prank(solver);
        vault.fulfil(request3, sig3);
        
        // Verify all fulfilments
        
        assertTrue(vault.fillNonce(10), "User1 fill nonce should be marked");
        assertTrue(vault.fillNonce(11), "User2 fill nonce should be marked");
        assertTrue(vault.fillNonce(12), "User3 fill nonce should be marked");
        
        // Verify recipients received assets
        assertEq(recipient1.balance, fulfil1, "Recipient1 should have ETH");
        assertEq(token.balanceOf(recipient2), fulfil2, "Recipient2 should have token");
        assertEq(token2.balanceOf(recipient3), fulfil3, "Recipient3 should have token2");
    }
    
    /// @notice Test multiple deposits from same user with different nonces
    function test_MultipleDeposits_SameUser_DifferentNonces() public {
        address recipient = makeAddr("recipient");
        uint256 expiry = _futureTimestamp(1 hours);
        
        // First deposit
        uint256 deposit1 = 1 ether;
        Vault.Request memory request1 = _createRequestForUser(
            bytes32(0),
            deposit1,
            bytes32(0),
            0.9 ether,
            USER1_PRIVATE_KEY,
            recipient,
            100,
            expiry
        );
        bytes memory sig1 = sigHelper.signRequest(request1, USER1_PRIVATE_KEY);
        
        vm.prank(solver);
        vault.deposit{value: deposit1}(request1, sig1, 0);
        
        // Second deposit (different nonce)
        uint256 deposit2 = 2 ether;
        Vault.Request memory request2 = _createRequestForUser(
            bytes32(0),
            deposit2,
            bytes32(0),
            1.8 ether,
            USER1_PRIVATE_KEY,
            recipient,
            101,
            expiry
        );
        bytes memory sig2 = sigHelper.signRequest(request2, USER1_PRIVATE_KEY);
        
        vm.prank(solver);
        vault.deposit{value: deposit2}(request2, sig2, 0);
        
        // Third deposit (different nonce)
        uint256 deposit3 = 0.5 ether;
        Vault.Request memory request3 = _createRequestForUser(
            bytes32(0),
            deposit3,
            bytes32(0),
            0.45 ether,
            USER1_PRIVATE_KEY,
            recipient,
            102,
            expiry
        );
        bytes memory sig3 = sigHelper.signRequest(request3, USER1_PRIVATE_KEY);
        
        vm.prank(solver);
        vault.deposit{value: deposit3}(request3, sig3, 0);
        
        // Verify all deposits
        assertTrue(vault.depositNonce(100), "First deposit nonce should be marked");
        assertTrue(vault.depositNonce(101), "Second deposit nonce should be marked");
        assertTrue(vault.depositNonce(102), "Third deposit nonce should be marked");
        
        // Verify total vault balance
        assertEq(address(vault).balance, deposit1 + deposit2 + deposit3, "Vault should hold all deposits");
    }

    // Flow 3: Upgrade with State Preservation
    
    /// @notice Test upgrade preserves all state (nonces, request states, balances)
    function test_Upgrade_PreservesState() public {
        // Setup initial state
        
        // Make some deposits
        uint256 deposit1 = 1 ether;
        Vault.Request memory request1 = _createRequestForUser(
            bytes32(0),
            deposit1,
            bytes32(0),
            0.9 ether,
            USER1_PRIVATE_KEY,
            solver,
            200,
            _futureTimestamp(1 hours)
        );
        bytes memory sig1 = sigHelper.signRequest(request1, USER1_PRIVATE_KEY);
        
        vm.prank(solver);
        vault.deposit{value: deposit1}(request1, sig1, 0);
        
        // Make another deposit with ERC20
        uint256 deposit2 = 500 * 10 ** 18;
        Vault.Request memory request2 = _createRequestForUser(
            bytes32(uint256(uint160(address(token)))),
            deposit2,
            bytes32(uint256(uint160(address(token)))),
            480 * 10 ** 18,
            USER2_PRIVATE_KEY,
            solver,
            201,
            _futureTimestamp(1 hours)
        );
        bytes memory sig2 = sigHelper.signRequest(request2, USER2_PRIVATE_KEY);
        
        vm.prank(_getAddress(USER2_PRIVATE_KEY));
        token.approve(address(vault), deposit2);
        
        vm.prank(solver);
        vault.deposit(request2, sig2, 0);
        
        // Fulfil first request
        vm.prank(solver);
        vault.fulfil{value: 0.9 ether}(request1, sig1);
        
        // Record state before upgrade
        bytes32 requestHash1 = sigHelper.hashRequest(request1);
        bytes32 signedMessageHash1 = sigHelper.getEip191Hash(requestHash1);
        
        bytes32 requestHash2 = sigHelper.hashRequest(request2);
        bytes32 signedMessageHash2 = sigHelper.getEip191Hash(requestHash2);
        
        uint256 vaultEthBefore = address(vault).balance;
        uint256 vaultTokenBefore = token.balanceOf(address(vault));
        address winningSolverBefore = vault.winningSolver(signedMessageHash1);
        Vault.RFFState state1Before = vault.requestState(signedMessageHash1);
        Vault.RFFState state2Before = vault.requestState(signedMessageHash2);
        
        // Upgrade to new implementation
        
        Vault newImplementation = new Vault();
        
        vm.prank(admin);
        vault.upgradeToAndCall(address(newImplementation), "");
        
        // Verify state preserved after upgrade
        
        // Nonces should be preserved
        assertTrue(vault.depositNonce(200), "Deposit nonce 200 should be preserved");
        assertTrue(vault.depositNonce(201), "Deposit nonce 201 should be preserved");
        assertTrue(vault.fillNonce(200), "Fill nonce 200 should be preserved");
        
        // Request states should be preserved
        assertEq(
            uint256(vault.requestState(signedMessageHash1)),
            uint256(state1Before),
            "Request 1 state should be preserved"
        );
        assertEq(
            uint256(vault.requestState(signedMessageHash2)),
            uint256(state2Before),
            "Request 2 state should be preserved"
        );
        
        // Winning solver should be preserved
        assertEq(
            vault.winningSolver(signedMessageHash1),
            winningSolverBefore,
            "Winning solver should be preserved"
        );
        
        // Balances should be preserved
        assertEq(address(vault).balance, vaultEthBefore, "ETH balance should be preserved");
        assertEq(token.balanceOf(address(vault)), vaultTokenBefore, "Token balance should be preserved");
        
        // Roles should be preserved
        assertTrue(vault.hasRole(DEFAULT_ADMIN_ROLE, admin), "Admin role should be preserved");
        assertTrue(vault.hasRole(UPGRADER_ROLE, admin), "Upgrader role should be preserved");
        assertTrue(
            vault.hasRole(SETTLEMENT_VERIFIER_ROLE, _getAddress(VERIFIER_PRIVATE_KEY)),
            "Verifier role should be preserved"
        );
    }
    
    /// @notice Test operations continue to work after upgrade
    function test_Upgrade_ContinuesOperations() public {
        // Make initial deposit
        
        uint256 deposit1 = 1 ether;
        Vault.Request memory request1 = _createRequestForUser(
            bytes32(0),
            deposit1,
            bytes32(0),
            0.9 ether,
            USER1_PRIVATE_KEY,
            solver,
            300,
            _futureTimestamp(1 hours)
        );
        bytes memory sig1 = sigHelper.signRequest(request1, USER1_PRIVATE_KEY);
        
        vm.prank(solver);
        vault.deposit{value: deposit1}(request1, sig1, 0);
        
        // Upgrade
        
        Vault newImplementation = new Vault();
        vm.prank(admin);
        vault.upgradeToAndCall(address(newImplementation), "");
        
        // Continue operations after upgrade
        
        // Fulfil the pre-upgrade request
        vm.prank(solver);
        vault.fulfil{value: 0.9 ether}(request1, sig1);
        
        assertTrue(vault.fillNonce(300), "Fill nonce should work after upgrade");
        
        // Make new deposit after upgrade
        uint256 deposit2 = 2 ether;
        Vault.Request memory request2 = _createRequestForUser(
            bytes32(0),
            deposit2,
            bytes32(0),
            1.8 ether,
            USER2_PRIVATE_KEY,
            solver,
            301,
            _futureTimestamp(1 hours)
        );
        bytes memory sig2 = sigHelper.signRequest(request2, USER2_PRIVATE_KEY);
        
        vm.prank(solver);
        vault.deposit{value: deposit2}(request2, sig2, 0);
        
        assertTrue(vault.depositNonce(301), "New deposit should work after upgrade");
        
        // Settle after upgrade
        uint256 settleNonce = 500;
        Vault.SettleData memory settleData = _createSimpleSettleData(
            solver,
            address(0),
            0.5 ether,
            settleNonce
        );
        bytes memory settleSig = _signSettleData(settleData);
        
        vm.prank(user);
        vault.settle(settleData, settleSig);
        
        assertTrue(vault.settleNonce(settleNonce), "Settle should work after upgrade");
    }
    
    /// @notice Test upgrade with multiple deposits and partial fulfilments
    function test_Upgrade_ComplexState() public {
        // Create complex state with multiple operations
        
        address user1 = _getAddress(USER1_PRIVATE_KEY);
        address user2 = _getAddress(USER2_PRIVATE_KEY);
        address user3 = _getAddress(USER3_PRIVATE_KEY);
        
        uint256 expiry = _futureTimestamp(1 hours);
        
        // User 1: Deposit and fulfil
        Vault.Request memory req1 = _createRequestForUser(
            bytes32(0), 1 ether, bytes32(0), 0.9 ether,
            USER1_PRIVATE_KEY, user1, 400, expiry
        );
        bytes memory sig1 = sigHelper.signRequest(req1, USER1_PRIVATE_KEY);
        vm.prank(solver);
        vault.deposit{value: 1 ether}(req1, sig1, 0);
        vm.prank(solver);
        vault.fulfil{value: 0.9 ether}(req1, sig1);
        
        // User 2: Deposit only (not fulfilled)
        Vault.Request memory req2 = _createRequestForUser(
            bytes32(uint256(uint160(address(token)))),
            1000 * 10 ** 18,
            bytes32(uint256(uint160(address(token)))),
            900 * 10 ** 18,
            USER2_PRIVATE_KEY, user2, 401, expiry
        );
        bytes memory sig2 = sigHelper.signRequest(req2, USER2_PRIVATE_KEY);
        vm.prank(user2);
        token.approve(address(vault), 1000 * 10 ** 18);
        vm.prank(solver);
        vault.deposit(req2, sig2, 0);
        
        // User 3: Deposit only
        Vault.Request memory req3 = _createRequestForUser(
            bytes32(0), 2 ether, bytes32(0), 1.8 ether,
            USER3_PRIVATE_KEY, user3, 402, expiry
        );
        bytes memory sig3 = sigHelper.signRequest(req3, USER3_PRIVATE_KEY);
        vm.prank(solver);
        vault.deposit{value: 2 ether}(req3, sig3, 0);
        
        // Do a settlement
        Vault.SettleData memory settleData = _createSimpleSettleData(
            solver, address(0), 0.3 ether, 600
        );
        bytes memory settleSig = _signSettleData(settleData);
        vm.prank(user);
        vault.settle(settleData, settleSig);
        
        // Record all state
        bytes32 hash1 = sigHelper.getEip191Hash(sigHelper.hashRequest(req1));
        bytes32 hash2 = sigHelper.getEip191Hash(sigHelper.hashRequest(req2));
        bytes32 hash3 = sigHelper.getEip191Hash(sigHelper.hashRequest(req3));
        
        Vault.RFFState state1Before = vault.requestState(hash1);
        Vault.RFFState state2Before = vault.requestState(hash2);
        Vault.RFFState state3Before = vault.requestState(hash3);
        
        uint256 ethBefore = address(vault).balance;
        uint256 tokenBefore = token.balanceOf(address(vault));
        
        // Upgrade
        
        Vault newImpl = new Vault();
        vm.prank(admin);
        vault.upgradeToAndCall(address(newImpl), "");
        
        // Verify all state preserved
        
        assertEq(uint256(vault.requestState(hash1)), uint256(state1Before), "State 1 preserved");
        assertEq(uint256(vault.requestState(hash2)), uint256(state2Before), "State 2 preserved");
        assertEq(uint256(vault.requestState(hash3)), uint256(state3Before), "State 3 preserved");
        
        assertEq(address(vault).balance, ethBefore, "ETH preserved");
        assertEq(token.balanceOf(address(vault)), tokenBefore, "Token preserved");
        
        assertTrue(vault.depositNonce(400), "Deposit nonce 400 preserved");
        assertTrue(vault.depositNonce(401), "Deposit nonce 401 preserved");
        assertTrue(vault.depositNonce(402), "Deposit nonce 402 preserved");
        assertTrue(vault.fillNonce(400), "Fill nonce 400 preserved");
        assertTrue(vault.settleNonce(600), "Settle nonce 600 preserved");
        
        // Continue operations
        
        // Fulfil user 2's pending request
        token.mint(solver, 900 * 10 ** 18);
        vm.prank(solver);
        token.approve(address(vault), 900 * 10 ** 18);
        vm.prank(solver);
        vault.fulfil(req2, sig2);
        
        assertTrue(vault.fillNonce(401), "Fill nonce 401 should work");
        
        // Fulfil user 3's pending request
        vm.prank(solver);
        vault.fulfil{value: 1.8 ether}(req3, sig3);
        
        assertTrue(vault.fillNonce(402), "Fill nonce 402 should work");
    }
}
