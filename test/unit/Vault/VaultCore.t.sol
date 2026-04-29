// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

// Imports
import {BaseVaultTest} from "../../BaseVaultTest.t.sol";
import {SignatureHelper} from "../../helpers/SignatureHelper.sol";
import {Vault} from "../../../contracts/Vault.sol";
import {MockFeeOnTransfer} from "../../mocks/MockFeeOnTransfer.sol";

// VaultCoreTest - Core Functionality Tests for Vault.sol
// @title VaultCoreTest
// @notice Core unit tests covering deposit(), fulfil(), settle(), and extractAddress()
// @dev Tests core functionality with success and revert paths
contract VaultCoreTest is BaseVaultTest {
    // State Variables

    MockFeeOnTransfer public feeToken;
    SignatureHelper public sigHelper;

    // Test private keys for signature generation
    uint256 public constant USER_PRIVATE_KEY = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
    uint256 public constant VERIFIER_PRIVATE_KEY = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321;

    // Setup

    function setUp() public virtual override {
        super.setUp();

        // Deploy signature helper
        sigHelper = new SignatureHelper();

        // Deploy fee-on-transfer token
        feeToken = new MockFeeOnTransfer("Fee Token", "FEE");

        // Get the user address from private key and mint tokens to it
        address requester = _getAddress(USER_PRIVATE_KEY);
        token.mint(requester, 1_000_000 * 10 ** 18);
        token2.mint(requester, 1_000_000 * 10 ** 18);
        feeToken.mint(requester, 1_000_000 * 10 ** 18);

        // Fund the requester with ETH
        vm.deal(requester, 100 ether);

        // Get the verifier address from private key and grant role
        address verifierFromKey = _getAddress(VERIFIER_PRIVATE_KEY);
        vm.prank(admin);
        vault.grantRole(SETTLEMENT_VERIFIER_ROLE, verifierFromKey);

        // Fund the verifier
        vm.deal(verifierFromKey, 100 ether);

        // Set fee to 1% for testing
        feeToken.setFeePercent(100);
    }

    // Helper Functions

    /// @notice Gets the address derived from a private key
    function _getAddress(uint256 privateKey) internal pure returns (address) {
        return vm.addr(privateKey);
    }

    /// @notice Creates a request with a specific user address from private key
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
        sources[0] = _createSourcePair(Vault.Universe.ETHEREUM, block.chainid, sourceToken, sourceValue, 0);

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

    // deposit() Tests - Success Cases

    /// @notice Test depositing ETH with valid signature
    function test_Deposit_ETH_Success() public {
        uint256 depositAmount = 1 ether;
        uint256 nonce = 1;
        uint256 expiry = _futureTimestamp(1 hours);

        // Create request with user's derived address
        Vault.Request memory request = _createRequestForUser(
            bytes32(0), // ETH
            depositAmount,
            bytes32(0), // ETH destination
            depositAmount,
            USER_PRIVATE_KEY,
            solver,
            nonce,
            expiry
        );

        // Generate signature
        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Get request hash for event verification
        bytes32 requestHash = sigHelper.hashRequest(request);

        // Expect Deposit event
        vm.expectEmit(true, true, false, false);
        emit Vault.Deposit(requestHash, _getAddress(USER_PRIVATE_KEY));

        // Execute deposit as relayer (anyone can call)
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, signature, 0);

        // Verify state changes
        assertTrue(vault.depositNonce(nonce), "Nonce should be marked as used");

        bytes32 signedMessageHash = sigHelper.getEip191Hash(requestHash);
        assertEq(
            uint256(vault.requestState(signedMessageHash)),
            uint256(Vault.RFFState.DEPOSITED),
            "Request state should be DEPOSITED"
        );
    }

    /// @notice Test depositing ERC20 with valid signature
    function test_Deposit_ERC20_Success() public {
        uint256 depositAmount = 1000 * 10 ** 18;
        uint256 nonce = 2;
        uint256 expiry = _futureTimestamp(1 hours);

        address requester = _getAddress(USER_PRIVATE_KEY);

        // Create request
        Vault.Request memory request = _createRequestForUser(
            bytes32(uint256(uint160(address(token)))), // ERC20 token
            depositAmount,
            bytes32(uint256(uint160(address(token)))), // Same token as destination
            depositAmount,
            USER_PRIVATE_KEY,
            solver,
            nonce,
            expiry
        );

        // Generate signature
        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Approve tokens
        vm.prank(requester);
        token.approve(address(vault), depositAmount);

        // Get request hash
        bytes32 requestHash = sigHelper.hashRequest(request);

        // Expect Deposit event
        vm.expectEmit(true, true, false, false);
        emit Vault.Deposit(requestHash, requester);

        // Execute deposit
        vm.prank(solver);
        vault.deposit(request, signature, 0);

        // Verify state changes
        assertTrue(vault.depositNonce(nonce), "Nonce should be marked as used");

        bytes32 signedMessageHash = sigHelper.getEip191Hash(requestHash);
        assertEq(
            uint256(vault.requestState(signedMessageHash)),
            uint256(Vault.RFFState.DEPOSITED),
            "Request state should be DEPOSITED"
        );

        // Verify token transfer
        assertEq(token.balanceOf(address(vault)), depositAmount, "Vault should have deposited tokens");
    }

    // deposit() Tests - Revert Cases

    /// @notice Test deposit reverts with invalid signature
    function test_Deposit_InvalidSignature_Reverts() public {
        uint256 depositAmount = 1 ether;
        uint256 nonce = 3;
        uint256 expiry = _futureTimestamp(1 hours);

        Vault.Request memory request = _createRequestForUser(
            bytes32(0), depositAmount, bytes32(0), depositAmount, USER_PRIVATE_KEY, solver, nonce, expiry
        );

        // Sign with wrong key
        uint256 wrongKey = 0x9999999999999999999999999999999999999999999999999999999999999999;
        bytes memory wrongSignature = sigHelper.signRequest(request, wrongKey);

        vm.expectRevert("Vault: Invalid signature or from");
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, wrongSignature, 0);
    }

    /// @notice Test deposit reverts with wrong chainID
    function test_Deposit_WrongChainID_Reverts() public {
        uint256 depositAmount = 1 ether;
        uint256 nonce = 4;
        uint256 expiry = _futureTimestamp(1 hours);

        // Create request with wrong chainID
        Vault.SourcePair[] memory sources = new Vault.SourcePair[](1);
        sources[0] = _createSourcePair(
            Vault.Universe.ETHEREUM,
            999999, // Wrong chainID
            bytes32(0),
            depositAmount,
            0
        );

        Vault.DestinationPair[] memory destinations = new Vault.DestinationPair[](1);
        destinations[0] = _createDestinationPair(bytes32(0), depositAmount);

        address requester = _getAddress(USER_PRIVATE_KEY);
        Vault.Party[] memory parties = new Vault.Party[](1);
        parties[0] = _createParty(Vault.Universe.ETHEREUM, bytes32(uint256(uint160(requester))));

        Vault.Request memory request = _createRequest(
            sources,
            Vault.Universe.ETHEREUM,
            block.chainid,
            bytes32(uint256(uint160(solver))),
            destinations,
            nonce,
            expiry,
            parties
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        vm.expectRevert("Vault: Chain ID mismatch");
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, signature, 0);
    }

    /// @notice Test deposit reverts with wrong universe (not ETHEREUM)
    function test_Deposit_WrongUniverse_Reverts() public {
        uint256 depositAmount = 1 ether;
        uint256 nonce = 5;
        uint256 expiry = _futureTimestamp(1 hours);

        // Create request with wrong universe
        Vault.SourcePair[] memory sources = new Vault.SourcePair[](1);
        sources[0] = Vault.SourcePair({
            universe: Vault.Universe.SOLANA, // Wrong universe
            chainID: block.chainid,
            contractAddress: bytes32(0),
            value: depositAmount,
            fee: 0
        });

        Vault.DestinationPair[] memory destinations = new Vault.DestinationPair[](1);
        destinations[0] = _createDestinationPair(bytes32(0), depositAmount);

        address requester = _getAddress(USER_PRIVATE_KEY);
        Vault.Party[] memory parties = new Vault.Party[](1);
        parties[0] = _createParty(Vault.Universe.ETHEREUM, bytes32(uint256(uint160(requester))));

        Vault.Request memory request = _createRequest(
            sources,
            Vault.Universe.ETHEREUM,
            block.chainid,
            bytes32(uint256(uint160(solver))),
            destinations,
            nonce,
            expiry,
            parties
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        vm.expectRevert("Vault: Universe mismatch");
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, signature, 0);
    }

    /// @notice Test deposit reverts when nonce already used (replay protection)
    function test_Deposit_NonceAlreadyUsed_Reverts() public {
        uint256 depositAmount = 1 ether;
        uint256 nonce = 6;
        uint256 expiry = _futureTimestamp(1 hours);

        Vault.Request memory request = _createRequestForUser(
            bytes32(0), depositAmount, bytes32(0), depositAmount, USER_PRIVATE_KEY, solver, nonce, expiry
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // First deposit should succeed
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, signature, 0);

        // Second deposit with same nonce should revert
        vm.expectRevert("Vault: Nonce already used");
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, signature, 0);
    }

    /// @notice Test deposit reverts when request is expired
    function test_Deposit_ExpiredRequest_Reverts() public {
        // Warp to a time well in the future first to avoid underflow
        vm.warp(2 hours);

        uint256 depositAmount = 1 ether;
        uint256 nonce = 7;
        uint256 expiry = block.timestamp - 1 hours; // Expired 1 hour ago

        Vault.Request memory request = _createRequestForUser(
            bytes32(0), depositAmount, bytes32(0), depositAmount, USER_PRIVATE_KEY, solver, nonce, expiry
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        vm.expectRevert("Vault: Request expired");
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, signature, 0);
    }

    /// @notice Test deposit reverts when ETH value doesn't match
    function test_Deposit_ValueMismatch_Reverts() public {
        uint256 depositAmount = 1 ether;
        uint256 nonce = 8;
        uint256 expiry = _futureTimestamp(1 hours);

        Vault.Request memory request = _createRequestForUser(
            bytes32(0), depositAmount, bytes32(0), depositAmount, USER_PRIVATE_KEY, solver, nonce, expiry
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Send wrong amount of ETH
        vm.expectRevert("Vault: Value mismatch");
        vm.prank(solver);
        vault.deposit{value: depositAmount - 0.1 ether}(request, signature, 0);
    }

    /// @notice Test deposit reverts with fee-on-transfer token (balance delta mismatch)
    function test_Deposit_FeeOnTransferToken_Reverts() public {
        uint256 depositAmount = 1000 * 10 ** 18;
        uint256 nonce = 9;
        uint256 expiry = _futureTimestamp(1 hours);

        address requester = _getAddress(USER_PRIVATE_KEY);

        Vault.Request memory request = _createRequestForUser(
            bytes32(uint256(uint160(address(feeToken)))),
            depositAmount,
            bytes32(uint256(uint160(address(feeToken)))),
            depositAmount,
            USER_PRIVATE_KEY,
            solver,
            nonce,
            expiry
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Approve tokens
        vm.prank(requester);
        feeToken.approve(address(vault), depositAmount);

        // Should revert because fee-on-transfer token causes balance delta mismatch
        vm.expectRevert("Vault: failed to transfer the source amount");
        vm.prank(solver);
        vault.deposit(request, signature, 0);
    }

    // fulfil() Tests - Success Cases

    /// @notice Test fulfilling with ETH transfer
    function test_Fulfil_ETH_Success() public {
        uint256 depositAmount = 1 ether;
        uint256 fulfilAmount = 1 ether;
        uint256 nonce = 10;
        uint256 expiry = _futureTimestamp(1 hours);

        address requester = _getAddress(USER_PRIVATE_KEY);

        // First deposit
        Vault.Request memory request = _createRequestForUser(
            bytes32(0),
            depositAmount,
            bytes32(0),
            fulfilAmount,
            USER_PRIVATE_KEY,
            requester, // Recipient is the requester
            nonce,
            expiry
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Deposit first
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, signature, 0);

        // Record recipient balance before fulfilment
        uint256 recipientBalanceBefore = requester.balance;

        bytes32 requestHash = sigHelper.hashRequest(request);

        // Expect Fulfilment event
        vm.expectEmit(true, true, true, false);
        emit Vault.Fulfilment(requestHash, requester, solver);

        // Fulfill as solver
        vm.prank(solver);
        vault.fulfil{value: fulfilAmount}(request, signature);

        // Verify state changes
        assertTrue(vault.fillNonce(nonce), "Fill nonce should be marked as used");

        bytes32 signedMessageHash = sigHelper.getEip191Hash(requestHash);
        assertEq(
            uint256(vault.requestState(signedMessageHash)),
            uint256(Vault.RFFState.FULFILLED),
            "Request state should be FULFILLED"
        );
        assertEq(vault.winningSolver(signedMessageHash), solver, "Winning solver should be recorded");

        // Verify ETH transfer
        assertEq(requester.balance - recipientBalanceBefore, fulfilAmount, "Recipient should receive ETH");
    }

    /// @notice Test fulfilling with ERC20 transfer
    function test_Fulfil_ERC20_Success() public {
        uint256 depositAmount = 1000 * 10 ** 18;
        uint256 fulfilAmount = 1000 * 10 ** 18;
        uint256 nonce = 11;
        uint256 expiry = _futureTimestamp(1 hours);

        address requester = _getAddress(USER_PRIVATE_KEY);

        // Create request
        Vault.Request memory request = _createRequestForUser(
            bytes32(uint256(uint160(address(token)))),
            depositAmount,
            bytes32(uint256(uint160(address(token)))),
            fulfilAmount,
            USER_PRIVATE_KEY,
            requester,
            nonce,
            expiry
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Approve and deposit
        vm.prank(requester);
        token.approve(address(vault), depositAmount);

        vm.prank(solver);
        vault.deposit(request, signature, 0);

        // Approve solver's tokens for fulfilment
        vm.prank(solver);
        token.approve(address(vault), fulfilAmount);

        uint256 recipientBalanceBefore = token.balanceOf(requester);

        // Fulfill
        vm.prank(solver);
        vault.fulfil(request, signature);

        // Verify token transfer
        assertEq(token.balanceOf(requester) - recipientBalanceBefore, fulfilAmount, "Recipient should receive tokens");
    }

    /// @notice Test fulfilling with multiple tokens
    function test_Fulfil_MultipleTokens_success() public {
        uint256 nonce = 12;
        uint256 expiry = _futureTimestamp(1 hours);

        address requester = _getAddress(USER_PRIVATE_KEY);

        // Create request with multiple destinations
        Vault.SourcePair[] memory sources = new Vault.SourcePair[](1);
        sources[0] = _createSourcePair(Vault.Universe.ETHEREUM, block.chainid, bytes32(0), 2 ether, 0);

        Vault.DestinationPair[] memory destinations = new Vault.DestinationPair[](2);
        destinations[0] = _createDestinationPair(bytes32(0), 0.5 ether);
        // Use actual token address for second destination
        destinations[1] = _createDestinationPair(bytes32(uint256(uint160(address(token)))), 0.5 ether);

        Vault.Party[] memory parties = new Vault.Party[](1);
        parties[0] = _createParty(Vault.Universe.ETHEREUM, bytes32(uint256(uint160(requester))));

        Vault.Request memory request = _createRequest(
            sources,
            Vault.Universe.ETHEREUM,
            block.chainid,
            bytes32(uint256(uint160(requester))), // Both destinations go to requester
            destinations,
            nonce,
            expiry,
            parties
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Deposit
        vm.prank(solver);
        vault.deposit{value: 2 ether}(request, signature, 0);

        // Fund solver with tokens for second destination
        token.mint(solver, 1 ether);
        vm.prank(solver);
        token.approve(address(vault), 0.5 ether);

        uint256 recipientEthBalanceBefore = requester.balance;
        uint256 recipientTokenBalanceBefore = token.balanceOf(requester);

        // Fulfill with enough ETH for both destinations
        vm.prank(solver);
        vault.fulfil{value: 0.5 ether}(request, signature);

        // Verify transfers - both destinations go to requester
        assertEq(requester.balance - recipientEthBalanceBefore, 0.5 ether, "Recipient should receive ETH");
        assertEq(token.balanceOf(requester) - recipientTokenBalanceBefore, 0.5 ether, "Recipient should receive tokens");
    }

    /// @notice Test excess ETH is refunded to solver
    function test_Fulfil_ExcessETHRefunded_Success() public {
        uint256 depositAmount = 1 ether;
        uint256 fulfilAmount = 0.5 ether;
        uint256 excessAmount = 0.3 ether;
        uint256 nonce = 13;
        uint256 expiry = _futureTimestamp(1 hours);

        address requester = _getAddress(USER_PRIVATE_KEY);

        Vault.Request memory request = _createRequestForUser(
            bytes32(0), depositAmount, bytes32(0), fulfilAmount, USER_PRIVATE_KEY, requester, nonce, expiry
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Deposit
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, signature, 0);

        uint256 solverBalanceBefore = solver.balance;

        vm.prank(solver);
        vault.fulfil{value: fulfilAmount + excessAmount}(request, signature);

        // Verify excess is refunded
        uint256 expectedBalance = solverBalanceBefore - fulfilAmount; // Spent fulfilAmount, got excess back
        assertApproxEqAbs(solver.balance, expectedBalance, 0.01 ether, "Solver should get excess ETH refunded");
    }

    // fulfil() Tests - Revert Cases

    /// @notice Test fulfil reverts with invalid signature
    function test_Fulfil_InvalidSignature_Reverts() public {
        uint256 depositAmount = 1 ether;
        uint256 fulfilAmount = 1 ether;
        uint256 nonce = 14;
        uint256 expiry = _futureTimestamp(1 hours);

        address requester = _getAddress(USER_PRIVATE_KEY);

        Vault.Request memory request = _createRequestForUser(
            bytes32(0), depositAmount, bytes32(0), fulfilAmount, USER_PRIVATE_KEY, requester, nonce, expiry
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Deposit first
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, signature, 0);

        // Try to fulfil with wrong signature
        uint256 wrongKey = 0x9999999999999999999999999999999999999999999999999999999999999999;
        bytes memory wrongSignature = sigHelper.signRequest(request, wrongKey);

        vm.expectRevert("Vault: Invalid signature or from");
        vm.prank(solver);
        vault.fulfil{value: fulfilAmount}(request, wrongSignature);
    }

    /// @notice Test fulfil reverts with wrong destination chainID
    function test_Fulfil_WrongDestinationChainID_Reverts() public {
        uint256 depositAmount = 1 ether;
        uint256 fulfilAmount = 1 ether;
        uint256 nonce = 15;
        uint256 expiry = _futureTimestamp(1 hours);

        address requester = _getAddress(USER_PRIVATE_KEY);

        // Create request with wrong destination chainID
        Vault.SourcePair[] memory sources = new Vault.SourcePair[](1);
        sources[0] = _createSourcePair(Vault.Universe.ETHEREUM, block.chainid, bytes32(0), depositAmount, 0);

        Vault.DestinationPair[] memory destinations = new Vault.DestinationPair[](1);
        destinations[0] = _createDestinationPair(bytes32(0), fulfilAmount);

        Vault.Party[] memory parties = new Vault.Party[](1);
        parties[0] = _createParty(Vault.Universe.ETHEREUM, bytes32(uint256(uint160(requester))));

        Vault.Request memory request = _createRequest(
            sources,
            Vault.Universe.ETHEREUM,
            999999, // Wrong destination chainID
            bytes32(uint256(uint160(requester))),
            destinations,
            nonce,
            expiry,
            parties
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Deposit first (deposit uses source chainID which is correct)
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, signature, 0);

        vm.expectRevert("Vault: Chain ID mismatch");
        vm.prank(solver);
        vault.fulfil{value: fulfilAmount}(request, signature);
    }

    /// @notice Test fulfil reverts with wrong destination universe
    function test_Fulfil_WrongDestinationUniverse_Reverts() public {
        uint256 depositAmount = 1 ether;
        uint256 fulfilAmount = 1 ether;
        uint256 nonce = 16;
        uint256 expiry = _futureTimestamp(1 hours);

        address requester = _getAddress(USER_PRIVATE_KEY);

        Vault.SourcePair[] memory sources = new Vault.SourcePair[](1);
        sources[0] = _createSourcePair(Vault.Universe.ETHEREUM, block.chainid, bytes32(0), depositAmount, 0);

        Vault.DestinationPair[] memory destinations = new Vault.DestinationPair[](1);
        destinations[0] = _createDestinationPair(bytes32(0), fulfilAmount);

        Vault.Party[] memory parties = new Vault.Party[](1);
        parties[0] = _createParty(Vault.Universe.ETHEREUM, bytes32(uint256(uint160(requester))));

        // Wrong destination universe
        Vault.Request memory request = _createRequest(
            sources,
            Vault.Universe.SOLANA, // Wrong universe
            block.chainid,
            bytes32(uint256(uint160(requester))),
            destinations,
            nonce,
            expiry,
            parties
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Deposit first
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, signature, 0);

        vm.expectRevert("Vault: Universe mismatch");
        vm.prank(solver);
        vault.fulfil{value: fulfilAmount}(request, signature);
    }

    /// @notice Test fulfil reverts when nonce already used
    function test_Fulfil_NonceAlreadyUsed_Reverts() public {
        uint256 depositAmount = 1 ether;
        uint256 fulfilAmount = 1 ether;
        uint256 nonce = 17;
        uint256 expiry = _futureTimestamp(1 hours);

        address requester = _getAddress(USER_PRIVATE_KEY);

        Vault.Request memory request = _createRequestForUser(
            bytes32(0), depositAmount, bytes32(0), fulfilAmount, USER_PRIVATE_KEY, requester, nonce, expiry
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Deposit and fulfil first time
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, signature, 0);

        vm.prank(solver);
        vault.fulfil{value: fulfilAmount}(request, signature);

        // Try to fulfil again with same nonce
        vm.expectRevert("Vault: Nonce already used");
        vm.prank(solver);
        vault.fulfil{value: fulfilAmount}(request, signature);
    }

    /// @notice Test fulfil reverts when request is expired
    function test_Fulfil_ExpiredRequest_Reverts() public {
        uint256 depositAmount = 1 ether;
        uint256 fulfilAmount = 1 ether;
        uint256 nonce = 18;

        // Warp to future first
        vm.warp(block.timestamp + 2 hours);
        uint256 expiry = _pastTimestamp(1 hours); // Expired 1 hour ago

        address requester = _getAddress(USER_PRIVATE_KEY);

        Vault.Request memory request = _createRequestForUser(
            bytes32(0), depositAmount, bytes32(0), fulfilAmount, USER_PRIVATE_KEY, requester, nonce, expiry
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Note: Can't deposit because request is already expired
        // But we can test the fulfil revert directly
        vm.expectRevert("Vault: Request expired");
        vm.prank(solver);
        vault.fulfil{value: fulfilAmount}(request, signature);
    }

    /// @notice Test fulfil reverts with insufficient ETH for destinations
    function test_Fulfil_InsufficientETH_Reverts() public {
        uint256 depositAmount = 1 ether;
        uint256 fulfilAmount = 1 ether;
        uint256 nonce = 19;
        uint256 expiry = _futureTimestamp(1 hours);

        address requester = _getAddress(USER_PRIVATE_KEY);

        Vault.Request memory request = _createRequestForUser(
            bytes32(0), depositAmount, bytes32(0), fulfilAmount, USER_PRIVATE_KEY, requester, nonce, expiry
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Deposit
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, signature, 0);

        // Try to fulfil with insufficient ETH
        vm.expectRevert("Vault: Value mismatch");
        vm.prank(solver);
        vault.fulfil{value: fulfilAmount - 0.1 ether}(request, signature);
    }

    /// @notice Test fulfil reverts with fee-on-transfer token
    function test_Fulfil_FeeOnTransferToken_Reverts() public {
        uint256 depositAmount = 1000 * 10 ** 18;
        uint256 fulfilAmount = 1000 * 10 ** 18;
        uint256 nonce = 20;
        uint256 expiry = _futureTimestamp(1 hours);

        address requester = _getAddress(USER_PRIVATE_KEY);

        // Use regular token for source (deposit) and feeToken for destination (fulfil)
        Vault.Request memory request = _createRequestForUser(
            bytes32(uint256(uint160(address(token)))), // Regular token for deposit
            depositAmount,
            bytes32(uint256(uint160(address(feeToken)))), // Fee token for fulfil
            fulfilAmount,
            USER_PRIVATE_KEY,
            requester,
            nonce,
            expiry
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Approve and deposit with regular token
        vm.prank(requester);
        token.approve(address(vault), depositAmount);

        vm.prank(solver);
        vault.deposit(request, signature, 0);

        // Mint fee tokens to solver for fulfilment
        feeToken.mint(solver, fulfilAmount);

        // Approve solver's fee tokens
        vm.prank(solver);
        feeToken.approve(address(vault), fulfilAmount);

        // Should revert due to fee-on-transfer
        vm.expectRevert("Vault: failed to transfer the destination amount");
        vm.prank(solver);
        vault.fulfil(request, signature);
    }

    // settle() Tests - Success Cases

    /// @notice Test settling with single solver and ETH
    function test_Settle_SingleSolverETH_Success() public {
        uint256 settleAmount = 0.5 ether;
        uint256 nonce = 21;

        // Fund vault with ETH
        vm.deal(address(vault), 10 ether);

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
                settleData.vaultAddress,
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

        // Expect Settle event
        vm.expectEmit(true, false, false, false);
        emit Vault.Settle(nonce, settleData.solvers, settleData.contractAddresses, settleData.amounts);

        // Execute settle as anyone
        vm.prank(user);
        vault.settle(settleData, signature);

        // Verify settlement
        assertTrue(vault.settleNonce(nonce), "Settle nonce should be marked as used");
        assertEq(solver.balance - solverBalanceBefore, settleAmount, "Solver should receive ETH");
    }

    /// @notice Test settling with multiple solvers and mixed tokens
    function test_Settle_MultipleSolversMixedTokens_Success() public {
        uint256 nonce = 22;

        // Fund vault
        vm.deal(address(vault), 10 ether);
        token.mint(address(vault), 10000 * 10 ** 18);

        address solver2 = makeAddr("solver2");

        // Create settle data with multiple solvers
        address[] memory solvers = new address[](2);
        solvers[0] = solver;
        solvers[1] = solver2;

        address[] memory contractAddresses = new address[](2);
        contractAddresses[0] = address(0); // ETH
        contractAddresses[1] = address(token); // ERC20

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 0.5 ether;
        amounts[1] = 1000 * 10 ** 18;

        Vault.SettleData memory settleData = _createSettleData(
            Vault.Universe.ETHEREUM, block.chainid, address(vault), solvers, contractAddresses, amounts, nonce
        );

        // Sign with verifier key
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(VERIFIER_PRIVATE_KEY, signatureHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        uint256 solver1BalanceBefore = solver.balance;
        uint256 solver2BalanceBefore = token.balanceOf(solver2);

        vm.prank(user);
        vault.settle(settleData, signature);

        // Verify payments
        assertEq(solver.balance - solver1BalanceBefore, 0.5 ether, "Solver1 should receive ETH");
        assertEq(token.balanceOf(solver2) - solver2BalanceBefore, 1000 * 10 ** 18, "Solver2 should receive tokens");
    }

    // extractAddress() Tests

    /// @notice Test extractAddress returns first ETHEREUM party
    function test_ExtractAddress_ReturnsFirstEthereumParty() public {
        uint256 depositAmount = 1 ether;
        uint256 nonce = 34;
        uint256 expiry = _futureTimestamp(1 hours);

        address requester = _getAddress(USER_PRIVATE_KEY);

        // Create request with multiple parties, first is ETHEREUM
        Vault.SourcePair[] memory sources = new Vault.SourcePair[](1);
        sources[0] = _createSourcePair(Vault.Universe.ETHEREUM, block.chainid, bytes32(0), depositAmount, 0);

        Vault.DestinationPair[] memory destinations = new Vault.DestinationPair[](1);
        destinations[0] = _createDestinationPair(bytes32(0), depositAmount);

        // Multiple parties, first is ETHEREUM
        Vault.Party[] memory parties = new Vault.Party[](3);
        parties[0] = _createParty(Vault.Universe.ETHEREUM, bytes32(uint256(uint160(requester))));
        parties[1] = _createParty(Vault.Universe.SOLANA, bytes32(uint256(uint160(makeAddr("solana")))));
        parties[2] = _createParty(Vault.Universe.FUEL, bytes32(uint256(uint160(makeAddr("fuel")))));

        Vault.Request memory request = _createRequest(
            sources,
            Vault.Universe.ETHEREUM,
            block.chainid,
            bytes32(uint256(uint160(solver))),
            destinations,
            nonce,
            expiry,
            parties
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Should succeed - extracts first ETHEREUM party
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, signature, 0);

        // Verify it used the correct address by checking nonce was marked
        assertTrue(vault.depositNonce(nonce), "Deposit should succeed with first ETHEREUM party");
    }

    /// @notice Test extractAddress reverts when no ETHEREUM parties found
    function test_ExtractAddress_NoEthereumParty_Reverts() public {
        uint256 depositAmount = 1 ether;
        uint256 nonce = 35;
        uint256 expiry = _futureTimestamp(1 hours);

        Vault.SourcePair[] memory sources = new Vault.SourcePair[](1);
        sources[0] = _createSourcePair(Vault.Universe.ETHEREUM, block.chainid, bytes32(0), depositAmount, 0);

        Vault.DestinationPair[] memory destinations = new Vault.DestinationPair[](1);
        destinations[0] = _createDestinationPair(bytes32(0), depositAmount);

        // Only non-ETHEREUM parties
        Vault.Party[] memory parties = new Vault.Party[](2);
        parties[0] = _createParty(Vault.Universe.SOLANA, bytes32(uint256(uint160(makeAddr("solana")))));
        parties[1] = _createParty(Vault.Universe.FUEL, bytes32(uint256(uint160(makeAddr("fuel")))));

        Vault.Request memory request = _createRequest(
            sources,
            Vault.Universe.ETHEREUM,
            block.chainid,
            bytes32(uint256(uint160(solver))),
            destinations,
            nonce,
            expiry,
            parties
        );

        // Sign with any key since it will fail before signature check
        bytes memory signature = hex"123456";

        vm.expectRevert("Vault: Party not found");
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, signature, 0);
    }

    // Edge Case Tests

    /// @notice Test deposit with zero value ETH
    function test_Deposit_ZeroETH_Success() public {
        uint256 nonce = 37;
        uint256 expiry = _futureTimestamp(1 hours);

        Vault.Request memory request = _createRequestForUser(
            bytes32(0),
            0, // Zero value
            bytes32(0),
            0,
            USER_PRIVATE_KEY,
            solver,
            nonce,
            expiry
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        vm.prank(solver);
        vault.deposit{value: 0}(request, signature, 0);

        assertTrue(vault.depositNonce(nonce), "Zero ETH deposit should succeed");
    }

    /// @notice Test fulfil with zero value destination
    function test_Fulfil_ZeroValueDestination_Reverts() public {
        uint256 depositAmount = 1 ether;
        uint256 nonce = 38;
        uint256 expiry = _futureTimestamp(1 hours);

        address requester = _getAddress(USER_PRIVATE_KEY);

        Vault.Request memory request = _createRequestForUser(
            bytes32(0),
            depositAmount,
            bytes32(0),
            0, // Zero destination value
            USER_PRIVATE_KEY,
            requester,
            nonce,
            expiry
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Deposit
        vm.prank(solver);
        vault.deposit{value: depositAmount}(request, signature, 0);

        // Fulfil should revert due to "Vault: Value mismatch" (value > 0 check)
        vm.expectRevert("Vault: Value mismatch");
        vm.prank(solver);
        vault.fulfil(request, signature);
    }

    /// @notice Test settle with zero amount
    function test_Settle_ZeroAmount_Success() public {
        uint256 nonce = 39;

        vm.deal(address(vault), 10 ether);

        Vault.SettleData memory settleData = _createSimpleSettleData(
            solver,
            address(0),
            0, // Zero amount
            nonce
        );

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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(VERIFIER_PRIVATE_KEY, signatureHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        vault.settle(settleData, signature);

        assertTrue(vault.settleNonce(nonce), "Zero amount settle should succeed");
    }

    // deposit() Tests - from == msg.sender (self-deposit) Cases

    /// @notice Helper to create a request with a fee in the source pair
    function _createRequestForUserWithFee(
        bytes32 sourceToken,
        uint256 sourceValue,
        uint256 fee,
        bytes32 destToken,
        uint256 destValue,
        uint256 userPrivateKey,
        address recipient,
        uint256 nonce,
        uint256 expiry
    ) internal view returns (Vault.Request memory) {
        address requester = _getAddress(userPrivateKey);

        Vault.SourcePair[] memory sources = new Vault.SourcePair[](1);
        sources[0] = _createSourcePair(Vault.Universe.ETHEREUM, block.chainid, sourceToken, sourceValue, fee);

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

    /// @notice Test self-deposit of ERC20 with no fee succeeds
    function test_Deposit_ERC20_SelfDeposit_NoFee_Success() public {
        uint256 depositAmount = 1000 * 10 ** 18;
        uint256 nonce = 50;
        uint256 expiry = _futureTimestamp(1 hours);

        address requester = _getAddress(USER_PRIVATE_KEY);

        Vault.Request memory request = _createRequestForUser(
            bytes32(uint256(uint160(address(token)))),
            depositAmount,
            bytes32(uint256(uint160(address(token)))),
            depositAmount,
            USER_PRIVATE_KEY,
            solver,
            nonce,
            expiry
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Approve tokens
        vm.prank(requester);
        token.approve(address(vault), depositAmount);

        bytes32 requestHash = sigHelper.hashRequest(request);

        // Expect Deposit event
        vm.expectEmit(true, true, false, false);
        emit Vault.Deposit(requestHash, requester);

        // Self-deposit: from == msg.sender
        vm.prank(requester);
        vault.deposit(request, signature, 0);

        assertTrue(vault.depositNonce(nonce), "Nonce should be marked as used");
        assertEq(token.balanceOf(address(vault)), depositAmount, "Vault should have deposited tokens");
    }

    /// @notice Test self-deposit of ERC20 with fee reverts
    function test_Deposit_ERC20_SelfDeposit_WithFee_Reverts() public {
        uint256 depositAmount = 1000 * 10 ** 18;
        uint256 fee = 10 * 10 ** 18;
        uint256 nonce = 51;
        uint256 expiry = _futureTimestamp(1 hours);

        address requester = _getAddress(USER_PRIVATE_KEY);

        Vault.Request memory request = _createRequestForUserWithFee(
            bytes32(uint256(uint160(address(token)))),
            depositAmount,
            fee,
            bytes32(uint256(uint160(address(token)))),
            depositAmount,
            USER_PRIVATE_KEY,
            solver,
            nonce,
            expiry
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Approve tokens (value + fee)
        vm.prank(requester);
        token.approve(address(vault), depositAmount + fee);

        // Self-deposit with fee should revert
        vm.expectRevert("Vault: self-fee transfer not allowed");
        vm.prank(requester);
        vault.deposit(request, signature, 0);
    }

    /// @notice Test self-deposit of ETH succeeds (ETH path has no fee logic)
    function test_Deposit_ETH_SelfDeposit_Success() public {
        uint256 depositAmount = 1 ether;
        uint256 nonce = 52;
        uint256 expiry = _futureTimestamp(1 hours);

        address requester = _getAddress(USER_PRIVATE_KEY);

        Vault.Request memory request = _createRequestForUser(
            bytes32(0), depositAmount, bytes32(0), depositAmount, USER_PRIVATE_KEY, solver, nonce, expiry
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        bytes32 requestHash = sigHelper.hashRequest(request);

        vm.expectEmit(true, true, false, false);
        emit Vault.Deposit(requestHash, requester);

        // Self-deposit ETH: from == msg.sender
        vm.prank(requester);
        vault.deposit{value: depositAmount}(request, signature, 0);

        assertTrue(vault.depositNonce(nonce), "Nonce should be marked as used");
        assertEq(address(vault).balance, depositAmount, "Vault should have deposited ETH");
    }

    /// @notice Test deposit of ERC20 with fee by a different sender (solver) succeeds
    function test_Deposit_ERC20_WithFee_DifferentSender_Success() public {
        uint256 depositAmount = 1000 * 10 ** 18;
        uint256 fee = 10 * 10 ** 18;
        uint256 nonce = 53;
        uint256 expiry = _futureTimestamp(1 hours);

        address requester = _getAddress(USER_PRIVATE_KEY);

        Vault.Request memory request = _createRequestForUserWithFee(
            bytes32(uint256(uint160(address(token)))),
            depositAmount,
            fee,
            bytes32(uint256(uint160(address(token)))),
            depositAmount,
            USER_PRIVATE_KEY,
            solver,
            nonce,
            expiry
        );

        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        // Approve tokens (value + fee) from requester to vault
        vm.prank(requester);
        token.approve(address(vault), depositAmount + fee);

        bytes32 requestHash = sigHelper.hashRequest(request);

        vm.expectEmit(true, true, false, false);
        emit Vault.Deposit(requestHash, requester);

        uint256 solverBalBefore = token.balanceOf(solver);

        // Deposit by solver (different sender), fee goes to solver
        vm.prank(solver);
        vault.deposit(request, signature, 0);

        assertTrue(vault.depositNonce(nonce), "Nonce should be marked as used");
        assertEq(token.balanceOf(address(vault)), depositAmount, "Vault should have deposited tokens");
        assertEq(token.balanceOf(solver) - solverBalBefore, fee, "Solver should have received fee");
    }

    // Helper Functions for Arrays

    function _toAddressArray(address addr) internal pure returns (address[] memory) {
        address[] memory arr = new address[](1);
        arr[0] = addr;
        return arr;
    }

    function _toUintArray(uint256 val) internal pure returns (uint256[] memory) {
        uint256[] memory arr = new uint256[](1);
        arr[0] = val;
        return arr;
    }
}
