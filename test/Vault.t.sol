// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test, console} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {Vault} from "../contracts/Vault.sol";
import {USDC} from "../contracts/USDC.sol";

contract VaultTest is Test {
    Vault public vault;
    USDC public usdc;

    address public admin;
    uint256 public adminKey;
    address public user;
    uint256 public userKey;
    address public solver;
    uint256 public solverKey;

    bytes32 constant SIGNATURE_PREFIX = "Sign this intent to proceed \n";
    bytes32 constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 constant SETTLEMENT_VERIFIER_ROLE = keccak256("SETTLEMENT_VERIFIER_ROLE");

    function setUp() public {
        (admin, adminKey) = makeAddrAndKey("admin");
        (user, userKey) = makeAddrAndKey("user");
        (solver, solverKey) = makeAddrAndKey("solver");

        vm.startPrank(admin);

        // Deploy implementation + proxy
        Vault impl = new Vault();
        bytes memory initData = abi.encodeWithSelector(Vault.initialize.selector, admin);
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        vault = Vault(address(proxy));

        // Deploy mock USDC
        usdc = new USDC();

        vm.stopPrank();

        // Fund accounts
        vm.deal(user, 100 ether);
        vm.deal(solver, 100 ether);
        vm.deal(address(vault), 1 ether);
    }

    // ════════════════════════════════════════════════════════════════════
    // Helpers
    // ════════════════════════════════════════════════════════════════════

    function _makeRequest(
        uint256 sourceChainId,
        bytes32 sourceToken,
        uint256 sourceValue,
        uint256 sourceFee,
        uint256 destChainId,
        bytes32 destToken,
        uint256 destValue,
        uint256 nonce,
        uint256 expiry
    ) internal pure returns (Vault.Request memory) {
        Vault.SourcePair[] memory sources = new Vault.SourcePair[](1);
        sources[0] = Vault.SourcePair({
            universe: Vault.Universe.ETHEREUM,
            chainID: sourceChainId,
            contractAddress: sourceToken,
            value: sourceValue,
            fee: sourceFee
        });

        Vault.DestinationPair[] memory destinations = new Vault.DestinationPair[](1);
        destinations[0] = Vault.DestinationPair({contractAddress: destToken, value: destValue});

        Vault.Party[] memory parties = new Vault.Party[](1);
        parties[0] = Vault.Party({universe: Vault.Universe.ETHEREUM, address_: bytes32(uint256(uint160(0)))});

        return Vault.Request({
            sources: sources,
            destinationUniverse: Vault.Universe.ETHEREUM,
            destinationChainID: destChainId,
            recipientAddress: bytes32(uint256(uint160(0))),
            destinations: destinations,
            nonce: nonce,
            expiry: expiry,
            parties: parties
        });
    }

    function _makeERC20DepositRequest(uint256 nonce) internal view returns (Vault.Request memory) {
        Vault.Request memory req = _makeRequest(
            block.chainid,
            bytes32(uint256(uint160(address(usdc)))),
            1_000_000, // 1 USDC
            1_000, // 0.001 USDC fee
            block.chainid,
            bytes32(uint256(uint160(address(usdc)))),
            1_000_000,
            nonce,
            block.timestamp + 1 hours
        );
        req.parties[0].address_ = bytes32(uint256(uint160(user)));
        req.recipientAddress = bytes32(uint256(uint160(user)));
        return req;
    }

    function _makeNativeDepositRequest(uint256 nonce) internal view returns (Vault.Request memory) {
        Vault.Request memory req = _makeRequest(
            block.chainid,
            bytes32(0), // native ETH
            1 ether,
            0.001 ether,
            block.chainid,
            bytes32(0),
            1 ether,
            nonce,
            block.timestamp + 1 hours
        );
        req.parties[0].address_ = bytes32(uint256(uint160(user)));
        req.recipientAddress = bytes32(uint256(uint160(user)));
        return req;
    }

    function _hashRequest(Vault.Request memory request) internal pure returns (bytes32) {
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

    function _signRequest(Vault.Request memory request, uint256 privateKey)
        internal
        pure
        returns (bytes memory)
    {
        bytes32 requestHash = _hashRequest(request);
        bytes32 prefixedHash = keccak256(abi.encodePacked(SIGNATURE_PREFIX, requestHash));
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", prefixedHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedHash);
        return abi.encodePacked(r, s, v);
    }

    function _mintAndApprove(address to, uint256 amount) internal {
        vm.prank(admin);
        usdc.mint(to, amount);
        vm.prank(to);
        usdc.approve(address(vault), amount);
    }

    // ════════════════════════════════════════════════════════════════════
    // Initialization
    // ════════════════════════════════════════════════════════════════════

    function test_initialize_grantsAdminRole() public view {
        assertTrue(vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_initialize_grantsUpgraderRole() public view {
        assertTrue(vault.hasRole(UPGRADER_ROLE, admin));
    }

    function test_initialize_nonAdminHasNoRole() public view {
        assertFalse(vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), user));
        assertFalse(vault.hasRole(UPGRADER_ROLE, user));
    }

    function test_initialize_cannotReinitialize() public {
        vm.expectRevert();
        vault.initialize(user);
    }

    // ════════════════════════════════════════════════════════════════════
    // Deposit — ERC20
    // ════════════════════════════════════════════════════════════════════

    function test_deposit_erc20() public {
        Vault.Request memory req = _makeERC20DepositRequest(1);
        bytes memory sig = _signRequest(req, userKey);
        _mintAndApprove(user, 1_000_000);

        vm.prank(user);
        vault.deposit(req, sig, 0);

        assertEq(usdc.balanceOf(address(vault)), 1_000_000);
        assertEq(usdc.balanceOf(user), 0);
        assertTrue(vault.depositNonce(1));
    }

    function test_deposit_erc20_emitsEvent() public {
        Vault.Request memory req = _makeERC20DepositRequest(1);
        bytes memory sig = _signRequest(req, userKey);
        _mintAndApprove(user, 1_000_000);

        vm.expectEmit(true, false, false, true);
        emit Vault.Deposit(_hashRequest(req), user);

        vm.prank(user);
        vault.deposit(req, sig, 0);
    }

    // ════════════════════════════════════════════════════════════════════
    // Deposit — Native ETH
    // ════════════════════════════════════════════════════════════════════

    function test_deposit_native() public {
        Vault.Request memory req = _makeNativeDepositRequest(1);
        bytes memory sig = _signRequest(req, userKey);

        uint256 vaultBefore = address(vault).balance;

        vm.prank(user);
        vault.deposit{value: 1 ether}(req, sig, 0);

        assertEq(address(vault).balance, vaultBefore + 1 ether);
        assertTrue(vault.depositNonce(1));
    }

    function test_deposit_native_wrongValue() public {
        Vault.Request memory req = _makeNativeDepositRequest(1);
        bytes memory sig = _signRequest(req, userKey);

        vm.prank(user);
        vm.expectRevert("Vault: Value mismatch");
        vault.deposit{value: 0.5 ether}(req, sig, 0);
    }

    // ════════════════════════════════════════════════════════════════════
    // Deposit — Validation
    // ════════════════════════════════════════════════════════════════════

    function test_deposit_revertsOnInvalidSignature() public {
        Vault.Request memory req = _makeERC20DepositRequest(1);
        bytes memory sig = _signRequest(req, solverKey); // wrong signer
        _mintAndApprove(user, 1_000_000);

        vm.prank(user);
        vm.expectRevert("Vault: Invalid signature or from");
        vault.deposit(req, sig, 0);
    }

    function test_deposit_revertsOnChainIdMismatch() public {
        Vault.Request memory req = _makeERC20DepositRequest(1);
        req.sources[0].chainID = 999; // wrong chain
        bytes memory sig = _signRequest(req, userKey);
        _mintAndApprove(user, 1_000_000);

        vm.prank(user);
        vm.expectRevert("Vault: Chain ID mismatch");
        vault.deposit(req, sig, 0);
    }

    function test_deposit_revertsOnUniverseMismatch() public {
        Vault.Request memory req = _makeERC20DepositRequest(1);
        req.sources[0].universe = Vault.Universe.SOLANA;
        bytes memory sig = _signRequest(req, userKey);
        _mintAndApprove(user, 1_000_000);

        vm.prank(user);
        vm.expectRevert("Vault: Universe mismatch");
        vault.deposit(req, sig, 0);
    }

    function test_deposit_revertsOnNonceReplay() public {
        Vault.Request memory req = _makeERC20DepositRequest(1);
        bytes memory sig = _signRequest(req, userKey);
        _mintAndApprove(user, 2_000_000);

        vm.startPrank(user);
        vault.deposit(req, sig, 0);

        vm.expectRevert("Vault: Nonce already used");
        vault.deposit(req, sig, 0);
        vm.stopPrank();
    }

    function test_deposit_revertsOnExpired() public {
        Vault.Request memory req = _makeERC20DepositRequest(1);
        req.expiry = block.timestamp - 1; // already expired
        bytes memory sig = _signRequest(req, userKey);
        _mintAndApprove(user, 1_000_000);

        vm.prank(user);
        vm.expectRevert("Vault: Request expired");
        vault.deposit(req, sig, 0);
    }

    // ════════════════════════════════════════════════════════════════════
    // Fulfil — ERC20
    // ════════════════════════════════════════════════════════════════════

    function test_fulfil_erc20() public {
        Vault.Request memory req = _makeERC20DepositRequest(1);
        bytes memory sig = _signRequest(req, userKey);

        // Solver fulfils — sends tokens to recipient
        _mintAndApprove(solver, 1_000_000);

        vm.prank(solver);
        vault.fulfil(req, sig);

        assertEq(usdc.balanceOf(user), 1_000_000);
        assertTrue(vault.fillNonce(1));
    }

    function test_fulfil_erc20_emitsEvent() public {
        Vault.Request memory req = _makeERC20DepositRequest(1);
        bytes memory sig = _signRequest(req, userKey);
        _mintAndApprove(solver, 1_000_000);

        vm.expectEmit(true, false, false, true);
        emit Vault.Fulfilment(_hashRequest(req), user, solver);

        vm.prank(solver);
        vault.fulfil(req, sig);
    }

    // ════════════════════════════════════════════════════════════════════
    // Fulfil — Native ETH
    // ════════════════════════════════════════════════════════════════════

    function test_fulfil_native() public {
        Vault.Request memory req = _makeNativeDepositRequest(1);
        bytes memory sig = _signRequest(req, userKey);

        uint256 userBefore = user.balance;

        vm.prank(solver);
        vault.fulfil{value: 1 ether}(req, sig);

        assertEq(user.balance, userBefore + 1 ether);
        assertTrue(vault.fillNonce(1));
    }

    function test_fulfil_native_refundsExcessETH() public {
        Vault.Request memory req = _makeNativeDepositRequest(1);
        bytes memory sig = _signRequest(req, userKey);

        uint256 solverBefore = solver.balance;

        vm.prank(solver);
        vault.fulfil{value: 1.5 ether}(req, sig); // overpay by 0.5

        // Solver gets 0.5 back
        assertEq(solver.balance, solverBefore - 1 ether);
        assertEq(user.balance, 100 ether + 1 ether);
    }

    function test_fulfil_native_insufficientValue() public {
        Vault.Request memory req = _makeNativeDepositRequest(1);
        bytes memory sig = _signRequest(req, userKey);

        vm.prank(solver);
        vm.expectRevert("Vault: Value mismatch");
        vault.fulfil{value: 0.5 ether}(req, sig);
    }

    // ════════════════════════════════════════════════════════════════════
    // Fulfil — Multi-Destination
    // ════════════════════════════════════════════════════════════════════

    function test_fulfil_multiDestination() public {
        Vault.Request memory req = _makeERC20DepositRequest(1);

        // Add a second destination
        Vault.DestinationPair[] memory dests = new Vault.DestinationPair[](2);
        dests[0] = Vault.DestinationPair({
            contractAddress: bytes32(uint256(uint160(address(usdc)))),
            value: 500_000
        });
        dests[1] = Vault.DestinationPair({
            contractAddress: bytes32(uint256(uint160(address(usdc)))),
            value: 500_000
        });
        req.destinations = dests;

        bytes memory sig = _signRequest(req, userKey);
        _mintAndApprove(solver, 1_000_000);

        vm.prank(solver);
        vault.fulfil(req, sig);

        assertEq(usdc.balanceOf(user), 1_000_000);
    }

    // ════════════════════════════════════════════════════════════════════
    // Fulfil — Validation
    // ════════════════════════════════════════════════════════════════════

    function test_fulfil_revertsOnInvalidSignature() public {
        Vault.Request memory req = _makeERC20DepositRequest(1);
        bytes memory sig = _signRequest(req, solverKey); // wrong signer
        _mintAndApprove(solver, 1_000_000);

        vm.prank(solver);
        vm.expectRevert("Vault: Invalid signature or from");
        vault.fulfil(req, sig);
    }

    function test_fulfil_revertsOnChainIdMismatch() public {
        Vault.Request memory req = _makeERC20DepositRequest(1);
        req.destinationChainID = 999;
        bytes memory sig = _signRequest(req, userKey);
        _mintAndApprove(solver, 1_000_000);

        vm.prank(solver);
        vm.expectRevert("Vault: Chain ID mismatch");
        vault.fulfil(req, sig);
    }

    function test_fulfil_revertsOnUniverseMismatch() public {
        Vault.Request memory req = _makeERC20DepositRequest(1);
        req.destinationUniverse = Vault.Universe.SOLANA;
        bytes memory sig = _signRequest(req, userKey);
        _mintAndApprove(solver, 1_000_000);

        vm.prank(solver);
        vm.expectRevert("Vault: Universe mismatch");
        vault.fulfil(req, sig);
    }

    function test_fulfil_revertsOnNonceReplay() public {
        Vault.Request memory req = _makeERC20DepositRequest(1);
        bytes memory sig = _signRequest(req, userKey);
        _mintAndApprove(solver, 2_000_000);

        vm.startPrank(solver);
        vault.fulfil(req, sig);

        vm.expectRevert("Vault: Nonce already used");
        vault.fulfil(req, sig);
        vm.stopPrank();
    }

    function test_fulfil_revertsOnExpired() public {
        Vault.Request memory req = _makeERC20DepositRequest(1);
        req.expiry = block.timestamp - 1;
        bytes memory sig = _signRequest(req, userKey);
        _mintAndApprove(solver, 1_000_000);

        vm.prank(solver);
        vm.expectRevert("Vault: Request expired");
        vault.fulfil(req, sig);
    }

    // ════════════════════════════════════════════════════════════════════
    // Fulfil — State tracking
    // ════════════════════════════════════════════════════════════════════

    function test_fulfil_setsRequestStateAndWinningSolver() public {
        Vault.Request memory req = _makeERC20DepositRequest(1);
        bytes memory sig = _signRequest(req, userKey);
        _mintAndApprove(solver, 1_000_000);

        vm.prank(solver);
        vault.fulfil(req, sig);

        bytes32 requestHash = _hashRequest(req);
        bytes32 prefixedHash = keccak256(abi.encodePacked(SIGNATURE_PREFIX, requestHash));
        bytes32 signedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", prefixedHash));

        assertEq(uint256(vault.requestState(signedMessageHash)), uint256(Vault.RFFState.FULFILLED));
        assertEq(vault.winningSolver(signedMessageHash), solver);
    }

    // ════════════════════════════════════════════════════════════════════
    // Settle
    // ════════════════════════════════════════════════════════════════════

    function _grantSettlementRole(address account) internal {
        vm.prank(admin);
        vault.grantRole(SETTLEMENT_VERIFIER_ROLE, account);
    }

    function _signSettle(Vault.SettleData memory data, uint256 privateKey)
        internal
        pure
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                data.universe,
                data.chainID,
                data.solvers,
                data.contractAddresses,
                data.amounts,
                data.nonce
            )
        );
        bytes32 signedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, signedHash);
        return abi.encodePacked(r, s, v);
    }

    function _makeSettleData(uint256 nonce) internal view returns (Vault.SettleData memory) {
        address[] memory solvers_ = new address[](1);
        solvers_[0] = solver;
        address[] memory tokens = new address[](1);
        tokens[0] = address(usdc);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1_000_000;

        return Vault.SettleData({
            universe: Vault.Universe.ETHEREUM,
            chainID: block.chainid,
            solvers: solvers_,
            contractAddresses: tokens,
            amounts: amounts,
            nonce: nonce
        });
    }

    function test_settle_erc20() public {
        _grantSettlementRole(admin);

        // Fund vault with USDC
        vm.prank(admin);
        usdc.mint(address(vault), 1_000_000);

        Vault.SettleData memory data = _makeSettleData(1);
        bytes memory sig = _signSettle(data, adminKey);

        vault.settle(data, sig);

        assertEq(usdc.balanceOf(solver), 1_000_000);
        assertTrue(vault.settleNonce(1));
    }

    function test_settle_native() public {
        _grantSettlementRole(admin);

        Vault.SettleData memory data = _makeSettleData(1);
        data.contractAddresses[0] = address(0);
        data.amounts[0] = 0.5 ether;
        bytes memory sig = _signSettle(data, adminKey);

        uint256 solverBefore = solver.balance;
        vault.settle(data, sig);

        assertEq(solver.balance, solverBefore + 0.5 ether);
    }

    function test_settle_emitsEvent() public {
        _grantSettlementRole(admin);

        vm.prank(admin);
        usdc.mint(address(vault), 1_000_000);

        Vault.SettleData memory data = _makeSettleData(1);
        bytes memory sig = _signSettle(data, adminKey);

        vm.expectEmit(true, false, false, true);
        emit Vault.Settle(1, data.solvers, data.contractAddresses, data.amounts);

        vault.settle(data, sig);
    }

    function test_settle_revertsOnInvalidSigner() public {
        // Don't grant role to user
        Vault.SettleData memory data = _makeSettleData(1);
        bytes memory sig = _signSettle(data, userKey); // user doesn't have role

        vm.expectRevert("Vault: Invalid signature");
        vault.settle(data, sig);
    }

    function test_settle_revertsOnNonceReplay() public {
        _grantSettlementRole(admin);

        vm.prank(admin);
        usdc.mint(address(vault), 2_000_000);

        Vault.SettleData memory data = _makeSettleData(1);
        bytes memory sig = _signSettle(data, adminKey);

        vault.settle(data, sig);

        vm.expectRevert("Vault: Nonce already used");
        vault.settle(data, sig);
    }

    function test_settle_revertsOnChainIdMismatch() public {
        _grantSettlementRole(admin);

        Vault.SettleData memory data = _makeSettleData(1);
        data.chainID = 999;
        bytes memory sig = _signSettle(data, adminKey);

        vm.expectRevert("Vault: Chain ID mismatch");
        vault.settle(data, sig);
    }

    function test_settle_revertsOnUniverseMismatch() public {
        _grantSettlementRole(admin);

        Vault.SettleData memory data = _makeSettleData(1);
        data.universe = Vault.Universe.SOLANA;
        bytes memory sig = _signSettle(data, adminKey);

        vm.expectRevert("Vault: Universe mismatch");
        vault.settle(data, sig);
    }

    function test_settle_revertsOnSolversTokensLengthMismatch() public {
        _grantSettlementRole(admin);

        Vault.SettleData memory data = _makeSettleData(1);
        // Add extra solver without matching token
        address[] memory moreSolvers = new address[](2);
        moreSolvers[0] = solver;
        moreSolvers[1] = solver;
        data.solvers = moreSolvers;
        bytes memory sig = _signSettle(data, adminKey);

        vm.expectRevert("tokens length mismatch");
        vault.settle(data, sig);
    }

    function test_settle_revertsOnSolversAmountsLengthMismatch() public {
        _grantSettlementRole(admin);

        Vault.SettleData memory data = _makeSettleData(1);
        uint256[] memory moreAmounts = new uint256[](2);
        moreAmounts[0] = 1_000_000;
        moreAmounts[1] = 500_000;
        data.amounts = moreAmounts;
        bytes memory sig = _signSettle(data, adminKey);

        vm.expectRevert("amounts length mismatch");
        vault.settle(data, sig);
    }

    // ════════════════════════════════════════════════════════════════════
    // Verify Request Signature
    // ════════════════════════════════════════════════════════════════════

    function test_verifyRequestSignature_validSignature() public view {
        Vault.Request memory req = _makeERC20DepositRequest(1);
        bytes memory sig = _signRequest(req, userKey);

        (bool valid,) = vault.verifyRequestSignature(req, sig);
        assertTrue(valid);
    }

    function test_verifyRequestSignature_invalidSignature() public view {
        Vault.Request memory req = _makeERC20DepositRequest(1);
        bytes memory sig = _signRequest(req, solverKey); // wrong signer

        (bool valid,) = vault.verifyRequestSignature(req, sig);
        assertFalse(valid);
    }

    // ════════════════════════════════════════════════════════════════════
    // Extract Address — edge case
    // ════════════════════════════════════════════════════════════════════

    function test_deposit_revertsWhenNoEvmParty() public {
        Vault.Request memory req = _makeERC20DepositRequest(1);
        // Change party universe to non-EVM
        req.parties[0].universe = Vault.Universe.SOLANA;
        bytes memory sig = _signRequest(req, userKey);
        _mintAndApprove(user, 1_000_000);

        vm.prank(user);
        vm.expectRevert("Vault: Party not found");
        vault.deposit(req, sig, 0);
    }

    // ════════════════════════════════════════════════════════════════════
    // End-to-end: Deposit → Fulfil → Settle
    // ════════════════════════════════════════════════════════════════════

    function test_e2e_deposit_fulfil_settle() public {
        // 1. User deposits ERC20
        Vault.Request memory req = _makeERC20DepositRequest(1);
        bytes memory sig = _signRequest(req, userKey);
        _mintAndApprove(user, 1_000_000);

        vm.prank(user);
        vault.deposit(req, sig, 0);

        assertEq(usdc.balanceOf(address(vault)), 1_000_000);

        // 2. Solver fulfils on destination (same chain for test)
        _mintAndApprove(solver, 1_000_000);

        vm.prank(solver);
        vault.fulfil(req, sig);

        assertEq(usdc.balanceOf(user), 1_000_000);

        // 3. Settlement — pay solver from vault
        _grantSettlementRole(admin);
        Vault.SettleData memory settleData = _makeSettleData(1);
        bytes memory settleSig = _signSettle(settleData, adminKey);

        vault.settle(settleData, settleSig);

        assertEq(usdc.balanceOf(solver), 1_000_000);
        assertEq(usdc.balanceOf(address(vault)), 0);
    }
}
