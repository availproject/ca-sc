// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {BaseVaultTest} from "../../BaseVaultTest.t.sol";
import {SignatureHelper} from "../../helpers/SignatureHelper.sol";
import {MockArbSys} from "../../mocks/MockArbSys.sol";
import {MockRouter} from "../../mocks/MockRouter.sol";
import {ArbitrumVault} from "../../../src/ArbitrumVault.sol";
import {Vault} from "../../../src/Vault.sol";
import {Request, SettleData} from "../../../src/types.sol";

/// @title VaultEventDigestTest
/// @notice Unit tests for Vault.eventDigest and Vault.checkpoint
contract VaultEventDigestTest is BaseVaultTest {
    uint256 internal constant USER_PRIVATE_KEY = 0xA11CE;
    uint256 internal constant VERIFIER_PRIVATE_KEY = 0xB0B;
    uint256 internal constant AMOUNT = 1 ether;

    SignatureHelper internal sigHelper;
    address internal requester;

    function setUp() public override {
        super.setUp();
        sigHelper = new SignatureHelper();
        requester = vm.addr(USER_PRIVATE_KEY);
        vm.deal(requester, 100 ether);

        vm.prank(admin);
        vault.grantRole(SETTLEMENT_VERIFIER_ROLE, vm.addr(VERIFIER_PRIVATE_KEY));
    }

    function test_Initialize_DigestStartsAtZero() public view {
        assertEq(vault.eventDigest(), bytes32(0));
    }

    function test_Deposit_FoldsTheDepositEvent() public {
        Request memory request = _ethRequest(1);
        _deposit(request);

        bytes32 expected =
            _fold(bytes32(0), block.number, Vault.Deposit.selector, _requestHash(request), abi.encode(requester));
        assertEq(vault.eventDigest(), expected);
    }

    function test_Fulfil_FoldsTheFulfilmentEvent() public {
        Request memory request = _ethRequest(1);
        _fulfil(request);

        bytes32 expected = _fold(
            bytes32(0), block.number, Vault.Fulfilment.selector, _requestHash(request), abi.encode(requester, solver)
        );
        assertEq(vault.eventDigest(), expected);
    }

    function test_Settle_FoldsTheSettleEvent() public {
        SettleData memory settleData = _settle(1);

        bytes32 expected = _fold(
            bytes32(0),
            block.number,
            Vault.Settle.selector,
            bytes32(uint256(1)),
            abi.encode(settleData.solvers, settleData.contractAddresses, settleData.amounts)
        );
        assertEq(vault.eventDigest(), expected);
    }

    function test_Fold_RecomputedFromLogsMatchesDigest() public {
        bytes32 digest;

        vm.roll(100);
        vm.recordLogs();
        Request memory first = _ethRequest(1);
        _deposit(first);
        _fulfil(first);
        digest = _foldLogs(digest, vm.getRecordedLogs(), 100);

        vm.roll(101);
        vm.recordLogs();
        _depositMayan(_ethRequest(2));
        _settle(1);
        _deposit(_ethRequest(3));
        digest = _foldLogs(digest, vm.getRecordedLogs(), 101);

        assertEq(vault.eventDigest(), digest);
        assertTrue(digest != bytes32(0));
    }

    function test_DepositMayan_LeavesDigestUnchanged() public {
        _depositMayan(_ethRequest(1));

        assertTrue(vault.depositNonce(_depositNonceKey(1, 0)));
        assertEq(vault.eventDigest(), bytes32(0));
    }

    function test_AdminCalls_LeaveDigestUnchanged() public {
        _deposit(_ethRequest(1));
        bytes32 before = vault.eventDigest();

        vm.startPrank(admin);
        vault.setRouter(address(new MockRouter()));
        vault.grantRole(SETTLEMENT_VERIFIER_ROLE, makeAddr("other verifier"));
        vm.stopPrank();

        assertEq(vault.eventDigest(), before);
    }

    function test_Deposit_RevertLeavesDigestUnchanged() public {
        _deposit(_ethRequest(1));
        bytes32 before = vault.eventDigest();
        Request memory request = _ethRequest(2);
        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);

        vm.expectRevert("Vault: Value mismatch");
        vm.prank(solver);
        vault.deposit{value: AMOUNT - 1}(request, signature, 0);

        assertEq(vault.eventDigest(), before);
    }

    function test_Checkpoint_ReturnsDigestBlockAndTimestamp() public {
        vm.roll(4242);
        vm.warp(1_700_000_000);
        _deposit(_ethRequest(1));

        (bytes32 digest, uint256 number, uint256 timestamp) = vault.checkpoint();
        assertEq(digest, vault.eventDigest());
        assertEq(number, 4242);
        assertEq(timestamp, 1_700_000_000);
    }

    function test_ArbitrumVault_FoldsTheL2BlockNumber() public {
        vm.etch(address(100), address(new MockArbSys()).code);
        Vault nitroVault = _deployVault(new ArbitrumVault());
        vm.prank(admin);
        nitroVault.grantRole(SETTLEMENT_VERIFIER_ROLE, vm.addr(VERIFIER_PRIVATE_KEY));
        vault = nitroVault;

        vm.roll(55);
        vm.recordLogs();
        _deposit(_ethRequest(1));
        uint256 l2Number = MockArbSys(address(100)).L2_BLOCK_NUMBER();
        bytes32 expected = _foldLogs(bytes32(0), vm.getRecordedLogs(), l2Number);

        (bytes32 digest, uint256 number,) = vault.checkpoint();
        assertEq(number, l2Number);
        assertEq(digest, expected);
    }

    function test_Vault_ReportsBlockNumberEvenWithArbSys() public {
        vm.etch(address(100), address(new MockArbSys()).code);
        vm.roll(55);

        (, uint256 number,) = vault.checkpoint();
        assertEq(number, 55);
    }

    function _foldLogs(bytes32 digest, Vm.Log[] memory logs, uint256 blockNumber) internal view returns (bytes32) {
        for (uint256 i = 0; i < logs.length; ++i) {
            Vm.Log memory log = logs[i];
            if (log.emitter != address(vault)) continue;
            bytes32 topic0 = log.topics[0];
            if (
                topic0 != Vault.Deposit.selector && topic0 != Vault.Fulfilment.selector
                    && topic0 != Vault.Settle.selector
            ) continue;
            digest = _fold(digest, blockNumber, topic0, log.topics[1], log.data);
        }
        return digest;
    }

    function _fold(bytes32 digest, uint256 blockNumber, bytes32 topic0, bytes32 topic1, bytes memory data)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(digest, blockNumber, topic0, topic1, keccak256(data)));
    }

    function _deployVault(Vault impl) internal returns (Vault) {
        bytes memory initData = abi.encodeWithSelector(impl.initialize.selector, admin, verifier);
        return Vault(payable(address(new ERC1967Proxy(address(impl), initData))));
    }

    function _requestHash(Request memory request) internal view returns (bytes32) {
        return sigHelper.hashRequest(request);
    }

    function _ethRequest(uint256 nonce) internal view returns (Request memory) {
        return _createSimpleRequest(
            bytes32(0), AMOUNT, bytes32(0), AMOUNT, requester, requester, nonce, _futureTimestamp(1 hours)
        );
    }

    function _deposit(Request memory request) internal {
        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);
        vm.prank(solver);
        vault.deposit{value: AMOUNT}(request, signature, 0);
    }

    function _depositMayan(Request memory request) internal {
        if (address(vault.mayanRouter()) == address(0)) {
            MockRouter router = new MockRouter();
            vm.prank(admin);
            vault.setRouter(address(router));
        }
        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);
        vm.prank(requester);
        vault.depositMayan{value: AMOUNT}(request, signature, 0, "");
    }

    function _fulfil(Request memory request) internal {
        bytes memory signature = sigHelper.signRequest(request, USER_PRIVATE_KEY);
        vm.prank(solver);
        vault.fulfil{value: AMOUNT}(request, signature);
    }

    function _settle(uint256 nonce) internal returns (SettleData memory settleData) {
        vm.deal(address(vault), AMOUNT);
        settleData = _createSimpleSettleData(solver, address(0), AMOUNT, nonce);
        settleData.vaultAddress = address(vault);
        vm.prank(user);
        vault.settle(settleData, _signSettle(settleData));
    }

    function _signSettle(SettleData memory settleData) internal pure returns (bytes memory) {
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
        return abi.encodePacked(r, s, v);
    }
}
