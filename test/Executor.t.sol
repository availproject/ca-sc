// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";

import {Executor} from "../src/Executor.sol";
import {Approval, RoutingPayload} from "../src/types.sol";
import {Router} from "../src/Router.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {MockTarget} from "./mocks/MockTarget.sol";

contract ExecutorTest is Test {
    Executor public executor;
    MockERC20 public token;
    MockTarget public mockTarget;

    address public gateway;
    address public vault;
    address public refundRecipient;

    function setUp() public {
        gateway = makeAddr("gateway");
        vault = makeAddr("vault");
        refundRecipient = makeAddr("refund");

        executor = new Executor(gateway, vault);
        token = new MockERC20("Test Token", "TEST");
        mockTarget = new MockTarget();
    }

    function _payload(
        string memory protocolTag,
        address target,
        address approvalToken,
        uint256 approvalAmount,
        uint256 nativeValue,
        bytes memory callData
    ) internal pure returns (bytes memory) {
        return abi.encode(
            RoutingPayload({
                protocolTag: protocolTag,
                target: target,
                approval: Approval({token: approvalToken, amount: approvalAmount}),
                nativeValue: nativeValue,
                callData: callData
            })
        );
    }

    function test_Execute_Native_HappyPath() public {
        uint256 amount = 1 ether;
        uint256 nativeValue = 0.4 ether;
        bytes memory callData = hex"12345678";
        bytes memory payload = _payload("native-happy", address(mockTarget), address(0), 0, nativeValue, callData);

        vm.deal(gateway, amount);
        vm.expectEmit(true, true, true, true);
        emit Executor.PayloadExecuted(
            keccak256(payload), address(mockTarget), refundRecipient, address(0), amount, "native-happy"
        );
        vm.prank(gateway);
        executor.execute{value: amount}(address(0), amount, refundRecipient, payload);

        assertEq(mockTarget.lastCaller(), address(executor));
        assertEq(mockTarget.lastCallData(), callData);
        assertEq(mockTarget.lastNativeValue(), nativeValue);
        assertEq(address(mockTarget).balance, nativeValue);
        assertEq(address(executor).balance, 0);
        assertEq(refundRecipient.balance, amount - nativeValue);
    }

    function test_Execute_ERC20_HappyPath() public {
        uint256 amount = 1000e18;
        uint256 approvalAmount = 600e18;
        bytes memory callData = hex"abcdef";
        bytes memory payload = _payload("erc20-happy", address(mockTarget), address(token), approvalAmount, 0, callData);

        token.mint(address(executor), amount);

        vm.expectEmit(true, true, true, true);
        emit Executor.PayloadExecuted(
            keccak256(payload), address(mockTarget), refundRecipient, address(token), amount, "erc20-happy"
        );
        vm.prank(gateway);
        executor.execute(address(token), amount, refundRecipient, payload);

        assertEq(mockTarget.lastCaller(), address(executor));
        assertEq(mockTarget.lastCallData(), callData);
        assertEq(mockTarget.lastNativeValue(), 0);
        assertEq(token.allowance(address(executor), address(mockTarget)), 0);
        assertEq(token.balanceOf(address(executor)), 0);
        assertEq(token.balanceOf(refundRecipient), amount);
    }

    function test_Execute_RevertsWhenCallerNotGateway() public {
        bytes memory payload = _payload("tag", address(mockTarget), address(0), 0, 0, hex"");

        vm.expectRevert(abi.encodeWithSelector(Router.UnauthorizedCaller.selector, address(this)));
        executor.execute(address(0), 1, refundRecipient, payload);
    }

    function test_Execute_RevertsOnZeroRefundRecipient() public {
        bytes memory payload = _payload("tag", address(mockTarget), address(0), 0, 0, hex"");

        vm.deal(gateway, 1);
        vm.expectRevert(Router.ZeroAddress.selector);
        vm.prank(gateway);
        executor.execute{value: 1}(address(0), 1, address(0), payload);
    }

    function test_Execute_RevertsOnZeroAmount() public {
        bytes memory payload = _payload("tag", address(mockTarget), address(0), 0, 0, hex"");

        vm.expectRevert(Router.ZeroAmount.selector);
        vm.prank(gateway);
        executor.execute(address(0), 0, refundRecipient, payload);
    }

    function test_Execute_RevertsOnForbiddenTargets() public {
        address[4] memory badTargets = [address(0), address(executor), gateway, vault];
        vm.deal(gateway, 4);

        for (uint256 i = 0; i < badTargets.length; i++) {
            bytes memory payload = _payload("tag", badTargets[i], address(0), 0, 0, hex"");
            vm.expectRevert(abi.encodeWithSelector(Router.ForbiddenTarget.selector, badTargets[i]));
            vm.prank(gateway);
            executor.execute{value: 1}(address(0), 1, refundRecipient, payload);
        }
    }

    function test_Execute_RevertsOnNativeValueMismatch() public {
        bytes memory payload = _payload("tag", address(mockTarget), address(0), 0, 0, hex"");

        // Native funding with msg.value != amount.
        vm.deal(gateway, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(Router.InvalidNativeValue.selector, 2 ether, 1 ether));
        vm.prank(gateway);
        executor.execute{value: 1 ether}(address(0), 2 ether, refundRecipient, payload);

        // ERC-20 funding with nonzero msg.value.
        vm.expectRevert(abi.encodeWithSelector(Router.InvalidNativeValue.selector, 0, 1));
        vm.prank(gateway);
        executor.execute{value: 1}(address(token), 100, refundRecipient, payload);

        // Native payload nativeValue above the funded amount.
        bytes memory overValue = _payload("tag", address(mockTarget), address(0), 0, 2 ether, hex"");
        vm.deal(gateway, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(Router.InvalidNativeValue.selector, 1 ether, 2 ether));
        vm.prank(gateway);
        executor.execute{value: 1 ether}(address(0), 1 ether, refundRecipient, overValue);

        // ERC-20 payload with nonzero nativeValue.
        token.mint(address(executor), 100);
        bytes memory erc20Value = _payload("tag", address(mockTarget), address(0), 0, 1, hex"");
        vm.expectRevert(abi.encodeWithSelector(Router.InvalidNativeValue.selector, 0, 1));
        vm.prank(gateway);
        executor.execute(address(token), 100, refundRecipient, erc20Value);
    }

    function test_Execute_RevertsOnInvalidApproval() public {
        // Native funding with approval fields set.
        bytes memory nativeApproval = _payload("tag", address(mockTarget), address(token), 5, 0, hex"");
        vm.deal(gateway, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(Router.InvalidApproval.selector, address(token), 5));
        vm.prank(gateway);
        executor.execute{value: 1 ether}(address(0), 1 ether, refundRecipient, nativeApproval);

        token.mint(address(executor), 100);

        // Approval token different from the funded asset.
        bytes memory wrongToken = _payload("tag", address(mockTarget), address(0xdead), 10, 0, hex"");
        vm.expectRevert(abi.encodeWithSelector(Router.InvalidApproval.selector, address(0xdead), 10));
        vm.prank(gateway);
        executor.execute(address(token), 100, refundRecipient, wrongToken);

        // Approval amount above the funded amount.
        bytes memory overAmount = _payload("tag", address(mockTarget), address(token), 200, 0, hex"");
        vm.expectRevert(abi.encodeWithSelector(Router.InvalidApproval.selector, address(token), 200));
        vm.prank(gateway);
        executor.execute(address(token), 100, refundRecipient, overAmount);

        // Mixed zero/nonzero approval pair.
        bytes memory mixed = _payload("tag", address(mockTarget), address(0), 10, 0, hex"");
        vm.expectRevert(abi.encodeWithSelector(Router.InvalidApproval.selector, address(0), 10));
        vm.prank(gateway);
        executor.execute(address(token), 100, refundRecipient, mixed);
    }

    function test_Execute_BubblesTargetRevertData() public {
        mockTarget.setRevertMode(1);
        uint256 amount = 1 ether;
        bytes memory payload = _payload("tag", address(mockTarget), address(0), 0, 0, hex"12345678");

        vm.deal(gateway, amount);
        vm.expectRevert(abi.encodeWithSelector(MockTarget.MockTargetError.selector, "mock revert"));
        vm.prank(gateway);
        executor.execute{value: amount}(address(0), amount, refundRecipient, payload);
    }

    function test_Execute_TargetCallFailedOnEmptyRevertData() public {
        mockTarget.setRevertMode(2);
        uint256 amount = 1 ether;
        bytes memory payload = _payload("tag", address(mockTarget), address(0), 0, 0, hex"12345678");

        vm.deal(gateway, amount);
        vm.expectRevert(Router.TargetCallFailed.selector);
        vm.prank(gateway);
        executor.execute{value: amount}(address(0), amount, refundRecipient, payload);
    }

    function test_Execute_NativeFundingSingleRefundTransfer() public {
        uint256 amount = 1 ether;
        uint256 spent = 0.3 ether;
        bytes memory payload = _payload("tag", address(mockTarget), address(0), 0, spent, hex"");

        vm.deal(gateway, amount);
        uint256 refundBefore = refundRecipient.balance;
        vm.prank(gateway);
        executor.execute{value: amount}(address(0), amount, refundRecipient, payload);

        assertEq(refundRecipient.balance - refundBefore, amount - spent);
        assertEq(address(executor).balance, 0);
        assertEq(address(mockTarget).balance, spent);
    }

    function test_Execute_ApprovalClearedAfterSuccess() public {
        uint256 amount = 1000;
        bytes memory payload = _payload("tag", address(mockTarget), address(token), 400, 0, hex"");

        token.mint(address(executor), amount);
        vm.prank(gateway);
        executor.execute(address(token), amount, refundRecipient, payload);

        assertEq(token.allowance(address(executor), address(mockTarget)), 0);
        assertEq(token.balanceOf(address(executor)), 0);
        assertEq(token.balanceOf(refundRecipient), amount);
    }

    function test_Sweep_ERC20TransfersEntireBalance() public {
        token.mint(address(executor), 12_345);
        address randomEoa = makeAddr("randomEoa");

        vm.prank(randomEoa);
        executor.sweep(address(token), refundRecipient);

        assertEq(token.balanceOf(refundRecipient), 12_345);
        assertEq(token.balanceOf(address(executor)), 0);
    }

    function test_Sweep_NativeTransfersEntireBalance() public {
        vm.deal(address(executor), 7 ether);
        address randomEoa = makeAddr("randomEoa");

        vm.prank(randomEoa);
        executor.sweep(address(0), refundRecipient);

        assertEq(refundRecipient.balance, 7 ether);
        assertEq(address(executor).balance, 0);
    }

    function test_Sweep_RevertsOnZeroRecipient() public {
        vm.expectRevert(Router.ZeroAddress.selector);
        executor.sweep(address(token), address(0));

        vm.expectRevert(Router.ZeroAddress.selector);
        executor.sweep(address(0), address(0));
    }

    function test_Sweep_ZeroBalanceNoOp() public {
        executor.sweep(address(token), refundRecipient);
        executor.sweep(address(0), refundRecipient);

        assertEq(token.balanceOf(refundRecipient), 0);
        assertEq(refundRecipient.balance, 0);
    }

    function test_RoutingPayload_FieldOrderGoldenVector() public pure {
        RoutingPayload memory samplePayload = RoutingPayload({
            protocolTag: "test",
            target: 0x000000000000000000000000000000000000dEaD,
            approval: Approval({token: 0x0000000000000000000000000000000000000001, amount: 1000}),
            nativeValue: 0,
            callData: hex"12345678"
        });

        bytes32 expected = 0x02ea7984789a2f37074c54004691abff3a336265615179919362eb261001f76f;
        assertEq(keccak256(abi.encode(samplePayload)), expected);
    }
}
