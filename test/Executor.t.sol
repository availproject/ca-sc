// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";

import {Executor} from "../src/Executor.sol";
import {RoutingPayload} from "../src/types.sol";
import {Router} from "../src/Router.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {MockTarget} from "./mocks/MockTarget.sol";

contract ExecutorTest is Test {
    Executor public executor;
    MockERC20 public token;
    MockTarget public mockTarget;

    address public gateway;
    address public vault;
    address public party;

    function setUp() public {
        gateway = makeAddr("gateway");
        vault = makeAddr("vault");
        party = makeAddr("party");

        executor = new Executor(gateway, vault);
        token = new MockERC20("Test Token", "TEST");
        mockTarget = new MockTarget();
    }

    function _payload(string memory protocolTag, address target, uint256 nativeValue, bytes memory callData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(
            RoutingPayload({protocolTag: protocolTag, target: target, nativeValue: nativeValue, callData: callData})
        );
    }

    function test_Execute_Native_HappyPath() public {
        uint256 amount = 1 ether;
        uint256 nativeValue = 0.4 ether;
        bytes memory callData = hex"12345678";
        bytes memory payload = _payload("native-happy", address(mockTarget), nativeValue, callData);

        vm.deal(gateway, amount);
        vm.expectEmit(true, true, true, true);
        emit Executor.PayloadExecuted(
            keccak256(payload), address(mockTarget), party, address(0), amount, "native-happy"
        );
        vm.prank(gateway);
        executor.execute{value: amount}(address(0), amount, party, payload);

        assertEq(mockTarget.lastCaller(), address(executor));
        assertEq(mockTarget.lastCallData(), callData);
        assertEq(mockTarget.lastNativeValue(), nativeValue);
        assertEq(address(mockTarget).balance, nativeValue);
        assertEq(address(executor).balance, 0);
        assertEq(gateway.balance, amount - nativeValue);
    }

    function test_Execute_ERC20_HappyPath() public {
        uint256 amount = 1000e18;
        bytes memory callData = hex"abcdef";
        bytes memory payload = _payload("erc20-happy", address(mockTarget), 0, callData);

        token.mint(address(executor), amount);

        vm.expectEmit(true, true, true, true);
        emit Executor.PayloadExecuted(
            keccak256(payload), address(mockTarget), party, address(token), amount, "erc20-happy"
        );
        vm.prank(gateway);
        executor.execute(address(token), amount, party, payload);

        assertEq(mockTarget.lastCaller(), address(executor));
        assertEq(mockTarget.lastCallData(), callData);
        assertEq(mockTarget.lastNativeValue(), 0);
        assertEq(token.balanceOf(address(executor)), 0);
        assertEq(token.balanceOf(gateway), amount);
    }

    function test_Execute_RevertsWhenCallerNotGateway() public {
        bytes memory payload = _payload("tag", address(mockTarget), 0, hex"");

        vm.expectRevert(abi.encodeWithSelector(Router.UnauthorizedCaller.selector, address(this)));
        executor.execute(address(0), 1, party, payload);
    }

    function test_Execute_RevertsOnZeroAmount() public {
        bytes memory payload = _payload("tag", address(mockTarget), 0, hex"");

        vm.expectRevert(Router.ZeroAmount.selector);
        vm.prank(gateway);
        executor.execute(address(0), 0, party, payload);
    }

    function test_Execute_RevertsOnForbiddenTargets() public {
        address[4] memory badTargets = [address(0), address(executor), gateway, vault];
        vm.deal(gateway, 4);

        for (uint256 i = 0; i < badTargets.length; i++) {
            bytes memory payload = _payload("tag", badTargets[i], 0, hex"");
            vm.expectRevert(abi.encodeWithSelector(Router.ForbiddenTarget.selector, badTargets[i]));
            vm.prank(gateway);
            executor.execute{value: 1}(address(0), 1, party, payload);
        }
    }

    function test_Execute_RevertsOnNativeValueMismatch() public {
        bytes memory payload = _payload("tag", address(mockTarget), 0, hex"");

        // Native funding with msg.value != amount.
        vm.deal(gateway, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(Router.InvalidNativeValue.selector, 2 ether, 1 ether));
        vm.prank(gateway);
        executor.execute{value: 1 ether}(address(0), 2 ether, party, payload);

        // ERC-20 funding with nonzero msg.value.
        vm.expectRevert(abi.encodeWithSelector(Router.InvalidNativeValue.selector, 0, 1));
        vm.prank(gateway);
        executor.execute{value: 1}(address(token), 100, party, payload);
    }

    function test_Execute_BubblesTargetRevertData() public {
        mockTarget.setRevertMode(1);
        uint256 amount = 1 ether;
        bytes memory payload = _payload("tag", address(mockTarget), 0, hex"12345678");

        vm.deal(gateway, amount);
        vm.expectRevert(abi.encodeWithSelector(MockTarget.MockTargetError.selector, "mock revert"));
        vm.prank(gateway);
        executor.execute{value: amount}(address(0), amount, party, payload);
    }

    function test_Execute_TargetCallFailedOnEmptyRevertData() public {
        mockTarget.setRevertMode(2);
        uint256 amount = 1 ether;
        bytes memory payload = _payload("tag", address(mockTarget), 0, hex"12345678");

        vm.deal(gateway, amount);
        vm.expectRevert(Router.TargetCallFailed.selector);
        vm.prank(gateway);
        executor.execute{value: amount}(address(0), amount, party, payload);
    }

    function test_Execute_NativeFundingSingleRefundTransfer() public {
        uint256 amount = 1 ether;
        uint256 spent = 0.3 ether;
        bytes memory payload = _payload("tag", address(mockTarget), spent, hex"");

        vm.deal(gateway, amount);
        uint256 gatewayBefore = gateway.balance;
        vm.prank(gateway);
        executor.execute{value: amount}(address(0), amount, party, payload);

        assertEq(gateway.balance, amount - spent);
        assertEq(address(executor).balance, 0);
        assertEq(address(mockTarget).balance, spent);
    }

    function test_RoutingPayload_FieldOrderGoldenVector() public pure {
        RoutingPayload memory samplePayload = RoutingPayload({
            protocolTag: "test",
            target: 0x000000000000000000000000000000000000dEaD,
            nativeValue: 0,
            callData: hex"12345678"
        });

        bytes32 expected = 0x48f64d781f9372ee7bc0d9208357b4007afbb55d7cc87d1da22c8aff0b6ecf1d;
        assertEq(keccak256(abi.encode(samplePayload)), expected);
    }
}
