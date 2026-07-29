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

    function _payload(string memory protocolTag, address target, bytes memory callData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(
            RoutingPayload({protocolTag: protocolTag, target: target, callData: callData, arbitary_data: bytes("")})
        );
    }

    function test_Execute_Native_HappyPath() public {
        uint256 amount = 1 ether;
        bytes memory callData = hex"12345678";
        bytes memory payload = _payload("native-happy", address(mockTarget), callData);

        vm.deal(gateway, amount);
        vm.expectEmit(true, true, true, true);
        emit Executor.PayloadExecuted(
            keccak256(payload), address(mockTarget), party, address(0), amount, "native-happy"
        );
        vm.prank(gateway);
        executor.execute{value: amount}(address(0), amount, party, payload);

        assertEq(mockTarget.lastCaller(), address(executor));
        assertEq(mockTarget.lastCallData(), callData);
        assertEq(mockTarget.lastNativeValue(), amount);
        assertEq(address(mockTarget).balance, amount);
        assertEq(address(executor).balance, 0);
        assertEq(gateway.balance, 0);
    }

    function test_Execute_ERC20_HappyPath() public {
        uint256 amount = 1000e18;
        bytes memory callData = hex"abcdef";
        bytes memory payload = _payload("erc20-happy", address(mockTarget), callData);

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
        assertEq(token.allowance(address(executor), address(mockTarget)), 0);
    }

    function test_Execute_RevertsWhenCallerNotGateway() public {
        bytes memory payload = _payload("tag", address(mockTarget), hex"");

        vm.expectRevert(abi.encodeWithSelector(Router.UnauthorizedCaller.selector, address(this)));
        executor.execute(address(0), 1, party, payload);
    }

    function test_Execute_RevertsOnZeroAmount() public {
        bytes memory payload = _payload("tag", address(mockTarget), hex"");

        vm.expectRevert(Router.ZeroAmount.selector);
        vm.prank(gateway);
        executor.execute(address(0), 0, party, payload);
    }

    function test_Execute_RevertsOnForbiddenTargets() public {
        address[4] memory badTargets = [address(0), address(executor), gateway, vault];
        vm.deal(gateway, 4);

        for (uint256 i = 0; i < badTargets.length; i++) {
            bytes memory payload = _payload("tag", badTargets[i], hex"");
            vm.expectRevert(abi.encodeWithSelector(Router.ForbiddenTarget.selector, badTargets[i]));
            vm.prank(gateway);
            executor.execute{value: 1}(address(0), 1, party, payload);
        }
    }

    function test_Execute_RevertsOnNativeValueMismatch() public {
        bytes memory payload = _payload("tag", address(mockTarget), hex"");

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
        bytes memory payload = _payload("tag", address(mockTarget), hex"12345678");

        vm.deal(gateway, amount);
        vm.expectRevert(abi.encodeWithSelector(MockTarget.MockTargetError.selector, "mock revert"));
        vm.prank(gateway);
        executor.execute{value: amount}(address(0), amount, party, payload);
    }

    function test_Execute_TargetCallFailedOnEmptyRevertData() public {
        mockTarget.setRevertMode(2);
        uint256 amount = 1 ether;
        bytes memory payload = _payload("tag", address(mockTarget), hex"12345678");

        vm.deal(gateway, amount);
        vm.expectRevert(Router.TargetCallFailed.selector);
        vm.prank(gateway);
        executor.execute{value: amount}(address(0), amount, party, payload);
    }

    function test_Execute_NativeFundingSingleRefundTransfer() public {
        uint256 amount = 1 ether;
        bytes memory payload = _payload("tag", address(mockTarget), hex"");

        vm.deal(gateway, amount);
        vm.prank(gateway);
        executor.execute{value: amount}(address(0), amount, party, payload);

        assertEq(gateway.balance, 0);
        assertEq(address(executor).balance, 0);
        assertEq(address(mockTarget).balance, amount);
    }

    function test_RoutingPayload_FieldOrderGoldenVector() public pure {
        RoutingPayload memory samplePayload = RoutingPayload({
            protocolTag: "test",
            target: 0x000000000000000000000000000000000000dEaD,
            callData: hex"12345678",
            arbitary_data: bytes("")
        });

        bytes32 expected = 0xd034e7b461cd9c424bcaf82fc75a89a3dc18307a6ad398168ee4aa451aba4ca4;
        assertEq(keccak256(abi.encode(samplePayload)), expected);
    }
}
