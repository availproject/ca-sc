// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {Executor} from "../src/Executor.sol";
import {RoutingPayload} from "../src/types.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {MockTarget} from "./mocks/MockTarget.sol";

/// @notice Target that moves the caller's entire balance of a token out to a third party. Stands
/// in for the general shape of the residual-theft payload: an allowlisted-looking call that spends
/// more than the execution funded.
contract DrainingTarget {
    function drain(address token, address to, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, to, amount);
    }
}

contract ExecutorTest is Test {
    Executor public executor;
    MockERC20 public token;
    MockTarget public mockTarget;

    address public gateway;
    address public vault;
    address public party;

    function setUp() public {
        vault = makeAddr("vault");
        gateway = vault;
        party = makeAddr("party");

        executor = new Executor(vault, address(this));
        token = new MockERC20("Test Token", "TEST");
        mockTarget = new MockTarget();

        // The routing allowlist is closed by default; register the selectors these tests drive.
        // hex"abcdef" and hex"" are both shorter than four bytes and map to bytes4(0).
        executor.setTarget(address(mockTarget), true);
        executor.setSelector(address(mockTarget), 0x12345678, true);
        executor.setSelector(address(mockTarget), bytes4(0), true);
    }

    function _payload(string memory protocolTag, address target, bytes memory callData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(
            RoutingPayload({protocolTag: protocolTag, target: target, callData: callData, arbitaryData: bytes("")})
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

        // Funding is pulled from the vault's allowance, so the vault holds it beforehand.
        token.mint(vault, amount);
        vm.prank(vault);
        token.approve(address(executor), amount);

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

        vm.expectRevert(abi.encodeWithSelector(Executor.UnauthorizedCaller.selector, address(this)));
        executor.execute(address(0), 1, party, payload);
    }

    function test_Execute_RevertsOnZeroAmount() public {
        bytes memory payload = _payload("tag", address(mockTarget), hex"");

        vm.expectRevert(Executor.ZeroAmount.selector);
        vm.prank(gateway);
        executor.execute(address(0), 0, party, payload);
    }

    function test_Execute_RevertsOnForbiddenTargets() public {
        address[4] memory badTargets = [address(0), address(executor), gateway, vault];
        vm.deal(gateway, 4);

        for (uint256 i = 0; i < badTargets.length; i++) {
            bytes memory payload = _payload("tag", badTargets[i], hex"");
            vm.expectRevert(abi.encodeWithSelector(Executor.ForbiddenTarget.selector, badTargets[i]));
            vm.prank(gateway);
            executor.execute{value: 1}(address(0), 1, party, payload);
        }
    }

    function test_Execute_RevertsOnNativeValueMismatch() public {
        bytes memory payload = _payload("tag", address(mockTarget), hex"");

        // Native funding with msg.value != amount.
        vm.deal(gateway, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(Executor.InvalidNativeValue.selector, 2 ether, 1 ether));
        vm.prank(gateway);
        executor.execute{value: 1 ether}(address(0), 2 ether, party, payload);

        // ERC-20 funding with nonzero msg.value.
        vm.expectRevert(abi.encodeWithSelector(Executor.InvalidNativeValue.selector, 0, 1));
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
        vm.expectRevert(Executor.TargetCallFailed.selector);
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

    // ------------------------------------------------------------------
    // Routing allowlist
    // ------------------------------------------------------------------

    function test_Execute_RevertsOnUnallowlistedTarget() public {
        MockTarget stranger = new MockTarget();
        bytes memory payload = _payload("tag", address(stranger), hex"12345678");

        vm.deal(gateway, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(Executor.ForbiddenTarget.selector, address(stranger)));
        vm.prank(gateway);
        executor.execute{value: 1 ether}(address(0), 1 ether, party, payload);
    }

    function test_Execute_RevertsOnUnallowlistedSelector() public {
        bytes memory payload = _payload("tag", address(mockTarget), hex"deadbeef");

        vm.deal(gateway, 1 ether);
        vm.expectRevert(
            abi.encodeWithSelector(Executor.ForbiddenSelector.selector, address(mockTarget), bytes4(0xdeadbeef))
        );
        vm.prank(gateway);
        executor.execute{value: 1 ether}(address(0), 1 ether, party, payload);
    }

    function test_Execute_SelectorAllowlistIsPerTarget() public {
        MockTarget other = new MockTarget();
        executor.setTarget(address(other), true);
        // 0x12345678 is allowed on mockTarget but was never allowed on `other`.

        bytes memory payload = _payload("tag", address(other), hex"12345678");
        vm.deal(gateway, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(Executor.ForbiddenSelector.selector, address(other), bytes4(0x12345678)));
        vm.prank(gateway);
        executor.execute{value: 1 ether}(address(0), 1 ether, party, payload);
    }

    function test_Execute_RevokedTargetBecomesUnreachable() public {
        executor.setTarget(address(mockTarget), false);

        bytes memory payload = _payload("tag", address(mockTarget), hex"12345678");
        vm.deal(gateway, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(Executor.ForbiddenTarget.selector, address(mockTarget)));
        vm.prank(gateway);
        executor.execute{value: 1 ether}(address(0), 1 ether, party, payload);
    }

    function test_SetTarget_OnlyOwner() public {
        address stranger = makeAddr("stranger");
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        vm.prank(stranger);
        executor.setTarget(address(mockTarget), true);
    }

    function test_SetSelector_OnlyOwner() public {
        address stranger = makeAddr("stranger");
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        vm.prank(stranger);
        executor.setSelector(address(mockTarget), 0x12345678, true);
    }

    function test_SetTarget_RejectsStructurallyForbiddenTargets() public {
        address[3] memory bad = [address(0), address(executor), vault];
        for (uint256 i = 0; i < bad.length; i++) {
            vm.expectRevert(abi.encodeWithSelector(Executor.ForbiddenTarget.selector, bad[i]));
            executor.setTarget(bad[i], true);
        }
    }

    // ------------------------------------------------------------------
    // Baseline floor
    // ------------------------------------------------------------------

    /// @notice Defence in depth behind the allowlist. If an allowlisted target can move the
    /// executor's own balance -- the token contract itself, or a router exposing a `sweepToken`
    /// style helper -- spending below the pre-execution balance reverts the whole execution rather
    /// than silently paying out a short refund. Encoded here as the worst case: the funded asset
    /// allowlisted as its own routing target.
    function test_Execute_RevertsWhenTargetSpendsBelowBaseline() public {
        uint256 stranded = 500e18;
        uint256 amount = 1;
        token.mint(address(executor), stranded);

        executor.setTarget(address(token), true);
        executor.setSelector(address(token), IERC20.transfer.selector, true);

        token.mint(vault, amount);
        vm.prank(vault);
        token.approve(address(executor), amount);

        address thief = makeAddr("thief");
        bytes memory callData = abi.encodeCall(IERC20.transfer, (thief, stranded + amount));
        bytes memory payload = _payload("drain", address(token), callData);

        vm.expectRevert(abi.encodeWithSelector(Executor.BaselineViolated.selector, stranded, 0));
        vm.prank(gateway);
        executor.execute(address(token), amount, party, payload);

        assertEq(token.balanceOf(thief), 0, "no residual escaped");
        assertEq(token.balanceOf(address(executor)), stranded, "stranded balance intact");
    }

    /// @notice A target that spends only what this execution funded stays within the floor.
    function test_Execute_TargetMaySpendExactlyItsFunding() public {
        uint256 stranded = 500e18;
        uint256 amount = 10e18;
        token.mint(address(executor), stranded);

        DrainingTarget drainer = new DrainingTarget();
        executor.setTarget(address(drainer), true);
        executor.setSelector(address(drainer), DrainingTarget.drain.selector, true);

        token.mint(vault, amount);
        vm.prank(vault);
        token.approve(address(executor), amount);

        address sink = makeAddr("sink");
        bytes memory callData = abi.encodeCall(DrainingTarget.drain, (address(token), sink, amount));
        bytes memory payload = _payload("spend", address(drainer), callData);

        vm.prank(gateway);
        executor.execute(address(token), amount, party, payload);

        assertEq(token.balanceOf(sink), amount, "target consumed its funding");
        assertEq(token.balanceOf(address(executor)), stranded, "stranded balance untouched");
        assertEq(token.balanceOf(vault), 0, "nothing refunded, nothing over-paid");
    }

    function test_RoutingPayload_FieldOrderGoldenVector() public pure {
        RoutingPayload memory samplePayload = RoutingPayload({
            protocolTag: "test",
            target: 0x000000000000000000000000000000000000dEaD,
            callData: hex"12345678",
            arbitaryData: bytes("")
        });

        bytes32 expected = 0xd034e7b461cd9c424bcaf82fc75a89a3dc18307a6ad398168ee4aa451aba4ca4;
        assertEq(keccak256(abi.encode(samplePayload)), expected);
    }
}
