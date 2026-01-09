// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {ERC20Sweeper} from "../src/ERC20Sweeper.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract ERC20SweeperTest is Test {
    ERC20Sweeper public sweeper;
    MockERC20 public token;

    address public user;
    address public recipient;

    function setUp() public {
        user = makeAddr("user");
        recipient = makeAddr("recipient");

        sweeper = new ERC20Sweeper();
        token = new MockERC20("Test Token", "TEST", 18);

        token.mint(user, 1000e18);
    }

    function test_SweepERC20_TransfersEntireBalance() public {
        vm.prank(user);
        token.approve(address(sweeper), type(uint256).max);

        uint256 userBalanceBefore = token.balanceOf(user);

        vm.prank(user);
        sweeper.sweepERC20(token, recipient);

        assertEq(token.balanceOf(user), 0);
        assertEq(token.balanceOf(recipient), userBalanceBefore);
    }

    function test_SweepERC20_DoesNothingOnZeroBalance() public {
        address emptyUser = makeAddr("emptyUser");

        vm.prank(emptyUser);
        token.approve(address(sweeper), type(uint256).max);

        vm.prank(emptyUser);
        sweeper.sweepERC20(token, recipient);

        assertEq(token.balanceOf(recipient), 0);
    }

    function test_SweepERC20_Fuzz(uint256 amount) public {
        vm.assume(amount > 0 && amount < type(uint128).max);

        address fuzzUser = makeAddr("fuzzUser");
        token.mint(fuzzUser, amount);

        vm.prank(fuzzUser);
        token.approve(address(sweeper), type(uint256).max);

        vm.prank(fuzzUser);
        sweeper.sweepERC20(token, recipient);

        assertEq(token.balanceOf(fuzzUser), 0);
        assertEq(token.balanceOf(recipient), amount);
    }
}
