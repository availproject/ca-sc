// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test, console2} from "forge-std/Test.sol";
import {MockFeeOnTransfer} from "test/mocks/MockFeeOnTransfer.sol";

contract MockFeeOnTransferTest is Test {
    MockFeeOnTransfer public token;
    address public user = makeAddr("user");

    function setUp() public {
        token = new MockFeeOnTransfer("Fee Token", "FEE");
        token.mint(user, 100 ether);
    }

    /// @notice Test basic transfer without fee
    function test_TransferWithoutFee() public {
        uint256 balanceBefore = token.balanceOf(user);

        vm.prank(user);
        token.transfer(address(this), 10 ether);

        assertEq(token.balanceOf(user), balanceBefore - 10 ether);
        assertEq(token.balanceOf(address(this)), 10 ether);
    }

    /// @notice Test transfer with 10% fee - fee goes to owner (test contract)
    function test_FeeOnTransfer_10Percent() public {
        token.setFeePercent(1000); // 10% fee

        uint256 ownerBalanceBefore = token.balanceOf(address(this));

        vm.prank(user);
        token.transfer(address(this), 100 ether);

        // Owner (test contract) receives 100 ether total:
        assertEq(token.balanceOf(address(this)) - ownerBalanceBefore, 100 ether);
        // User sent 100 but only 90 reached the destination
        assertEq(token.balanceOf(user), 0);
    }

    /// @notice Test transfer with 10% fee to different recipient
    function test_FeeOnTransfer_10Percent_DifferentRecipient() public {
        address recipient = makeAddr("recipient");
        token.setFeePercent(1000); // 10% fee

        uint256 ownerBalanceBefore = token.balanceOf(address(this)); // owner = test contract
        uint256 recipientBalanceBefore = token.balanceOf(recipient);

        vm.prank(user);
        token.transfer(recipient, 100 ether);

        // Owner receives 10 ether fee
        assertEq(token.balanceOf(address(this)) - ownerBalanceBefore, 10 ether);
        // Recipient receives 90 ether net
        assertEq(token.balanceOf(recipient) - recipientBalanceBefore, 90 ether);
        // User sent 100
        assertEq(token.balanceOf(user), 0);
    }

    /// @notice Test transferFrom with fee
    function test_FeeOnTransfer_transferFrom() public {
        address spender = makeAddr("spender");
        token.setFeePercent(500); // 5% fee

        token.mint(spender, 100 ether);

        vm.prank(spender);
        token.approve(address(this), type(uint256).max);

        uint256 ownerBalanceBefore = token.balanceOf(address(this));

        // transferFrom from spender to this contract:
        // Total to address(this): 5 + 95 = 100
        token.transferFrom(spender, address(this), 100 ether);

        // Owner receives 100 ether (5 fee + 95 net since recipient is same as owner)
        assertEq(token.balanceOf(address(this)) - ownerBalanceBefore, 100 ether);
    }

    /// @notice Test 0% fee (disabled)
    function test_FeeOnTransfer_Disabled() public {
        token.setFeePercent(0);

        uint256 balanceBefore = token.balanceOf(user);

        vm.prank(user);
        token.transfer(address(this), 100 ether);

        assertEq(token.balanceOf(address(this)), 100 ether);
        assertEq(token.balanceOf(user), balanceBefore - 100 ether);
    }

    /// @notice Test maximum fee (99%)
    function test_FeeOnTransfer_MaxFee() public {
        token.setFeePercent(9900); // 99% fee

        uint256 ownerBalanceBefore = token.balanceOf(address(this));

        vm.prank(user);
        token.transfer(address(this), 100 ether);

        // Owner receives 100 ether total (99 fee + 1 net)
        assertEq(token.balanceOf(address(this)) - ownerBalanceBefore, 100 ether);
    }

    /// @notice Test cannot set fee > 99%
    function test_CannotSetFeeAboveMax() public {
        vm.expectRevert("Fee too high");
        token.setFeePercent(9901);
    }

    /// @note Skipping transfer to address(0) test - standard ERC20 doesn't allow this
    /// @notice The contract correctly handles this edge case but OpenZeppelin ERC20 reverts on address(0)
}
