// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface IERC7914 {
    function transferFromNative(address from, address recipient, uint256 amount) external returns (bool);
}

contract ERC20Sweeper {
    using SafeERC20 for IERC20;

    function sweepERC20(IERC20 token, address to) external {
        uint256 bal = token.balanceOf(msg.sender);
        if (bal == 0) {
            return;
        }
        token.safeTransferFrom(msg.sender, to, bal);
    }

    function sweepERC7914(address user, address to) external {
        uint256 bal = user.balance;
        if (bal == 0) {
            return;
        }
        bool ok = IERC7914(user).transferFromNative(user, to, bal);
        if (!ok) {
            revert("ERC7914 transferFromNative reverted");
        }
    }
}