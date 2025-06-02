// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract ERC20Sweeper {
    using SafeERC20 for IERC20;

    function sweepERC20(IERC20 token, address to) external {
        uint256 bal = token.balanceOf(msg.sender);
        if (bal == 0) {
            return;
        }
        token.safeTransferFrom(msg.sender, to, bal);
    }
}