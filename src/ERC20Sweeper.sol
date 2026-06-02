// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title ERC7914 Token Interface
/// @notice Interface for ERC7914 token standard supporting native token transfers
interface IERC7914 {
    /// @notice Transfers native tokens from one address to another
    /// @param from The address to transfer from
    /// @param recipient The address to transfer to
    /// @param amount The amount to transfer
    /// @return True if the transfer succeeded
    function transferFromNative(address from, address recipient, uint256 amount) external returns (bool);
}

/// @title ERC20Sweeper
/// @notice Utility contract for sweeping ERC20 token balances from msg.sender to a specified address
/// @dev Uses SafeERC20 for safe transfers. Skips silently if balance is zero.
contract ERC20Sweeper {
    using SafeERC20 for IERC20;

    /// @notice Sweeps the entire ERC20 token balance of msg.sender to the specified address
    /// @dev Returns early if balance is zero. Uses SafeERC20 for safe transfer.
    /// @param token The ERC20 token to sweep
    /// @param to The address to receive the swept tokens
    function sweepERC20(IERC20 token, address to) external {
        uint256 bal = token.balanceOf(msg.sender);
        if (bal == 0) {
            return;
        }
        token.safeTransferFrom(msg.sender, to, bal);
    }

    /// @notice Sweeps the entire native token balance of msg.sender to the specified address via ERC7914
    /// @dev Returns early if balance is zero. Reverts if ERC7914 transfer fails.
    /// @param to The address to receive the swept native tokens
    function sweepERC7914(address to) external {
        uint256 bal = msg.sender.balance;
        if (bal == 0) {
            return;
        }
        bool ok = IERC7914(msg.sender).transferFromNative(msg.sender, to, bal);
        if (!ok) {
            revert("ERC7914 transferFromNative reverted");
        }
    }
}
