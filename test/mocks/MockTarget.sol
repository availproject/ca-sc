// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/// @title MockTarget
/// @notice Configurable call target for Executor tests. Records the last call it received and
/// can be switched between succeeding, reverting with a custom error, or reverting with empty
/// revert data. Retains any native currency or tokens it receives.
contract MockTarget {
    error MockTargetError(string reason);

    /// @notice The caller of the most recent successful call.
    address public lastCaller;

    /// @notice The calldata of the most recent successful call.
    bytes public lastCallData;

    /// @notice The native value of the most recent successful call.
    uint256 public lastNativeValue;

    /// @dev 0 = succeed, 1 = revert with MockTargetError, 2 = revert with empty data.
    uint8 private revertMode;

    /// @notice Sets the revert behavior for subsequent calls.
    /// @param mode 0 to succeed, 1 to revert with MockTargetError, 2 to revert with empty data
    function setRevertMode(uint8 mode) external {
        revertMode = mode;
    }

    receive() external payable {
        _handle();
    }

    fallback() external payable {
        _handle();
    }

    function _handle() private {
        lastCaller = msg.sender;
        lastCallData = msg.data;
        lastNativeValue = msg.value;

        if (revertMode == 1) {
            revert MockTargetError("mock revert");
        }
        if (revertMode == 2) {
            assembly {
                revert(0, 0)
            }
        }
    }
}
