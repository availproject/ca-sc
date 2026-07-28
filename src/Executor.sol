// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {IExternalIntentExecutor} from "./interfaces/IExternalIntentExecutor.sol";
import {RoutingPayload} from "./types.sol";
import {Router} from "./Router.sol";

/// @title Executor (ExternalIntentExecutorV1)
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Executes hash-committed routing payloads on behalf of the immutable external intent
/// gateway. Validates the funding envelope, grants and clears any bounded target approval,
/// invokes the routing target, and refunds every residual balance to the signed party.
/// @dev Immutable and unowned by design: no initializer, proxy, owner, roles, pause switch, or
/// upgrade entry point. The only contract permitted to decode RoutingPayload.
contract Executor is IExternalIntentExecutor {
    using SafeERC20 for IERC20;

    /// @notice The immutable gateway permitted to invoke {execute}.
    address public immutable gateway;

    /// @notice The immutable protocol vault excluded as a routing target.
    address public immutable vault;

    /// @notice Emitted after a routing payload executes successfully.
    /// @param payloadHash The keccak256 of the executed payload
    /// @param target The routing target that was invoked
    /// @param refundRecipient The receiver of all residual funds
    /// @param asset The funded asset (address(0) for native)
    /// @param amount The signed source amount that funded the execution
    /// @param protocolTag The payload's protocol tag
    event PayloadExecuted(
        bytes32 indexed payloadHash,
        address indexed target,
        address indexed refundRecipient,
        address asset,
        uint256 amount,
        string protocolTag
    );

    /// @notice Deploys the executor bound to its immutable gateway and vault.
    /// @param gateway_ The gateway address permitted to invoke {execute}
    /// @param vault_ The protocol vault address excluded as a routing target
    constructor(address gateway_, address vault_) {
        if (gateway_ == address(0) || vault_ == address(0)) revert Router.ZeroAddress();
        gateway = gateway_;
        vault = vault_;
    }

    /// @dev Accepts native currency so protocol refunds can return to this contract.
    receive() external payable {}

    /// @inheritdoc IExternalIntentExecutor
    /// @dev On success the full residual balance of `asset` and the full native balance are
    /// refunded, so a native-funded execution performs exactly one native transfer.
    function execute(address asset, uint256 amount, address refundRecipient, bytes calldata payload)
        external
        payable
        override
    {
        if (msg.sender != gateway) revert Router.UnauthorizedCaller(msg.sender);
        if (refundRecipient == address(0)) revert Router.ZeroAddress();

        RoutingPayload memory p = abi.decode(payload, (RoutingPayload));

        if (p.target == address(0) || p.target == address(this) || p.target == gateway || p.target == vault) {
            revert Router.ForbiddenTarget(p.target);
        }
        if (amount == 0) revert Router.ZeroAmount();

        bool approvalPresent;
        if (asset == address(0)) {
            if (msg.value != amount) revert Router.InvalidNativeValue(amount, msg.value);
            if (p.approval.token != address(0) || p.approval.amount != 0) {
                revert Router.InvalidApproval(p.approval.token, p.approval.amount);
            }
            if (p.nativeValue > amount) revert Router.InvalidNativeValue(amount, p.nativeValue);
        } else {
            if (msg.value != 0) revert Router.InvalidNativeValue(0, msg.value);
            uint256 actualBalance = IERC20(asset).balanceOf(address(this));
            if (actualBalance < amount) revert Router.NonExactTransfer(amount, actualBalance);
            if (p.nativeValue != 0) revert Router.InvalidNativeValue(0, p.nativeValue);

            bool tokenZero = p.approval.token == address(0);
            bool amountZero = p.approval.amount == 0;
            if (tokenZero != amountZero) revert Router.InvalidApproval(p.approval.token, p.approval.amount);
            approvalPresent = !tokenZero;
            if (approvalPresent && (p.approval.token != asset || p.approval.amount > amount)) {
                revert Router.InvalidApproval(p.approval.token, p.approval.amount);
            }
        }

        if (approvalPresent) {
            IERC20(asset).forceApprove(p.target, p.approval.amount);
        }

        (bool ok, bytes memory ret) = p.target.call{value: p.nativeValue}(p.callData);
        if (!ok) {
            if (ret.length > 0) {
                assembly {
                    revert(add(ret, 0x20), mload(ret))
                }
            }
            revert Router.TargetCallFailed();
        }

        if (approvalPresent) {
            IERC20(asset).forceApprove(p.target, 0);
        }

        if (asset != address(0)) {
            uint256 tokenBalance = IERC20(asset).balanceOf(address(this));
            if (tokenBalance > 0) {
                IERC20(asset).safeTransfer(refundRecipient, tokenBalance);
            }
        }
        uint256 bal = address(this).balance;
        if (bal > 0) {
            (bool sent,) = refundRecipient.call{value: bal}("");
            if (!sent) revert Router.NativeTransferFailed(refundRecipient, bal);
        }

        emit PayloadExecuted(keccak256(payload), p.target, refundRecipient, asset, amount, p.protocolTag);
    }

    /// @inheritdoc IExternalIntentExecutor
    function sweep(address asset, address recipient) external override {
        if (recipient == address(0)) revert Router.ZeroAddress();
        if (asset == address(0)) {
            uint256 bal = address(this).balance;
            if (bal > 0) {
                (bool sent,) = recipient.call{value: bal}("");
                if (!sent) revert Router.NativeTransferFailed(recipient, bal);
            }
            return;
        }
        IERC20(asset).safeTransfer(recipient, IERC20(asset).balanceOf(address(this)));
    }
}
