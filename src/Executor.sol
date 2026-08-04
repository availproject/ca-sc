// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {IExternalIntentExecutor} from "./interfaces/IExternalIntentExecutor.sol";
import {RoutingPayload} from "./types.sol";

/// @title Executor (ExternalIntentExecutorV1)
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Executes hash-committed routing payloads on behalf of the immutable external intent
/// gateway. Validates the funding envelope, grants and clears any bounded target approval,
/// invokes the routing target, and refunds every residual balance to the signed party.
/// @dev Immutable and unowned by design: no initializer, proxy, owner, roles, pause switch, or
/// upgrade entry point. The only contract permitted to decode RoutingPayload.
contract Executor is IExternalIntentExecutor {
    using SafeERC20 for IERC20;

    /// @notice The immutable protocol vault excluded as a routing target.
    address public immutable vault;

    /// @notice Emitted after a routing payload executes successfully.
    /// @param payloadHash The keccak256 of the executed payload
    /// @param target The routing target that was invoked
    /// @param party The signed party whose source entry funded the execution
    /// @param asset The funded asset (address(0) for native)
    /// @param amount The signed source amount that funded the execution
    /// @param protocolTag The payload's protocol tag
    event PayloadExecuted(
        bytes32 indexed payloadHash,
        address indexed target,
        address indexed party,
        address asset,
        uint256 amount,
        string protocolTag
    );

    /// @notice Thrown when the vault address supplied at deployment is the zero address.
    error ZeroAddress();

    /// @notice Thrown when any account other than the vault calls `execute`.
    /// @param caller The rejected caller
    error UnauthorizedCaller(address caller);

    /// @notice Thrown when the payload targets the zero address, this contract, or the vault.
    /// @param target The rejected routing target
    error ForbiddenTarget(address target);

    /// @notice Thrown when the signed source amount is zero.
    error ZeroAmount();

    /// @notice Thrown when the native value attached by the vault does not match the funding mode.
    /// @param expected The required native value
    /// @param actual The native value received
    error InvalidNativeValue(uint256 expected, uint256 actual);

    /// @notice Thrown when the token balance held by this contract is below the signed amount.
    /// @param expected The signed source amount
    /// @param actual The balance actually held
    error NonExactTransfer(uint256 expected, uint256 actual);

    /// @notice Thrown when the routing target reverts without returning any revert data.
    error TargetCallFailed();

    /// @notice Thrown when a native refund to the vault fails.
    /// @param recipient The intended refund recipient
    /// @param amount The refund amount
    error NativeTransferFailed(address recipient, uint256 amount);

    /// @notice Deploys the executor bound to its immutable vault.
    /// @param vault_ The protocol vault address excluded as a routing target
    constructor(address vault_) {
        if (vault_ == address(0)) revert ZeroAddress();
        vault = vault_;
    }

    /// @dev Accepts native currency so protocol refunds can return to this contract.
    receive() external payable {}

    /// @inheritdoc IExternalIntentExecutor
    /// @dev On success the full residual balance of `asset` and the full native balance are
    /// refunded, so a native-funded execution performs exactly one native transfer.
    function execute(address asset, uint256 amount, address party, bytes calldata payload) external payable override {
        if (msg.sender != vault) revert UnauthorizedCaller(msg.sender);

        RoutingPayload memory routing = abi.decode(payload, (RoutingPayload));

        if (routing.target == address(0) || routing.target == address(this) || routing.target == vault) {
            revert ForbiddenTarget(routing.target);
        }
        if (amount == 0) revert ZeroAmount();

        if (asset == address(0)) {
            if (msg.value != amount) revert InvalidNativeValue(amount, msg.value);
        } else {
            if (msg.value != 0) revert InvalidNativeValue(0, msg.value);

            uint256 actualBalance = IERC20(asset).balanceOf(address(this));
            if (actualBalance < amount) revert NonExactTransfer(amount, actualBalance);

            IERC20(asset).forceApprove(routing.target, amount);
        }

        uint256 callValue = asset == address(0) ? amount : 0;
        (bool success, bytes memory returnData) = routing.target.call{value: callValue}(routing.callData);
        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    revert(add(returnData, 0x20), mload(returnData))
                }
            }
            revert TargetCallFailed();
        }

        if (asset == address(0)) {
            uint256 nativeBalance = address(this).balance;
            if (nativeBalance > 0) {
                (bool sent,) = vault.call{value: nativeBalance}("");
                if (!sent) revert NativeTransferFailed(vault, nativeBalance);
            }
        } else {
            IERC20(asset).forceApprove(routing.target, 0);

            uint256 tokenBalance = IERC20(asset).balanceOf(address(this));
            if (tokenBalance > 0) {
                IERC20(asset).safeTransfer(vault, tokenBalance);
            }
        }

        emit PayloadExecuted(keccak256(payload), routing.target, party, asset, amount, routing.protocolTag);
    }
}
