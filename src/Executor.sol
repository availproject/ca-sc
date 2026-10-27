// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

import {IExternalIntentExecutor} from "./interfaces/IExternalIntentExecutor.sol";
import {RoutingPayload} from "./types.sol";

/// @title Executor (ExternalIntentExecutorV1)
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Executes hash-committed routing payloads on behalf of the immutable external intent
/// gateway. Validates the funding envelope, grants and clears any bounded target approval,
/// invokes the routing target, and refunds every residual balance to the signed party.
/// @dev Not upgradeable: no initializer, proxy, or upgrade entry point. The only contract
/// permitted to decode RoutingPayload. Ownership gates {sweep} and the routing allowlist; it
/// confers no power to move value to an address of the owner's choosing.
///
/// This contract holds no custody between transactions and never assumes it starts empty. Both
/// `receive` and plain ERC-20 transfers let anyone raise its balance at any time, and a routing
/// target may pay output in an asset the caller was not funded with. Value that no execution can
/// attribute leaves through {sweep}, which is owner-gated and has a fixed destination.
///
/// Two rules keep a payload from reaching that value. First, {execute} calls only an allowlisted
/// (target, selector) pair, so a payload cannot direct this contract at an arbitrary token to
/// transfer or approve its balance away. Second, every payout is measured as the delta this
/// execution created and the pre-execution balance is asserted as a floor, so a target that
/// spends below it reverts rather than silently draining funds that predate the call.
contract Executor is IExternalIntentExecutor, Ownable, ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    /// @notice The immutable protocol vault excluded as a routing target.
    address public immutable vault;

    /// @notice Routing targets {execute} is permitted to call.
    /// @dev A payload commits to a target by hash, but the signer of that hash may be the
    /// attacker. Restricting the callable set on-chain is what stops a payload from pointing this
    /// contract at an arbitrary token contract under its own identity.
    mapping(address target => bool allowed) public allowedTarget;

    /// @notice Function selectors {execute} is permitted to invoke on a given routing target.
    /// @dev Keyed per target rather than globally so that allowlisting an entry point on one
    /// protocol does not implicitly allow the same selector elsewhere. Calldata shorter than four
    /// bytes maps to `bytes4(0)`, which must be allowlisted explicitly to permit a bare
    /// value-only call.
    mapping(address target => mapping(bytes4 selector => bool allowed)) public allowedSelector;

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

    /// @notice Emitted when an unattributable balance is moved out to the vault.
    /// @param asset The swept asset (address(0) for native)
    /// @param amount The amount transferred to the vault
    event Swept(address indexed asset, uint256 amount);

    /// @notice Emitted when a routing target is added to or removed from the allowlist.
    /// @param target The routing target
    /// @param allowed Whether the target may now be called
    event TargetAllowed(address indexed target, bool allowed);

    /// @notice Emitted when a selector is added to or removed from a target's allowlist.
    /// @param target The routing target the selector belongs to
    /// @param selector The four-byte function selector
    /// @param allowed Whether the selector may now be invoked on that target
    event SelectorAllowed(address indexed target, bytes4 indexed selector, bool allowed);

    /// @notice Thrown when the vault address supplied at deployment is the zero address.
    error ZeroAddress();

    /// @notice Thrown when any account other than the vault calls `execute`.
    /// @param caller The rejected caller
    error UnauthorizedCaller(address caller);

    /// @notice Thrown when the payload targets the zero address, this contract, the vault, or an
    /// address that is not on the routing allowlist.
    /// @param target The rejected routing target
    error ForbiddenTarget(address target);

    /// @notice Thrown when the payload invokes a selector not allowlisted for its target.
    /// @param target The routing target
    /// @param selector The rejected selector
    error ForbiddenSelector(address target, bytes4 selector);

    /// @notice Thrown when a routing target spent balance that predates this execution.
    /// @param baseline The balance this execution had no title to
    /// @param actual The balance remaining after the target call
    error BaselineViolated(uint256 baseline, uint256 actual);

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
    /// @param owner_ The account permitted to call {sweep}
    constructor(address vault_, address owner_) Ownable(owner_) {
        if (vault_ == address(0)) revert ZeroAddress();
        vault = vault_;
    }

    /// @dev Accepts native currency so protocol refunds can return to this contract.
    receive() external payable {}

    /// @inheritdoc IExternalIntentExecutor
    /// @dev ERC-20 funding is pulled from the vault's allowance so the pre-funding balance can be
    /// observed rather than inferred from a caller-supplied `amount`, and so the exact-transfer
    /// check lives in this immutable contract rather than in the upgradeable vault. The residual
    /// paid out is the delta against that baseline, so a balance this call did not create is
    /// never paid out by it, and a native-funded execution still performs exactly one native
    /// transfer.
    function execute(address asset, uint256 amount, address party, bytes calldata payload)
        external
        payable
        override
        nonReentrant
    {
        if (msg.sender != vault) revert UnauthorizedCaller(msg.sender);

        RoutingPayload memory routing = abi.decode(payload, (RoutingPayload));

        if (routing.target == address(0) || routing.target == address(this) || routing.target == vault) {
            revert ForbiddenTarget(routing.target);
        }
        if (!allowedTarget[routing.target]) revert ForbiddenTarget(routing.target);

        bytes4 selector = _selectorOf(routing.callData);
        if (!allowedSelector[routing.target][selector]) revert ForbiddenSelector(routing.target, selector);

        if (amount == 0) revert ZeroAmount();

        // Balance of the funded asset this execution has no title to. Measured before the funding
        // arrives, so nothing already sitting here is attributed to the current party.
        uint256 baseline;

        if (asset == address(0)) {
            if (msg.value != amount) revert InvalidNativeValue(amount, msg.value);

            // Native funding arrives with the call and cannot be snapshotted beforehand.
            // `msg.value` is what the EVM actually credited, not a figure the caller asserted.
            baseline = address(this).balance - msg.value;
        } else {
            if (msg.value != 0) revert InvalidNativeValue(0, msg.value);

            baseline = IERC20(asset).balanceOf(address(this));
            IERC20(asset).safeTransferFrom(vault, address(this), amount);

            uint256 funded = IERC20(asset).balanceOf(address(this)) - baseline;
            if (funded != amount) revert NonExactTransfer(amount, funded);

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

        // The baseline is a floor, not just a subtrahend. A target that ends the call holding less
        // than the balance that predated it has spent value this execution had no title to, so the
        // whole execution reverts rather than silently paying out a short refund.
        if (asset == address(0)) {
            uint256 nativeBalance = address(this).balance;
            if (nativeBalance < baseline) revert BaselineViolated(baseline, nativeBalance);
            if (nativeBalance > baseline) {
                uint256 refund = nativeBalance - baseline;
                (bool sent,) = vault.call{value: refund}("");
                if (!sent) revert NativeTransferFailed(vault, refund);
            }
        } else {
            IERC20(asset).forceApprove(routing.target, 0);

            uint256 tokenBalance = IERC20(asset).balanceOf(address(this));
            if (tokenBalance < baseline) revert BaselineViolated(baseline, tokenBalance);
            if (tokenBalance > baseline) {
                IERC20(asset).safeTransfer(vault, tokenBalance - baseline);
            }
        }

        emit PayloadExecuted(keccak256(payload), routing.target, party, asset, amount, routing.protocolTag);
    }

    /// @notice Adds or removes a routing target from the allowlist.
    /// @dev Removing a target leaves its selector entries in place; both must pass, so a removed
    /// target is unreachable regardless. The three structurally forbidden targets are rejected
    /// here as well as in {execute} so the allowlist can never contain them.
    /// @param target The routing target
    /// @param allowed Whether the target may be called
    function setTarget(address target, bool allowed) external onlyOwner {
        if (target == address(0) || target == address(this) || target == vault) {
            revert ForbiddenTarget(target);
        }
        allowedTarget[target] = allowed;
        emit TargetAllowed(target, allowed);
    }

    /// @notice Adds or removes a selector from a routing target's allowlist.
    /// @dev `bytes4(0)` covers calldata shorter than four bytes, which is how a bare native
    /// transfer to a target reaches it.
    /// @param target The routing target the selector belongs to
    /// @param selector The four-byte function selector
    /// @param allowed Whether the selector may be invoked on that target
    function setSelector(address target, bytes4 selector, bool allowed) external onlyOwner {
        allowedSelector[target][selector] = allowed;
        emit SelectorAllowed(target, selector, allowed);
    }

    /// @dev Reads the leading four bytes of `callData`, or `bytes4(0)` when it is shorter. Memory
    /// is only read once the length guarantees four bytes exist, so no trailing padding is
    /// interpreted as part of the selector.
    function _selectorOf(bytes memory callData) private pure returns (bytes4 selector) {
        if (callData.length < 4) return bytes4(0);
        assembly ("memory-safe") {
            selector := mload(add(callData, 0x20))
        }
    }

    /// @inheritdoc IExternalIntentExecutor
    /// @dev Recovers value no execution can attribute: assets a routing target paid out in a
    /// denomination the caller was not funded with, and refunds that arrive after `execute` has
    /// returned. The destination is fixed to the vault, so ownership cannot redirect value to an
    /// address of the owner's choosing. `nonReentrant` keeps a routing target from sweeping
    /// mid-execution, which would move an unattributable balance into the vault where the
    /// residual sweep of the currently executing intent would credit it to that intent's party.
    function sweep(address asset) external onlyOwner nonReentrant returns (uint256 amount) {
        if (asset == address(0)) {
            amount = address(this).balance;
            if (amount > 0) {
                (bool sent,) = vault.call{value: amount}("");
                if (!sent) revert NativeTransferFailed(vault, amount);
            }
        } else {
            amount = IERC20(asset).balanceOf(address(this));
            if (amount > 0) {
                IERC20(asset).safeTransfer(vault, amount);
            }
        }

        emit Swept(asset, amount);
    }
}
