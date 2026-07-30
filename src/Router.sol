// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

import {ExternalRequest, ExternalSourcePair, Party, Universe} from "./types.sol";
import {IExternalIntentExecutor} from "./interfaces/IExternalIntentExecutor.sol";

/// @title Router (ExternalIntentGatewayV1)
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Gateway for executing externally settled intents. Verifies the External RFF EIP-191
/// signature, consumes one source entry, acquires exactly the signed source amount, and funds
/// and invokes its immutable Executor with the hash-committed routing payload.
/// @dev Immutable and unowned by design: no initializer, proxy, owner, roles, pause switch, or
/// upgrade entry point. MUST NOT decode RoutingPayload; payload interpretation happens only in
/// the Executor. A new version is a new Router/Executor deployment pair.
contract Router is ReentrancyGuardTransient {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    /// @notice The immutable ExternalIntentExecutor funded and invoked by this gateway.
    address public immutable executor;
    address public immutable vault;

    /// @dev EIP-191 message prefix for External RFF signatures. Currently identical to the
    /// Vault prefix, so one signed message validates on both the Vault and this gateway.
    string private constant SIGNATURE_PREFIX = "Sign this intent to proceed \n";

    mapping(uint256 => bool) public depositNonce;

    // External intent errors.
    error ZeroAddress();
    error InvalidSourceIndex(uint256 sourceIndex);
    error InvalidParty();
    error DuplicateEvmParty();
    error NonCanonicalAddress(bytes32 encoded);
    error InvalidSignature();
    error InvalidUniverse(Universe universe);
    error InvalidChain(uint256 expected, uint256 actual);
    error RequestExpired(uint256 expiry);
    error ZeroAmount();
    error UnsupportedFee(uint256 fee);
    error PayloadHashMismatch(bytes32 expected, bytes32 actual);
    error NonceBoundToDifferentRequest(uint256 nonce, bytes32 expectedRequestHash, bytes32 actualRequestHash);
    error SourceAlreadyConsumed(bytes32 requestHash, uint256 sourceIndex);
    error InvalidPermitData();
    error InsufficientAllowance(uint256 required, uint256 actual);
    error InvalidNativeValue(uint256 expected, uint256 actual);
    error NonExactTransfer(uint256 expected, uint256 actual);
    error UnauthorizedCaller(address caller);
    error ForbiddenTarget(address target);
    error InvalidApproval(address token, uint256 amount);
    error TargetCallFailed();
    error NativeTransferFailed(address recipient, uint256 amount);
    error AlreadyProcessed();
    error InvalidSender();

    /// @notice Canonical execution record for one source entry. Exactly one per execution.
    /// @param requestHash Raw External RFF request hash (distinct from the EIP-191 digest)
    /// @param sourceIndex Index of the executed source entry
    /// @param party The signing EVM party that funded the execution
    /// @param asset The funded asset (address(0) for native)
    /// @param amount The signed source amount
    /// @param payloadHash The committed keccak256 of the routing payload
    /// @param caller The user or relayer that submitted the transaction
    event Executed(
        bytes32 indexed requestHash,
        uint256 indexed sourceIndex,
        address indexed party,
        address asset,
        uint256 amount,
        bytes32 payloadHash,
        address caller
    );

    /// @notice Deploys the gateway bound to its immutable executor.
    /// @dev The address is prediction-derived and verified by deployment tooling; it cannot be
    /// changed after deployment.
    /// @param executor_ The ExternalIntentExecutor address of this deployment pair
    constructor(address executor_, address vault_) {
        if (executor_ == address(0) || vault_ == address(0)) revert ZeroAddress();
        executor = executor_;
        vault = vault_;
    }

    /// @dev Accepts native currency returned by the executor after execution; the balance is
    /// swept to the party before {execute} returns.
    receive() external payable {}

    /// @notice Executes one source entry of an External RFF request.
    /// @dev Replay protection is written before the first external call, and any failure
    /// reverts the whole transaction.
    /// @param request The signed External RFF request
    /// @param signature EIP-191 signature of the single EVM party over the request
    /// @param sourceIndex Index of the source entry to execute
    /// @param payload ABI-encoded RoutingPayload; keccak256(payload) must equal source.payloadHash
    /// @param authorization Funding authorization byte stream for ERC-20 sources: empty to use
    /// the party's existing allowance, or abi.encode(value, deadline, v, r, s) for EIP-2612
    function execute(
        ExternalRequest calldata request,
        bytes calldata signature,
        uint256 sourceIndex,
        bytes calldata payload,
        bytes calldata authorization
    ) external payable nonReentrant {
        if (msg.sender != vault) revert InvalidSender();
        if (sourceIndex >= request.sources.length) revert InvalidSourceIndex(sourceIndex);

        address party = _selectParty(request.parties);

        bytes32 requestHash = _hashRequest(request);
        if (_signatureDigest(requestHash).recover(signature) != party) revert InvalidSignature();

        ExternalSourcePair calldata source = request.sources[sourceIndex];
        if (source.universe != Universe.ETHEREUM) revert InvalidUniverse(source.universe);
        if (source.chainID != block.chainid) revert InvalidChain(source.chainID, block.chainid);
        if (block.timestamp >= request.expiry) revert RequestExpired(request.expiry);
        if (source.value == 0) revert ZeroAmount();
        if (source.fee != 0) revert UnsupportedFee(source.fee);
        bytes32 payloadHash = keccak256(payload);
        if (payloadHash != source.payloadHash) {
            revert PayloadHashMismatch(source.payloadHash, payloadHash);
        }

        uint256 depositKey = _depositNonceKey(request.nonce, sourceIndex);

        if (depositNonce[depositKey]) revert AlreadyProcessed();

        depositNonce[depositKey] = true;

        address asset = _acquireFunding(source, party, authorization);
        _fundExecutor(asset, source.value, party, payload);

        // Defensive sweep of any funded asset unexpectedly held by this contract or returned to this contract by executor.
        _sweepFundedAsset(asset, party);

        // Canonical execution event.
        emit Executed(requestHash, sourceIndex, party, asset, source.value, source.payloadHash, msg.sender);
    }

    /// @notice Computes the raw External RFF request hash.
    /// @dev Normal ABI encoding of arrays of tuples; never packed encoding.
    /// @param request The External RFF request
    /// @return The keccak256 request identifier used by storage, the API, and the Executed event
    function hashRequest(ExternalRequest calldata request) external pure returns (bytes32) {
        return _hashRequest(request);
    }

    /// @notice Computes the EIP-191 signature digest for a request hash.
    /// @param requestHash The raw request hash
    /// @return The digest the EVM party signs with the v1 prefix
    function signatureDigest(bytes32 requestHash) external pure returns (bytes32) {
        return _signatureDigest(requestHash);
    }

    /// @dev Selects the first EVM party in the parties array.
    function _selectParty(Party[] calldata parties) internal pure returns (address party) {
        for (uint256 i = 0; i < parties.length; ++i) {
            if (parties[i].universe == Universe.ETHEREUM) {
                return (address(uint160(uint256(parties[i].address_))));
            }
        }
        revert InvalidParty();
    }

    function _hashRequest(ExternalRequest calldata request) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                "nexusExternalRouter",
                request.sources,
                request.destinationUniverse,
                request.destinationChainID,
                request.recipientAddress,
                request.destinations,
                request.nonce,
                request.expiry,
                request.parties,
                request.arbitaryData
            )
        );
    }

    function _depositNonceKey(uint256 nonce, uint256 sourceIndex) private pure returns (uint256) {
        return uint256(keccak256(abi.encode(nonce, sourceIndex)));
    }

    function _signatureDigest(bytes32 requestHash) internal pure returns (bytes32) {
        return MessageHashUtils.toEthSignedMessageHash(
            abi.encodePacked(SIGNATURE_PREFIX, Strings.toHexString(uint256(requestHash), 32))
        );
    }

    /// @dev Validates and acquires exact funding. Returns the funded asset, or address(0) for
    /// the native asset.
    function _acquireFunding(ExternalSourcePair calldata source, address party, bytes calldata authorization)
        internal
        returns (address asset)
    {
        if (source.contractAddress == bytes32(0)) {
            if (authorization.length != 0) revert InvalidPermitData();
            if (msg.value != source.value) revert InvalidNativeValue(source.value, msg.value);
            return address(0);
        }

        if (uint256(source.contractAddress) >> 160 != 0) revert NonCanonicalAddress(source.contractAddress);
        if (msg.value != 0) revert InvalidNativeValue(0, msg.value);

        asset = address(uint160(uint256(source.contractAddress)));
        IERC20 token = IERC20(asset);
        uint256 balanceBefore = token.balanceOf(address(this));

        if (authorization.length == 0) {
            token.safeTransferFrom(party, address(this), source.value);
        } else {
            _acquireWithPermit(token, party, source.value, authorization);
        }

        uint256 received = token.balanceOf(address(this)) - balanceBefore;
        if (received != source.value) revert NonExactTransfer(source.value, received);
    }

    /// @dev Acquires funding via an EIP-2612 permit on top of any existing allowance. A reverted
    /// permit call is non-fatal if the resulting allowance is sufficient, so a previously used
    /// or front-run permit does not block execution.
    function _acquireWithPermit(IERC20 token, address party, uint256 amount, bytes calldata data) internal {
        (uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) =
            abi.decode(data, (uint256, uint256, uint8, bytes32, bytes32));
        if (value < amount) revert InsufficientAllowance(amount, value);

        if (token.allowance(party, address(this)) < amount) {
            try IERC20Permit(address(token)).permit(party, address(this), value, deadline, v, r, s) {}
                catch {
                // Non-fatal: the allowance check below remains authoritative.
            }
        }

        uint256 allowance = token.allowance(party, address(this));
        if (allowance < amount) revert InsufficientAllowance(amount, allowance);

        token.safeTransferFrom(party, address(this), amount);
    }

    /// @dev Funds the immutable executor with exactly the signed amount and invokes it. Both
    /// funding hops require exact balance deltas.
    function _fundExecutor(address asset, uint256 amount, address party, bytes calldata payload) internal {
        if (asset == address(0)) {
            IExternalIntentExecutor(executor).execute{value: amount}(address(0), amount, party, payload);
            return;
        }

        IERC20 token = IERC20(asset);
        uint256 balanceBefore = token.balanceOf(executor);
        token.safeTransfer(executor, amount);
        uint256 received = token.balanceOf(executor) - balanceBefore;
        if (received != amount) revert NonExactTransfer(amount, received);

        IExternalIntentExecutor(executor).execute(asset, amount, party, payload);
    }

    /// @dev Defensive cleanup: transfers any balance of the funded asset held by this contract
    /// after execution back to the party. Not a normal path.
    function _sweepFundedAsset(address asset, address party) internal {
        if (asset == address(0)) {
            uint256 residual = address(this).balance;
            if (residual > 0) {
                (bool sent,) = party.call{value: residual}("");
                if (!sent) revert NativeTransferFailed(party, residual);
            }
        } else {
            uint256 residual = IERC20(asset).balanceOf(address(this));
            if (residual > 0) {
                IERC20(asset).safeTransfer(party, residual);
            }
        }
    }
}
