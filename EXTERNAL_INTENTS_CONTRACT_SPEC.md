# External Intents Contract Specification

> Status: Draft  
> Version: 0.1.0  
> RFC: Custom Data Signing (External Intents)  
> Scope: EVM source chains  
> Last updated: July 23, 2026

## 1. Purpose

This document specifies the EVM contracts for executing externally settled intents. It
translates the External Intents RFC into an implementation and review contract for:

- `ExternalIntentGatewayV1`, which verifies user consent, consumes a source entry, and
  acquires exactly the signed source amount; and
- `ExternalIntentExecutor`, which executes the hash-committed routing payload with only that
  entry's funds.

The contracts do not validate protocol-specific delivery semantics. The intent service builds
payloads and the SDK verifies their decoded delivery terms before the user signs. Onchain
contracts enforce authorization, replay protection, source-chain binding, exact funding, and
transaction-scoped fund isolation.

This specification does not change `Request`, its signature prefix, or the Vault
`deposit`/`fulfil`/`settle` flow.

### 1.1 Normative language

The terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

## 2. Design invariants

The implementation MUST preserve all of the following:

1. A source entry executes only when the user signed its exact `payloadHash`.
2. A source entry executes at most once in one Gateway deployment.
3. One nonce identifies one request in one Gateway deployment. Multiple source entries from
   that request may use the nonce without colliding.
4. A failed execution is atomic: consumption, permits, transfers, approvals, and calls all
   revert.
5. The Gateway executes no user-selected call and grants no approval to a user-selected
   address.
6. The Executor receives no user approval and cannot access Vault custody or Gateway-held user
   approvals.
7. An Executor approval is limited to the current entry's ERC-20, limited to the signed source
   amount, and cleared before success is returned.
8. The funded asset remaining after execution is returned to the source-chain party.
9. The Gateway and Executor are immutable and unowned. A new version is a new deployment pair.
10. A malicious payload can put at risk no more than the source amount committed by the signer
    for that execution. Assets accidentally sent to the Executor are outside this guarantee and
    are permissionlessly recoverable.

## 3. Contract set and trust boundaries

### 3.1 `ExternalIntentGatewayV1`

The Gateway:

- verifies the External RFF EIP-191 signature;
- validates the selected source and EVM party;
- binds `nonce` to `requestHash`;
- consumes `(requestHash, sourceIndex)`;
- optionally applies an ERC-20 funding authorization;
- acquires the exact signed amount;
- funds its immutable Executor and invokes it; and
- emits the canonical execution event.

The Gateway MUST NOT decode `RoutingPayload`.

### 3.2 `ExternalIntentExecutor`

The Executor:

- accepts execution only from its immutable Gateway;
- decodes the generic `RoutingPayload` envelope;
- rejects calls to itself, the Gateway, and the Vault;
- optionally grants a bounded, transient approval to `payload.target`;
- calls `payload.target`;
- clears the approval; and
- returns remaining funded asset and native value to the signed party.

It has no owner, upgrade mechanism, registry, or persistent mutable state.

### 3.3 Deployment relationship

Each chain deployment is a fixed pair:

```text
ExternalIntentGatewayV1 --immutable--> ExternalIntentExecutor
ExternalIntentExecutor  --immutable--> ExternalIntentGatewayV1
ExternalIntentExecutor  --immutable--> Vault proxy
```

Because the circular immutable references cannot both be constructor-derived directly, the
deployment MUST use address prediction whose result does not create a circular init-code
dependency. Examples include CREATE3-style deployment or predicting one address from a
deployer nonce and deriving the other with CREATE2. Naively deriving both addresses with
CREATE2 does not satisfy this requirement. Neither address may be set after deployment.

Replacing the Executor requires deploying a new Gateway/Executor pair and updating the intent
service's chain configuration. The contracts themselves contain no pointer that can be
reconfigured.

## 4. ABI types

Types inherited unchanged from `src/types.sol` are shown for clarity. Production code SHOULD
reuse the existing `Universe`, `DestinationPair`, and `Party` declarations.

```solidity
enum Universe {
    ETHEREUM,
    FUEL,
    SOLANA,
    TRON
}

struct ExternalSourcePair {
    Universe universe;
    uint256 chainID;
    bytes32 contractAddress;
    uint256 value;
    uint256 fee;
    bytes32 payloadHash;
}

struct ExternalRequest {
    ExternalSourcePair[] sources;
    Universe destinationUniverse;
    uint256 destinationChainID;
    bytes32 recipientAddress;
    DestinationPair[] destinations;
    uint256 nonce;
    uint256 expiry;
    Party[] parties;
}

struct Approval {
    address token;
    uint256 amount;
}

struct RoutingPayload {
    string protocolTag;
    address target;
    Approval approval;
    uint256 nativeValue;
    bytes callData;
}

enum PermitKind {
    NONE,
    EIP2612,
    PERMIT2
}

struct PermitAuthorization {
    PermitKind kind;
    bytes data;
}

struct EIP2612Authorization {
    uint256 value;
    uint256 deadline;
    uint8 v;
    bytes32 r;
    bytes32 s;
}

struct Permit2Authorization {
    ISignatureTransfer.PermitTransferFrom permit;
    bytes signature;
}
```

Field order is part of the signed and payload ABIs and MUST NOT change within v1.

### 4.1 Address representation

For an EVM source or party, an address is represented as:

```solidity
bytes32(uint256(uint160(evmAddress)))
```

The upper 12 bytes MUST be zero. The Gateway MUST reject non-canonical EVM address encodings
instead of silently truncating them.

The native asset is represented by `bytes32(0)` in `ExternalSourcePair.contractAddress` and by
`address(0)` when passed to the Executor.

### 4.2 Routing payload encoding

`payload` MUST be the exact result of:

```solidity
abi.encode(
    RoutingPayload({
        protocolTag: ...,
        target: ...,
        approval: Approval({token: ..., amount: ...}),
        nativeValue: ...,
        callData: ...
    })
)
```

The commitment stored in a source entry is:

```solidity
source.payloadHash == keccak256(payload)
```

`protocolTag` is for observability only. It is not a registry key and grants no authority.

## 5. Request hash and signature

### 5.1 Request identity

The raw External RFF request hash is:

```solidity
bytes32 requestHash = keccak256(
    abi.encode(
        request.sources,
        request.destinationUniverse,
        request.destinationChainID,
        request.recipientAddress,
        request.destinations,
        request.nonce,
        request.expiry,
        request.parties
    )
);
```

This is the identifier used by the API, Gateway storage, and `Executed` event. It is distinct
from the EIP-191 signature digest.

The encoding intentionally matches the current `Request` hash except that every encoded source
tuple has one trailing `bytes32 payloadHash`. Solidity's normal ABI encoding of arrays of tuples
is used; packed encoding MUST NOT be used.

### 5.2 External signature prefix

The v1 implementation MUST define one byte-exact prefix shared by all v1 Gateways:

```text
Sign this external intent to proceed (v1)
```

The final byte is line feed `0x0a`; there is no space before it. In Solidity:

```solidity
string internal constant SIGNATURE_PREFIX =
    "Sign this external intent to proceed (v1)\n";
```

This prefix is intentionally different from the Vault prefix:

```text
Sign this intent to proceed \n
```

The Vault prefix has a space before its line feed and MUST remain unchanged.

### 5.3 Message and digest

The wallet message bytes are:

```solidity
bytes memory message = abi.encodePacked(
    SIGNATURE_PREFIX,
    Strings.toHexString(uint256(requestHash), 32)
);
```

`Strings.toHexString(..., 32)` produces lowercase `0x` followed by exactly 64 hexadecimal
characters. The signature digest is:

```solidity
bytes32 digest = MessageHashUtils.toEthSignedMessageHash(message);
```

The Gateway MUST recover with OpenZeppelin `ECDSA.recover` and require the recovered EOA to
equal the selected EVM party. ERC-1271 and EIP-7702 account validation are out of scope for v1.

### 5.4 Version behavior

All chains participating in one multi-source request MUST use Gateways with the same signature
prefix. A later incompatible contract fleet MUST use a different prefix.

A chain MUST have at most one production Gateway for a given signature prefix. The External RFF
signature is not bound to a Gateway address, so deploying a second Gateway on the same chain
with the same prefix would create an independent consumption map and allow the same source
entry to execute once on each deployment. Deployment tooling and service configuration MUST
reject duplicate `(chainID, signaturePrefix)` domains.

A prefix bump prevents an old signature from executing on the new Gateway. It cannot invalidate
the signature on an already deployed old Gateway. An old signed request remains executable
there until expiry unless the user revokes its funding authorization.

## 6. Gateway specification

### 6.1 Constructor and immutables

```solidity
constructor(address executor_, address permit2_)
```

The constructor MUST reject zero addresses and MUST set:

```solidity
address public immutable executor;
address public immutable permit2;
```

`permit2` MUST be the canonical Permit2 deployment configured for that chain. Deployment tooling
MUST verify its bytecode and chain-specific address. The Gateway has no initializer, proxy,
owner, roles, pause switch, or upgrade entry point.

### 6.2 Storage

```solidity
mapping(uint256 nonce => bytes32 requestHash) public nonceRequestHash;
mapping(uint256 nonce => bool bound) public nonceBound;
mapping(bytes32 requestHash => mapping(uint256 sourceIndex => bool consumed))
    public consumed;
```

`nonceBound` avoids treating `bytes32(0)` as an unbound sentinel. No other persistent mutable
storage is permitted in v1.

The storage is local to one Gateway deployment. Vault nonces and other Gateway deployments use
separate domains.

### 6.3 External interface

```solidity
function execute(
    ExternalRequest calldata request,
    bytes calldata signature,
    uint256 sourceIndex,
    bytes calldata payload,
    PermitAuthorization calldata authorization
) external payable nonReentrant;

function hashRequest(ExternalRequest calldata request)
    external
    pure
    returns (bytes32);

function signatureDigest(bytes32 requestHash)
    external
    pure
    returns (bytes32);
```

The two pure helpers are normative interoperability surfaces for SDK and middleware testing.

### 6.4 Party selection

The Gateway MUST scan `request.parties` and require exactly one entry whose universe is
`Universe.ETHEREUM`. It MUST reject:

- no EVM party;
- more than one EVM party;
- a zero party address; or
- a non-canonical `bytes32` EVM address.

That address is `party`, the signer, token owner, and refund recipient for the source execution.

### 6.5 Validation and effects order

`execute` MUST perform the following checks and effects in this order, except that pure
computations may be reordered:

1. Require `sourceIndex < request.sources.length`.
2. Select and validate `party` as specified in Section 6.4.
3. Compute `requestHash` and verify `signature` as specified in Section 5.
4. Load `source = request.sources[sourceIndex]`.
5. Require `source.universe == Universe.ETHEREUM`.
6. Require `source.chainID == block.chainid`.
7. Require `block.timestamp < request.expiry`.
8. Require `source.value > 0`.
9. Require `source.fee == 0` for v1.
10. Require `keccak256(payload) == source.payloadHash`.
11. If `nonceBound[request.nonce]` is false, set it true and set
    `nonceRequestHash[request.nonce] = requestHash`.
12. Otherwise require `nonceRequestHash[request.nonce] == requestHash`.
13. Require `consumed[requestHash][sourceIndex] == false`.
14. Set `consumed[requestHash][sourceIndex] = true`.
15. Acquire and verify exact funding as specified in Section 6.6.
16. Fund and invoke the Executor as specified in Section 6.7.
17. Sweep any funded asset unexpectedly returned to the Gateway to `party`.
18. Emit `Executed`.

Steps 11 through 14 MUST occur before the first external call. `nonReentrant` MUST cover the
whole function.

Destination fields are signed but intentionally not interpreted by the Gateway.

### 6.6 Funding

#### 6.6.1 Native asset

When `source.contractAddress == bytes32(0)`:

- `authorization.kind` MUST be `PermitKind.NONE`;
- `authorization.data` MUST be empty;
- `msg.sender` MUST equal `party`;
- `msg.value` MUST equal `source.value`; and
- no relayed native execution is supported in v1.

#### 6.6.2 ERC-20

When `source.contractAddress != bytes32(0)`:

- its upper 12 bytes MUST be zero;
- `msg.value` MUST be zero; and
- the Gateway MUST receive exactly `source.value`.

For all authorization kinds, the Gateway MUST compare its token balance immediately before and
after acquisition. If the increase is not exactly `source.value`, execution MUST revert. This
excludes fee-on-transfer tokens. Rebasing tokens and tokens whose balance changes unexpectedly
during one transaction are unsupported.

The intent service MUST maintain the supported-token allowlist offchain; the immutable Gateway
does not maintain a token registry.

#### 6.6.3 `NONE`

`authorization.data` MUST be empty. The Gateway MUST use:

```solidity
token.safeTransferFrom(party, address(this), source.value);
```

This path uses an existing allowance to the Gateway.

#### 6.6.4 `EIP2612`

`authorization.data` MUST decode as `EIP2612Authorization`.

The Gateway MUST:

1. read `token.allowance(party, address(this))`;
2. if it is below `source.value`, call `IERC20Permit.permit` in `try/catch`;
3. after the attempt, require allowance of at least `source.value`; and
4. call `safeTransferFrom(party, address(this), source.value)`.

The permit call MUST use:

- `owner = party`;
- `spender = address(this)`; and
- the exact `value`, `deadline`, `v`, `r`, and `s` supplied in the authorization.

The Gateway MUST require `authorization.value >= source.value`. A reverted permit call is not
itself fatal if the post-call allowance is sufficient. This makes a previously used or
front-run permit non-blocking without weakening the allowance check.

#### 6.6.5 `PERMIT2`

`authorization.data` MUST decode as `Permit2Authorization`. The Gateway MUST require:

- `permit.permitted.token == source token`;
- `permit.permitted.amount >= source.value`; and
- `permit.deadline >= block.timestamp`.

It MUST call Permit2 `permitTransferFrom` with:

```solidity
SignatureTransferDetails({
    to: address(this),
    requestedAmount: source.value
})
```

and `owner = party`. Permit2 binds the spender to the calling Gateway. The Gateway MUST NOT
accept a caller-supplied transfer recipient or requested amount.

Witness-bound Permit2 is deferred from v1. It may be added as a new `PermitKind` only after its
type string and SDK encoding are frozen and tested against the canonical Permit2 implementation.

### 6.7 Executor funding and invocation

For an ERC-20 source, the Gateway MUST:

1. record `token.balanceOf(executor)`;
2. `safeTransfer(executor, source.value)`;
3. require the Executor balance increased by exactly `source.value`; and
4. call:

```solidity
IExternalIntentExecutor(executor).execute(
    token,
    source.value,
    party,
    payload
);
```

For a native source, the Gateway MUST call:

```solidity
IExternalIntentExecutor(executor).execute{value: source.value}(
    address(0),
    source.value,
    party,
    payload
);
```

After the Executor returns, the Gateway MUST transfer any balance of the funded asset held by
the Gateway to `party`. This is defensive cleanup, not a normal execution path.

### 6.8 Event

```solidity
event Executed(
    bytes32 indexed requestHash,
    uint256 indexed sourceIndex,
    address indexed party,
    address asset,
    uint256 amount,
    bytes32 payloadHash,
    address caller
);
```

For native asset execution, `asset == address(0)`. `caller` identifies the user or relayer that
submitted the transaction. One successful source execution emits exactly one `Executed` event.

## 7. Executor specification

### 7.1 Constructor and immutables

```solidity
constructor(address gateway_, address vault_)
```

The constructor MUST reject zero addresses and MUST set:

```solidity
address public immutable gateway;
address public immutable vault;
```

The Executor has no initializer, proxy, owner, roles, storage-backed configuration, receive
hook with logic, or upgrade entry point.

It MUST include an empty payable receiver so protocol refunds can return native currency:

```solidity
receive() external payable {}
```

### 7.2 External interface

```solidity
function execute(
    address asset,
    uint256 amount,
    address refundRecipient,
    bytes calldata payload
) external payable;

function sweep(address asset, address recipient) external;
```

`execute` MUST require `msg.sender == gateway`. `refundRecipient` MUST be nonzero.

`sweep` is intentionally permissionless because the Executor is not custody. It MUST transfer
the Executor's entire balance of `asset` to nonzero `recipient`, where `address(0)` means native
currency. Integrators MUST treat every asset left in the Executor after a transaction as
publicly claimable.

### 7.3 Envelope validation

The Executor MUST decode `payload` as `RoutingPayload` and require:

- `payload.target != address(0)`;
- `payload.target != address(this)`;
- `payload.target != gateway`;
- `payload.target != vault`;
- `amount > 0`; and
- the funding rules below.

For native funding (`asset == address(0)`):

- `msg.value == amount`;
- `payload.approval.token == address(0)`;
- `payload.approval.amount == 0`; and
- `payload.nativeValue <= amount`.

For ERC-20 funding (`asset != address(0)`):

- `msg.value == 0`;
- `IERC20(asset).balanceOf(address(this)) >= amount`;
- `payload.nativeValue == 0`; and
- approval is either absent or bounded as follows.

An absent approval MUST have both `token == address(0)` and `amount == 0`. A present approval
MUST have:

- `payload.approval.token == asset`; and
- `0 < payload.approval.amount <= amount`.

One zero approval field and one nonzero approval field is invalid.

These are generic fund-isolation checks, not protocol validation.

### 7.4 Call sequence

After envelope validation, the Executor MUST:

1. if approval is present, call
   `IERC20(asset).forceApprove(payload.target, payload.approval.amount)`;
2. call `payload.target` with `payload.callData` and `payload.nativeValue`;
3. bubble the target's revert data on failure;
4. if approval was present, call `IERC20(asset).forceApprove(payload.target, 0)`;
5. transfer the entire remaining balance of `asset` to `refundRecipient`; and
6. transfer the entire remaining native balance to `refundRecipient`.

The cleanup transfers MUST use `SafeERC20` for ERC-20 and a checked low-level call for native
currency. Failure to clear approval or refund MUST revert the whole execution.

For a native-funded execution, steps 5 and 6 refer to the same asset and MUST result in only one
native transfer.

The Executor MAY emit:

```solidity
event PayloadExecuted(
    bytes32 indexed payloadHash,
    address indexed target,
    address indexed refundRecipient,
    address asset,
    uint256 amount,
    string protocolTag
);
```

This event is supplemental. The Gateway `Executed` event is the canonical source-entry audit
record.

### 7.5 Residual assets

The Executor guarantees cleanup only for:

- the funded ERC-20, if any; and
- native currency.

A target may send other tokens or assets to the Executor. The contract MUST NOT enumerate or
interpret them. Payload builders and SDK decoders MUST ensure normal execution strands no such
value. Any residual ERC-20 or native value is recoverable through permissionless `sweep`.

NFT receiver interfaces are not implemented in v1.

## 8. Errors

The implementation SHOULD use the following custom errors. Names are normative for the ABI;
parameter ordering may change only before the ABI is frozen.

```solidity
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
error NonceBoundToDifferentRequest(
    uint256 nonce,
    bytes32 expectedRequestHash,
    bytes32 actualRequestHash
);
error SourceAlreadyConsumed(bytes32 requestHash, uint256 sourceIndex);
error InvalidPermitKind(PermitKind kind);
error InvalidPermitData();
error InsufficientAllowance(uint256 required, uint256 actual);
error InvalidPermitToken(address expected, address actual);
error InvalidNativeValue(uint256 expected, uint256 actual);
error NonExactTransfer(uint256 expected, uint256 actual);
error UnauthorizedCaller(address caller);
error ForbiddenTarget(address target);
error InvalidApproval(address token, uint256 amount);
error TargetCallFailed();
error NativeTransferFailed(address recipient, uint256 amount);
```

When bubbling target revert data, `TargetCallFailed` is used only if the target returned empty
revert data.

## 9. State transitions and replay behavior

For a request hash `H`, source index `i`, and nonce `N`:

```text
UNBOUND(N), UNCONSUMED(H, i)
    |
    | successful execute
    v
BOUND(N -> H), CONSUMED(H, i)
```

For a sibling source index `j` in the same request:

```text
BOUND(N -> H), UNCONSUMED(H, j)
    |
    | successful execute
    v
BOUND(N -> H), CONSUMED(H, j)
```

A request `H2 != H` using nonce `N` always reverts. The same `(H, i)` always reverts after one
success. A revert at any point restores the prior binding and consumption state.

The same request may execute on different chains because each chain has an independent Gateway
storage domain. A source entry cannot execute on the wrong chain because its signed `chainID`
must equal `block.chainid`.

## 10. Security properties and limitations

### 10.1 Enforced onchain

- EOA consent over the complete External RFF, including payload hashes.
- Exact source selection, EVM universe, source chain, amount, nonce, and expiry.
- Per-entry replay protection.
- Exact ERC-20 receipt at the Gateway and Executor.
- No arbitrary call from the approval-holding Gateway.
- Only-Gateway entry to the Executor execution path.
- Forbidden calls from the Executor to itself, its Gateway, and the Vault.
- Bounded, asset-matching, transient Executor approvals.
- Atomic execution and refund of the funded asset.

### 10.2 Not enforced onchain

- Destination chain, recipient, token, or minimum output encoded inside protocol calldata.
- Protocol identity or safety.
- Slippage, quote validity, refund timing, or destination completion.
- Correctness of `protocolTag`.
- Recovery of NFTs or unknown assets produced by a target.
- Cross-source atomicity.

These are service and SDK responsibilities. The user signs only after the SDK independently
decodes the protocol calldata and checks it against the signed destination fields.

### 10.3 Approval warning

Users MUST approve the Gateway or Permit2, never the Executor. Any allowance granted directly
to the Executor is outside the intended design and may be abused by a signed target interaction
or future token behavior. SDK and frontend code MUST reject an Executor address as an approval
spender.

### 10.4 Calldata-created authority

The Executor can clear the approval described by `RoutingPayload.approval`, but a generic
arbitrary call cannot prove that `callData` creates no other authority under the Executor's
identity. For example, a payload could directly call an ERC-20 `approve` function and create an
allowance not represented by the envelope.

This does not expose Gateway approvals or Vault custody, and transaction-scoped funding means
such an allowance cannot reach more than the signed source amount during the current execution.
It can affect assets later sent accidentally to the Executor, which are already outside the
custody guarantee and permissionlessly claimable.

SDK payload decoders MUST therefore allow only the expected protocol entry-point selector and
MUST reject payloads whose direct call creates token, Permit2, NFT, or operator approval from
the Executor. This limitation must be included explicitly in the audit scope; the contract
cannot enforce it generically without introducing protocol-specific calldata validation.

### 10.5 Token compatibility

V1 supports standard ERC-20 balance accounting. It rejects fee-on-transfer behavior observed
during either hop:

```text
party -> Gateway -> Executor
```

Rebasing, callback-heavy, ERC-777-like, or otherwise nonstandard tokens require explicit review
and MUST remain disabled in the intent service until covered by dedicated tests.

## 11. Vault and Mayan retirement

After external Mayan traffic has migrated and the v1 API sunset criteria are met:

1. Remove `Vault.depositMayan`.
2. Remove `Vault.router`, `setRouter`, `RouterSet`, and `DepositMayan`.
3. Remove `MIDDLEWARE_ROLE` if no other Vault path uses it.
4. Return the consumed Vault storage slot to the storage gap without reordering any earlier
   storage. The exact upgrade layout MUST be validated with the OpenZeppelin upgrades checker.
5. Stop deploying and configuring `MayanRouter`.
6. Retire `IRouter`, `IMayanForwarder`, `IMayanSwiftV1`, and `IMayanSwiftV2` only after repository
   and downstream reference searches confirm they are unused.
7. Remove or replace the Mayan-specific deploy and upgrade scripts and `MayanRouter` tests.
8. Update `README.md` and deployment documentation to remove the Mayan route-data trust
   boundary.
9. Revoke operational roles and allowances associated with the retired router where applicable.

Removing code from the Vault is a separate upgrade from deploying the external contracts. The
external contracts MUST be deployable and testable without modifying Vault core behavior.

## 12. Deployment requirements

For each supported EVM chain, deployment tooling MUST:

1. verify the expected `block.chainid`;
2. verify the configured Vault proxy;
3. verify the configured canonical Permit2 contract;
4. deterministically derive the Gateway and Executor addresses;
5. deploy both contracts with matching immutable references;
6. verify constructor arguments and runtime bytecode;
7. publish Gateway, Executor, Vault, Permit2, signature version, and deployment block in service
   configuration; and
8. execute a post-deployment smoke test with both an ERC-20 and native asset where supported.

Deployment tooling MUST also verify that no other production Gateway is registered for the same
`(chainID, signaturePrefix)` pair.

There is no privileged deployer state after construction.

## 13. Test and acceptance requirements

### 13.1 Hashing and signatures

- Golden-vector test shared by Solidity, SDK, and middleware for `ExternalRequest` ABI encoding,
  request hash, message bytes, digest, and recovered signer.
- Payload hash golden vectors for empty and nonempty dynamic calldata.
- Vault signatures fail against the Gateway and External RFF signatures fail against the Vault.
- Any source field or `payloadHash` mutation invalidates the signature.
- Non-canonical addresses, zero party, missing EVM party, and duplicate EVM parties revert.

### 13.2 Replay and source selection

- First source succeeds and exact replay fails.
- Two same-chain sibling sources with one nonce both succeed once.
- A different request with the same nonce fails.
- A deployment-manifest check rejects a second Gateway with the same chain and signature prefix.
- Wrong chain, wrong universe, out-of-bounds index, zero amount, nonzero fee, and expired request
  fail before funding.
- A reverted target call leaves nonce binding and consumption unchanged.

### 13.3 Funding authorization

- Existing allowance path succeeds.
- EIP-2612 path succeeds.
- EIP-2612 permit revert plus sufficient existing allowance succeeds.
- EIP-2612 permit revert plus insufficient allowance fails.
- Permit2 path succeeds and cannot redirect the transfer recipient.
- Wrong Permit2 token, insufficient permitted amount, expired permit, used nonce, and bad signer
  fail.
- Permit data on native execution fails.
- Relayed native execution fails.
- Unexpected `msg.value` on ERC-20 execution fails.

### 13.4 Asset behavior

- Exact standard ERC-20 transfer succeeds.
- Fee-on-transfer on either funding hop fails atomically.
- Remaining input tokens are refunded to the party.
- Remaining native currency is refunded to the party.
- Target revert data is propagated.
- Approval is zero after success.
- A known token `approve` calldata payload is rejected by every supported SDK decoder.
- Approval setup, target call, approval reset, and refund failure each revert atomically.

### 13.5 Isolation and adversarial targets

- Non-Gateway callers cannot invoke Executor `execute`.
- Calls targeting the Gateway, Vault, Executor, or zero address fail.
- Approval token different from funded token fails.
- Approval greater than signed amount fails.
- Native payload with an ERC-20 approval fails.
- ERC-20 payload with nonzero `nativeValue` fails.
- A reentrant token or target cannot execute or consume another source.
- A malicious target cannot transfer from any user's Gateway allowance.
- Forced residual ERC-20 and native balances are permissionlessly sweepable.

### 13.6 Stateful and invariant tests

Foundry invariant tests MUST cover:

```text
consumed[H][i] can transition only false -> true
nonceRequestHash[N] never changes after nonceBound[N] becomes true
successful Executor calls leave zero envelope-granted allowance to payload.target
successful execution leaves no funded asset in Gateway
no successful source execution emits more than one Executed event
```

Fork tests SHOULD cover the production USDC implementation, canonical Permit2, and the first
Mayan payload on every initially supported chain.

## 14. Pre-implementation decisions

The following RFC questions are resolved for contract v1:

| Topic | V1 contract rule |
| --- | --- |
| `SourcePair.fee` | MUST be zero; nonzero values revert. |
| Fee-on-transfer tokens | Unsupported; both funding hops require exact balance deltas. |
| Rebasing tokens | Unsupported unless separately reviewed and enabled offchain. |
| Gateway upgrades | Immutable redeployment; approvals target the new Gateway. |
| Executor replacement | Deploy a new Gateway/Executor pair. |
| Permit2 witness | Deferred; base SignatureTransfer ships first. |
| Native gasless funding | Unsupported because native requires `msg.sender == party`. |

The following items still require owner approval before ABI freeze:

1. Confirm the exact v1 signature prefix in Section 5.2.
2. Confirm that rejecting nonzero `source.fee` is the intended launch behavior.
3. Confirm whether permissionless `sweep(asset, recipient)` should remain unrestricted or send
   only to a fixed recovery address. A fixed recovery address introduces governance or another
   immutable deployment parameter.
4. Confirm the Vault proxy address model when a chain has more than one active Vault. V1 assumes
   one forbidden Vault target per Executor.
5. Confirm supported-chain Permit2 addresses from verified deployment records.
6. Confirm the Mayan payload does not produce a secondary residual token in the Executor on any
   swap-and-forward path.

No production deployment should occur until these six items are closed and the golden encoding
vectors are checked into the contract, SDK, and intent-service repositories.

## 15. References

- Existing request types: [`src/types.sol`](src/types.sol)
- Existing Vault hash and signature flow: [`src/Vault.sol`](src/Vault.sol)
- Existing Mayan route: [`src/routes/mayan.sol`](src/routes/mayan.sol)
- Canonical Permit2
  [`ISignatureTransfer`](https://github.com/Uniswap/permit2/blob/main/src/interfaces/ISignatureTransfer.sol)
