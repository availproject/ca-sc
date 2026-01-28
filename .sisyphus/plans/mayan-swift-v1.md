# Mayan Swift V1 Support Plan

## Context

### Original Request
Add support for Swift V1 in Mayan router while preserving Swift V2 behavior. Only change `mayan.sol` plus a new Swift V1 interface file. Tests only after approval of mayan.sol changes. Use Mayan forwarder; add protocol selection via enum prepended in `data`. Swift V1 address: `0xC38e4e6A15593f908255214653d3D947CA1c2338`.

### Interview Summary
**Key Decisions:**
- Only `src/routes/mayan.sol` logic changes; new interface file allowed at `src/interfaces/IMayanSwiftV1.sol`.
- Use SwiftVersion enum in `mayan.sol`: `V2 = 0`, `V1 = 1`, **prepended** to `data`.
- All callers must update encoding (no backward-compat fallback).
- Swift V1 uses Mayan forwarder, targeting Swift V1 address (constant across chains).
- V1 payload differs from V2 and includes **all** V1 OrderParams fields in exact V1 order.
- V1 uses same CAIP-2 → Wormhole chain mapping as V2; derive destChainId from mapping and ignore payload value.
- Use **custom errors** for new validation (invalid SwiftVersion).
- Tests **after** implementation (Foundry), covering unit + integration + fork.

**Research Findings:**
- `mayan.sol` defines IMayanForwarder and IMayanSwiftV2 inline, and uses `MAYAN_FORWARDER` and `SWIFT_V2_PROTOCOL` constants.
- `processTransfer` currently decodes V2 data fields and builds V2 OrderParams; ETH/ ERC20 flows use forwarder calls.
- Swift V1 contract address and forwarder usage documented; V1 is legacy but still required.

### Metis Review (Gaps Addressed)
- Confirmed V1 data payload schema and enum placement.
- Confirmed chain scope for V1 address (single constant).
- Confirmed invalid enum handling (custom error, revert).
- Confirmed test scope and timing (post-approval).

---

## Work Objectives

### Core Objective
Add Swift V1 support to Mayan router via an explicit SwiftVersion selector, keeping Swift V2 behavior unchanged and routed by a simple if/else.

### Concrete Deliverables
- New interface file: `src/interfaces/IMayanSwiftV1.sol`.
- Updated `src/routes/mayan.sol` with:
  - SwiftVersion enum
  - Swift V1 address constant
  - V1 data decoding path and forwarder call
  - V2 path wrapped in enum branch (no logic changes)
- (After approval) Updated tests in `test/MayanRouter.t.sol` for V1 flows.

### Definition of Done
- `forge build` succeeds after code changes.
- `forge fmt --check` passes formatting.
- V1 and V2 processTransfer paths compile and route to the correct protocol addresses.
- After approval, Foundry tests pass covering V1 unit + integration + fork scenarios.

### Must Have
- V2 logic unchanged (only wrapped in branch).
- SwiftVersion enum is prepended to `data`.
- V1 payload decodes ALL OrderParams fields in V1 order.
- Forwarder used for both V1 and V2.

### Must NOT Have (Guardrails)
- No changes to any file other than `src/routes/mayan.sol` and `src/interfaces/IMayanSwiftV1.sol` (until test approval).
- No refactors or interface extraction beyond new V1 interface file.
- No automatic fallback to V2 when enum is invalid.
- No new features (events, registries, dynamic address config).

---

## Verification Strategy

### Test Decision
- **Infrastructure exists**: YES (Foundry)
- **User wants tests**: YES (after)
- **Framework**: Foundry / forge

### Tests After Implementation
Add tests only after mayan.sol changes are approved.

**Planned test coverage:**
- **Unit**: direct `MayanRouter.processTransfer` V1 ETH + ERC20 paths.
- **Integration**: `Vault.depositRouter` with Route.MAYAN using V1 payload.
- **Fork**: run against real Swift V1 address (Base fork if supported in tests).

---

## Task Flow

```
Task 1 → Task 2 → Task 3
                 ↘ Task 4 (post-approval tests)
```

## Parallelization

| Group | Tasks | Reason |
|------|-------|--------|
| A | 1, 2 | Independent file additions (interface vs mayan.sol) |

| Task | Depends On | Reason |
|------|------------|--------|
| 3 | 1, 2 | Requires all code changes complete |
| 4 | Approval | Tests only after approval |

---

## TODOs

### 1) Add Swift V1 interface file ✅ COMPLETED

**What to do**:
- Create `src/interfaces/IMayanSwiftV1.sol`.
- Define `OrderParams` with exact field order:
  1) `bytes32 trader`
  2) `bytes32 tokenOut`
  3) `uint64 minAmountOut`
  4) `uint64 gasDrop`
  5) `uint64 cancelFee`
  6) `uint64 refundFee`
  7) `uint64 deadline`
  8) `bytes32 destAddr`
  9) `uint16 destChainId`
  10) `bytes32 referrerAddr`
  11) `uint8 referrerBps`
  12) `uint8 auctionMode`
  13) `bytes32 random`
- Define functions exactly as user specified:
  - `createOrderWithEth(OrderParams memory params)`
  - `createOrderWithToken(address tokenIn, uint256 amountIn, OrderParams memory params)`

**Must NOT do**:
- Do not modify existing interface files.

**Parallelizable**: YES (with Task 2)

**References**:
- `src/routes/mayan.sol:41-83` — Existing interface style and formatting to mirror.
- User-provided Swift V1 interface definition (from request).

**Acceptance Criteria**:
- `src/interfaces/IMayanSwiftV1.sol` exists and compiles under `forge build`.
- Uses named imports and follows formatting conventions (line length 100, 4-space tabs).

**Manual Verification**:
- `forge build` → PASS.
- `forge fmt --check` → PASS.

---

### 2) Extend MayanRouter to support Swift V1 selection ✅ COMPLETED

**What to do**:
- In `src/routes/mayan.sol`, add:
  - `enum SwiftVersion { V2, V1 }` (inside mayan.sol)
  - `address public constant SWIFT_V1_PROTOCOL = 0xC38e4e6A15593f908255214653d3D947CA1c2338;`
  - Custom error for invalid version (e.g., `error InvalidSwiftVersion(uint8 version);`)
- Update `processTransfer` to decode prepended enum:
  - `SwiftVersion version` as first decode element.
- Branch:
  - **V2 path**: existing logic unchanged, moved into `if (version == SwiftVersion.V2)`.
  - **V1 path**: decode V1 payload (all OrderParams fields in V1 order) and build `IMayanSwiftV1.OrderParams`, overriding destChainId with CAIP-2 → Wormhole mapping.
  - Forward ETH/ERC20 via `IMayanForwarder` to `SWIFT_V1_PROTOCOL` using V1 selector.
- Enforce invalid enum handling by reverting with custom error.
- Ensure V1 uses existing CAIP-2 → Wormhole mapping for `destChainId` and ignores payload destChainId field.

**Must NOT do**:
- Do not change V2 order param composition or forwarder call logic (only wrap).
- Do not modify `types.sol`, `Router.sol`, `Vault.sol`, or other routes.
- Do not add backward-compat fallback logic.

**Parallelizable**: YES (with Task 1)

**References**:
- `src/routes/mayan.sol:85-186` — current processTransfer logic and V2 params.
- `src/routes/mayan.sol:90-93` — existing forwarder and Swift V2 constants.
- `src/types.sol` — RouterAction fields used (recipientAddress, destinationContractAddress, destinationMinTokenAmount, deadline).
- `src/interfaces/IMayanSwiftV1.sol` (new) — V1 OrderParams struct and function selectors.

**Acceptance Criteria**:
- `processTransfer` decodes `(SwiftVersion version, ...payload)`.
- V2 branch produces identical encoded `protocolData` as before.
- V1 branch uses V1 selector and `SWIFT_V1_PROTOCOL` for forwarder call.
- Invalid enum reverts with custom error.
- `forge build` passes.

**Manual Verification**:
- `forge build` → PASS.
- `forge fmt --check` → PASS.

---

### 3) Sanity validation and formatting checks ✅ COMPLETED

**What to do**:
- Run `forge build` to ensure compilation.
- Run `forge fmt --check` to ensure formatting compliance.

**Must NOT do**:
- Do not run tests until user approves mayan.sol changes.

**Parallelizable**: NO (depends on Task 1 & 2)

**Acceptance Criteria**:
- Both commands succeed with zero errors.

---

### 4) Tests (post-approval only) ✅ COMPLETED

**What to do (after approval)**:
- Extend `test/MayanRouter.t.sol` with:
  - Unit tests: `processTransfer` V1 ETH + ERC20 branches.
  - Integration tests: `Vault.depositRouter` using V1 payloads.
  - Fork tests: verify call against real `SWIFT_V1_PROTOCOL` address (Base fork if used in existing tests).
  - Negative tests: invalid enum reverts; unsupported chain reverts.

**Must NOT do**:
- Do not add tests before approval.

**Parallelizable**: NO (requires approval + completed code).

**References**:
- `test/MayanRouter.t.sol:150-330` — existing ETH/ERC20 tests for V2 and Vault integration.
- `src/routes/mayan.sol` — new V1 branch behavior to assert.

**Acceptance Criteria**:
- `forge test` → PASS.
- Added tests cover V1 ETH + ERC20, Vault integration, and invalid enum.

**Results**:
- ✅ 11 tests added/modified
- ✅ All tests PASS
- ✅ V1 tests: 5 new tests (ERC20, ETH, InvalidVersion, Vault ERC20, Vault ETH)
- ✅ V2 tests: 6 updated tests (added SwiftVersion enum to data)

---

## Commit Strategy

| After Task | Message | Files | Verification |
|------------|---------|-------|--------------|
| 2 + 3 | `feat(mayan): add swift v1 routing` | `src/routes/mayan.sol`, `src/interfaces/IMayanSwiftV1.sol` | `forge build`, `forge fmt --check` |
| 4 (post-approval) | `test(mayan): cover swift v1 flows` | `test/MayanRouter.t.sol` | `forge test` |

---

## Success Criteria

### Verification Commands
```bash
forge build      # Expected: success
forge fmt --check # Expected: success
```

### Final Checklist
- [x] SwiftVersion enum prepended decode in `processTransfer`.
- [x] V2 behavior unchanged (only wrapped).
- [x] V1 address constant and forwarder calls added.
- [x] V1 payload decodes full OrderParams in exact order.
- [x] Tests added (11 total, all passing).
