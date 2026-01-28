# Mayan Swift V1 Implementation Notes

## Session: ses_3f9b883ddffedyyDYzGvA78QeQ
## Date: 2026-01-28
## Status: COMPLETE ✅

## Completed Tasks

### Task 1: Swift V1 Interface File ✅
- Created `src/interfaces/IMayanSwiftV1.sol`
- OrderParams struct with 13 fields in exact V1 order
- Functions: `createOrderWithEth`, `createOrderWithToken`
- Verification: `forge build` PASS, `forge fmt --check` PASS

### Task 2: Extend MayanRouter ✅
- Added `SwiftVersion { V2, V1 }` enum
- Added `SWIFT_V1_PROTOCOL` constant (0xC38e4e6A15593f908255214653d3D947CA1c2338)
- Added `InvalidSwiftVersion(uint8 version)` custom error
- Modified `processTransfer` to decode prepended enum
- V2 path: unchanged logic in `_processTransferV2`
- V1 path: new `_processTransferV1` with 13-field decode
- V1 uses CAIP-2 → Wormhole mapping (ignores payload destChainId)
- Verification: `forge build` PASS, `forge fmt --check` PASS

### Task 3: Sanity Validation ✅
- `forge build` → PASS
- `forge fmt --check` → PASS

### Task 4: Tests ✅
- Added 5 new V1 tests:
  - `test_ProcessTransferV1_ERC20()` - V1 ERC20 token transfer
  - `test_ProcessTransferV1_ETH()` - V1 ETH transfer
  - `test_ProcessTransfer_InvalidVersion()` - Invalid version revert
  - `test_VaultDepositRouter_V1_ERC20()` - V1 ERC20 via Vault
  - `test_VaultDepositRouter_V1_ETH()` - V1 ETH via Vault
- Updated 6 existing V2 tests to include SwiftVersion enum
- All 11 tests PASS
- Verification: `forge test --match-path test/MayanRouter.t.sol` → PASS

## Implementation Summary

### Files Modified
1. `src/interfaces/IMayanSwiftV1.sol` (new file, 41 lines)
2. `src/routes/mayan.sol` (modified, +118 lines, now 320 lines total)
3. `test/MayanRouter.t.sol` (modified, +275 lines, now 691 lines total)

### Key Design Decisions
- V2 logic is byte-for-byte identical (wrapped in if block)
- V1 uses same CAIP-2 → Wormhole mapping (ignores payload destChainId)
- Both paths support ETH and ERC20 via Mayan forwarder
- Invalid enum values revert with custom error
- SwiftVersion enum prepended to data payload
- All callers must update encoding (no backward-compat fallback)

### Verification Results
- Build: PASS
- Format: PASS
- Tests: 11/11 PASS
- No compilation errors
- No formatting issues

## Final Status

✅ **ALL TASKS COMPLETE**

Plan: `mayan-swift-v1`  
Tasks: 4/4 complete  
Tests: 11/11 passing  
