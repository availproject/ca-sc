# Mayan Swift V1 Implementation - Cleanup Complete

## Date: 2026-01-29

## Summary

Removed duplication by extracting interfaces to separate files.

## Files Created

1. **src/interfaces/IMayanForwarder.sol**
   - Extracted from src/routes/mayan.sol
   - Contains PermitParams struct and forwardERC20/forwardEth functions

2. **src/interfaces/IMayanSwiftV2.sol**
   - Extracted from src/routes/mayan.sol
   - Contains OrderParams struct and createOrderWithEth/createOrderWithToken functions

3. **src/interfaces/IMayanSwiftV1.sol** (already existed)
   - Contains V1 OrderParams and functions

## Files Modified

1. **src/routes/mayan.sol**
   - Removed inline IMayanForwarder interface
   - Removed inline IMayanSwiftV2 interface
   - Added imports for both interfaces
   - Kept SwiftVersion enum and IMayanSwiftV1 import

2. **test/MayanRouter.t.sol**
   - Removed inline interface definitions
   - Removed inline SwiftVersion enum
   - Added imports for all interfaces from src/interfaces/
   - Imports SwiftVersion from mayan.sol

## Verification

- ✅ forge build → PASS
- ✅ forge fmt --check → PASS
- ✅ forge test --match-path test/MayanRouter.t.sol → 11/11 PASS

## Interface Files Structure

```
src/interfaces/
├── ICaRouter.sol
├── IMayanForwarder.sol (NEW)
├── IMayanSwiftV1.sol
├── IMayanSwiftV2.sol (NEW)
└── IRouter.sol
```

## Benefits

1. **No duplication**: Interfaces defined once, used everywhere
2. **Single source of truth**: Changes to interfaces only need to be made in one place
3. **Cleaner code**: mayan.sol and test file are more readable
4. **Better maintainability**: Easier to update interfaces in the future
