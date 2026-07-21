// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";

/// @notice Minimal interface to the owner-only configuration surface of MayanRouter.
interface IMayanRouterConfig {
    function owner() external view returns (address);
    function wormholeChainID(uint8 universe, uint256 chainId) external view returns (uint16);
    function tokenOutDecimals(uint16 wormholeChainId, address token) external view returns (uint8);
    function setWormholeChainMapping(uint8 universe, uint256 chainId, uint16 wormholeChainId) external;
    function setTokenOutDecimals(uint16 wormholeChainId, address token, uint8 decimals) external;
}

/// @title ConfigureMegaEth
/// @notice Enables MegaETH as a Mayan destination on a MayanRouter deployment:
///         1. maps (ETHEREUM universe, chainId 4326) -> MegaETH Wormhole chain id
///         2. sets tokenOutDecimals for MegaETH native / USDM / USDT under that Wormhole id
/// @dev Idempotent: skips writes that already hold the target value. Must be broadcast by
///      the router owner. Run once per network (point --rpc-url at each deployment).
///
/// Required env:
///   PRIVATE_KEY      owner private key (owner is an EOA: 0x3273656fe82E6eB179b0b24da4a8f7684C0b8165)
///   MEGAETH_WH_ID    MegaETH Wormhole chain id (uint16) -- there is NO safe default; supply the real value
/// Optional env:
///   ROUTER           router address (default 0x5c688B2f4D9Da1569BBDec3543C7357f57Ce1Aeb)
contract ConfigureMegaEth is Script {
    // Universe.ETHEREUM == 0 (see src/types.sol)
    uint8 internal constant UNIVERSE_ETHEREUM = 0;
    uint256 internal constant MEGAETH_CHAIN_ID = 4326;

    address internal constant DEFAULT_ROUTER = 0x5c688B2f4D9Da1569BBDec3543C7357f57Ce1Aeb;

    // MegaETH tokens (from the supported-token sheet) + their on-chain decimals.
    address internal constant MEGAETH_USDM = 0xFAfDdbb3FC7688494971a79cc65DCa3EF82079E7; // 18 decimals
    address internal constant MEGAETH_USDT = 0xB8CE59FC3717ada4C02eaDF9682A9e934F625ebb; // 6 decimals

    function run() external {
        uint256 ownerKey = vm.envUint("PRIVATE_KEY");
        uint16 megaWh = uint16(vm.envUint("MEGAETH_WH_ID"));
        address routerAddr = vm.envOr("ROUTER", DEFAULT_ROUTER);

        require(megaWh != 0, "MEGAETH_WH_ID must be non-zero");

        IMayanRouterConfig router = IMayanRouterConfig(routerAddr);

        // Skip cleanly if the router isn't deployed at this address on this chain.
        require(routerAddr.code.length > 0, "No router code at ROUTER on this RPC");

        address signer = vm.addr(ownerKey);
        require(router.owner() == signer, "PRIVATE_KEY is not the router owner");

        console.log("Router:", routerAddr);
        console.log("MegaETH Wormhole id:", megaWh);

        vm.startBroadcast(ownerKey);

        // 1) Chain mapping: ETHEREUM/4326 -> MegaETH Wormhole id
        if (router.wormholeChainID(UNIVERSE_ETHEREUM, MEGAETH_CHAIN_ID) == megaWh) {
            console.log("[skip] chain mapping already set");
        } else {
            router.setWormholeChainMapping(UNIVERSE_ETHEREUM, MEGAETH_CHAIN_ID, megaWh);
            console.log("[set ] wormholeChainID(0, 4326) =", megaWh);
        }

        // 2) Destination token decimals under the MegaETH Wormhole id
        _setDecimals(router, megaWh, address(0), 18, "native");
        _setDecimals(router, megaWh, MEGAETH_USDM, 18, "USDM");
        _setDecimals(router, megaWh, MEGAETH_USDT, 6, "USDT");

        vm.stopBroadcast();

        console.log("MegaETH configuration complete for router on this chain.");
    }

    function _setDecimals(IMayanRouterConfig router, uint16 wh, address token, uint8 decimals, string memory label)
        internal
    {
        if (router.tokenOutDecimals(wh, token) == decimals) {
            console.log("[skip] tokenOutDecimals already set:", label);
        } else {
            router.setTokenOutDecimals(wh, token, decimals);
            console.log("[set ] tokenOutDecimals:", label, decimals);
        }
    }
}
