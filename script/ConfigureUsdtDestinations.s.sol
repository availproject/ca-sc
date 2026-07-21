// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";

/// @notice Minimal interface to the owner-only configuration surface of MayanRouter.
interface IMayanRouterConfig {
    function owner() external view returns (address);
    function tokenOutDecimals(uint16 wormholeChainId, address token) external view returns (uint8);
    function setTokenOutDecimals(uint16 wormholeChainId, address token, uint8 decimals) external;
}

/// @title ConfigureUsdtDestinations
/// @notice Fills in the USDT rows of the destination `tokenOutDecimals` table so USDT can be a
///         valid Mayan destination token on every Wormhole-supported chain. The destination table
///         is global (the same on every router deployment), but the post-deploy USDT step only set
///         each router's OWN chain. This script sets USDT for ALL nine Mayan-supported destination
///         chains, so it is the missing piece for the routers at 0x1F03...c8f1 (Ethereum, Polygon,
///         Arbitrum, Optimism, Base, Monad) and a no-op on the routers at 0x5c68...1Aeb (BNB,
///         Avalanche, HyperEVM) which already have the full USDT row.
///
/// @dev    Idempotent: an entry already at the target value is skipped. Must be broadcast by the
///         router owner. Run ONCE PER NETWORK — point --rpc-url at each deployment and set ROUTER
///         to that network's router address.
///
/// Required env:
///   PRIVATE_KEY   owner private key (must equal router.owner())
///   ROUTER        router address on the target network
///                   - 0x1F035f26710d5a3C4F7052f184564C8e4707c8f1 : Ethereum, Polygon, Arbitrum,
///                                                                   Optimism, Base, Monad
///                   - 0x5c688B2f4D9Da1569BBDec3543C7357f57Ce1Aeb : BNB, Avalanche, HyperEVM
///
/// Example:
///   PRIVATE_KEY=0x... ROUTER=0x1F035f26710d5a3C4F7052f184564C8e4707c8f1 \
///     forge script script/ConfigureUsdtDestinations.s.sol --rpc-url $BASE_MAINNET_RPC_URL --broadcast
contract ConfigureUsdtDestinations is Script {
    function run() external {
        uint256 ownerKey = vm.envUint("PRIVATE_KEY");
        address routerAddr = vm.envAddress("ROUTER");

        require(routerAddr.code.length > 0, "No router code at ROUTER on this RPC");

        IMayanRouterConfig router = IMayanRouterConfig(routerAddr);
        require(router.owner() == vm.addr(ownerKey), "PRIVATE_KEY is not the router owner");

        (uint16[] memory whIds, address[] memory tokens, uint8[] memory decs) = _usdtTable();

        console.log("Router:", routerAddr);
        console.log("Configuring USDT destination decimals; entries:", tokens.length);

        vm.startBroadcast(ownerKey);

        uint256 written;
        for (uint256 i = 0; i < tokens.length; ++i) {
            written += _set(router, whIds[i], tokens[i], decs[i]);
        }

        vm.stopBroadcast();

        console.log("Done. Newly written this run:", written);
    }

    /// @dev Sets a destination token's decimals unless already at the target. Returns 1 if it wrote.
    function _set(IMayanRouterConfig router, uint16 wh, address token, uint8 decimals) internal returns (uint256) {
        if (router.tokenOutDecimals(wh, token) == decimals) {
            console.log("[skip] already set   wh:", wh, "token:", token);
            return 0;
        }
        router.setTokenOutDecimals(wh, token, decimals);
        console.log("[set ] decimals      wh:", wh, "token:", token);
        return 1;
    }

    /// @dev USDT (wormholeChainId, address, decimals) for all nine Mayan-supported destination chains.
    ///      Decimals verified on-chain against the routers that already hold the full USDT row.
    ///      BNB USDT is 18 decimals; every other chain's USDT is 6.
    function _usdtTable() internal pure returns (uint16[] memory whIds, address[] memory tokens, uint8[] memory decs) {
        whIds = new uint16[](9);
        tokens = new address[](9);
        decs = new uint8[](9);

        uint256 i;
        i = _add(whIds, tokens, decs, i, 2, 0xdAC17F958D2ee523a2206206994597C13D831ec7, 6); // Ethereum
        i = _add(whIds, tokens, decs, i, 4, 0x55d398326f99059fF775485246999027B3197955, 18); // BNB
        i = _add(whIds, tokens, decs, i, 5, 0xc2132D05D31c914a87C6611C10748AEb04B58e8F, 6); // Polygon
        i = _add(whIds, tokens, decs, i, 6, 0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7, 6); // Avalanche
        i = _add(whIds, tokens, decs, i, 23, 0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9, 6); // Arbitrum
        i = _add(whIds, tokens, decs, i, 24, 0x94b008aA00579c1307B0EF2c499aD98a8ce58e58, 6); // Optimism
        i = _add(whIds, tokens, decs, i, 30, 0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2, 6); // Base
        i = _add(whIds, tokens, decs, i, 47, 0xB8CE59FC3717ada4C02eaDF9682A9e934F625ebb, 6); // HyperEVM
        i = _add(whIds, tokens, decs, i, 48, 0xe7cd86e13AC4309349F30B3435a9d337750fC82D, 6); // Monad
    }

    function _add(
        uint16[] memory whIds,
        address[] memory tokens,
        uint8[] memory decs,
        uint256 index,
        uint16 wh,
        address token,
        uint8 decimals
    ) internal pure returns (uint256) {
        whIds[index] = wh;
        tokens[index] = token;
        decs[index] = decimals;
        return index + 1;
    }
}
