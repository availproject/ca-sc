// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";

/// @notice Read-only view of the owner-gated configuration surface of MayanRouter.
interface IMayanRouterConfig {
    function owner() external view returns (address);
    function tokenOutDecimals(uint16 wormholeChainId, address token) external view returns (uint8);
    function setTokenOutDecimals(uint16 wormholeChainId, address token, uint8 decimals) external;
}

/// @title FixRouterUsdtForSafe
/// @notice Brings the MayanRouter destination-token table in line with the canonical supported-token
///         sheet by enabling USDT on all nine Mayan-supported destination chains. On the current
///         mainnet router (0x415B73cf575376C4892dE05bD311b98e829DBe1c) `initialize()` configured
///         native + USDC for the nine chains but never USDT, so `tokenOutDecimals(wh, USDT) == 0`
///         everywhere and no USDT route can be created. Native and USDC already match the sheet and
///         need no change; the disabled chains (Scroll, MegaETH, Citrea) have no Wormhole mapping on
///         this router, so no route can originate from them — they already match "should not be
///         enabled" and are intentionally left untouched.
///
/// @dev    The router owner is a 2-of-6 Gnosis Safe, so these owner-only calls CANNOT be broadcast
///         with a single key. This script does NOT broadcast: it reads the live table and prints the
///         per-call Safe transaction calldata (To / Value / Data) for every USDT entry that still
///         differs. Submit each printed call from the Safe (Transaction Builder, "raw" custom data).
///         The destination table content is identical on every deployment, so run this once per
///         network and execute the printed calls through the Safe on that network.
///
/// Optional env:
///   ROUTER   router address (default 0x415B73cf575376C4892dE05bD311b98e829DBe1c)
///
/// Example:
///   forge script script/FixRouterUsdtForSafe.s.sol --rpc-url $ETHEREUM_RPC_URL
contract FixRouterUsdtForSafe is Script {
    address internal constant DEFAULT_ROUTER = 0x415B73cf575376C4892dE05bD311b98e829DBe1c;

    function run() external view {
        address routerAddr = vm.envOr("ROUTER", DEFAULT_ROUTER);
        require(routerAddr.code.length > 0, "No router code at ROUTER on this RPC");

        IMayanRouterConfig router = IMayanRouterConfig(routerAddr);

        (uint16[] memory whIds, address[] memory tokens, uint8[] memory decs) = _usdtTable();

        console.log("Router:", routerAddr);
        console.log("Owner (Safe):", router.owner());
        console.log("Chain id:", block.chainid);
        console.log("Checking USDT destination decimals; entries:", tokens.length);
        console.log("");

        uint256 pending;
        for (uint256 i = 0; i < tokens.length; ++i) {
            uint8 current = router.tokenOutDecimals(whIds[i], tokens[i]);
            if (current == decs[i]) {
                console.log("[ok  ] already set   wh:", whIds[i], "token:", tokens[i]);
                continue;
            }

            bytes memory data = abi.encodeCall(IMayanRouterConfig.setTokenOutDecimals, (whIds[i], tokens[i], decs[i]));

            console.log("--- SAFE TX: setTokenOutDecimals ---");
            console.log("  To    :", routerAddr);
            console.log("  Value :", uint256(0));
            console.log("  wh    :", whIds[i]);
            console.log("  token :", tokens[i]);
            console.log("  dec   :", decs[i]);
            console.log("  Data  :");
            console.logBytes(data);
            pending++;
        }

        console.log("");
        if (pending == 0) {
            console.log("Nothing to do: USDT already configured on this router.");
        } else {
            console.log("Pending USDT entries on this network:", pending);
            console.log("Submit each printed call from the 2-of-6 Safe (Transaction Builder, raw data).");
        }
    }

    /// @dev USDT (wormholeChainId, address, decimals) for all nine Mayan-supported destination chains.
    ///      Decimals verified on-chain against each token contract: BNB USDT is 18, every other is 6.
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
