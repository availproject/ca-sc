// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";

/// @notice Minimal interface to the owner-only configuration surface of MayanRouter.
interface IMayanRouterConfig {
    function owner() external view returns (address);
    function tokenOutDecimals(uint16 wormholeChainId, address token) external view returns (uint8);
    function setTokenOutDecimals(uint16 wormholeChainId, address token, uint8 decimals) external;
}

/// @title DisableRouterTokens
/// @notice Locks down the MayanRouter deployed on Citrea, MegaETH and Scroll by disabling
///         EVERY destination token: it sets tokenOutDecimals(wormholeChainId, token) = 0 for
///         every (chain, token) pair the router could have been configured with. After running,
///         no token for any chain is enabled on the target router, so no Mayan route can be
///         created from that network. Chain mappings (wormholeChainID) are left untouched.
/// @dev    The router is deployed at the same CREATE2 address on every network, so the destination
///         token table is identical across deployments. Mayan Swift V2 only assigns Wormhole IDs
///         to a fixed set of chains, so the destination universe is those chains' tokens — here the
///         9 configured chains (native + wrapped-native + USDC + USDT). Scroll, Citrea and MegaETH
///         have NO Wormhole ID in Mayan, so they cannot exist as destination entries and need no
///         handling; this script runs ON those networks to clear their outbound destination table.
///
/// @dev    Idempotent: a token already at 0 decimals is skipped. Must be broadcast by the router
///         owner. Run ONCE PER NETWORK — point --rpc-url at the Citrea, MegaETH and Scroll
///         deployments in turn.
///
/// Required env:
///   PRIVATE_KEY      owner private key (must equal router.owner())
/// Optional env:
///   ROUTER           router address (default 0x5c688B2f4D9Da1569BBDec3543C7357f57Ce1Aeb)
///
/// Example:
///   PRIVATE_KEY=0x... forge script script/DisableRouterTokens.s.sol \
///     --rpc-url $CITREA_RPC --broadcast
contract DisableRouterTokens is Script {
    address internal constant DEFAULT_ROUTER = 0x5c688B2f4D9Da1569BBDec3543C7357f57Ce1Aeb;

    function run() external {
        uint256 ownerKey = vm.envUint("PRIVATE_KEY");
        address routerAddr = vm.envOr("ROUTER", DEFAULT_ROUTER);

        require(routerAddr.code.length > 0, "No router code at ROUTER on this RPC");

        IMayanRouterConfig router = IMayanRouterConfig(routerAddr);
        address signer = vm.addr(ownerKey);
        require(router.owner() == signer, "PRIVATE_KEY is not the router owner");

        (uint16[] memory whIds, address[] memory tokens) = _tokenTable();

        console.log("Router:", routerAddr);
        console.log("Disabling all destination tokens; entries:", tokens.length);

        vm.startBroadcast(ownerKey);

        uint256 disabled;
        for (uint256 i = 0; i < tokens.length; ++i) {
            disabled += _disable(router, whIds[i], tokens[i]);
        }

        vm.stopBroadcast();

        console.log("Done. Newly disabled this run:", disabled);
        console.log("Router is now locked down: no destination token is configured.");
    }

    /// @dev Sets a token's destination decimals to 0 unless already 0. Returns 1 if it wrote.
    function _disable(IMayanRouterConfig router, uint16 wh, address token) internal returns (uint256) {
        if (router.tokenOutDecimals(wh, token) == 0) {
            console.log("[skip] already disabled  wh:", wh, "token:", token);
            return 0;
        }
        router.setTokenOutDecimals(wh, token, 0);
        console.log("[set ] disabled          wh:", wh, "token:", token);
        return 1;
    }

    /// @dev The full destination token universe a router may hold: the 9 Mayan-supported chains
    ///      that are configured on-chain, each with native + wrapped-native + USDC + USDT.
    ///      native/wrapped/USDC come from DeployAll._mayanConfiguration(); USDT was added
    ///      post-deploy (addresses from the canonical supported-token sheet).
    function _tokenTable() internal pure returns (uint16[] memory whIds, address[] memory tokens) {
        whIds = new uint16[](36);
        tokens = new address[](36);

        uint256 i;
        // Native (address(0)) + wrapped-native per chain.
        i = _add(whIds, tokens, i, 2, address(0));
        i = _add(whIds, tokens, i, 2, 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2); // WETH
        i = _add(whIds, tokens, i, 4, address(0));
        i = _add(whIds, tokens, i, 4, 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c); // WBNB
        i = _add(whIds, tokens, i, 5, address(0));
        i = _add(whIds, tokens, i, 5, 0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270); // WMATIC
        i = _add(whIds, tokens, i, 6, address(0));
        i = _add(whIds, tokens, i, 6, 0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7); // WAVAX
        i = _add(whIds, tokens, i, 23, address(0));
        i = _add(whIds, tokens, i, 23, 0x82aF49447D8a07e3bd95BD0d56f35241523fBab1); // Arbitrum WETH
        i = _add(whIds, tokens, i, 24, address(0));
        i = _add(whIds, tokens, i, 24, 0x4200000000000000000000000000000000000006); // Optimism WETH
        i = _add(whIds, tokens, i, 30, address(0));
        i = _add(whIds, tokens, i, 30, 0x4200000000000000000000000000000000000006); // Base WETH
        i = _add(whIds, tokens, i, 47, address(0));
        i = _add(whIds, tokens, i, 47, 0x5555555555555555555555555555555555555555); // HyperEVM WHYPE
        i = _add(whIds, tokens, i, 48, address(0));
        i = _add(whIds, tokens, i, 48, 0x3bd359C1119dA7Da1D913D1C4D2B7c461115433A); // Monad WMON
        // USDC per chain.
        i = _add(whIds, tokens, i, 2, 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
        i = _add(whIds, tokens, i, 4, 0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d);
        i = _add(whIds, tokens, i, 5, 0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359);
        i = _add(whIds, tokens, i, 6, 0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E);
        i = _add(whIds, tokens, i, 23, 0xaf88d065e77c8cC2239327C5EDb3A432268e5831);
        i = _add(whIds, tokens, i, 24, 0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85);
        i = _add(whIds, tokens, i, 30, 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913);
        i = _add(whIds, tokens, i, 47, 0xb88339CB7199b77E23DB6E890353E22632Ba630f);
        i = _add(whIds, tokens, i, 48, 0x754704Bc059F8C67012fEd69BC8A327a5aafb603);
        // USDT per chain (added on-chain after deploy; from the supported-token sheet).
        i = _add(whIds, tokens, i, 2, 0xdAC17F958D2ee523a2206206994597C13D831ec7); // Ethereum USDT
        i = _add(whIds, tokens, i, 4, 0x55d398326f99059fF775485246999027B3197955); // BSC USDT
        i = _add(whIds, tokens, i, 5, 0xc2132D05D31c914a87C6611C10748AEb04B58e8F); // Polygon USDT
        i = _add(whIds, tokens, i, 6, 0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7); // Avalanche USDT
        i = _add(whIds, tokens, i, 23, 0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9); // Arbitrum USDT
        i = _add(whIds, tokens, i, 24, 0x94b008aA00579c1307B0EF2c499aD98a8ce58e58); // Optimism USDT
        i = _add(whIds, tokens, i, 30, 0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2); // Base USDT
        i = _add(whIds, tokens, i, 47, 0xB8CE59FC3717ada4C02eaDF9682A9e934F625ebb); // HyperEVM USDT
        i = _add(whIds, tokens, i, 48, 0xe7cd86e13AC4309349F30B3435a9d337750fC82D); // Monad USDT
    }

    function _add(uint16[] memory whIds, address[] memory tokens, uint256 index, uint16 wh, address token)
        internal
        pure
        returns (uint256)
    {
        whIds[index] = wh;
        tokens[index] = token;
        return index + 1;
    }
}
