#!/usr/bin/env bash
# Audit the MayanRouter destination-token table on a single deployment.
#   ✅ = configured (tokenOutDecimals != 0), ❌ = not configured (0)
# Target per the supported-token sheet: native + USDC + USDT for the 9 chains.
# Wrapped-native entries are flagged separately (set at init, NOT in the sheet -> "extra").
# Disabled chains (Scroll/MegaETH/Citrea) have no Wormhole id -> any nonzero entry is "extra".
set -euo pipefail
R="${ROUTER:-0x415B73cf575376C4892dE05bD311b98e829DBe1c}"
RPC="${RPC:?set RPC}"
N=0x0000000000000000000000000000000000000000

d(){ cast call "$R" "tokenOutDecimals(uint16,address)(uint8)" "$1" "$2" --rpc-url "$RPC" 2>/dev/null || echo err; }
mark(){ [ "$1" != err ] && [ "$1" != 0 ] 2>/dev/null && echo "✅($1)" || echo "❌"; }

# Chain|wh|native|wrapped|USDC|USDT
ROWS=(
 "Ethereum|2|$N|0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2|0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48|0xdAC17F958D2ee523a2206206994597C13D831ec7"
 "BNB|4|$N|0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c|0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d|0x55d398326f99059fF775485246999027B3197955"
 "Polygon|5|$N|0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270|0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359|0xc2132D05D31c914a87C6611C10748AEb04B58e8F"
 "Avalanche|6|$N|0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7|0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E|0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7"
 "Arbitrum|23|$N|0x82aF49447D8a07e3bd95BD0d56f35241523fBab1|0xaf88d065e77c8cC2239327C5EDb3A432268e5831|0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9"
 "Optimism|24|$N|0x4200000000000000000000000000000000000006|0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85|0x94b008aA00579c1307B0EF2c499aD98a8ce58e58"
 "Base|30|$N|0x4200000000000000000000000000000000000006|0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913|0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2"
 "HyperEVM|47|$N|0x5555555555555555555555555555555555555555|0xb88339CB7199b77E23DB6E890353E22632Ba630f|0xB8CE59FC3717ada4C02eaDF9682A9e934F625ebb"
 "Monad|48|$N|0x3bd359C1119dA7Da1D913D1C4D2B7c461115433A|0x754704Bc059F8C67012fEd69BC8A327a5aafb603|0xe7cd86e13AC4309349F30B3435a9d337750fC82D"
)

echo "Router $R"
printf "%-10s %-3s %-9s %-12s %-9s %-9s\n" Chain WH native "wrapped(xtra)" USDC USDT
for row in "${ROWS[@]}"; do
  IFS='|' read -r c wh nat wrap usdc usdt <<< "$row"
  printf "%-10s %-3s %-9s %-12s %-9s %-9s\n" "$c" "$wh" \
    "$(mark "$(d "$wh" "$nat")")" "$(mark "$(d "$wh" "$wrap")")" \
    "$(mark "$(d "$wh" "$usdc")")" "$(mark "$(d "$wh" "$usdt")")"
done
