#!/usr/bin/env bash
#
# Check the FULL destination token table (all wormhole chains in the sheet)
# on a given MayanRouter deployment.
#
#   token configured == tokenOutDecimals(whChainId, token) != 0
#
# Usage:
#   RPC_URL=https://... ROUTER=0x5c68... ./script/check_full_table.sh
set -euo pipefail

ROUTER="${ROUTER:?set ROUTER}"
RPC_URL="${RPC_URL:?set RPC_URL}"
NATIVE="0x0000000000000000000000000000000000000000"

# rows: "Chain|whId|native|USDC|USDT"  (whId from DeployAll.s.sol wormhole config)
ROWS=(
  "Ethereum|2|$NATIVE|0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48|0xdAC17F958D2ee523a2206206994597C13D831ec7"
  "BNB|4|$NATIVE|0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d|0x55d398326f99059fF775485246999027B3197955"
  "Polygon|5|$NATIVE|0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359|0xc2132D05D31c914a87C6611C10748AEb04B58e8F"
  "Avalanche|6|$NATIVE|0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E|0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7"
  "Arbitrum|23|$NATIVE|0xaf88d065e77c8cC2239327C5EDb3A432268e5831|0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9"
  "Optimism|24|$NATIVE|0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85|0x94b008aA00579c1307B0EF2c499aD98a8ce58e58"
  "Base|30|$NATIVE|0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913|0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2"
  "HyperEVM|47|$NATIVE|0xb88339CB7199b77E23DB6E890353E22632Ba630f|0xB8CE59FC3717ada4C02eaDF9682A9e934F625ebb"
  "Monad|48|$NATIVE|0x754704Bc059F8C67012fEd69BC8A327a5aafb603|0xe7cd86e13AC4309349F30B3435a9d337750fC82D"
)

d() { cast call "$ROUTER" "tokenOutDecimals(uint16,address)(uint8)" "$1" "$2" --rpc-url "$RPC_URL" 2>/dev/null || echo err; }
m() { [ "$1" != err ] && [ "$1" -ne 0 ] 2>/dev/null && echo "✅ $1" || echo "❌ 0"; }

printf "%-11s %-4s %-10s %-10s %-10s\n" "Chain" "WH" "native" "USDC" "USDT"
for row in "${ROWS[@]}"; do
  IFS='|' read -r c wh nat usdc usdt <<< "$row"
  printf "%-11s %-4s %-10s %-10s %-10s\n" "$c" "$wh" "$(m "$(d "$wh" "$nat")")" "$(m "$(d "$wh" "$usdc")")" "$(m "$(d "$wh" "$usdt")")"
done
