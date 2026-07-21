#!/usr/bin/env bash
#
# Check, on the MayanRouter deployed on a given network, whether THAT network's
# own tokens (native / USDC / USDT) are configured.
#
#   token configured  == tokenOutDecimals(whChainId, token) != 0
#   chain mapped       == wormholeChainID(0 /*ETHEREUM universe*/, chainId) != 0  (== whChainId)
#
# Usage:
#   RPC_URL=https://... CHAIN_ID=56 \
#   TOKENS="native=0x0 USDC=0x8AC7... USDT=0x55d3..." \
#   ROUTER=0x5c68... ./script/check_token_config.sh
set -euo pipefail

ROUTER="${ROUTER:?set ROUTER}"
RPC_URL="${RPC_URL:?set RPC_URL}"
CHAIN_ID="${CHAIN_ID:?set CHAIN_ID}"
TOKENS="${TOKENS:?set TOKENS as 'label=addr label=addr ...'}"

if [ "$(cast code "$ROUTER" --rpc-url "$RPC_URL" 2>/dev/null | head -c 4)" = "0x" ] &&
   [ "$(cast code "$ROUTER" --rpc-url "$RPC_URL" 2>/dev/null | wc -c)" -le 4 ]; then
  echo "  ✗ no contract code at $ROUTER on this RPC"; exit 0
fi

WH=$(cast call "$ROUTER" "wormholeChainID(uint8,uint256)(uint16)" 0 "$CHAIN_ID" --rpc-url "$RPC_URL")
if [ "$WH" -eq 0 ]; then
  echo "  chain mapping: ❌ wormholeChainID(0,$CHAIN_ID)=0  (chain not enabled as a Mayan route)"
else
  echo "  chain mapping: ✅ wormholeChainID(0,$CHAIN_ID)=$WH"
fi

for pair in $TOKENS; do
  label="${pair%%=*}"; addr="${pair#*=}"
  [ "$addr" = "0x0" ] && addr="0x0000000000000000000000000000000000000000"
  dec=$(cast call "$ROUTER" "tokenOutDecimals(uint16,address)(uint8)" "$WH" "$addr" --rpc-url "$RPC_URL" 2>/dev/null || echo "err")
  if [ "$dec" = "err" ]; then
    printf "    %-7s %-44s -> ERROR\n" "$label" "$addr"
  elif [ "$dec" -ne 0 ] 2>/dev/null; then
    printf "    %-7s %-44s -> ✅ configured (decimals=%s)\n" "$label" "$addr" "$dec"
  else
    printf "    %-7s %-44s -> ❌ not configured (0)\n" "$label" "$addr"
  fi
done
