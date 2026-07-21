#!/usr/bin/env bash
#
# Configure the FULL Mayan supported-token destination table (499 entries, see
# ConfigureMayanTokenList.s.sol) on every internal-mainnet MayanRouter:
#
#   Router B 0x1F035f26710d5a3C4F7052f184564C8e4707c8f1 : Ethereum, Polygon,
#            Arbitrum, Optimism, Base, Monad
#   Router C 0x5c688B2f4D9Da1569BBDec3543C7357f57Ce1Aeb : BNB, Avalanche,
#            HyperEVM, MegaETH
#
# Owner of both routers is the deployer EOA (verified on-chain 2026-07-14),
# so this broadcasts directly with PRIVATE_KEY. Idempotent — re-running skips
# entries already set (e.g. the 36 native/wrapped/USDC/USDT entries).
#
# Usage:
#   ./script/configure_mayan_token_list.sh <PRIVATE_KEY>              # broadcast
#   ./script/configure_mayan_token_list.sh <PRIVATE_KEY> --dry-run    # report only
#
#   PRIVATE_KEY may also be passed via the PRIVATE_KEY env var instead of an arg.
#   To run a subset of networks: NETWORKS="Ethereum MegaETH" ./script/...
#
# RPC URLs are read from .env (same vars as foundry.toml).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# --- args -------------------------------------------------------------------
# Capture the key BEFORE sourcing .env (which may define/clobber PRIVATE_KEY).
KEY="${1:-${PRIVATE_KEY:-}}"
DRY_RUN=0
for a in "$@"; do [ "$a" = "--dry-run" ] && DRY_RUN=1; done

# --- env --------------------------------------------------------------------
[ -f .env ] && { set -a; source .env; set +a; }

PRIVATE_KEY="$KEY"
if [ "$DRY_RUN" = 0 ]; then
  [ -z "$PRIVATE_KEY" ] && { echo "usage: $0 <PRIVATE_KEY> [--dry-run]"; exit 1; }
  [[ "$PRIVATE_KEY" == 0x* ]] || PRIVATE_KEY="0x$PRIVATE_KEY"
  export PRIVATE_KEY
fi

ROUTER_B="0x1F035f26710d5a3C4F7052f184564C8e4707c8f1"
ROUTER_C="0x5c688B2f4D9Da1569BBDec3543C7357f57Ce1Aeb"

# name|rpc|router  (Monad uses the public RPC; drpc rejects eth_call)
NETS=(
  "Ethereum|${ETHEREUM_RPC_URL:-}|$ROUTER_B"
  "Polygon|${POLYGON_MAINNET_RPC_URL:-}|$ROUTER_B"
  "Arbitrum|${ARBITRUM_ONE_RPC_URL:-}|$ROUTER_B"
  "Optimism|${OPTIMISM_MAINNET_RPC_URL:-}|$ROUTER_B"
  "Base|${BASE_MAINNET_RPC_URL:-}|$ROUTER_B"
  "Monad|https://rpc.monad.xyz|$ROUTER_B"
  "BNB|${BNB_SMART_CHAIN_MAINNET_RPC_URL:-}|$ROUTER_C"
  "Avalanche|${AVALANCHE_C_CHAIN_RPC_URL:-}|$ROUTER_C"
  "HyperEVM|${HYPERLIQUID_RPC_URL:-}|$ROUTER_C"
  "MegaETH|${MEGA_ETH_RPC_URL:-}|$ROUTER_C"
)

ONLY="${NETWORKS:-}"

echo "Mode    : $([ "$DRY_RUN" = 1 ] && echo 'DRY RUN (report only)' || echo 'BROADCAST')"
echo "Networks: ${ONLY:-all (${#NETS[@]})}"
echo

fail=0
for n in "${NETS[@]}"; do
  IFS='|' read -r name rpc router <<< "$n"
  if [ -n "$ONLY" ] && ! grep -qw "$name" <<< "$ONLY"; then continue; fi
  echo "======================================================"
  echo "### $name ($router)"
  if [ -z "$rpc" ]; then echo "  ✗ no RPC configured in .env — skipped"; fail=1; continue; fi
  if [ "$DRY_RUN" = 1 ]; then
    if DRY_RUN=true ROUTER="$router" forge script script/ConfigureMayanTokenList.s.sol --rpc-url "$rpc"; then
      echo "  ✓ $name checked"
    else
      echo "  ✗ $name FAILED"; fail=1
    fi
  else
    if PRIVATE_KEY="$PRIVATE_KEY" ROUTER="$router" \
         forge script script/ConfigureMayanTokenList.s.sol --rpc-url "$rpc" --broadcast --slow; then
      echo "  ✓ $name done"
    else
      echo "  ✗ $name FAILED"; fail=1
    fi
  fi
  echo
done

echo "======================================================"
[ "$fail" = 0 ] && echo "All networks processed successfully." || { echo "One or more networks failed — see above."; exit 1; }
