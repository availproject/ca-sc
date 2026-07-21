#!/usr/bin/env bash
#
# Configure the USDT destination tokenOutDecimals table on every Router-B
# (0x1F03...c8f1) MayanRouter deployment that is missing it: Ethereum, Polygon,
# Arbitrum, Optimism, Base, Monad. Idempotent — re-running skips entries already set.
#
# Usage:
#   ./script/configure_usdt_destinations.sh <PRIVATE_KEY>     # broadcast
#   ./script/configure_usdt_destinations.sh <PRIVATE_KEY> --dry-run   # simulate only
#
#   PRIVATE_KEY may also be passed via the PRIVATE_KEY env var instead of an arg.
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

# Arg/caller-provided key wins over anything in .env.
PRIVATE_KEY="$KEY"
[ -z "$PRIVATE_KEY" ] && { echo "usage: $0 <PRIVATE_KEY> [--dry-run]"; exit 1; }
[[ "$PRIVATE_KEY" == 0x* ]] || PRIVATE_KEY="0x$PRIVATE_KEY"
export PRIVATE_KEY

ROUTER="0x1F035f26710d5a3C4F7052f184564C8e4707c8f1"   # Router B
BROADCAST="--broadcast"; [ "$DRY_RUN" = 1 ] && BROADCAST=""

# name|rpc  (Monad uses the public RPC; drpc rejects eth_call)
NETS=(
  "Ethereum|${ETHEREUM_RPC_URL:-}"
  "Polygon|${POLYGON_MAINNET_RPC_URL:-}"
  "Arbitrum|${ARBITRUM_ONE_RPC_URL:-}"
  "Optimism|${OPTIMISM_MAINNET_RPC_URL:-}"
  "Base|${BASE_MAINNET_RPC_URL:-}"
  "Monad|https://rpc.monad.xyz"
)

echo "Router : $ROUTER"
echo "Mode   : $([ "$DRY_RUN" = 1 ] && echo 'DRY RUN (simulate)' || echo 'BROADCAST')"
echo "Networks: ${#NETS[@]}"
echo

fail=0
for n in "${NETS[@]}"; do
  name="${n%%|*}"; rpc="${n#*|}"
  echo "======================================================"
  echo "### $name"
  if [ -z "$rpc" ]; then echo "  ✗ no RPC configured in .env — skipped"; fail=1; continue; fi
  if PRIVATE_KEY="$PRIVATE_KEY" ROUTER="$ROUTER" \
       forge script script/ConfigureUsdtDestinations.s.sol --rpc-url "$rpc" $BROADCAST; then
    echo "  ✓ $name done"
  else
    echo "  ✗ $name FAILED"; fail=1
  fi
  echo
done

echo "======================================================"
[ "$fail" = 0 ] && echo "All networks processed successfully." || { echo "One or more networks failed — see above."; exit 1; }
