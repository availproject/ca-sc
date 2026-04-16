#!/bin/bash

# UpgradeVaultMultiNetwork.sh
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

declare -A RPC_URLS=(
	["sepolia"]="$SEPOLIA_RPC_URL"
	["base_sepolia"]="$BASE_SEPOLIA_RPC_URL"
	["arb_sepolia"]="$ARB_SEPOLIA_RPC_URL"
	["op_sepolia"]="$OP_SEPOLIA_RPC_URL"
	["polygon_amoy"]="$POLYGON_AMOY_RPC_URL"
	["mega_eth"]="$MEGA_ETH_RPC_URL"
	["monad_testnet"]="$MONAD_TESTNET_RPC_URL"
	["citrea_testnet"]="$CITREA_TESTNET_RPC_URL"
	["ethereum"]="$ETHEREUM_RPC_URL"
	["base_mainnet"]="$BASE_MAINNET_RPC_URL"
	["arbitrum_one"]="$ARB_MAINNET_RPC_URL"
	["optimism_mainnet"]="$OP_MAINNET_RPC_URL"
)

declare -A NATIVE_TOKENS=(
	["sepolia"]="ETH"
	["base_sepolia"]="ETH"
	["arb_sepolia"]="ETH"
	["op_sepolia"]="ETH"
	["polygon_amoy"]="MATIC"
	["mega_eth"]="ETH"
	["monad_testnet"]="MONAD"
	["citrea_testnet"]="cBTC"
	["ethereum"]="ETH"
	["base_mainnet"]="ETH"
	["arbitrum_one"]="ETH"
	["optimism_mainnet"]="ETH"
)

if [ $# -lt 1 ]; then
	echo -e "${RED}Error: No proxy addresses provided${NC}"
	echo "Usage: $0 <network:proxy,network2:proxy2>"
	echo ""
	echo "Environment:"
	echo "  UPGRADE_SALT - Optional CREATE2 salt for new implementation"
	echo "  PRIVATE_KEY - Deployer private key"
	exit 1
fi

if [ -z "$PRIVATE_KEY" ]; then
	echo -e "${RED}Error: PRIVATE_KEY not set${NC}"
	exit 1
fi

UPGRADE_SALT=${UPGRADE_SALT:-"0x$(openssl rand -hex 32)"}
VAULT_PAIRS="$1"

OUTPUT_FILE="upgrades-$(date +%Y%m%d-%H%M%S).json"

echo "{"
echo '  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",'
echo '  "salt": "'$UPGRADE_SALT'",'
echo '  "upgrades": {'

IFS=',' read -ra PAIRS <<<"$VAULT_PAIRS"
FIRST=true

for pair in "${PAIRS[@]}"; do
	NETWORK=$(echo "$pair" | cut -d':' -f1)
	PROXY=$(echo "$pair" | cut -d':' -f2)

	RPC_URL="${RPC_URLS[$NETWORK]}"

	if [ -z "$RPC_URL" ]; then
		echo -e "${YELLOW}⚠ Skipping $NETWORK: RPC_URL not configured${NC}"
		continue
	fi

	if [ -z "$PROXY" ] || [ "$PROXY" = "$NETWORK" ]; then
		echo -e "${RED}✗ $NETWORK: Invalid proxy address${NC}"
		continue
	fi

	echo -e "${BLUE}Processing $NETWORK...${NC}"
	echo "  Proxy: $PROXY"
	echo "  Salt: $UPGRADE_SALT"

	CURRENT_IMPL=$(cast impl $PROXY --rpc-url $RPC_URL 2>/dev/null || echo "unknown")
	echo "  Current Implementation: $CURRENT_IMPL"

	DEPLOYER=$(cast wallet address --private-key $PRIVATE_KEY)
	BALANCE=$(cast balance $DEPLOYER --rpc-url $RPC_URL 2>/dev/null || echo "0")
	echo "  Balance: $(cast from-wei $BALANCE) ${NATIVE_TOKENS[$NETWORK]:-ETH}"

	if UPGRADE_SALT="$UPGRADE_SALT" forge script script/UpgradeVault.s.sol \
		--rpc-url $RPC_URL \
		--broadcast \
		--sig "run(address,bytes32)" \
		"$PROXY" \
		"$UPGRADE_SALT" \
		-vvvv >/tmp/upgrade-$NETWORK.log 2>&1; then

		NEW_IMPL=$(cast impl $PROXY --rpc-url $RPC_URL 2>/dev/null || echo "unknown")

		echo -e "${GREEN}✓ $NETWORK: Upgrade successful${NC}"
		echo "  New Implementation: $NEW_IMPL"

		if [ "$FIRST" = true ]; then
			FIRST=false
		else
			echo ","
		fi

		echo "    \"$NETWORK\": {"
		echo '      "proxy": "'$PROXY'",'
		echo '      "oldImplementation": "'$CURRENT_IMPL'",'
		echo '      "newImplementation": "'$NEW_IMPL'",'
		echo '      "salt": "'$UPGRADE_SALT'",'
		echo '      "status": "success",'
		echo '      "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S)'"'
		echo "    }"
	else
		echo -e "${RED}✗ $NETWORK: Upgrade failed${NC}"
		cat /tmp/upgrade-$NETWORK.log

		if [ "$FIRST" = true ]; then
			FIRST=false
		else
			echo ","
		fi

		echo "    \"$NETWORK\": {"
		echo '      "proxy": "'$PROXY'",'
		echo '      "oldImplementation": "'$CURRENT_IMPL'",'
		echo '      "status": "failed",'
		echo '      "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S)'"'
		echo "    }"
	fi

	echo ""

	if [ "$pair" != "${PAIRS[-1]}" ]; then
		echo "Waiting 3 seconds..."
		sleep 3
	fi
done

echo "  }"
echo "}"

echo "========================================"
echo -e "${GREEN}Multi-network upgrade complete!${NC}"
echo "Results: $OUTPUT_FILE"
echo "========================================"
