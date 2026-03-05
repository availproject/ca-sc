#!/bin/bash

# GrantRoleMultiNetwork.sh
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

if [ $# -lt 2 ]; then
	echo -e "${RED}Error: Insufficient arguments${NC}"
	echo "Usage: $0 <network:vault,network2:vault2> <address1,address2>"
	exit 1
fi

if [ -z "$PRIVATE_KEY" ]; then
	echo -e "${RED}Error: PRIVATE_KEY not set${NC}"
	exit 1
fi

VAULT_PAIRS="$1"
GRANT_ADDRESSES="$2"

echo "========================================"
echo "Granting SETTLEMENT_VERIFIER_ROLE"
echo "========================================"
echo "Addresses: $GRANT_ADDRESSES"
echo ""

IFS=',' read -ra PAIRS <<<"$VAULT_PAIRS"

for pair in "${PAIRS[@]}"; do
	NETWORK=$(echo "$pair" | cut -d':' -f1)
	VAULT=$(echo "$pair" | cut -d':' -f2)

	RPC_URL="${RPC_URLS[$NETWORK]}"

	if [ -z "$RPC_URL" ]; then
		echo -e "${YELLOW}⚠ Skipping $NETWORK: RPC_URL not configured${NC}"
		continue
	fi

	if [ -z "$VAULT" ] || [ "$VAULT" = "$NETWORK" ]; then
		echo -e "${RED}✗ $NETWORK: Invalid vault address${NC}"
		continue
	fi

	echo -e "${YELLOW}Processing $NETWORK...${NC}"
	echo "  Vault: $VAULT"

	DEPLOYER=$(cast wallet address --private-key $PRIVATE_KEY)
	BALANCE=$(cast balance $DEPLOYER --rpc-url $RPC_URL 2>/dev/null || echo "0")
	echo "  Balance: $(cast from-wei $BALANCE) ${NATIVE_TOKENS[$NETWORK]:-ETH}"

	if forge script script/GrantRole.s.sol \
		--rpc-url $RPC_URL \
		--broadcast \
		--sig "run(address,address[])" \
		"$VAULT" \
		"[$GRANT_ADDRESSES]" \
		-vv; then

		echo -e "${GREEN}✓ $NETWORK: Role granted${NC}"
	else
		echo -e "${RED}✗ $NETWORK: Failed${NC}"
	fi

	echo ""
done

echo "========================================"
echo -e "${GREEN}Multi-network role grant complete!${NC}"
echo "========================================"
