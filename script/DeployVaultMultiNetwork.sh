#!/bin/bash

# DeployVaultMultiNetwork.sh
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
	echo -e "${RED}Error: No networks specified${NC}"
	echo "Usage: $0 <network1,network2,...>"
	echo ""
	echo "Environment:"
	echo "  SALT - Optional CREATE2 salt (same salt = same address on all chains)"
	echo "  PRIVATE_KEY - Deployer private key"
	exit 1
fi

if [ -z "$PRIVATE_KEY" ]; then
	echo -e "${RED}Error: PRIVATE_KEY not set${NC}"
	exit 1
fi

SALT=${SALT:-"0x$(openssl rand -hex 32)"}
NETWORKS="$1"

OUTPUT_FILE="proxy-addresses-$(date +%Y%m%d-%H%M%S).json"

echo "{"
echo '  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",'
echo '  "salt": "'"$SALT"'",'
echo '  "deployments": {'

IFS=',' read -ra NETWORK_LIST <<<"$NETWORKS"
FIRST=true

for NETWORK in "${NETWORK_LIST[@]}"; do
	RPC_URL="${RPC_URLS[$NETWORK]}"

	if [ -z "$RPC_URL" ]; then
		echo -e "${YELLOW}⚠ Skipping $NETWORK: RPC_URL not configured${NC}"
		continue
	fi

	echo -e "${BLUE}Deploying to $NETWORK...${NC}"
	echo "  Salt: $SALT"

	DEPLOYER=$(cast wallet address --private-key $PRIVATE_KEY)
	BALANCE=$(cast balance $DEPLOYER --rpc-url $RPC_URL 2>/dev/null || echo "0")
	CHAIN_ID=$(cast chain-id --rpc-url $RPC_URL 2>/dev/null || echo "unknown")

	echo "  Chain ID: $CHAIN_ID"
	echo "  Deployer: $DEPLOYER"
	echo "  Balance: $(cast from-wei $BALANCE) ${NATIVE_TOKENS[$NETWORK]:-ETH}"

	if SALT="$SALT" forge script script/DeployVault.s.sol \
		--rpc-url $RPC_URL \
		--broadcast \
		-vvvv >/tmp/deploy-$NETWORK.log 2>&1; then

		PROXY=$(grep "DEPLOYED_ADDRESS:" /tmp/deploy-$NETWORK.log | tail -1 | awk '{print $2}')
		IMPL=$(grep "Implementation:" /tmp/deploy-$NETWORK.log | tail -1 | awk '{print $2}')

		echo -e "${GREEN}✓ Deployed to $NETWORK${NC}"
		echo "  Proxy: $PROXY"
		echo "  Implementation: $IMPL"

		if [ "$FIRST" = true ]; then
			FIRST=false
		else
			echo ","
		fi

		echo "    \"$NETWORK\": {"
		echo '      "chainId": "'$CHAIN_ID'",'
		echo '      "proxyAddress": "'$PROXY'",'
		echo '      "implementationAddress": "'$IMPL'",'
		echo '      "salt": "'$SALT'",'
		echo '      "deployer": "'$DEPLOYER'",'
		echo '      "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S)'"'
		echo "    }"
	else
		echo -e "${RED}✗ Failed to deploy to $NETWORK${NC}"
		cat /tmp/deploy-$NETWORK.log

		if [ "$FIRST" = true ]; then
			FIRST=false
		else
			echo ","
		fi

		echo "    \"$NETWORK\": {"
		echo '      "status": "failed",'
		echo '      "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S)'"'
		echo "    }"
	fi

	echo ""

	if [ "$NETWORK" != "${NETWORK_LIST[-1]}" ]; then
		echo "Waiting 3 seconds..."
		sleep 3
	fi
done

echo "  }"
echo "}"
