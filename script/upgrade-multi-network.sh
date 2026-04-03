#!/bin/bash

# Multi-Network Proxy Upgrade Script for macOS Bash 3.2+
# Usage: ./script/upgrade-multi-network.sh [networks]
# Example: ./script/upgrade-multi-network.sh "ethereum,arbitrum_one"
# If no networks specified, uses the default list

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default networks to upgrade
DEFAULT_NETWORKS=("polygon_mainnet" "arbitrum_one" "base_mainnet" "ethereum")

# Function to get RPC endpoint name from network
get_rpc_name() {
	case "$1" in
	"ethereum") echo "ethereum" ;;
	"polygon_mainnet") echo "polygon" ;;
	"arbitrum_one") echo "arbitrum" ;;
	"base_mainnet") echo "base" ;;
	"optimism_mainnet") echo "optimism" ;;
	"scroll_mainnet") echo "scroll" ;;
	"linea_mainnet") echo "linea" ;;
	"sophon_mainnet") echo "sophon" ;;
	"avalanche_c_chain") echo "avalanche" ;;
	"hyperliquid") echo "hyperliquid" ;;
	"kaia_mainnet") echo "kaia" ;;
	"bnb_smart_chain_mainnet") echo "bnb" ;;
	"monad_mainnet") echo "monad" ;;
	"tron_mainnet") echo "tron" ;;
	"mega_eth") echo "megaeth" ;;
	"arb_sepolia") echo "arb-sepolia" ;;
	"op_sepolia") echo "op-sepolia" ;;
	"base_sepolia") echo "base-sepolia" ;;
	"sepolia") echo "sepolia" ;;
	"monad_testnet") echo "monad-testnet" ;;
	"citrea_testnet") echo "citrea-testnet" ;;
	"polygon_amony") echo "polygon-amoy" ;;
	*) echo "$1" ;;
	esac
}

# Function to get native token symbol
get_native_token() {
	case "$1" in
	"ethereum" | "arbitrum_one" | "base_mainnet" | "optimism_mainnet" | "scroll_mainnet" | "linea_mainnet" | "mega_eth" | "arb_sepolia" | "op_sepolia" | "base_sepolia" | "sepolia")
		echo "ETH"
		;;
	"polygon_mainnet" | "polygon_amony")
		echo "MATIC"
		;;
	"avalanche_c_chain")
		echo "AVAX"
		;;
	"hyperliquid")
		echo "HYPE"
		;;
	"kaia_mainnet")
		echo "KAI"
		;;
	"bnb_smart_chain_mainnet")
		echo "BNB"
		;;
	"monad_mainnet" | "monad_testnet")
		echo "MONAD"
		;;
	"tron_mainnet")
		echo "TRX"
		;;
	"citrea_testnet")
		echo "cBTC"
		;;
	*)
		echo "ETH"
		;;
	esac
}

# Parse networks from argument or use default
if [ -n "$1" ]; then
	IFS=',' read -ra NETWORKS <<<"$1"
else
	NETWORKS=("${DEFAULT_NETWORKS[@]}")
fi

echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}  Multi-Network Proxy Upgrade Script${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""

# Debug: Show which auth method is being used
echo "Debug - Environment variables:"
echo "  PRIVATE_KEY: ${PRIVATE_KEY:+set (hidden)}${PRIVATE_KEY:-not set}"
echo "  AWS_KMS_KEY_ID: ${AWS_KMS_KEY_ID:-not set}"
echo "  AWS_REGION: ${AWS_REGION:-not set}"
echo "  AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID:+set}${AWS_ACCESS_KEY_ID:-not set}"
echo ""

echo -e "Networks to upgrade: ${YELLOW}${NETWORKS[*]}${NC}"
echo ""

# Check required environment variables
if [ -z "$PRIVATE_KEY" ] && [ -z "$AWS_KMS_KEY_ID" ]; then
	echo -e "${RED}Error: Either PRIVATE_KEY or AWS_KMS_KEY_ID environment variable must be set${NC}"
	echo "For private key: export PRIVATE_KEY=0x..."
	echo "For AWS KMS: export AWS_KMS_KEY_ID=arn:aws:kms:..."
	exit 1
fi

# Determine auth mode and resolve sender address
USE_AWS=false
SENDER_ADDRESS=""

if [ -n "$PRIVATE_KEY" ]; then
	echo -e "${BLUE}Auth mode: Private Key${NC}"
	SENDER_ADDRESS=$(cast wallet address "$PRIVATE_KEY" 2>/dev/null)
	if [ -z "$SENDER_ADDRESS" ]; then
		echo -e "${RED}Error: Could not derive address from PRIVATE_KEY${NC}"
		exit 1
	fi
else
	USE_AWS=true
	echo -e "${BLUE}Auth mode: AWS KMS${NC}"
	if [ -z "$SENDER_ADDRESS_OVERRIDE" ]; then
		echo -e "${RED}Error: SENDER_ADDRESS_OVERRIDE must be set when using AWS KMS${NC}"
		echo "Export the address corresponding to your KMS key: export SENDER_ADDRESS_OVERRIDE=0x..."
		exit 1
	fi
	SENDER_ADDRESS="$SENDER_ADDRESS_OVERRIDE"
fi

echo -e "Sender address: ${YELLOW}${SENDER_ADDRESS}${NC}"

# Optional: UPGRADER_WALLET to grant UPGRADER_ROLE to before upgrading
if [ -n "$UPGRADER_WALLET" ]; then
	echo -e "Upgrader wallet: ${YELLOW}${UPGRADER_WALLET}${NC}"
fi
echo ""

# Role constants
UPGRADER_ROLE=$(cast keccak "UPGRADER_ROLE")
DEFAULT_ADMIN_ROLE="0x0000000000000000000000000000000000000000000000000000000000000000"

# Read proxy addresses from JSON file
PROXY_FILE="proxy-addresses.json"
if [ ! -f "$PROXY_FILE" ]; then
	echo -e "${RED}Error: $PROXY_FILE not found${NC}"
	exit 1
fi

# Function to extract proxy address from JSON
get_proxy_address() {
	local network=$1
	local json_file=$2

	if command -v jq >/dev/null 2>&1; then
		# Try proxies.network first, then network directly
		jq -r ".proxies.${network} // .${network} // empty" "$json_file" 2>/dev/null
	else
		# Fallback: grep for the network and extract the address
		grep -A1 "\"${network}\"" "$json_file" 2>/dev/null | grep -o '"0x[^"]*"' | tr -d '"' | head -1
	fi
}

# Arrays to store results (using parallel arrays instead of associative)
RESULTS_NETWORKS=()
RESULTS_STATUSES=()
RESULTS_ERRORS=()
SUCCESS_COUNT=0
FAIL_COUNT=0

# Upgrade each network
for network in "${NETWORKS[@]}"; do
	echo -e "${BLUE}============================================================${NC}"
	echo -e "${BLUE}Upgrading ${network}...${NC}"
	echo -e "${BLUE}============================================================${NC}"

	# Get RPC name
	rpc_name=$(get_rpc_name "$network")

	# Get proxy address
	proxy_address=$(get_proxy_address "$network" "$PROXY_FILE")

	if [ -z "$proxy_address" ] || [ "$proxy_address" = "null" ]; then
		echo -e "${RED}Error: No proxy address found for ${network}${NC}"
		RESULTS_NETWORKS+=("$network")
		RESULTS_STATUSES+=("FAILED")
		RESULTS_ERRORS+=("Missing proxy address")
		FAIL_COUNT=$((FAIL_COUNT + 1))
		continue
	fi

	echo -e "Proxy Address: ${YELLOW}${proxy_address}${NC}"
	echo -e "RPC Endpoint: ${rpc_name}"
	echo ""

	# Check if sender has UPGRADER_ROLE or DEFAULT_ADMIN_ROLE
	echo -e "${BLUE}Checking roles for ${SENDER_ADDRESS}...${NC}"

	has_upgrader=$(cast call "$proxy_address" "hasRole(bytes32,address)(bool)" "$UPGRADER_ROLE" "$SENDER_ADDRESS" --rpc-url "${rpc_name}" 2>/dev/null || echo "false")
	has_admin=$(cast call "$proxy_address" "hasRole(bytes32,address)(bool)" "$DEFAULT_ADMIN_ROLE" "$SENDER_ADDRESS" --rpc-url "${rpc_name}" 2>/dev/null || echo "false")

	echo -e "  UPGRADER_ROLE: ${has_upgrader}"
	echo -e "  DEFAULT_ADMIN_ROLE: ${has_admin}"

	if [ "$has_upgrader" != "true" ] && [ "$has_admin" != "true" ]; then
		echo -e "${RED}Error: ${SENDER_ADDRESS} has neither UPGRADER_ROLE nor DEFAULT_ADMIN_ROLE on ${network}${NC}"
		RESULTS_NETWORKS+=("$network")
		RESULTS_STATUSES+=("SKIPPED")
		RESULTS_ERRORS+=("Missing UPGRADER_ROLE and ADMIN_ROLE")
		FAIL_COUNT=$((FAIL_COUNT + 1))
		continue
	fi

	# Grant UPGRADER_ROLE to UPGRADER_WALLET if set and sender has admin role
	if [ -n "$UPGRADER_WALLET" ] && [ "$has_admin" = "true" ]; then
		upgrader_has_role=$(cast call "$proxy_address" "hasRole(bytes32,address)(bool)" "$UPGRADER_ROLE" "$UPGRADER_WALLET" --rpc-url "${rpc_name}" 2>/dev/null || echo "false")

		if [ "$upgrader_has_role" != "true" ]; then
			echo -e "${BLUE}Granting UPGRADER_ROLE to ${UPGRADER_WALLET} on ${network}...${NC}"

			GRANT_ARGS=(
				"$proxy_address"
				"grantRole(bytes32,address)"
				"$UPGRADER_ROLE"
				"$UPGRADER_WALLET"
				--rpc-url "${rpc_name}"
			)

			if [ "$USE_AWS" = true ]; then
				GRANT_ARGS+=(--aws --sender "$SENDER_ADDRESS")
			else
				GRANT_ARGS+=(--private-key "$PRIVATE_KEY")
			fi

			if cast send "${GRANT_ARGS[@]}"; then
				echo -e "${GREEN}Granted UPGRADER_ROLE to ${UPGRADER_WALLET}${NC}"
			else
				echo -e "${RED}Failed to grant UPGRADER_ROLE to ${UPGRADER_WALLET} on ${network}${NC}"
				RESULTS_NETWORKS+=("$network")
				RESULTS_STATUSES+=("FAILED")
				RESULTS_ERRORS+=("Failed to grant UPGRADER_ROLE")
				FAIL_COUNT=$((FAIL_COUNT + 1))
				continue
			fi
		else
			echo -e "${GREEN}UPGRADER_WALLET already has UPGRADER_ROLE on ${network}${NC}"
		fi
	fi

	echo ""

	# Set environment variable for the script
	export PROXY_ADDRESS="$proxy_address"

	# Build forge command args
	FORGE_ARGS=(
		script/UpgradeVault.s.sol:UpgradeVault
		--sig "run()"
		--rpc-url "${rpc_name}"
		--broadcast
	)

	if [ "$USE_AWS" = true ]; then
		# For AWS mode, map AWS_KMS_KEY_ID to ETH_KMS_KEY_ID (required by Foundry)
		export ETH_KMS_KEY_ID="${AWS_KMS_KEY_ID}"
		FORGE_ARGS+=(--aws --sender "$SENDER_ADDRESS")
	else
		FORGE_ARGS+=(--private-key "$PRIVATE_KEY")
	fi

	if env \
		PROXY_ADDRESS="$proxy_address" \
		ETH_KMS_KEY_ID="${ETH_KMS_KEY_ID:-}" \
		AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}" \
		AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}" \
		AWS_REGION="${AWS_REGION:-}" \
		forge script "${FORGE_ARGS[@]}"; then

		echo -e "${GREEN}✅ Successfully upgraded ${network}${NC}"
		RESULTS_NETWORKS+=("$network")
		RESULTS_STATUSES+=("SUCCESS")
		RESULTS_ERRORS+=("")
		SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
	else
		echo -e "${RED}❌ Failed to upgrade ${network}${NC}"
		RESULTS_NETWORKS+=("$network")
		RESULTS_STATUSES+=("FAILED")
		RESULTS_ERRORS+=("Upgrade transaction failed")
		FAIL_COUNT=$((FAIL_COUNT + 1))
	fi

	# Wait between upgrades (except for last one)
	if [ "$network" != "${NETWORKS[${#NETWORKS[@]} - 1]}" ]; then
		echo ""
		echo -e "${YELLOW}Waiting 3 seconds before next upgrade...${NC}"
		sleep 3
	fi

	echo ""
done

# Print summary report
echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}  UPGRADE REPORT${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""
echo -e "${BLUE}Network Results:${NC}"
echo ""
printf "%-20s %-15s %-50s\n" "Network" "Status" "Details"
echo "--------------------------------------------------------------------------------"

for i in "${!RESULTS_NETWORKS[@]}"; do
	network="${RESULTS_NETWORKS[$i]}"
	status="${RESULTS_STATUSES[$i]}"
	error="${RESULTS_ERRORS[$i]}"

	if [ "$status" = "SUCCESS" ]; then
		printf "%-20s ${GREEN}%-15s${NC} %-50s\n" "$network" "✅ SUCCESS" ""
	elif [ "$status" = "FAILED" ]; then
		printf "%-20s ${RED}%-15s${NC} %-50s\n" "$network" "❌ FAILED" "$error"
	else
		printf "%-20s ${YELLOW}%-15s${NC} %-50s\n" "$network" "⏭️  SKIPPED" "$error"
	fi
done

echo "--------------------------------------------------------------------------------"
echo ""
echo -e "${BLUE}Summary:${NC}"
echo -e "  ${GREEN}✅ Successful: ${SUCCESS_COUNT}${NC}"
echo -e "  ${RED}❌ Failed: ${FAIL_COUNT}${NC}"
echo -e "  📝 Total: ${#NETWORKS[@]}"
echo ""
echo -e "${BLUE}============================================================${NC}"

# Save results to JSON file
timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build JSON manually for compatibility
echo "{" >upgrades-foundry.json
echo "  \"timestamp\": \"${timestamp}\"," >>upgrades-foundry.json
echo "  \"upgrades\": {" >>upgrades-foundry.json

first=true
for i in "${!RESULTS_NETWORKS[@]}"; do
	network="${RESULTS_NETWORKS[$i]}"
	status="${RESULTS_STATUSES[$i]}"
	error="${RESULTS_ERRORS[$i]}"

	if [ "$first" = true ]; then
		first=false
	else
		echo "," >>upgrades-foundry.json
	fi

	if [ "$status" = "SUCCESS" ]; then
		echo -n "    \"${network}\": { \"status\": \"success\" }" >>upgrades-foundry.json
	else
		echo -n "    \"${network}\": { \"status\": \"failed\", \"error\": \"${error}\" }" >>upgrades-foundry.json
	fi
done

echo "" >>upgrades-foundry.json
echo "  }," >>upgrades-foundry.json
echo "  \"summary\": {" >>upgrades-foundry.json
echo "    \"successful\": ${SUCCESS_COUNT}," >>upgrades-foundry.json
echo "    \"failed\": ${FAIL_COUNT}" >>upgrades-foundry.json
echo "  }" >>upgrades-foundry.json
echo "}" >>upgrades-foundry.json

echo -e "Results saved to: ${YELLOW}upgrades-foundry.json${NC}"
echo ""

# Exit with error if any upgrades failed
if [ $FAIL_COUNT -gt 0 ]; then
	exit 1
fi

exit 0
