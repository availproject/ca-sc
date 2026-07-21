#!/usr/bin/env python3
"""Propose internal-mainnet Mayan token-list batches to the Safe Transaction Service.

Proposes each batch (the raw MultiSend files in this directory) as a Safe
transaction so the remaining owners can confirm + execute in the Safe web UI
(app.safe.global). Needs ONE owner (or delegate) key to propose.

Requires safe-eth-py (installed with safe-cli):  pip install safe-cli

Usage:
    PROPOSER_PRIVATE_KEY=0x... python propose.py <chain> [--rpc URL] [--dry-run]

    <chain>: ethereum polygon arbitrum optimism base monad bsc avalanche
             scroll megaeth
             (hyperevm has no Safe Transaction Service; execute directly:
              safe-cli send-custom ... --delegate, see README)

Optional env:
    SAFE_API_KEY   api.safe.global API key if the service rejects anonymous
                   proposals (get one free at https://developer.safe.global)
"""

import argparse
import glob
import json
import os
import re
import sys

from safe_eth.eth import EthereumClient, EthereumNetwork
from safe_eth.safe import Safe
from safe_eth.safe.api.transaction_service_api.transaction_service_api import (
    TransactionServiceApi,
)
from safe_eth.safe.safe_tx import SafeTx

SAFE_ADDRESS = "0xEe2167a697dEd59e5BF9e65D8D807a193bdAE13D"
MULTISEND_CALL_ONLY = "0x9641d764fc13c8B624c04430C7356C1C7C8102e2"

# chain -> (chain_id, default_rpc, tx_service_base_url_override)
CHAINS = {
    "ethereum": (1, "https://ethereum-rpc.publicnode.com", None),
    "polygon": (137, "https://polygon-bor-rpc.publicnode.com", None),
    "arbitrum": (42161, "https://arbitrum-one-rpc.publicnode.com", None),
    "optimism": (10, "https://optimism-rpc.publicnode.com", None),
    "base": (8453, "https://base-rpc.publicnode.com", None),
    "monad": (143, "https://rpc.monad.xyz", "https://api.safe.global/tx-service/monad"),
    "bsc": (56, "https://bsc-rpc.publicnode.com", None),
    "avalanche": (43114, "https://avalanche-c-chain-rpc.publicnode.com", None),
    "scroll": (534352, "https://rpc.scroll.io", None),
    # chain 4326 is not in safe-eth-py's enum yet, but the service exists
    "megaeth": (4326, "https://mainnet.megaeth.com/rpc", "https://api.safe.global/tx-service/mega"),
}


def batch_files(chain: str) -> list[str]:
    here = os.path.dirname(os.path.abspath(__file__))
    single = os.path.join(here, f"{chain}.json")
    if os.path.exists(single):
        return [single]
    parts = glob.glob(os.path.join(here, f"{chain}_*of*.json"))
    return sorted(parts, key=lambda p: int(re.search(r"_(\d+)of", p).group(1)))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("chain", choices=sorted(CHAINS))
    ap.add_argument("--rpc", help="override RPC url")
    ap.add_argument("--dry-run", action="store_true", help="build + print SafeTx hashes, do not sign/post")
    args = ap.parse_args()

    chain_id, default_rpc, service_url = CHAINS[args.chain]
    rpc = args.rpc or default_rpc

    key = os.environ.get("PROPOSER_PRIVATE_KEY")
    if not key and not args.dry_run:
        print("error: set PROPOSER_PRIVATE_KEY (an owner or delegate key)", file=sys.stderr)
        return 1

    client = EthereumClient(rpc)
    got = client.w3.eth.chain_id
    assert got == chain_id, f"RPC chain id {got} != expected {chain_id}"

    safe = Safe(SAFE_ADDRESS, client)  # type: ignore[abstract]
    onchain_nonce = safe.retrieve_nonce()

    try:
        network = EthereumNetwork(chain_id)
    except ValueError:
        network = EthereumNetwork.UNKNOWN
    api = TransactionServiceApi(
        network,
        ethereum_client=client,
        base_url=service_url,
        api_key=os.environ.get("SAFE_API_KEY"),
    )

    files = batch_files(args.chain)
    print(f"safe {SAFE_ADDRESS} on {args.chain} | on-chain nonce {onchain_nonce} | {len(files)} batch file(s)")

    for i, path in enumerate(files):
        batch = json.load(open(path))
        nonce = onchain_nonce + i
        if batch["nonce"] != nonce:
            print(f"  note: {os.path.basename(path)} embeds nonce {batch['nonce']}, using live nonce {nonce}")

        safe_tx: SafeTx = safe.build_multisig_tx(
            to=MULTISEND_CALL_ONLY,
            value=0,
            data=bytes.fromhex(batch["data"][2:]),
            operation=1,  # DELEGATE_CALL into MultiSendCallOnly
            safe_nonce=nonce,
        )
        print(f"  {os.path.basename(path)}: nonce={nonce} safeTxHash={safe_tx.safe_tx_hash.hex()}")

        if args.dry_run:
            continue
        safe_tx.sign(key)
        api.post_transaction(safe_tx)
        print("    proposed ✓ — confirm & execute in the Safe web UI")

    return 0


if __name__ == "__main__":
    sys.exit(main())
