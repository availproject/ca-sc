#!/usr/bin/env python3
"""Generate Safe txbatch JSON files using safe-cli's own machinery.

Mirrors exactly what `safe-cli tx-builder <safe> <rpc> <file>` does internally
(main.py -> convert_to_proposed_transactions -> SafeOperator.batch_safe_txs),
but stops before signing/executing and instead writes the resulting SafeTx as
a txbatch.json-style file:

    tx-builder file (txbuilder/<chain>.json)
      -> safe_cli.tx_builder.tx_builder_file_decoder.convert_to_proposed_transactions
      -> safe.build_multisig_tx(to, value, data) per transaction
      -> MultiSend(ethereum_client).build_tx_data(...)   # same call as batch_safe_txs
      -> SafeTx(..., operation=DELEGATE_CALL, safe_nonce=<live safe nonce>)
      -> <chain>.json  (execTransaction fields, same shape as txbatch.json)

Requires: pip install safe-cli
Usage:    python generate_with_safecli.py [chain ...]   (default: all)
"""

import glob
import json
import os
import re
import sys

from hexbytes import HexBytes
from safe_cli.tx_builder.tx_builder_file_decoder import convert_to_proposed_transactions
from safe_eth.eth import EthereumClient
from safe_eth.safe import Safe, SafeTx
from safe_eth.safe.enums import SafeOperationEnum
from safe_eth.safe.multi_send import MultiSend, MultiSendOperation, MultiSendTx
from safe_eth.util.util import to_0x_hex_str

SAFE_ADDRESS = "0xEe2167a697dEd59e5BF9e65D8D807a193bdAE13D"

RPCS = {
    "ethereum": "https://ethereum-rpc.publicnode.com",
    "bsc": "https://bsc-rpc.publicnode.com",
    "polygon": "https://polygon-bor-rpc.publicnode.com",
    "avalanche": "https://avalanche-c-chain-rpc.publicnode.com",
    "arbitrum": "https://arbitrum-one-rpc.publicnode.com",
    "optimism": "https://optimism-rpc.publicnode.com",
    "base": "https://base-rpc.publicnode.com",
    "monad": "https://rpc.monad.xyz",
    "hyperevm": "https://rpc.hyperliquid.xyz/evm",
}

HERE = os.path.dirname(os.path.abspath(__file__))


def txbuilder_files(chain: str) -> list[str]:
    single = os.path.join(HERE, "txbuilder", f"{chain}.json")
    if os.path.exists(single):
        return [single]
    parts = glob.glob(os.path.join(HERE, "txbuilder", f"{chain}_*of*.json"))
    return sorted(parts, key=lambda p: int(re.search(r"_(\d+)of", p).group(1)))


def main() -> int:
    chains = sys.argv[1:] or list(RPCS)
    for chain in chains:
        client = EthereumClient(RPCS[chain])
        safe = Safe(SAFE_ADDRESS, client)  # type: ignore[abstract]
        safe_nonce = safe.retrieve_nonce()
        # same detection safe-cli's batch_safe_txs performs
        multisend = MultiSend(ethereum_client=client)

        for i, path in enumerate(txbuilder_files(chain)):
            proposed = convert_to_proposed_transactions(json.loads(open(path).read()))
            # safe-cli: prepare_safe_transaction -> safe.build_multisig_tx per tx
            safe_txs = [
                safe.build_multisig_tx(t.to, int(t.value), HexBytes(t.data))
                for t in proposed
            ]
            # safe-cli: batch_safe_txs
            multisend_txs = [
                MultiSendTx(MultiSendOperation.CALL, tx.to, tx.value, tx.data)
                for tx in safe_txs
            ]
            batched: SafeTx = SafeTx(
                client,
                SAFE_ADDRESS,
                multisend.address,
                0,
                multisend.build_tx_data(multisend_txs),
                SafeOperationEnum.DELEGATE_CALL.value,
                0,
                0,
                0,
                None,
                None,
                safe_nonce=safe_nonce + i,
            )

            out = {
                "to": batched.to,
                "data": to_0x_hex_str(batched.data),
                "value": str(batched.value),
                "operation": batched.operation,
                "baseGas": str(batched.base_gas),
                "gasPrice": str(batched.gas_price),
                "gasToken": batched.gas_token,
                "nonce": batched.safe_nonce,
                "refundReceiver": batched.refund_receiver,
                "safeTxGas": str(batched.safe_tx_gas),
            }
            name = os.path.basename(path)
            out_path = os.path.join(HERE, name)
            with open(out_path, "w") as f:
                json.dump(out, f, indent=2)
                f.write("\n")
            print(
                f"{chain}: wrote {name} | txs={len(proposed)} | multisend={batched.to} "
                f"| nonce={batched.safe_nonce} | safeTxHash={to_0x_hex_str(batched.safe_tx_hash)}"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
