# Mayan token-list upgrade — Safe transaction batches

Generated 2026-07-13 from `Mayan Supported Tokens, Nexus Identifier Format.pdf`
(500 tokens across 12 Wormhole destination chains). Same format as `txbatch.json`.

Each file is one Safe transaction: a delegatecall into MultiSendCallOnly v1.4.1
(`0x9641d764fc13c8B624c04430C7356C1C7C8102e2`, verified deployed on all 9 chains)
containing `setTokenOutDecimals(uint16 wormholeChainId, address token, uint8 decimals)`
calls on the MayanRouter `0x415B73cf575376C4892dE05bD311b98e829DBe1c`
(owner verified on-chain = Safe `0xEe2167a697dEd59e5BF9e65D8D807a193bdAE13D` on every chain).

Every chain gets the identical full 500-entry destination table (idempotent —
re-setting an existing entry is a same-value SSTORE).

| Chain     | File(s)                | Entries per tx | Nonce(s) | Note |
|-----------|------------------------|----------------|----------|------|
| ethereum  | ethereum.json          | 500            | 4        | ~13M gas, fits 36M block |
| bsc       | bsc.json               | 500            | 3        | |
| polygon   | polygon.json           | 500            | 4        | |
| avalanche | avalanche_1of2.json, _2of2 | 250        | 5, 6     | split: 15M block gas limit |
| arbitrum  | arbitrum.json          | 500            | 4        | |
| optimism  | optimism.json          | 500            | 4        | |
| base      | base.json              | 500            | 5        | |
| monad     | monad.json             | 500            | 3        | |
| hyperevm  | hyperevm_1of9 … 9of9   | 60 (last: 20)  | 4–12     | split to fit 2M small-block limit; if the executor has big blocks enabled these could be one tx |

Nonces are the live Safe nonces fetched 2026-07-13; multi-part chains use
sequential nonces and must be executed in order. If the Safe executes anything
else first, regenerate/adjust the nonce.

## How to submit

The raw JSONs above are NOT importable in the Safe web UI. Use one of:

### A. Propose via Safe Transaction Service (recommended — co-sign in the web UI)

One owner key proposes; the other owners confirm + execute at app.safe.global.
Works on every chain except hyperevm (no official tx service there).

```sh
pip install safe-cli          # installs safe-eth-py used by propose.py
PROPOSER_PRIVATE_KEY=0x... python txbatches/propose.py ethereum
python txbatches/propose.py ethereum --dry-run   # no key needed, prints safeTxHash
```

The script fetches the live Safe nonce, builds the delegatecall MultiSend
SafeTx from the raw batch file, signs, and POSTs to the service. If the
service rejects anonymous proposals, set `SAFE_API_KEY`
(free at https://developer.safe.global).

### B. Direct execution with safe-cli (works everywhere, incl. hyperevm)

Needs 2 owner keys (threshold 2 of 6). Executes on-chain immediately:

```sh
safe-cli send-custom 0xEe2167a697dEd59e5BF9e65D8D807a193bdAE13D $RPC \
  0x9641d764fc13c8B624c04430C7356C1C7C8102e2 0 $(jq -r .data txbatches/ethereum.json) \
  --delegate --private-key $OWNER_KEY_1 --private-key $OWNER_KEY_2 --non-interactive
```

`--delegate` is required (MultiSendCallOnly must be delegatecalled).
For multi-part chains run the parts in order (`avalanche_1of2.json` then `_2of2`).

### C. Transaction Builder files (`txbuilder/`)

`txbuilder/<chain>.json` are Safe Transaction Builder format (checksummed).
These DO import in the web UI (New transaction → Transaction Builder → drag
file in), and also work with:

```sh
safe-cli tx-builder 0xEe2167a697dEd59e5BF9e65D8D807a193bdAE13D $RPC \
  txbatches/txbuilder/ethereum.json --private-key $K1 --private-key $K2 --non-interactive
```

safe-cli batches the file into ONE MultiSend Safe tx (verified: its decoder
reproduces the raw batch data byte-for-byte for all 18 files).

Notes:
- The PDF includes tokens on linea (wh 38, 6 tokens), unichain (wh 44, 5) and
  sonic (wh 52, 3). These entries are included but are inert until
  `setWormholeChainMapping` is called for those chains (currently
  `wormholeChainID(0, 59144|130|146) == 0` on the router).
- Scroll / MegaETH / Citrea routers were intentionally disabled
  (`DisableRouterTokens.s.sol`) and are not in the PDF, so no batches were
  generated for them.
- Encoder validated byte-for-byte against the original `txbatch.json` (USDT
  batch) and every generated file was decoded back and diffed against the PDF
  table (500/500 match per chain).
