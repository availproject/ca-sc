# Mayan token-list — INTERNAL MAINNET routers — Safe transaction batches

Generated 2026-07-14 from `Mayan Supported Tokens, Nexus Identifier Format.pdf`.
499 `setTokenOutDecimals(uint16,address,uint8)` entries covering all 12 Mayan
destination chains (one sheet row excluded: BSC token
`0x7485a0aaC4856Fe63ec2Ece0C1D75C6fa82d7A22` has 0 decimals, which the router
treats as "disabled", so it cannot be enabled).

Safe (owner after ownership transfer): `0xEe2167a697dEd59e5BF9e65D8D807a193bdAE13D`
on every chain. Each file is one Safe tx: delegatecall into MultiSendCallOnly
v1.4.1 `0x9641d764fc13c8B624c04430C7356C1C7C8102e2` (verified deployed on all
11 chains, incl. scroll + megaeth).

## Router per chain

| Router | Chains |
|---|---|
| `0x1F035f26710d5a3C4F7052f184564C8e4707c8f1` | ethereum, polygon, arbitrum, optimism, base, monad |
| `0x5c688B2f4D9Da1569BBDec3543C7357f57Ce1Aeb` | bsc, avalanche, hyperevm, megaeth |
| `0x32D9d4ac2A32A35128eca3Ca3263469e3588CAE8` | scroll |

Ownership-transfer status (verified on-chain 2026-07-14): **done** on
ethereum, polygon, scroll; **still deployer-owned** (`0x3273656f...`) on
arbitrum, optimism, base, monad, bsc, avalanche, hyperevm, megaeth — those
batches execute only after the transfer lands (owner-only call would revert).

## Files

| Chain | File(s) | Entries/tx | Nonce(s) | Note |
|---|---|---|---|---|
| ethereum | ethereum.json | 499 | 4 | |
| polygon | polygon.json | 499 | 4 | |
| arbitrum | arbitrum.json | 499 | 4 | |
| optimism | optimism.json | 499 | 4 | |
| base | base.json | 499 | 5 | |
| monad | monad.json | 499 | 3 | |
| bsc | bsc.json | 499 | 3 | |
| avalanche | avalanche_1of2, _2of2 | 250/249 | 5, 6 | 15M block gas limit |
| hyperevm | hyperevm_1of9 … 9of9 | 60 (last 19) | 4–12 | 2M small-block limit |
| megaeth | megaeth.json | 499 | 2 | |
| scroll | scroll_1of2, _2of2 | 250/249 | 0, 1 | conservative block-limit split |

**Nonce warning:** this Safe (`0xEe2167...`) is the same one that owns the
public-mainnet router `0x415B73...`. The batches in `../` (public mainnet)
embed the SAME live nonces fetched earlier. If you queue both sets, the
embedded nonces will collide — use `propose.py` (it always uses the live
on-chain nonce) or adjust nonces manually.

## How to submit

### A. Propose via Safe Transaction Service (co-sign in the web UI)

Works on all chains except hyperevm (megaeth's service is at the `mega` slug,
scroll at `scr` — both handled by the script):

```sh
pip install safe-cli
PROPOSER_PRIVATE_KEY=0x... python propose.py ethereum
python propose.py megaeth --dry-run     # no key needed, prints safeTxHash
```

### B. Direct execution with safe-cli (needed for hyperevm)

Requires 2 owner keys (threshold 2/6). `--delegate` is mandatory:

```sh
safe-cli send-custom 0xEe2167a697dEd59e5BF9e65D8D807a193bdAE13D $RPC \
  0x9641d764fc13c8B624c04430C7356C1C7C8102e2 0 "$(jq -r .data hyperevm_1of9.json)" \
  --delegate --private-key $K1 --private-key $K2 --non-interactive
```

Multi-part chains must execute parts in order.

### C. Transaction Builder files (`txbuilder/`)

Checksummed Safe Transaction Builder format — importable in the web UI
(New transaction → Transaction Builder → drag file) and usable with
`safe-cli tx-builder <safe> <rpc> txbuilder/<chain>.json --private-key ...`.

## Validation performed

- All 21 raw batches decoded back and diffed against the parsed PDF table:
  499/499 exact match per chain, correct router per chain.
- All 21 txbuilder files run through safe-cli's own decoder reproduce the raw
  MultiSend payload byte-for-byte.
- MultiSendCallOnly presence, Safe existence/nonce, and router owner verified
  on-chain per network.
- linea (wh 38) / unichain (44) / sonic (52) destination entries are included
  but stay inert until `setWormholeChainMapping` is configured for those
  chains on these routers.

Note: the EOA-broadcast alternative (`script/ConfigureMayanTokenList.s.sol` +
`script/configure_mayan_token_list.sh`) covers the same table and remains
usable on chains where the deployer still owns the router.
