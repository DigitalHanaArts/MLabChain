<p align="center">
  <img src="materials/mlabchain.png" alt="MLabChain" width="333"/>
  &nbsp;&nbsp;&nbsp;
  <img src="materials/MERA_v3.png" alt="Mera" width="300"/>
</p>

<h1 align="center">Mera / MLabChain</h1>

<p align="center">
  <em>A scientific-work ledger with a native unit called Mera.</em><br>
  <strong>v0.3.0-devnet</strong> &nbsp;·&nbsp; reference testnet &nbsp;·&nbsp; Apache-2.0
</p>

---

<p align="center">
  <img src="https://github.com/DigitalHanaArts/DigitalHanaArts/blob/main/DHA_logo.png" width="333" alt="Digital Hana Arts">
</p>

<h1 align="center">Digital__Hana__Arts®</h1>

<p align="center">
  <strong>Computational Creativity · Data · Intelligence · Digital Art</strong>
</p>

<p align="center">
  <em>
    Exploring the space where technology becomes a creative medium.
  </em>
</p>

<p align="center">
  <a href="https://github.com/DigitalHanaArts">
    <img src="https://img.shields.io/badge/GitHub-Digital%20Hana%20Arts-111827?style=flat-square&logo=github&logoColor=white">
  </a>
  <img src="https://img.shields.io/badge/AI%20%26%20ML-Research-111827?style=flat-square">
  <img src="https://img.shields.io/badge/Data%20Science-Computing-111827?style=flat-square">
  <img src="https://img.shields.io/badge/Digital%20Art-Generative-111827?style=flat-square">
  <img src="https://img.shields.io/badge/Blockchain-Web3-111827?style=flat-square">
</p>

---

MLabChain is a small, honest ledger for machine-learning work. It records
training runs as signed, replayable transactions and issues a native unit
called **Mera** for the ones that measurably improve a pinned scientific
baseline. Deterministic work is paid. Everything else is recorded as
provenance, not money.

The project splits cleanly:

- **Python** owns the scientific layer — training, challenges, artifacts, wallet UX.
- **C++** owns the monetary layer — signatures, replay, fork choice, fees, supply.

That split is deliberate. The core can be audited without reading a line of
Python. The Python layer can be replaced without touching consensus rules.

---

## Table of contents

1. [What this is](#what-this-is)
2. [What this is not](#what-this-is-not)
3. [Architecture](#architecture)
4. [Quick start](#quick-start)
5. [The scientific work model](#the-scientific-work-model)
6. [The Mera asset](#the-mera-asset)
7. [Consensus and fork choice](#consensus-and-fork-choice)
8. [Wallet, keys, and accounts](#wallet-keys-and-accounts)
9. [Networking](#networking)
10. [Governance](#governance)
11. [Migration from v0.2](#migration-from-v02)
12. [Tests](#tests)
13. [Honest boundary](#honest-boundary)
14. [Repository layout](#repository-layout)
15. [Credits](#credits)
16. [License](#license)

---

## What this is

MLabChain is a **research-grade testnet** for one specific idea: that a
blockchain can pay for a bounded class of **deterministic, reproducible**
machine-learning computations.

A training run becomes a signed transaction containing the challenge, the
dataset commitment, the model, the architecture, the training parameters, and
the metrics. A C++ core validates signatures, account nonces, fixed-point
reward arithmetic, supply caps, Merkle roots, block PoW, and fork choice. A
Python client performs the training and writes the artifacts to disk.

The unit that gets issued is **Mera**. It is minted only when a submitted
model measurably improves the challenge's *current best frontier*, subject to a
finite per-challenge budget and a global supply cap of 100,000,000.

Chain security is a **separate** mechanism from scientific work:

- **Chain PoW** seals blocks and provides a Sybil-resistance signal.
- **Scientific work** is the ML computation committed by `ML_WORK` transactions.

This separation means a change to the ML verifier does not require a change to
the block-sealing rules, and vice versa.

---

## What this is not

Stated plainly, because the project's credibility depends on saying it:

- **Not a currency.** There is no exchange listing, no price, no market, no
  promise of one.
- **Not a general ML verifier.** Only deterministic linear regression is
  consensus-paid in v0.3. GPU training, PyTorch, JAX, and stochastic
  optimisation are *not* consensus-valid.
- **Not a proof system.** A model hash is a commitment, not a proof that a
  training procedure ran. Deterministic re-execution is the only sound
  verifier, and it only works for verifier classes the node implements.
- **Not a trustless bridge.** The ERC-20 contract is a representation
  template. Mint authority is a trust boundary until a proof-based bridge
  exists.
- **Not an audited mainnet.** The reference node is a devnet. No security
  audit, no fuzzing, no battle-testing.
- **Not decentralised P2P.** The reference protocol is plaintext, single
  connection per request, and has no peer discovery, anti-eclipse, or
  connection quotas.

If you are looking for an investment, close the tab. If you are looking for a
scientific provenance ledger that pays for one narrow, verifiable class of ML
work, keep reading.

---

## Architecture

```
                  ┌──────────────────────────────────────┐
                  │  mlabchain.py — Python scientific    │
                  │  ────────────────────────────────    │
                  │  • deterministic ML training         │
                  │  • challenge manifest creation       │
                  │  • dataset / model / arch hashing    │
                  │  • LSWU audit score                  │
                  │  • Scrypt + AES-GCM wallet           │
                  │  • transaction construction          │
                  └─────────────────┬────────────────────┘
                                    │ subprocess boundary
                                    ▼
                  ┌──────────────────────────────────────┐
                  │  mera_core.cpp — C++ consensus core  │
                  │  ────────────────────────────────    │
                  │  • Ed25519 authentication            │
                  │  • SQLite canonical state            │
                  │  • signed block proposals            │
                  │  • adaptive SHA-256 PoW              │
                  │  • cumulative-work fork choice       │
                  │  • replay-based validation           │
                  │  • challenge registry                │
                  │  • fixed-point reward issuance       │
                  │  • fee market + mempool limits       │
                  │  • TCP sync + relay                  │
                  └─────────────────┬────────────────────┘
                                    │
                                    ▼
                             native MERA balance
                                    │
                                    ▼
                  ┌──────────────────────────────────────┐
                  │  MeraScientific.sol — ERC-20         │
                  │  representation template             │
                  │  (not a trustless bridge)            │
                  └──────────────────────────────────────┘
```

---

## Quick start

### Requirements

- Python 3.10 or newer
- A C++17 compiler, CMake ≥ 3.20
- OpenSSL, SQLite3, and Boost headers
- On Windows: MSYS2 (recommended), WSL, or Visual Studio Build Tools

### Build the native core

```bash
# Linux / macOS
./build.sh

# Windows PowerShell
./build.ps1
```

This produces `build/mera_core` (or `build/Release/mera_core.exe` on Windows)
and runs the C++ self-test plus CTest.

### Install the Python client

```bash
python -m pip install -e .
```

or, if you prefer explicit dependencies:

```bash
python -m pip install "cryptography>=42" pytest
```

### Create a devnet node

```bash
python mlabchain.py --data-dir ./node1 init --network devnet
python mlabchain.py --data-dir ./node1 create-wallet
```

The wallet password can be supplied through `MERAWALLET_PASSWORD` or entered
interactively. It must be at least 10 characters.

### Fund and inspect

```bash
MERAWALLET_PASSWORD='a-long-demo-password' \
  python mlabchain.py --data-dir ./node1 faucet --amount 5

python mlabchain.py --data-dir ./node1 balance
python mlabchain.py --data-dir ./node1 status
python mlabchain.py --data-dir ./node1 validate
```

### Register a challenge and submit work

```bash
python mlabchain.py --data-dir ./node1 challenge-create \
  --id MLC-LINEAR-001 \
  --output ./node1/challenges/MLC-LINEAR-001.json \
  --n-samples 1200 --n-features 4 --seed 42 \
  --noise 0.1 --train-fraction 0.8 --max-epochs 100

python mlabchain.py --data-dir ./node1 challenge-register \
  --manifest ./node1/challenges/MLC-LINEAR-001.json \
  --budget 100

python mlabchain.py --data-dir ./node1 mine \
  --challenge ./node1/challenges/MLC-LINEAR-001.json \
  --config ./config.json
```

### Transfer Mera

```bash
python mlabchain.py --data-dir ./node1 transfer \
  --to MERA1... \
  --amount 0.10 \
  --mine
```

### Run a two-node devnet

```bash
mera_core --data-dir ./node1 node \
  --listen-host 127.0.0.1 --port 19001 \
  --peers 127.0.0.1:19002

mera_core --data-dir ./node2 node \
  --listen-host 127.0.0.1 --port 19002 \
  --peers 127.0.0.1:19001

python mlabchain.py --data-dir ./node2 sync --peer 127.0.0.1:19001
```

---

## The scientific work model

### Challenges

A challenge is a registered object that pins the task:

| Field | Meaning |
|---|---|
| `challenge_id` | Unique name, e.g. `MLC-LINEAR-001` |
| `manifest_hash` | SHA-256 of the canonical challenge manifest |
| `dataset_sha256` | Commitment to the dataset |
| `verifier` | The verifier class that will pay for work |
| `metric` | The scoring metric (`NMSE` in v0.3) |
| `split_rule` | Deterministic train/test split |
| `n_samples`, `n_features` | Dataset dimensions |
| `train_fraction_ppm` | Training fraction, in parts per million |
| `max_epochs` | Bound on submitted training runs |
| `baseline_scaled` | Fixed-point baseline NMSE |
| `budget` | Finite Mera budget for the challenge |
| `activation_height` | Maturity delay before submissions are accepted |
| `expiry_height` | After this height, the challenge is closed |

A challenge must be registered with a **bond** (devnet: `0.001 MERA`),
becomes **active** after `CHALLENGE_MATURITY = 8` blocks, and **expires**
after `CHALLENGE_LIFETIME = 1000` blocks.

### Verifier classes

v0.3 pays for exactly one verifier: `MLabChain-linear-v4`. It is deterministic
linear regression with a seeded dataset generator, a fixed SGD order, and a
fixed train/test split. Every node can replay it byte-for-byte.

The symbolic operation model is:

```
ops = epochs × n_train × (3 × n_features + 4)
```

This is hardware-independent by design. A slower machine does not earn more.
A faster machine does not earn less per proof.

### Marginal rewards

Reward is measured against the challenge's **current best** accepted quality,
not against the original baseline:

```
quality_ppm = clamp( (baseline − model) × 1e6 / baseline, 0, 1e6 )

delta_q = quality_ppm − challenge.best_quality_ppm

reward  = min( 50 MERA,
               ops × delta_q × 1e8 / (1e7 × 1e6) )
```

Integer arithmetic only. Two constants matter:

- `OPS_PER_MERA = 10,000,000` — the reward scale.
- `MAX_WORK_REWARD = 50 MERA` — the per-proof cap.

The reward is additionally constrained by:

- `reward ≤ challenge.budget_remaining`
- `total_supply + reward ≤ 100,000,000 MERA`

### Anti-farming rules

- One reward claim per `(challenge, dataset, model)`.
- No reward if the submission does not improve the challenge frontier.
- Minimum challenge size (1000 samples on devnet).
- Registration bond and maturity delay.
- Per-proposer active-challenge limit (`MAX_ACTIVE_CHALLENGES_PER_PROPOSER = 8`).
- Maximum symbolic operations per proof (`MAX_OPS_PER_WORK = 10^15`).

These reduce duplicate payment and trivial-challenge farming. They do not
provide perfect Sybil resistance. See [Honest boundary](#honest-boundary).

### Wall time

Wall time is recorded in the transaction as an audit metric. It is **not** a
minting input. A miner cannot increase issuance by reporting a slower clock.

### LSWU

The LabChain Scientific Work Unit is computed and stored in the transaction
payload as a scientific audit score. The consensus reward does **not** depend
on it. See `docs/MERA_PROTOCOL.md` for the full formula and rationale.

---

## The Mera asset

| Parameter | Value |
|---|---:|
| Asset | MERA |
| Atomic units | 100,000,000 per MERA |
| Decimals | 8 |
| Maximum supply | 100,000,000 MERA |
| Per-proof reward cap | 50 MERA |
| Minimum transfer fee | 0.0001 MERA |
| Minimum ML-work fee | 0.001 MERA |
| Challenge bond (devnet) | 0.001 MERA |
| Fees | burned |
| Consensus seal | SHA-256 block PoW |

### Native ledger

Balances are maintained as O(1) chain metadata. State is defined by replaying
the canonical block history from genesis. SQLite is a materialised view of that
state, not the source of truth.

### EVM representation

`contracts/MeraScientific.sol` is an ERC-20 template with:

- 8 decimals
- Hard cap of 100,000,000 MERA
- `MINTER_ROLE` for a bridge authority
- Per-deposit replay protection (`usedDepositIds`)
- `PAUSER_ROLE` for incident response
- `AccessControlDefaultAdminRules` with a 2-day delayed admin transfer
- `ERC20Permit` and `ERC20Burnable`

It is **not** a trustless bridge. The bridge authority is a trust boundary
until a proof-based bridge or audited threshold signer replaces it.

---

## Consensus and fork choice

### Block structure

Each block contains:

- `height`, `timestamp_ms`
- `previous_hash`
- `merkle_root` over transaction IDs
- `producer` address, `producer_pubkey`, `producer_signature`
- `difficulty`, `nonce`
- `chain_work` (cumulative)
- `total_ops`, `total_rewards`

The block hash is `SHA256(header)`, where the header includes the producer
signature. A valid block requires `block_hash` to start with `difficulty`
hex zeroes.

### Fork choice

Nodes accept the chain with the **highest cumulative work**. Ties break by
lower tip hash. A candidate chain is validated by replaying it from genesis.
On reorg, the canonical SQLite state is replaced by replay.

### Difficulty

Retargeted every `DIFFICULTY_WINDOW = 16` blocks toward a target block time of
`TARGET_BLOCK_MS = 60,000`. The adjustment is bounded to ±1 step per retarget
and clamped to `[MIN_DIFFICULTY, MAX_DIFFICULTY] = [1, 8]`.

### Timestamps

A block's timestamp must be strictly greater than the median of the last 11
blocks and no more than `MAX_FUTURE_MS = 120,000` ms ahead of local time.

### Mempool

- `MAX_MEMPOOL_TX = 20,000` transactions
- `MAX_PENDING_PER_SENDER = 32`
- `MAX_BLOCK_TX = 2,048`
- `MAX_TX_BYTES = 64 KiB`
- `MAX_BLOCK_BYTES = 1 MiB`
- Fee-priority selection, with per-sender reservation for pending spend

### Limits

`MAX_NOTE_BYTES = 4096`. A `MAX_OPS_PER_WORK = 10^15` bound on symbolic work
per proof.

---

## Wallet, keys, and accounts

### Standard accounts

Ed25519 public keys with a **checksum address**:

```
address = "MERA1" + sha256(pubkey)[:40] + sha256("MERA-ADDR-V3|" + prefix)[:8]
```

A checksum mismatch causes the core to reject the address.

### Encryption

The wallet file is encrypted with **Scrypt + AES-GCM**:

```
KDF      = scrypt(N=2^15, r=8, p=1)
Cipher   = AES-256-GCM
Auth tag = "MERA-WALLET-V2"
```

The KDF parameters are stored in the wallet file so they can be raised in a
future version without invalidating existing wallets.

### Multisig

`MERA2` addresses require an `m-of-n` Ed25519 signature set. Keys are sorted
canonically before address derivation. Threshold and key set are stored in
the transaction for verification.

### Key rotation

`KEY_ROTATE` changes the authorized public key without changing the account
address. After rotation, the new key authorizes transfers, producer
signatures, and ML submissions.

### Backups

`backup --output FILE` uses SQLite's online backup API. The wallet is a
separate file and must be backed up separately:

```bash
python mlabchain.py --data-dir ./node1 wallet-backup --output ./backup/wallet.json
```

### Seed phrase, hardware wallets

Not implemented. See [Honest boundary](#honest-boundary).

---

## Networking

The reference P2P protocol supports:

| Message | Purpose |
|---|---|
| `PING` / `PONG` | Liveness |
| `STATUS` | Advertise height, tip, cumulative work |
| `GETCHAIN` | Request the full chain from a peer |
| `TX\|<wire>` | Relay a signed transaction |
| `BLOCK\|<wire>` | Relay a block |

The wire format is a length-delimited line of hex-encoded fields separated by
`|`. Blocks include their transactions inline.

Peer addresses are supplied on the command line. There is no discovery.

See [Honest boundary](#honest-boundary) for what the reference protocol does
not provide.

---

## Governance

Selected fee parameters can be scheduled through a governance mechanism:

- Genesis defines a governance multisig address and threshold.
- `GOV_PARAM` transactions schedule a bounded fee change.
- The change takes effect at `block_height + GOVERNANCE_TIMELOCK = 32`.
- Only `min_fee`, `min_work_fee`, and `challenge_bond` are modifiable.

The faucet status, supply cap, and reward formula are **not** modifiable by
governance. They are committed at genesis.

---

## Migration from v0.2

v0.3 does not silently interpret a v0.2 SQLite database as v0.3 state. The
schema version is checked on open, and a mismatch is a hard error.

To migrate:

```bash
python tools/migrate_v2.py \
  --input ./old/mera_data/mera.sqlite \
  --output ./migration/v2_snapshot.json
```

The output is an explicit migration snapshot containing account balances,
nonces, the old genesis and tip, and a snapshot SHA-256. A production migration
is expected to define a **new genesis/allocation ceremony** that commits to
this snapshot before importing balances.

This is intentional. Silently replaying v0.2 history under changed consensus
rules would be less safe than an explicit migration boundary.

---

## Tests

```bash
ctest --test-dir build --output-on-failure
pytest
```

The current suite covers:

- Address checksums
- Wallet encryption round trips
- Deterministic training reproducibility
- End-to-end ML submission, reward, transfer, and validation
- P2P chain synchronization between two nodes
- Genesis faucet policy on mainnet
- Schema mismatch refusal and migration snapshot export

Coverage is a work in progress. See `tests/test_protocol.py` for what is
present and what is missing.

### CI

The GitHub Actions workflow builds on Ubuntu 22.04, runs CTest and pytest,
and performs a Python compile check. Windows and macOS CI are not yet wired in.

---

## Honest boundary

### What v0.3 pays for

- Deterministic linear regression against a pinned challenge.
- Registered, budgeted, maturity-delayed challenges.
- Marginal rewards relative to the current best accepted quality.
- Signed transfers, nonces, multisig, key rotation.
- Fork choice by cumulative work, with reorg and replay.
- Signed block proposals and adaptive SHA-256 PoW.
- A small TCP P2P layer with sync and relay.
- Scrypt + AES-GCM encrypted wallets.

### What v0.3 does not claim

- That a model hash proves a training procedure ran.
- That verification is cheaper than re-execution.
- That GPU, PyTorch, JAX, or stochastic training are consensus-valid.
- That the P2P layer resists an Internet-scale adversary.
- That the ERC-20 contract is a trustless bridge.
- That Mera has a price, a market, or a future listing.
- That Sybil resistance exists beyond PoW and challenge bonds.
- That the reference node is an audited mainnet.

### Four research-grade open problems

1. **General ML proofs.** A model hash is a commitment, not a proof.
   Deterministic re-execution is the only sound verifier, and it only works
   for verifier classes the node implements.
2. **Stochastic and GPU training.** Not consensus-valid. Can be recorded as
   provenance, cannot be paid.
3. **Permissionless P2P hardening.** Peer discovery, anti-eclipse, connection
   quotas, fuzzing, formal message limits.
4. **Trustless L1↔EVM bridge.** Requires a proof or attestation protocol and
   audited contracts. Not in this release.

These four are not engineering gaps. They are research problems. The project
states them here and in every other document.

---

## Repository layout

```
Mera_MLabChain_v0.3.0-dev1/
├── mlabchain.py              Python scientific / ML client
├── README.md                 this document
├── CHANGELOG.md              version history
├── LICENSE.txt               Apache-2.0
├── pyproject.toml            Python package metadata
├── requirements.txt
├── build.sh                  Linux / macOS build
├── build.ps1                 Windows build
├── CMakePresets.json         CMake preset for `cmake --preset release`
├── Dockerfile                container build
├── Makefile
│
├── assets/                   Logos and graphics
│   ├── mlabchain.png
│   ├── MERA.png
│   ├── mlabchain_txt.png
│   ├── ascii-magic-1.png
│   ├── DHA_logo.png
│   ├── DHA_logo_h.png
│   └── Hana_the_kitten.jpeg
│
├── cpp/
│   ├── mera_core.cpp         C++ ledger / consensus / economic core
│   ├── CMakeLists.txt
│   └── README.md
│
├── contracts/
│   └── MeraScientific.sol    ERC-20 representation template
│
├── docs/
│   ├── ARCHITECTURE.txt      layer split and trust boundaries
│   ├── MERA_PROTOCOL.md      consensus, issuance, verification model
│   └── SECURITY.md           improvements, assumptions, production checklist
│
├── tests/
│   └── test_protocol.py      end-to-end protocol tests
│
├── tools/
│   ├── migrate_v2.py         v0.2 → v0.3 migration snapshot
│   └── release_manifest.py   SHA-256 release manifest
│
└── .github/workflows/
    └── ci.yml                build + test on Linux
```

---

## Credits

MLabChain is developed and maintained by
[**Digital Hana Arts**](https://github.com/). The project's mascot is
**Hana**, who supervises the repository from a comfortable distance and has
no opinions about Merkle trees.

Protocol design, C++ core, and Python client: Ali Bavarchee.

---

## License

Apache License 2.0. See [`LICENSE.txt`](LICENSE.txt).

---

<p align="center">
  <img src="assets/Hana_the_kitten.jpeg" alt="Hana" width="120" style="border-radius:8px;">
</p>

<p align="center">
  <em>Proof-of-Scientific-Work. Verified work is paid. Everything else is provenance.</em>
</p>
```

---
