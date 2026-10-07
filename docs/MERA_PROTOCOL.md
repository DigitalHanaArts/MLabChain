# Mera / MLabChain v0.3 Protocol Notes

## Scope

v0.3 upgrades the v0.2 single-node ledger into a small-network reference protocol. It addresses the engineering limitations that do not require a research-grade ML proof system, while making the remaining research boundary explicit.

## Consensus and chain selection

Each block contains:

- previous block hash
- Merkle root of transactions
- block producer address
- producer Ed25519 public key and signature over the block proposal
- timestamp
- nonce
- difficulty
- cumulative chain work
- operation/reward counters

A node validates a candidate chain by replaying it from genesis. Among competing valid tips, v0.3 selects the chain with the highest cumulative PoW work. A deterministic tip-hash tie break is used when cumulative work is equal.

This gives v0.3 an explicit fork-choice/reorg mechanism. Nodes replace their canonical SQLite state by replaying the selected chain, then return transactions that were not included into the local mempool.

## Difficulty

PoW uses a bounded SHA-256 leading-zero target. Difficulty is retargeted every 16 blocks toward a 60-second target with bounded one-step adjustment. The parameter is protocol state, not a CLI-controlled arbitrary value.

PoW remains a chain-sealing and Sybil-resistance mechanism. It is separate from scientific work. Scientific work is represented by `ML_WORK` transactions.

## Timestamps

A block must have a timestamp strictly after its parent and no more than two minutes into the node's future-clock window. This is intentionally simple for v0.3; a production network should add peer-clock sampling and a median-time-past style rule.

## Mempool and DoS controls

The reference node enforces:

- global mempool count limit
- per-sender pending transaction limit
- block transaction count limit
- maximum serialized transaction size
- maximum serialized block size
- minimum fee and separate minimum ML-work fee
- fee-priority transaction selection
- indexed sender/fee lookups

The protocol does not claim to defeat volumetric network attacks at Internet scale. Production deployment still needs peer scoring, connection quotas, bandwidth limits and rate limiting.

## Scientific-work registration

Challenges are registry objects, not free-form reward sources.

A registered challenge pins:

- challenge id
- manifest hash
- dataset hash
- verifier class
- metric and split rule
- sample count and feature count
- train fraction
- maximum epochs
- baseline
- finite reward budget
- activation delay and expiry

v0.3 pays only the built-in verifier class `MLabChain-linear-v4`.

For that verifier the exact operation model is:

`ops = epochs * n_train * (3 * n_features + 4)`

The core checks the symbolic work bound and the challenge parameters. A Python proof artifact can additionally be re-executed byte-for-byte for deterministic reproducibility.

## Baseline and anti-farming rules

The baseline is no longer an arbitrary challenge-author number for the native verifier. The core pins the baseline to the verifier-defined mean-predictor reference (`NMSE = 1` in scaled fixed-point form).

Reward is marginal:

`reward = min(cap, ops * incremental_quality / OPS_PER_MERA)`

where incremental quality is measured against the challenge's current best accepted quality, rather than always against the original baseline.

Additional protections:

- minimum challenge size
- challenge registration bond
- activation delay
- expiry height
- finite challenge reward budget
- one reward claim per `(challenge, model hash, verifier)`
- no reward when quality does not improve the challenge frontier
- max operations per proof

These rules reduce duplicate payment and trivial-challenge farming; they do not provide perfect Sybil resistance without an external identity/stake mechanism.

## Fees and supply

Native MERA uses fixed 8-decimal atomic units.

- maximum supply is 100,000,000 MERA
- transfer fees and work fees are burned in the reference policy
- ML issuance cannot exceed the global cap or the challenge budget
- supply is stored as O(1) chain metadata rather than recomputed by full account scans

The parameter set is committed at genesis. The v0.3 governance mechanism can schedule bounded fee changes, subject to a 32-block timelock and a genesis-defined governance signer set.

## Faucet

Faucet activation is a chain-genesis property. It is enabled only for a chain whose genesis was created with the `devnet` network value. An environment variable cannot turn the faucet on for a mainnet database.

## Keys and accounts

Standard accounts use Ed25519 public keys. Addresses have a checksum.

`KEY_ROTATE` changes the authorized public key without changing the account address.

`MERA2` multisig accounts can require an `m-of-n` set of Ed25519 signatures for a transfer.

The Python wallet uses a password-derived Scrypt key and AES-GCM encryption. v0.3 still does not provide seed-phrase recovery or hardware-wallet support.

## State and storage

SQLite is used only as the materialized canonical state database. Chain validity is determined by replaying the canonical block history.

The database schema is versioned. v2 databases are refused by v0.3 instead of being silently interpreted as v3. `tools/migrate_v2.py` exports a migration snapshot so an operator can perform an explicit genesis/reallocation migration ceremony.

The node exposes SQLite's backup API through `backup` so a consistent copy can be taken while WAL mode is active.

## What v0.3 still does not solve

### General ML proofs

A model hash remains a commitment, not a proof of training. Deterministic re-execution is only practical for the verifier classes that the node implements. Succinct, permissionless verification of arbitrary large ML computations remains a zkML / verifiable-computation research problem.

### Stochastic/GPU training

v0.3 does not pay consensus rewards for non-deterministic GPU training. Those runs can be recorded as provenance artifacts, but they are not native consensus work proofs.

### Fully permissionless P2P hardening

The reference P2P protocol is intentionally small. A production Internet network still needs peer discovery, anti-eclipse measures, connection management, DoS resistance, fuzzing and formal message limits beyond this reference implementation.

### Trustless L1↔EVM bridge

`MeraScientific.sol` is a representation token with replay-protected bridge minting. The bridge authority must be externally secured. A truly trustless bridge requires a proof/verification protocol and audited contracts.

### PoW economics

v0.3 provides an actual retarget rule, but the economic choice of PoW versus a stake-based finality system remains a design decision for a production network. No claim of Bitcoin-level decentralization or security is made by this reference implementation.
