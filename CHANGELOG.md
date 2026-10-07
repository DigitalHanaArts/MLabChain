# Changelog

## Mera / MLabChain

All notable changes to Mera / MLabChain are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the qualifier that **pre-1.0 minor versions may contain breaking changes**.

**Current status: reference testnet. Do not use for anything of value.**

---

## [Unreleased]

_Nothing pending. The next planned release is v0.3.1 with correctness fixes
and expanded test coverage. See the roadmap in `docs/MERA_PROTOCOL.md`._

---

## [0.3.0-devnet] — 2026-10-02

The v0.3 line upgrades MLabChain from a single-node SQLite ledger into a
small-network reference protocol with signed blocks, cumulative-work fork
choice, a challenge registry, marginal ML rewards, and an ERC-20
representation. It is the first release where the monetary layer is
structurally separate from the scientific layer.

### Added — Consensus

- **Signed block proposals.** Producers sign block headers with Ed25519.
  Verification is `address_from_pubkey(pubkey) == producer` plus an Ed25519
  signature check over the canonical header.
- **Cumulative-work fork choice.** Competing chains are compared by total
  work. Ties break by lower tip hash. Node state is replaced by replaying
  the winning chain from genesis.
- **Adaptive difficulty.** Retarget every 16 blocks toward a 60-second target
  with bounded one-step adjustment and clamped to `[1, 8]`.
- **Timestamp policy.** Median-time-past over the last 11 blocks, plus a
  2-minute future bound.
- **Block and transaction size limits.** `MAX_BLOCK_BYTES = 1 MiB`,
  `MAX_TX_BYTES = 64 KiB`, `MAX_NOTE_BYTES = 4096`.
- **Block transaction cap.** `MAX_BLOCK_TX = 2048`.

### Added — Networking

- **TCP P2P layer.** `PING`, `STATUS`, `GETCHAIN`, `TX|<wire>`,
  `BLOCK|<wire>` messages.
- **Chain sync.** `sync --peer host:port` and `node` commands.
- **Transaction and block relay.** `--broadcast` on `mine` and transaction
  submissions.
- **Sync loop.** Peer status polling and pull-based chain replacement when a
  peer has greater cumulative work.

### Added — Mempool and fees

- **Fee market.** `MIN_TX_FEE = 10000` atomic, `MIN_WORK_FEE = 100000` atomic
  on devnet.
- **Fee-priority selection.** Transactions ordered by descending fee with
  deterministic tie-break by txid.
- **Mempool quotas.** `MAX_MEMPOOL_TX = 20000`, `MAX_PENDING_PER_SENDER = 32`.
- **Pending-aware nonces.** Sender nonces account for unconfirmed transactions.
- **Pending balance reservation.** Prevents overspend across the mempool.

### Added — Challenge registry

- **Registered challenges.** On-chain objects with id, manifest hash, dataset
  hash, verifier, metric, split rule, dimensions, train fraction, max epochs,
  baseline, budget, activation height, expiry height.
- **Registration bond.** Devnet `CHALLENGE_BOND = 100000` atomic.
- **Maturity and expiry.** `CHALLENGE_MATURITY = 8`,
  `CHALLENGE_LIFETIME = 1000`.
- **Finite budgets.** `MAX_CHALLENGE_BUDGET = 1000 MERA` per challenge.
- **Per-proposer limit.** `MAX_ACTIVE_CHALLENGES_PER_PROPOSER = 8`.

### Added — ML work and issuance

- **`ML_WORK` transactions.** Commit challenge id, manifest hash, dataset
  hash, model hash, arch hash, ops, dimensions, fixed-point metrics, reward,
  wall time, LSWU, nonce, fee.
- **Native verifier registry.** The only consensus-paid verifier in v0.3 is
  `MLabChain-linear-v4`.
- **Symbolic operation model.** `ops = epochs × n_train × (3 × n_features + 4)`,
  bounded by `MAX_OPS_PER_WORK = 10^15`.
- **Marginal rewards.** Reward is computed against the challenge's current
  best accepted quality, not the original baseline.
- **Duplicate-work claims.** The `(challenge, dataset, model)` tuple is
  reserved once and cannot be re-claimed.
- **Baseline pinning.** For the native verifier, the baseline is fixed at
  `NMSE = 1` in scaled form.
- **Wall time is not money.** Recorded for audit only.
- **Integer-only reward arithmetic.** All fixed-point, all in C++.

### Added — Accounts and keys

- **Ed25519 addresses with checksums.**
  `MERA1` + payload + 8-character checksum.
- **`MERA2` multisig addresses.** `m-of-n` Ed25519 authorization for
  transfers and governance.
- **Key rotation.** `KEY_ROTATE` changes the authorized public key without
  changing the account address.
- **Scrypt + AES-GCM wallets.** `WALLET_VERSION = 2`, KDF parameters stored
  in the file.
- **`wallet-backup`** and **`backup`** commands for operational snapshots.

### Added — Governance

- **Genesis-defined governance multisig.** Optional keys and threshold
  committed at genesis.
- **`GOV_PARAM` transactions.** Timelocked changes to `min_fee`,
  `min_work_fee`, and `challenge_bond`.
- **`GOVERNANCE_TIMELOCK = 32` blocks.**

### Added — Storage

- **SQLite schema versioning.** v0.3 refuses v0.2 databases with a clear
  error instead of silently interpreting them.
- **Online backup.** `sqlite3_backup` exposed through `backup --output`.
- **Replay-based state comparison.** Per-account balance, nonce, and
  authorization key are checked address-by-address during validation.
- **O(1) total supply.** Stored as chain metadata.
- **Indexes.** `pending(sender, nonce)`, `pending(fee DESC, seq)`,
  `txs(height, ord)`, `txs(sender, nonce)`, `blocks(height)`.

### Added — Tooling

- **`tools/migrate_v2.py`.** Explicit v0.2 → v0.3 migration snapshot.
- **`tools/release_manifest.py`.** SHA-256 release manifest writer.
- **`CMakePresets.json`.** `cmake --preset release` support.
- **`Dockerfile`.** Container build.
- **`.github/workflows/ci.yml`.** Linux build and test.
- **`pyproject.toml`.** Installable Python package with a console entry
  point.

### Added — Contract

- **`MeraScientific.sol`.** Capped ERC-20 with `MINTER_ROLE`,
  `PAUSER_ROLE`, per-deposit replay protection, and
  `AccessControlDefaultAdminRules` with a 2-day delayed admin transfer.
  Explicitly **not** a trustless bridge.

### Changed

- **ML work no longer trusts wall-clock time for issuance.** Wall time is
  retained as an audit metric.
- **LSWU is retained as a scientific/provenance metric**, not a monetary
  input. The consensus reward uses symbolic operations and marginal quality.
- **Supply is maintained as chain metadata** rather than by summing account
  balances.
- **Block structure includes producer public key and signature.** Cumulative
  chain work is stored per block.
- **Mempool submission validates against the pending set**, not just the
  committed state.
- **Challenge manifest format bumped** to include `max_epochs`, `verifier`,
  and `schema_version`.
- **Wallet format bumped to v2** with Scrypt (was PBKDF2) and a
  version-tagged ciphertext.

### Fixed

- **Address checksums.** A typo in a recipient address is now rejected by the
  core instead of accepted.
- **Wallet integrity.** The decrypted public key is compared to the stored
  public key and the derived address.
- **Faucet is genesis-locked.** `faucet_enabled` is committed at genesis and
  cannot be flipped by an environment variable.
- **Replay account state is compared against the database.** A hand-edited
  accounts row that preserves total supply is now detected.
- **Block counters are checked during validation.** `total_ops` and
  `total_rewards` must equal the sums of their transactions.

### Security

- **Scrypt parameters:** `N=2^15, r=8, p=1`.
- **AES-GCM authentication tag bound to the string `MERA-WALLET-V2`.**
- **Ed25519 signatures over canonical message forms** for transfers,
  multisig transfers, ML work, challenge registration, key rotation,
  governance, and blocks.
- **Multisig key sorting and uniqueness.** The signer set must be sorted and
  free of duplicates.
- **Per-sender pending limits and balance reservation** to reduce spam.
- **Minimum fees and work fees** raised substantially from v0.2.
- **Transaction and block byte limits.**

### Deferred (research-grade)

These are **not** fixed in v0.3 and are not planned for v0.3.x:

- Succinct ML proofs / zkML.
- Permissionless verification of arbitrary GPU training.
- Production peer discovery and anti-eclipse hardening.
- Trustless L1↔EVM bridge.

### Deferred (engineering, targeted for v0.3.1)

- Correctness fix for marginal reward estimation on the Python side
  (the C++ core is authoritative; the client's local estimate is
  conservative).
- Explicit wallet overwrite protection on `create-wallet`.
- Artifact existence check in `verify-ml`.
- Removed dead branch in `mine` certificate path.
- Expanded test coverage for multisig, key rotation, governance timelock,
  reorg, block relay, transaction relay, fee market, mempool quotas, schema
  migration, challenge budget exhaustion, duplicate claim, retargeting,
  timestamp bounds.
- Windows and macOS CI.

---

## [0.2.0-devnet] — 2026-09-30 (superseded)

_Archived. Superseded by v0.3.0-devnet. Databases created by v0.2 are refused
by v0.3 and must be exported with `tools/migrate_v2.py`._

### Added

- Peer-to-peer TCP message layer.
- Chain sync and block/transaction relay.
- Cumulative-work fork choice and replay-based reorg.
- Signed block proposals.
- Adaptive PoW difficulty.
- Bounded timestamp policy.
- Block and transaction byte limits.
- Fee market and mempool quotas.
- Challenge registry with bond, maturity, expiry, and finite budgets.
- Native deterministic verifier registry.
- Marginal quality rewards and duplicate-work claims.
- Ed25519 address checksums.
- Key rotation.
- Native `m-of-n` multisig accounts.
- Timelocked governance for selected fee parameters.
- Immutable genesis faucet policy.
- SQLite schema versioning and migration snapshot tool.
- SQLite online backup command.
- Upgraded wallet encryption (Scrypt + AES-GCM).
- ERC-20 template with capped supply, bridge deposit replay protection,
  separated roles, and delayed admin rules.
- Unit, self, and end-to-end tests and CI configuration.

### Changed

- ML work no longer trusts wall-clock time for issuance.
- LSWU remains an audit metric; consensus reward uses deterministic symbolic
  work and marginal quality.
- Supply is maintained as chain metadata rather than full account summation.

---

## [0.1.7] — earlier

_Archived. Historical context only. Not compatible with v0.2 or v0.3._

- Original Python-only proof-of-scientific-work ledger.
- SHA-256 artifact hashing, Merkle trees, RSA-signed transactions,
  JSON chain persistence, local wallet.
- Non-transferable "credits" — no balances, no transfers.
- Reference implementation of the LSWU formula.

---

## Release tags

| Tag | Date | Status |
|---|---|---|
| `v0.3.0-devnet` | 2026-10-02 | current |
| `v0.2.0-devnet` | 2026-09-30 | superseded |
| `v0.1.7` | — | archived |

---

## Version policy

- **Major versions** (`1.0.0`) will mark a mainnet-ready release with
  independent cryptographic and consensus audit.
- **Minor versions** (`0.4.0`) may change consensus rules. They require a
  genesis change or an explicit migration snapshot.
- **Patch versions** (`0.3.1`) fix bugs and expand tests without changing
  consensus rules.

Chains are versioned by `PROTOCOL_VERSION`. A node refuses a database whose
schema version does not match.

---

<p align="center">
  <img src="assets/mlabchain_txt.png" alt="MLabChain" height="40">
</p>