# Mera / MLabChain v0.3 Security Notes

## Improvements over v0.2

- Ed25519 transaction and block-producer signatures
- Scrypt + AES-GCM encrypted Python wallets
- address checksums
- key rotation
- native multisig transfers
- signed blocks
- immutable genesis faucet setting
- bounded transactions/blocks/notes
- sender and fee indexes
- O(1) total-supply accounting
- account-state replay comparison
- cumulative-work fork choice and reorg
- timestamp validation
- adaptive difficulty
- challenge registration bond and maturity
- finite challenge budgets
- duplicate-work claim set
- timelocked parameter governance
- SQLite backup API
- schema-version refusal instead of silent cross-version loading

## Remaining trust assumptions

1. The node executable and its native ML verifier are trusted software components.
2. Deterministic native ML proofs are re-executable; arbitrary ML is not a consensus proof.
3. A challenge must use a verifier definition that is already implemented by every consensus node.
4. The P2P layer is a reference implementation and has not undergone adversarial Internet-scale testing.
5. The EVM representation depends on its bridge authority until a trustless proof bridge exists.
6. Wallet security depends on the operator password and host security.

## Production checklist

Before a public mainnet:

- independent cryptographic and consensus audit
- fuzzing of transaction/block parsers
- differential replay tests across platforms
- deterministic build/release pipeline
- signed binaries and release attestations
- peer discovery and anti-eclipse design
- rate limiting and peer scoring
- chain checkpoint/finality strategy
- audited governance/multisig controls
- audited bridge or remove the bridge dependency
- economic simulation of fee burn and scientific issuance
- formal specification of verifier bytecode/semantics for every paid ML class
- zkML/verifiable-compute research before paying arbitrary GPU/ML workloads
