#!/usr/bin/env python3
# MLabChain + Mera v0.3
# Copyright 2026 Ali Bavarchee
# SPDX-License-Identifier: Apache-2.0

"""Python scientific/ML front-end for the Mera v0.3 protocol.

The C++ core is authoritative for monetary state, signatures, block sealing,
fork choice, chain replay, mempool limits, challenge registry, and networking.
Python owns deterministic native ML training and scientific artifact creation.
"""
from __future__ import annotations
import argparse
import getpass
import hashlib
import json
import math
import os
import pickle
import random
import secrets
import subprocess
import sys
from dataclasses import asdict, dataclass
from decimal import Decimal, ROUND_DOWN
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "mera_data"
WALLET_FILE = DATA_DIR / "wallet.json"
CHALLENGE_DIR = DATA_DIR / "challenges"
MODEL_DIR = DATA_DIR / "models"
PROOF_DIR = DATA_DIR / "proofs"
CORE_ENV = "MERA_CORE_PATH"
ATOMIC_PER_MERA = 100_000_000
MIN_WORK_FEE_ATOMIC = 10_000
CHALLENGE_BOND_ATOMIC = 100_000
SCHEMA_VERSION = 4
WALLET_VERSION = 2
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1

LSWU_N0 = 1e5
LSWU_T0 = 60.0
LSWU_ETA = 2.0
LSWU_WN = 0.15
LSWU_WT = 0.30
LSWU_WQ = 1.0
NATIVE_VERIFIER = "MLabChain-linear-v4"

DEFAULT_CONFIG: dict[str, Any] = {
    "model_type": "linear-regression",
    "framework": "mlabchain-native",
    "seed": 42,
    "learning_rate": 0.01,
    "epochs": 30,
}


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def configure_data_dir(path: str | Path) -> None:
    global DATA_DIR, WALLET_FILE, CHALLENGE_DIR, MODEL_DIR, PROOF_DIR
    DATA_DIR = Path(path).expanduser().resolve()
    WALLET_FILE = DATA_DIR / "wallet.json"
    CHALLENGE_DIR = DATA_DIR / "challenges"
    MODEL_DIR = DATA_DIR / "models"
    PROOF_DIR = DATA_DIR / "proofs"
    os.environ["MERA_DATA_DIR"] = str(DATA_DIR)


def ensure_dirs() -> None:
    for p in (DATA_DIR, CHALLENGE_DIR, MODEL_DIR, PROOF_DIR):
        p.mkdir(parents=True, exist_ok=True)


def hash_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_from_mera(value: str) -> int:
    d = Decimal(value)
    if d <= 0:
        raise ValueError("amount must be positive")
    return int((d * ATOMIC_PER_MERA).quantize(Decimal("1"), rounding=ROUND_DOWN))


def mera_from_atomic(value: int) -> str:
    return f"{Decimal(value) / Decimal(ATOMIC_PER_MERA):.8f}"


def core_path() -> Path:
    override = os.environ.get(CORE_ENV)
    if override:
        p = Path(override)
        if p.exists():
            return p
        raise FileNotFoundError(f"MERA_CORE_PATH does not exist: {p}")
    candidates = [
        ROOT / "mera_core",
        ROOT / "mera_core.exe",
        ROOT / "build" / "mera_core",
        ROOT / "build" / "Release" / "mera_core.exe",
        ROOT / "build" / "Debug" / "mera_core.exe",
    ]
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError("mera_core executable not found; run build.sh/build.ps1 first")


def core(*args: str, timeout: float = 60.0, check: bool = True) -> dict[str, str]:
    cmd = [str(core_path()), *args]
    data_dir = os.environ.get("MERA_DATA_DIR")
    if data_dir and "--data-dir" not in args:
        cmd.extend(["--data-dir", data_dir])
    r = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout or "core command failed").strip())
    out: dict[str, str] = {}
    for line in (r.stdout or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


class Wallet:
    def __init__(self, private_key: Ed25519PrivateKey | None = None):
        self.private_key = private_key or Ed25519PrivateKey.generate()

    @property
    def public_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @property
    def public_hex(self) -> str:
        return self.public_bytes.hex()

    @property
    def address_payload(self) -> str:
        return sha256_bytes(self.public_bytes)[:40]

    @property
    def address(self) -> str:
        prefix_payload = "MERA1" + self.address_payload
        return prefix_payload + sha256_text("MERA-ADDR-V3|" + prefix_payload)[:8]

    def sign(self, message: str) -> str:
        return self.private_key.sign(message.encode("utf-8")).hex()

    def encrypted_dict(self, password: str) -> dict[str, Any]:
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        key = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(password.encode())
        raw = self.private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        ciphertext = AESGCM(key).encrypt(nonce, raw, b"MERA-WALLET-V2")
        return {
            "version": WALLET_VERSION,
            "address": self.address,
            "public_key": self.public_hex,
            "kdf": "scrypt",
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
        }

    @staticmethod
    def from_file(path: Path, password: str) -> "Wallet":
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
            if d.get("version") != WALLET_VERSION or d.get("kdf") != "scrypt":
                raise ValueError("unsupported wallet version/KDF")
            key = Scrypt(
                salt=bytes.fromhex(d["salt"]),
                length=32,
                n=int(d["n"]),
                r=int(d["r"]),
                p=int(d["p"]),
            ).derive(password.encode())
            raw = AESGCM(key).decrypt(
                bytes.fromhex(d["nonce"]), bytes.fromhex(d["ciphertext"]), b"MERA-WALLET-V2"
            )
            if len(raw) != 32:
                raise ValueError("wallet key length is invalid")
            w = Wallet(Ed25519PrivateKey.from_private_bytes(raw))
            if w.address != d["address"] or w.public_hex != d["public_key"]:
                raise ValueError("wallet integrity check failed")
            return w
        except Exception as exc:
            raise ValueError(f"cannot open wallet securely: {exc}") from exc


def wallet_password(confirm: bool = False) -> str:
    p = os.environ.get("MERAWALLET_PASSWORD")
    if p is None:
        p = getpass.getpass("Mera wallet password: ")
    if confirm:
        q = getpass.getpass("Repeat password: ")
        if p != q:
            raise ValueError("passwords do not match")
    if len(p) < 10:
        raise ValueError("wallet password must be at least 10 characters")
    return p


def save_wallet(w: Wallet, password: str | None = None) -> None:
    ensure_dirs()
    WALLET_FILE.write_text(json.dumps(w.encrypted_dict(password or wallet_password()), indent=2), encoding="utf-8")


def load_wallet() -> Wallet:
    if not WALLET_FILE.exists():
        w = Wallet()
        save_wallet(w, wallet_password(confirm=True))
        return w
    return Wallet.from_file(WALLET_FILE, wallet_password())


@dataclass
class Challenge:
    challenge_id: str
    description: str
    dataset_kind: str
    dataset_sha256: str
    n_samples: int
    n_features: int
    generator_seed: int
    generator_noise: float
    split_rule: str
    train_fraction: float
    metric: str
    baseline_kind: str
    baseline_nmse: float
    baseline_model_sha256: str | None
    max_epochs: int = 1000
    verifier: str = NATIVE_VERIFIER
    schema_version: int = SCHEMA_VERSION
    manifest_sha256: str = ""

    def compute_hash(self) -> str:
        d = asdict(self)
        d.pop("manifest_sha256", None)
        return sha256_text(canonical_json(d))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["manifest_sha256"] = self.compute_hash()
        return d


def synthesize_dataset(n_samples: int, n_features: int, seed: int, noise: float):
    rng = random.Random(seed)
    w_true = [rng.uniform(-1.0, 1.0) for _ in range(n_features)]
    b_true = rng.uniform(-1.0, 1.0)
    X: list[list[float]] = []
    y: list[float] = []
    for _ in range(n_samples):
        x = [rng.gauss(0.0, 1.0) for _ in range(n_features)]
        target = b_true + sum(w_true[j] * x[j] for j in range(n_features)) + rng.gauss(0.0, noise)
        X.append(x)
        y.append(target)
    return X, y


def dataset_commitment(X, y) -> str:
    h = hashlib.sha256()
    for row in X:
        h.update((",".join(f"{v:.12f}" for v in row) + "\n").encode())
    h.update(b"---\n")
    for v in y:
        h.update((f"{v:.12f}\n").encode())
    return h.hexdigest()


def split_dataset(X, y, fraction: float):
    k = int(len(X) * fraction)
    return X[:k], y[:k], X[k:], y[k:]


def train_linear_regression(X, y, n_features: int, lr: float, epochs: int):
    w = [0.0] * n_features
    b = 0.0
    for _ in range(epochs):
        for i, row in enumerate(X):
            pred = b + sum(w[j] * row[j] for j in range(n_features))
            err = pred - y[i]
            for j in range(n_features):
                w[j] -= lr * err * row[j]
            b -= lr * err
    return w, b


def mse(X, y, w, b):
    if not y:
        raise ValueError("empty evaluation set")
    return sum((b + sum(w[j] * X[i][j] for j in range(len(w))) - y[i]) ** 2 for i in range(len(y))) / len(y)


def variance(y):
    if not y:
        raise ValueError("empty target array")
    m = sum(y) / len(y)
    return sum((v - m) ** 2 for v in y) / len(y)


def r2(X, y, w, b):
    v = variance(y)
    return 1.0 - mse(X, y, w, b) / v if v > 0 else 0.0


def compute_lswu(n_train, wall_time_seconds, nmse_model, nmse_baseline, *, N0=LSWU_N0, t0=LSWU_T0, eta=LSWU_ETA, wN=LSWU_WN, wt=LSWU_WT, wQ=LSWU_WQ):
    D = max(math.log1p(n_train / N0), 1e-12)
    T = max(math.log1p(max(wall_time_seconds, 0.0) / t0), 1e-12)
    I = nmse_baseline / nmse_model if nmse_model > 0 and nmse_baseline > 0 else 1.0
    I_eta = I ** eta
    Q = max(I_eta / (1.0 + I_eta), 1e-12)
    return {"N": n_train, "t": wall_time_seconds, "I": I, "D": D, "T": T, "Q": Q, "LSWU": D ** wN * T ** wt * Q ** wQ}


def ops_for(n_train: int, n_features: int, epochs: int) -> int:
    return int(epochs) * int(n_train) * (3 * int(n_features) + 4)


def quality_ppm(nmse: float, baseline: float) -> int:
    ns = max(1, int(round(nmse * 1_000_000_000)))
    bs = max(1, int(round(baseline * 1_000_000_000)))
    if ns >= bs:
        return 0
    return min(1_000_000, ((bs - ns) * 1_000_000) // bs)


def load_challenge(path: str | Path) -> Challenge:
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    recorded = d.get("manifest_sha256")
    d.pop("manifest_sha256", None)
    d.setdefault("verifier", NATIVE_VERIFIER)
    d.setdefault("schema_version", SCHEMA_VERSION)
    d.setdefault("max_epochs", 1000)
    ch = Challenge(**d)
    if recorded and recorded != ch.compute_hash():
        raise ValueError("challenge manifest hash mismatch")
    return ch


def build_challenge(args: argparse.Namespace) -> Challenge:
    if args.n_samples < 1000:
        raise ValueError("public Mera challenges require at least 1000 samples")
    X, y = synthesize_dataset(args.n_samples, args.n_features, args.seed, args.noise)
    _, _, Xte, yte = split_dataset(X, y, args.train_fraction)
    baseline = mse(Xte, yte, [0.0] * args.n_features, sum(yte) / len(yte)) / variance(yte)
    ch = Challenge(
        challenge_id=args.id,
        description=f"Deterministic synthetic linear regression, N={args.n_samples}, F={args.n_features}, noise={args.noise}, seed={args.seed}",
        dataset_kind="synthetic_linear",
        dataset_sha256=dataset_commitment(X, y),
        n_samples=args.n_samples,
        n_features=args.n_features,
        generator_seed=args.seed,
        generator_noise=args.noise,
        split_rule="first_fraction",
        train_fraction=args.train_fraction,
        metric="NMSE",
        baseline_kind="mean_predictor",
        baseline_nmse=baseline,
        baseline_model_sha256=None,
        max_epochs=args.max_epochs,
    )
    output = getattr(args, "output", None)
    if output:
        Path(output).write_text(json.dumps(ch.to_dict(), indent=2), encoding="utf-8")
    return ch


def run_training(ch: Challenge, config: dict[str, Any]) -> dict[str, Any]:
    if config.get("model_type", "linear-regression") != "linear-regression":
        raise ValueError("the consensus-paid verifier currently supports only deterministic linear regression")
    if config.get("framework", "mlabchain-native") != "mlabchain-native":
        raise ValueError("consensus-paid work must use mlabchain-native verifier")
    epochs = int(config.get("epochs", 30))
    if epochs <= 0 or epochs > ch.max_epochs:
        raise ValueError("epochs outside challenge limit")
    X, y = synthesize_dataset(ch.n_samples, ch.n_features, ch.generator_seed, ch.generator_noise)
    if dataset_commitment(X, y) != ch.dataset_sha256:
        raise RuntimeError("dataset commitment mismatch")
    Xtr, ytr, Xte, yte = split_dataset(X, y, ch.train_fraction)
    lr = float(config.get("learning_rate", 0.01))
    start = __import__("time").perf_counter()
    w, b = train_linear_regression(Xtr, ytr, ch.n_features, lr, epochs)
    wall = __import__("time").perf_counter() - start
    mtrain = mse(Xtr, ytr, w, b)
    mtest = mse(Xte, yte, w, b)
    vtest = variance(yte)
    nmse = mtest / vtest if vtest > 0 else float("inf")
    baseline = ch.baseline_nmse
    model_bytes = pickle.dumps({"verifier": NATIVE_VERIFIER, "w": w, "b": b, "n_features": ch.n_features}, protocol=4)
    arch_text = "\n".join([
        "model_type=linear-regression",
        "framework=mlabchain-native",
        f"verifier={NATIVE_VERIFIER}",
        f"n_features={ch.n_features}",
        "optimizer=SGD",
        f"learning_rate={lr}",
        f"epochs={epochs}",
    ]) + "\n"
    ops = ops_for(len(Xtr), ch.n_features, epochs)
    lswu = compute_lswu(len(Xtr), wall, nmse, baseline)
    return {
        "model_bytes": model_bytes,
        "model_sha256": sha256_bytes(model_bytes),
        "arch_text": arch_text,
        "arch_sha256": sha256_text(arch_text),
        "training": {"n_train": len(Xtr), "n_test": len(Xte), "epochs": epochs, "learning_rate": lr, "wall_ms": max(1, int(round(wall * 1000)))},
        "metrics": {"mse_train": mtrain, "mse_test": mtest, "var_test": vtest, "nmse_model": nmse, "nmse_baseline": baseline, "r2_test": r2(Xte, yte, w, b)},
        "ops": ops,
        "quality_ppm": quality_ppm(nmse, baseline),
        "lswu": lswu,
    }


def save_training_artifacts(result: dict[str, Any], ch: Challenge, config: dict[str, Any]) -> tuple[Path, Path, Path]:
    model = MODEL_DIR / f"model_{result['model_sha256'][:16]}.pkl"
    arch = MODEL_DIR / f"model_{result['model_sha256'][:16]}.txt"
    proof = PROOF_DIR / f"proof_{result['model_sha256'][:16]}.json"
    model.write_bytes(result["model_bytes"])
    arch.write_text(result["arch_text"], encoding="utf-8")
    proof.write_text(json.dumps({"schema_version": SCHEMA_VERSION, "challenge": ch.to_dict(), "config": config, "result": {k: v for k, v in result.items() if k != "model_bytes"}}, indent=2), encoding="utf-8")
    return model, arch, proof


def transfer_message(sender, recipient, amount, fee, nonce, pubkey, note):
    return f"TRANSFER-V3|{sender}|{recipient}|{amount}|{fee}|{nonce}|{pubkey}|{note}"


def ml_message(sender, ch_id, manifest, dataset, model, arch, ops, ntrain, nfeatures, epochs, nmse_s, baseline_s, reward, wall_ms, lswu_micro, nonce, fee, pubkey, note):
    return f"ML_WORK-V3|{sender}|{ch_id}|{manifest}|{dataset}|{model}|{arch}|{ops}|{ntrain}|{nfeatures}|{epochs}|{nmse_s}|{baseline_s}|{reward}|{wall_ms}|{lswu_micro}|{nonce}|{fee}|{pubkey}|{note}"


def challenge_message(sender, ch: Challenge, fee: int, nonce: int, budget: int):
    train_ppm = int(round(ch.train_fraction * 1_000_000))
    return f"CHALLENGE_REGISTER-V3|{sender}|{ch.challenge_id}|{ch.compute_hash()}|{ch.dataset_sha256}|{NATIVE_VERIFIER}|NMSE|first_fraction|{ch.n_samples}|{ch.n_features}|{train_ppm}|{ch.max_epochs}|1000000000|{budget}|{nonce}|{fee}|{''}"


def main_mine_certificate(w: Wallet, ch: Challenge, config: dict[str, Any], args: argparse.Namespace) -> None:
    result = run_training(ch, config)
    model, arch, proof = save_training_artifacts(result, ch, config)
    tx_nonce = int(core("nonce", "--address", w.address)["NONCE"]) + 1
    nmse_scaled = max(1, int(round(result["metrics"]["nmse_model"] * 1_000_000_000)))
    baseline_scaled = max(1, int(round(result["metrics"]["metrics"]["nmse_baseline"] * 1_000_000_000))) if False else max(1, int(round(result["metrics"]["nmse_baseline"] * 1_000_000_000)))
    fee = atomic_from_mera(args.fee) if args.fee else MIN_WORK_FEE_ATOMIC
    # Core computes the exact marginal reward. Before submission we do a pessimistic local estimate from current challenge baseline only;
    # a core rejection is still possible if another miner has already improved the challenge best.
    reward_guess = (result["ops"] * result["quality_ppm"] * ATOMIC_PER_MERA) // (10_000_000 * 1_000_000)
    reward_guess = min(reward_guess, 50 * ATOMIC_PER_MERA)
    if reward_guess <= 0:
        raise ValueError("training did not improve the baseline")
    # The core will validate the exact marginal reward against the challenge's current best.
    lswu_micro = max(0, int(round(result["lswu"]["LSWU"] * 1_000_000)))
    note = f"proof={proof.name}"
    msg = ml_message(w.address, ch.challenge_id, ch.compute_hash(), ch.dataset_sha256, result["model_sha256"], result["arch_sha256"], result["ops"], result["training"]["n_train"], ch.n_features, result["training"]["epochs"], nmse_scaled, baseline_scaled, reward_guess, result["training"]["wall_ms"], lswu_micro, tx_nonce, fee, w.public_hex, note)
    sig = w.sign(msg)
    out = core("submit-ml", "--sender", w.address, "--challenge-id", ch.challenge_id, "--manifest-sha256", ch.compute_hash(), "--dataset-sha256", ch.dataset_sha256, "--model-sha256", result["model_sha256"], "--arch-sha256", result["arch_sha256"], "--ops", str(result["ops"]), "--n-train", str(result["training"]["n_train"]), "--n-features", str(ch.n_features), "--epochs", str(result["training"]["epochs"]), "--nmse-scaled", str(nmse_scaled), "--baseline-scaled", str(baseline_scaled), "--work-reward", str(reward_guess), "--wall-ms", str(result["training"]["wall_ms"]), "--lswu-micro", str(lswu_micro), "--fee", str(fee), "--nonce", str(tx_nonce), "--public-key", w.public_hex, "--signature", sig, "--note", note)
    template = core("block-template", "--producer", w.address, "--public-key", w.public_hex)
    bsig = w.sign(template["SIGNING_MESSAGE"])
    mine_args = ["mine", "--producer", w.address, "--public-key", w.public_hex, "--signature", bsig, "--timestamp-ms", template["TIMESTAMP_MS"]]
    mine_args.extend(["--broadcast", "--peers", args.peers]) if args.peers else None
    mined = core(*mine_args, timeout=args.timeout)
    print(f"MERA reward: {mera_from_atomic(int(out.get('WORK_REWARD_ATOMIC', reward_guess)))}")
    print(f"TXID: {out.get('TXID', '?')}")
    print(f"Block: {mined.get('HEIGHT')} {mined.get('BLOCK_HASH')}")


def command_create_wallet(_args):
    w = Wallet()
    save_wallet(w)
    print(f"Address: {w.address}\nWallet: {WALLET_FILE}")


def command_challenge_create(args):
    ensure_dirs()
    ch = build_challenge(args)
    print(json.dumps(ch.to_dict(), indent=2))


def command_register_challenge(args):
    w = load_wallet(); ch = load_challenge(args.manifest)
    budget = atomic_from_mera(args.budget)
    if budget > 1000 * ATOMIC_PER_MERA:
        raise ValueError("challenge budget exceeds protocol cap")
    fee = CHALLENGE_BOND_ATOMIC
    nonce = int(core("nonce", "--address", w.address)["NONCE"]) + 1
    # challenge_message's final public key must match the core format exactly.
    train_ppm = int(round(ch.train_fraction * 1_000_000))
    msg = f"CHALLENGE_REGISTER-V3|{w.address}|{ch.challenge_id}|{ch.compute_hash()}|{ch.dataset_sha256}|{NATIVE_VERIFIER}|NMSE|first_fraction|{ch.n_samples}|{ch.n_features}|{train_ppm}|{ch.max_epochs}|1000000000|{budget}|{nonce}|{fee}|{w.public_hex}"
    sig = w.sign(msg)
    out = core("register-challenge", "--sender", w.address, "--challenge-id", ch.challenge_id, "--manifest-sha256", ch.compute_hash(), "--dataset-sha256", ch.dataset_sha256, "--samples", str(ch.n_samples), "--features", str(ch.n_features), "--train-fraction-ppm", str(train_ppm), "--max-epochs", str(ch.max_epochs), "--budget", str(budget), "--fee", str(fee), "--nonce", str(nonce), "--public-key", w.public_hex, "--signature", sig, "--note", "native-deterministic")
    template = core("block-template", "--producer", w.address, "--public-key", w.public_hex)
    bsig = w.sign(template["SIGNING_MESSAGE"])
    core("mine", "--producer", w.address, "--public-key", w.public_hex, "--signature", bsig, "--timestamp-ms", template["TIMESTAMP_MS"], timeout=args.timeout)
    print(f"Challenge registered: {ch.challenge_id}\nTXID: {out['TXID']}")


def command_mine(args):
    w = load_wallet(); ch = load_challenge(args.challenge)
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    main_mine_certificate(w, ch, config, args)


def command_transfer(args):
    w = load_wallet(); amount = atomic_from_mera(args.amount); fee = atomic_from_mera(args.fee) if args.fee else MIN_WORK_FEE_ATOMIC
    nonce = int(core("nonce", "--address", w.address)["NONCE"]) + 1
    msg = transfer_message(w.address, args.to, amount, fee, nonce, w.public_hex, args.note)
    sig = w.sign(msg)
    out = core("submit-transfer", "--sender", w.address, "--recipient", args.to, "--amount", str(amount), "--fee", str(fee), "--nonce", str(nonce), "--public-key", w.public_hex, "--signature", sig, "--note", args.note)
    if args.mine:
        t = core("block-template", "--producer", w.address, "--public-key", w.public_hex)
        bsig = w.sign(t["SIGNING_MESSAGE"])
        core("mine", "--producer", w.address, "--public-key", w.public_hex, "--signature", bsig, "--timestamp-ms", t["TIMESTAMP_MS"], timeout=args.timeout)
    print(f"TXID: {out['TXID']}")


def command_faucet(args):
    w = load_wallet() if not args.address else None
    addr = args.address or w.address
    amount = atomic_from_mera(args.amount)
    core("faucet", "--recipient", addr, "--amount", str(amount))
    # Faucet itself is not trusted block production; the user's wallet still signs the block.
    producer = load_wallet()
    t = core("block-template", "--producer", producer.address, "--public-key", producer.public_hex)
    bsig = producer.sign(t["SIGNING_MESSAGE"])
    core("mine", "--producer", producer.address, "--public-key", producer.public_hex, "--signature", bsig, "--timestamp-ms", t["TIMESTAMP_MS"], timeout=args.timeout)
    print(f"Devnet faucet: {mera_from_atomic(amount)} MERA -> {addr}")


def command_balance(args):
    addr = args.address or load_wallet().address
    print(f"{addr}: {core('balance', '--address', addr)['BALANCE_MERA']} MERA")


def command_init(args):
    out = core("init", "--network", args.network, *( ["--governance-keys", args.governance_keys] if args.governance_keys else []), *( ["--governance-threshold", str(args.governance_threshold)] if args.governance_threshold else []))
    for k,v in out.items(): print(f"{k}: {v}")


def command_status(args):
    out = core("status")
    for k,v in out.items(): print(f"{k}: {v}")


def command_validate(args):
    out = core("validate")
    for k,v in out.items(): print(f"{k}: {v}")


def command_sync(args):
    out = core("sync", "--peer", args.peer, timeout=args.timeout)
    for k,v in out.items(): print(f"{k}: {v}")


def command_backup(args):
    print(core("backup", "--output", args.output))


def command_wallet_backup(args):
    src = WALLET_FILE
    if not src.exists():
        raise FileNotFoundError("wallet does not exist")
    dst = Path(args.output).expanduser().resolve()
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(src.read_bytes())
    print(f"WALLET_BACKUP={dst}")


def command_challenge_status(args):
    out = core("challenge-status", "--challenge-id", args.challenge_id)
    for k,v in out.items(): print(f"{k}: {v}")


def command_mine_empty(args):
    w = load_wallet()
    for _ in range(args.count):
        t = core("block-template", "--producer", w.address, "--public-key", w.public_hex)
        sig = w.sign(t["SIGNING_MESSAGE"])
        out = core("mine", "--producer", w.address, "--public-key", w.public_hex, "--signature", sig, "--timestamp-ms", t["TIMESTAMP_MS"], timeout=args.timeout)
        print(f"Mined empty block {out.get('HEIGHT')}: {out.get('BLOCK_HASH')}")


def command_show_tx(args):
    out = core("show-tx", "--txid", args.tx_hash)
    for k,v in out.items(): print(f"{k}: {v}")


def command_node(args):
    core("node", "--listen-host", args.listen_host, "--port", str(args.port), "--peers", args.peers, *(["--seconds", str(args.seconds)] if args.seconds else []), timeout=max(60.0, args.seconds + 30 if args.seconds else 3650.0))


def command_verify_ml(args):
    tx = core("show-tx", "--txid", args.tx_hash)
    challenge_path = next((p for p in CHALLENGE_DIR.glob("*.json") if json.loads(p.read_text()).get("challenge_id") == tx.get("CHALLENGE_ID")), None)
    if not challenge_path: raise RuntimeError("matching challenge manifest not found locally")
    ch = load_challenge(challenge_path)
    proof_path = next((p for p in PROOF_DIR.glob("*.json") if json.loads(p.read_text()).get("result", {}).get("model_sha256") == tx.get("MODEL_SHA256")), None)
    if not proof_path: raise RuntimeError("matching proof artifact not found locally")
    d = json.loads(proof_path.read_text())
    result = run_training(ch, d["config"])
    checks = {
        "manifest_hash": tx["MANIFEST_SHA256"] == ch.compute_hash(),
        "dataset_hash": tx["DATASET_SHA256"] == ch.dataset_sha256,
        "model_hash": result["model_sha256"] == tx["MODEL_SHA256"],
        "arch_hash": result["arch_sha256"] == tx["ARCH_SHA256"],
        "ops": str(result["ops"]) == tx["OPS"],
        "nmse": int(round(result["metrics"]["nmse_model"] * 1e9)) == int(tx["NMSE_SCALED"]),
        "reward": int(tx["WORK_REWARD_ATOMIC"]) >= 0,
    }
    for k,v in checks.items(): print(f"  {'OK' if v else 'FAIL':4s} {k}")
    print(f"STATUS: {'VERIFIED' if all(checks.values()) else 'MISMATCH'}")


def command_demo(args):
    # Fresh devnet DB for reproducible demo.
    demo_dir = DATA_DIR / "demo"
    if demo_dir.exists():
        import shutil; shutil.rmtree(demo_dir)
    w = Wallet(); save_wallet(w, os.environ.get("MERAWALLET_PASSWORD", "demo-password"))
    print(f"Demo wallet: {w.address}")
    os.environ["MERAWALLET_PASSWORD"] = "demo-password"
    core("init", "--data-dir", str(demo_dir), "--network", "devnet")
    # Temporarily route core through demo data via environment wrapper.
    # All subsequent calls need --data-dir, so invoke them directly for clarity.
    def dc(*xs, timeout=60): return core(*xs, "--data-dir", str(demo_dir), timeout=timeout)
    dc("faucet", "--recipient", w.address, "--amount", str(5 * ATOMIC_PER_MERA));
    for _ in range(1):
        t=dc("block-template", "--producer", w.address, "--public-key", w.public_hex); sig=w.sign(t["SIGNING_MESSAGE"]); dc("mine","--producer",w.address,"--public-key",w.public_hex,"--signature",sig,"--timestamp-ms",t["TIMESTAMP_MS"])
    ch=Challenge("MERA-DEMO-003","v0.3 deterministic challenge","synthetic_linear","",1200,4,7,0.1,"first_fraction",0.8,"NMSE","mean_predictor",1.0,None,40)
    X,y=synthesize_dataset(ch.n_samples,ch.n_features,ch.generator_seed,ch.generator_noise); ch.dataset_sha256=dataset_commitment(X,y); _,_,xt,yt=split_dataset(X,y,ch.train_fraction); ch.baseline_nmse=mse(xt,yt,[0.0]*ch.n_features,sum(yt)/len(yt))/variance(yt); cp=CHALLENGE_DIR/"MERA-DEMO-003.json"; cp.write_text(json.dumps(ch.to_dict(),indent=2))
    # register
    nonce=int(dc("nonce","--address",w.address)["NONCE"])+1; fee=100000; budget=100*ATOMIC_PER_MERA; train_ppm=800000; msg=f"CHALLENGE_REGISTER-V3|{w.address}|{ch.challenge_id}|{ch.compute_hash()}|{ch.dataset_sha256}|{NATIVE_VERIFIER}|NMSE|first_fraction|{ch.n_samples}|{ch.n_features}|{train_ppm}|{ch.max_epochs}|1000000000|{budget}|{nonce}|{fee}|{w.public_hex}"; sig=w.sign(msg); dc("register-challenge","--sender",w.address,"--challenge-id",ch.challenge_id,"--manifest-sha256",ch.compute_hash(),"--dataset-sha256",ch.dataset_sha256,"--samples",str(ch.n_samples),"--features","4","--train-fraction-ppm",str(train_ppm),"--max-epochs","40","--budget",str(budget),"--fee",str(fee),"--nonce",str(nonce),"--public-key",w.public_hex,"--signature",sig)
    for _ in range(8):
        t=dc("block-template","--producer",w.address,"--public-key",w.public_hex); sig=w.sign(t["SIGNING_MESSAGE"]); dc("mine","--producer",w.address,"--public-key",w.public_hex,"--signature",sig,"--timestamp-ms",t["TIMESTAMP_MS"])
    cfg={**DEFAULT_CONFIG,"epochs":20}
    # temporarily use data-dir arguments through a local copy
    result=run_training(ch,cfg); model,arch,proof=save_training_artifacts(result,ch,cfg); nonce=int(dc("nonce","--address",w.address)["NONCE"])+1; fee=10000; ns=int(round(result["metrics"]["nmse_model"]*1e9)); bs=int(round(result["metrics"]["nmse_baseline"]*1e9)); reward=(result["ops"]*result["quality_ppm"]*ATOMIC_PER_MERA)//(10_000_000*1_000_000); lm=int(round(result["lswu"]["LSWU"]*1e6)); note=f"proof={proof.name}"; msg=ml_message(w.address,ch.challenge_id,ch.compute_hash(),ch.dataset_sha256,result["model_sha256"],result["arch_sha256"],result["ops"],result["training"]["n_train"],4,result["training"]["epochs"],ns,bs,reward,result["training"]["wall_ms"],lm,nonce,fee,w.public_hex,note); sig=w.sign(msg); dc("submit-ml","--sender",w.address,"--challenge-id",ch.challenge_id,"--manifest-sha256",ch.compute_hash(),"--dataset-sha256",ch.dataset_sha256,"--model-sha256",result["model_sha256"],"--arch-sha256",result["arch_sha256"],"--ops",str(result["ops"]),"--n-train",str(result["training"]["n_train"]),"--n-features","4","--epochs",str(result["training"]["epochs"]),"--nmse-scaled",str(ns),"--baseline-scaled",str(bs),"--work-reward",str(reward),"--wall-ms",str(result["training"]["wall_ms"]),"--lswu-micro",str(lm),"--fee",str(fee),"--nonce",str(nonce),"--public-key",w.public_hex,"--signature",sig,"--note",note); t=dc("block-template","--producer",w.address,"--public-key",w.public_hex); sig=w.sign(t["SIGNING_MESSAGE"]); dc("mine","--producer",w.address,"--public-key",w.public_hex,"--signature",sig,"--timestamp-ms",t["TIMESTAMP_MS"]); print(dc("status")); print(dc("validate"))


def build_parser():
    p=argparse.ArgumentParser(prog="mlabchain",description="MLabChain / Mera v0.3")
    p.add_argument("--data-dir", default=str(DATA_DIR), help="Node data directory (SQLite, wallet, challenges, artifacts).")
    p.add_argument("--core-path", default=None, help="Path to mera_core executable.")
    s=p.add_subparsers(dest="cmd",required=True)
    i=s.add_parser("init"); i.add_argument("--network",choices=["devnet","testnet","mainnet"],default="devnet"); i.add_argument("--governance-keys"); i.add_argument("--governance-threshold",type=int); i.set_defaults(func=command_init)
    s.add_parser("create-wallet").set_defaults(func=command_create_wallet)
    c=s.add_parser("challenge-create"); c.add_argument("--id",required=True); c.add_argument("--output",required=True); c.add_argument("--n-samples",type=int,default=1200); c.add_argument("--n-features",type=int,default=4); c.add_argument("--seed",type=int,default=42); c.add_argument("--noise",type=float,default=0.1); c.add_argument("--train-fraction",type=float,default=0.8); c.add_argument("--max-epochs",type=int,default=1000); c.set_defaults(func=command_challenge_create)
    r=s.add_parser("challenge-register"); r.add_argument("--manifest",required=True); r.add_argument("--budget",required=True); r.add_argument("--timeout",type=float,default=300); r.set_defaults(func=command_register_challenge)
    m=s.add_parser("mine"); m.add_argument("--challenge",required=True); m.add_argument("--config",required=True); m.add_argument("--fee"); m.add_argument("--peers",default=""); m.add_argument("--timeout",type=float,default=300); m.set_defaults(func=command_mine)
    t=s.add_parser("transfer"); t.add_argument("--to",required=True); t.add_argument("--amount",required=True); t.add_argument("--fee"); t.add_argument("--note",default=""); t.add_argument("--mine",action="store_true"); t.add_argument("--timeout",type=float,default=300); t.set_defaults(func=command_transfer)
    f=s.add_parser("faucet"); f.add_argument("--address"); f.add_argument("--amount",required=True); f.add_argument("--timeout",type=float,default=300); f.set_defaults(func=command_faucet)
    b=s.add_parser("balance"); b.add_argument("--address"); b.set_defaults(func=command_balance)
    s0=s.add_parser("status"); s0.set_defaults(func=command_status)
    v=s.add_parser("validate"); v.set_defaults(func=command_validate)
    y=s.add_parser("sync"); y.add_argument("--peer",required=True); y.add_argument("--timeout",type=float,default=300); y.set_defaults(func=command_sync)
    bk=s.add_parser("backup"); bk.add_argument("--output",required=True); bk.set_defaults(func=command_backup)
    wb=s.add_parser("wallet-backup"); wb.add_argument("--output",required=True); wb.set_defaults(func=command_wallet_backup)
    cs=s.add_parser("challenge-status"); cs.add_argument("--challenge-id",required=True); cs.set_defaults(func=command_challenge_status)
    me=s.add_parser("mine-empty"); me.add_argument("--count",type=int,default=1); me.add_argument("--timeout",type=float,default=300); me.set_defaults(func=command_mine_empty)
    x=s.add_parser("show-tx"); x.add_argument("--tx-hash",required=True); x.set_defaults(func=command_show_tx)
    n=s.add_parser("node"); n.add_argument("--listen-host",default="0.0.0.0"); n.add_argument("--port",type=int,required=True); n.add_argument("--peers",default=""); n.add_argument("--seconds",type=int); n.set_defaults(func=command_node)
    q=s.add_parser("verify-ml"); q.add_argument("--tx-hash",required=True); q.set_defaults(func=command_verify_ml)
    d=s.add_parser("demo"); d.set_defaults(func=command_demo)
    return p


def main():
    args=build_parser().parse_args()
    configure_data_dir(args.data_dir)
    if args.core_path:
        os.environ[CORE_ENV]=args.core_path
    ensure_dirs()
    try: args.func(args)
    except subprocess.TimeoutExpired as exc: raise SystemExit(f"ERROR: core command timed out after {exc.timeout}s")
    except Exception as exc: print(f"ERROR: {exc}"); raise SystemExit(1)

if __name__ == "__main__": main()
