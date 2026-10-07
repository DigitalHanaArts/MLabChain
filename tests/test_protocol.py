import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "build" / "mera_core"
sys.path.insert(0, str(ROOT))
import mlabchain as ml


def run_core(data, *args, timeout=20):
    p = subprocess.run([str(CORE), *args, "--data-dir", str(data)], text=True, capture_output=True, timeout=timeout)
    assert p.returncode == 0, p.stderr or p.stdout
    out = {}
    for line in p.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


def seal(data, wallet):
    t = run_core(data, "block-template", "--producer", wallet.address, "--public-key", wallet.public_hex)
    sig = wallet.sign(t["SIGNING_MESSAGE"])
    return run_core(data, "mine", "--producer", wallet.address, "--public-key", wallet.public_hex, "--signature", sig, "--timestamp-ms", t["TIMESTAMP_MS"])


def test_address_checksum_and_wallet_roundtrip(tmp_path):
    w = ml.Wallet()
    assert ml.Wallet.from_file is not None
    assert len(w.address) == 53
    bad = w.address[:-1] + ("0" if w.address[-1] != "0" else "1")
    assert bad != w.address
    out = tmp_path / "wallet.json"
    w.encrypted_dict("strong-password-123")
    out.write_text(json.dumps(w.encrypted_dict("strong-password-123")))
    w2 = ml.Wallet.from_file(out, "strong-password-123")
    assert w2.address == w.address


def test_deterministic_training(tmp_path):
    args = type("A", (), {"id": "TEST", "n_samples": 1200, "n_features": 4, "seed": 42, "noise": 0.1, "train_fraction": 0.8, "max_epochs": 40})
    ch = ml.build_challenge(args)
    cfg = {**ml.DEFAULT_CONFIG, "epochs": 20}
    r1 = ml.run_training(ch, cfg)
    r2 = ml.run_training(ch, cfg)
    assert r1["model_sha256"] == r2["model_sha256"]
    assert r1["ops"] == r2["ops"]
    assert r1["quality_ppm"] == r2["quality_ppm"]


def test_end_to_end_ml_transfer_and_validation(tmp_path):
    data = tmp_path / "node"
    run_core(data, "init", "--network", "devnet")
    w = ml.Wallet()
    w2 = ml.Wallet()
    run_core(data, "faucet", "--recipient", w.address, "--amount", str(5 * ml.ATOMIC_PER_MERA))
    seal(data, w)

    ns = type("A", (), {"id": "TEST-CH", "n_samples": 1200, "n_features": 4, "seed": 7, "noise": 0.1, "train_fraction": 0.8, "max_epochs": 40})
    ch = ml.build_challenge(ns)
    manifest = tmp_path / "challenge.json"
    manifest.write_text(json.dumps(ch.to_dict(), indent=2))
    nonce = int(run_core(data, "nonce", "--address", w.address)["NONCE"]) + 1
    fee = 100000
    budget = 100 * ml.ATOMIC_PER_MERA
    train_ppm = 800000
    msg = f"CHALLENGE_REGISTER-V3|{w.address}|{ch.challenge_id}|{ch.compute_hash()}|{ch.dataset_sha256}|{ml.NATIVE_VERIFIER}|NMSE|first_fraction|{ch.n_samples}|{ch.n_features}|{train_ppm}|{ch.max_epochs}|1000000000|{budget}|{nonce}|{fee}|{w.public_hex}"
    sig = w.sign(msg)
    run_core(data, "register-challenge", "--sender", w.address, "--challenge-id", ch.challenge_id, "--manifest-sha256", ch.compute_hash(), "--dataset-sha256", ch.dataset_sha256, "--samples", str(ch.n_samples), "--features", str(ch.n_features), "--train-fraction-ppm", str(train_ppm), "--max-epochs", str(ch.max_epochs), "--budget", str(budget), "--fee", str(fee), "--nonce", str(nonce), "--public-key", w.public_hex, "--signature", sig)
    seal(data, w)
    for _ in range(8):
        seal(data, w)

    cfg = {**ml.DEFAULT_CONFIG, "epochs": 20}
    result = ml.run_training(ch, cfg)
    nonce = int(run_core(data, "nonce", "--address", w.address)["NONCE"]) + 1
    reward = (result["ops"] * result["quality_ppm"] * ml.ATOMIC_PER_MERA) // (10_000_000 * 1_000_000)
    assert reward > 0
    nscl = int(round(result["metrics"]["nmse_model"] * 1e9))
    bscl = int(round(result["metrics"]["nmse_baseline"] * 1e9))
    fee = 10000
    note = "proof=test"
    lm = max(0, int(round(result["lswu"]["LSWU"] * 1e6)))
    msg = ml.ml_message(w.address, ch.challenge_id, ch.compute_hash(), ch.dataset_sha256, result["model_sha256"], result["arch_sha256"], result["ops"], result["training"]["n_train"], ch.n_features, result["training"]["epochs"], nscl, bscl, reward, result["training"]["wall_ms"], lm, nonce, fee, w.public_hex, note)
    sig = w.sign(msg)
    run_core(data, "submit-ml", "--sender", w.address, "--challenge-id", ch.challenge_id, "--manifest-sha256", ch.compute_hash(), "--dataset-sha256", ch.dataset_sha256, "--model-sha256", result["model_sha256"], "--arch-sha256", result["arch_sha256"], "--ops", str(result["ops"]), "--n-train", str(result["training"]["n_train"]), "--n-features", str(ch.n_features), "--epochs", str(result["training"]["epochs"]), "--nmse-scaled", str(nscl), "--baseline-scaled", str(bscl), "--work-reward", str(reward), "--wall-ms", str(result["training"]["wall_ms"]), "--lswu-micro", str(lm), "--fee", str(fee), "--nonce", str(nonce), "--public-key", w.public_hex, "--signature", sig, "--note", note)
    seal(data, w)

    nonce = int(run_core(data, "nonce", "--address", w.address)["NONCE"]) + 1
    amount = 1000000
    fee = 1000
    note = "test-transfer"
    msg = ml.transfer_message(w.address, w2.address, amount, fee, nonce, w.public_hex, note)
    sig = w.sign(msg)
    run_core(data, "submit-transfer", "--sender", w.address, "--recipient", w2.address, "--amount", str(amount), "--fee", str(fee), "--nonce", str(nonce), "--public-key", w.public_hex, "--signature", sig, "--note", note)
    seal(data, w)
    v = run_core(data, "validate")
    assert v["STATUS"] == "VALID"
    assert int(run_core(data, "balance", "--address", w2.address)["BALANCE_ATOMIC"]) == amount


def test_p2p_sync(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    run_core(a, "init", "--network", "devnet")
    run_core(b, "init", "--network", "devnet")
    w = ml.Wallet()
    run_core(a, "faucet", "--recipient", w.address, "--amount", "100000000")
    seal(a, w)
    proc = subprocess.Popen([str(CORE), "node", "--data-dir", str(a), "--listen-host", "127.0.0.1", "--port", "19111", "--seconds", "20"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        time.sleep(0.4)
        out = run_core(b, "sync", "--peer", "127.0.0.1:19111")
        assert out["SYNCED_HEIGHT"] == "1"
        assert run_core(b, "validate")["STATUS"] == "VALID"
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_mainnet_faucet_is_genesis_locked(tmp_path):
    data = tmp_path / "mainnet"
    run_core(data, "init", "--network", "mainnet")
    w = ml.Wallet()
    p = subprocess.run([str(CORE), "faucet", "--recipient", w.address, "--amount", "1", "--data-dir", str(data)], text=True, capture_output=True)
    assert p.returncode != 0
    assert "faucet disabled by chain genesis" in (p.stderr + p.stdout)


def test_schema_mismatch_fails_closed_and_migration_exports(tmp_path):
    old = tmp_path / "old.sqlite"
    con = __import__('sqlite3').connect(old)
    con.execute("CREATE TABLE meta(k TEXT PRIMARY KEY,v TEXT NOT NULL)")
    con.execute("CREATE TABLE accounts(address TEXT PRIMARY KEY,balance INTEGER NOT NULL,nonce INTEGER NOT NULL)")
    con.execute("CREATE TABLE blocks(height INTEGER PRIMARY KEY,block_hash TEXT NOT NULL)")
    con.execute("CREATE TABLE txs(txid TEXT PRIMARY KEY)")
    con.execute("INSERT INTO meta VALUES('schema_version','2')")
    con.execute("INSERT INTO meta VALUES('network','devnet')")
    con.commit(); con.close()

    node = tmp_path / "node"
    node.mkdir()
    __import__('shutil').copy2(old, node / "mera.sqlite")
    p = subprocess.run([str(CORE), "status", "--data-dir", str(node)], text=True, capture_output=True)
    assert p.returncode != 0
    assert "unsupported database schema" in (p.stderr + p.stdout)

    snap = tmp_path / "snapshot.json"
    subprocess.run([sys.executable, str(ROOT / "tools" / "migrate_v2.py"), "--input", str(old), "--output", str(snap)], check=True, text=True, capture_output=True)
    d = json.loads(snap.read_text())
    assert d["source_schema_version"] == 2
    assert d["snapshot_sha256"]
