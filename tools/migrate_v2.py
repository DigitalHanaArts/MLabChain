#!/usr/bin/env python3
"""Export a Mera/MLabChain v0.2 SQLite database into an explicit v0.3
migration snapshot.

v0.3 deliberately does not mutate a v0.2 database in-place: its consensus and
state rules changed. The operator gets a signed-off snapshot instead, which can
be used as the input to a new genesis/allocation ceremony.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="Export a v0.2 Mera SQLite DB into a v0.3 migration snapshot")
    ap.add_argument("--input", required=True, help="v0.2 mera.sqlite")
    ap.add_argument("--output", required=True, help="migration snapshot JSON")
    args = ap.parse_args()

    src = Path(args.input)
    dst = Path(args.output)
    con = sqlite3.connect(src)
    con.row_factory = sqlite3.Row
    try:
        meta = {r[0]: r[1] for r in con.execute("SELECT k,v FROM meta")}
        schema = int(meta.get("schema_version", meta.get("protocol_version", "0")))
        if schema not in (2,):
            raise SystemExit(f"expected v0.2 schema, found {schema}")
        genesis = meta.get("genesis_hash", meta.get("GENESIS", ""))
        accounts = []
        for r in con.execute("SELECT address,balance,nonce FROM accounts ORDER BY address"):
            accounts.append({"address": r[0], "balance_atomic": int(r[1]), "nonce": int(r[2])})
        supply = sum(x["balance_atomic"] for x in accounts)
        tx_count = int(con.execute("SELECT COUNT(*) FROM txs").fetchone()[0]) if _table_exists(con, "txs") else 0
        block_count = int(con.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]) if _table_exists(con, "blocks") else 0
        tip = ""
        if block_count:
            tip = con.execute("SELECT block_hash FROM blocks ORDER BY height DESC LIMIT 1").fetchone()[0]
        snapshot = {
            "migration_version": 1,
            "source_protocol": "Mera/MLabChain-v0.2",
            "source_schema_version": schema,
            "source_network": meta.get("network", "unknown"),
            "source_genesis_hash": genesis,
            "source_tip_hash": tip,
            "source_block_count": block_count,
            "source_transaction_count": tx_count,
            "accounts": accounts,
            "total_balance_atomic": supply,
            "notes": [
                "This is an explicit migration snapshot, not an in-place schema conversion.",
                "v0.3 must create a new genesis that commits to this snapshot before importing balances.",
                "Historical v0.2 transactions remain archival evidence and are not automatically treated as v0.3 consensus history.",
            ],
        }
        snapshot["snapshot_sha256"] = sha256_text(canonical(snapshot))
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"WROTE={dst.resolve()}")
        print(f"SNAPSHOT_SHA256={snapshot['snapshot_sha256']}")
        print(f"ACCOUNTS={len(accounts)}")
        print(f"TOTAL_BALANCE_ATOMIC={supply}")
        print(f"SOURCE_TIP={tip}")
        return 0
    finally:
        con.close()


def _table_exists(con: sqlite3.Connection, name: str) -> bool:
    return con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


if __name__ == "__main__":
    raise SystemExit(main())
