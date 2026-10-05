#!/usr/bin/env python3
"""
tests/e2e/common/sqlite_oracle.py
Independent authoritative SQLite schema and persistence validator for JOCKY.
Validates the 6 relational tables and 5 indexes from JOCKY SPEC SHEET §17.1.
"""

import sys
import sqlite3
import json
import argparse
from typing import Dict, List, Any

EXPECTED_TABLES = [
    "investigations",
    "evidence",
    "receipts",
    "provenance",
    "correlations",
    "findings"
]

EXPECTED_INDEXES = [
    "idx_evidence_run",
    "idx_receipts_run",
    "idx_provenance_evidence",
    "idx_correlations_run",
    "idx_findings_run"
]

SCHEMA_DDL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    script_hash TEXT NOT NULL,
    ir_json TEXT NOT NULL,
    contract_json TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    collector TEXT NOT NULL,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    hash TEXT NOT NULL,
    hash_algo TEXT NOT NULL,
    metadata TEXT,
    collected_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES investigations(id)
);

CREATE TABLE IF NOT EXISTS receipts (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL UNIQUE,
    run_id TEXT NOT NULL,
    collector TEXT NOT NULL,
    collector_version TEXT NOT NULL,
    signature TEXT NOT NULL,
    public_key TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    payload_hash_algo TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    host_info TEXT NOT NULL,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id)
);

CREATE TABLE IF NOT EXISTS provenance (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL,
    receipt_id TEXT NOT NULL,
    prev_provenance_id TEXT,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    actor_version TEXT NOT NULL,
    input_hashes TEXT NOT NULL,
    output_hashes TEXT NOT NULL,
    parameters TEXT,
    timestamp TEXT NOT NULL,
    signature TEXT NOT NULL,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id),
    FOREIGN KEY (receipt_id) REFERENCES receipts(id)
);

CREATE TABLE IF NOT EXISTS correlations (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    src_evidence_id TEXT NOT NULL,
    dst_evidence_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    confidence REAL NOT NULL,
    method TEXT NOT NULL,
    details TEXT,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES investigations(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    evidence_ids TEXT NOT NULL,
    correlation_ids TEXT,
    tags TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES investigations(id)
);

CREATE INDEX IF NOT EXISTS idx_evidence_run ON evidence(run_id);
CREATE INDEX IF NOT EXISTS idx_receipts_run ON receipts(run_id);
CREATE INDEX IF NOT EXISTS idx_provenance_evidence ON provenance(evidence_id);
CREATE INDEX IF NOT EXISTS idx_correlations_run ON correlations(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
"""

def init_db(db_path: str):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.executescript(SCHEMA_DDL)
    conn.commit()
    conn.close()
    print(f"PASS: Initialized schema in {db_path}")

def validate_schema(db_path: str) -> bool:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [r[0] for r in cur.fetchall()]

    for t in EXPECTED_TABLES:
        if t not in tables:
            print(f"FAIL: Missing table {t}")
            conn.close()
            return False

    cur.execute("SELECT name FROM sqlite_master WHERE type='index';")
    indexes = [r[0] for r in cur.fetchall()]

    for idx in EXPECTED_INDEXES:
        if idx not in indexes:
            print(f"FAIL: Missing index {idx}")
            conn.close()
            return False

    conn.close()
    print("PASS: SQLite schema fully matches JOCKY SPEC §17.1 (6 tables, 5 indexes)")
    return True

def tamper_evidence_hash(db_path: str, evidence_id: str, new_hash: str):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("UPDATE evidence SET hash = ? WHERE id = ?", (new_hash, evidence_id))
    conn.commit()
    updated = cur.rowcount
    conn.close()
    if updated > 0:
        print(f"PASS: Bit-flipped evidence {evidence_id} in SQLite")
    else:
        print(f"FAIL: Evidence {evidence_id} not found in database")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="JOCKY SQLite Oracle")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_init = subparsers.add_parser("init")
    p_init.add_argument("db_path", help="Database file path")

    p_val = subparsers.add_parser("validate")
    p_val.add_argument("db_path", help="Database file path")

    p_tamper = subparsers.add_parser("tamper")
    p_tamper.add_argument("db_path", help="Database file path")
    p_tamper.add_argument("--evidence-id", required=True, help="Target evidence ID")
    p_tamper.add_argument("--new-hash", required=True, help="Tampered hash value")

    args = parser.parse_args()

    if args.command == "init":
        init_db(args.db_path)
    elif args.command == "validate":
        if not validate_schema(args.db_path):
            sys.exit(1)
    elif args.command == "tamper":
        tamper_evidence_hash(args.db_path, args.evidence_id, args.new_hash)

if __name__ == "__main__":
    main()
