#!/usr/bin/env python3
"""
tests/e2e/fixtures/generate_fixtures.py
Generates authentic cryptographic fixtures for JOCKY E2E testing.
Creates valid evidence objects, Ed25519 signed receipts, and provenance chains.
"""

import os
import sys
import json
import hashlib
from pathlib import Path

# Add common to sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
COMMON_DIR = SCRIPT_DIR.parent / "common"
sys.path.insert(0, str(COMMON_DIR))

import crypto_oracle

def generate_sample_case():
    base_dir = SCRIPT_DIR / "sample_case"
    ev_dir = base_dir / "evidence"
    rec_dir = base_dir / "receipts"
    prov_dir = base_dir / "provenance"

    os.makedirs(ev_dir, exist_ok=True)
    os.makedirs(rec_dir, exist_ok=True)
    os.makedirs(prov_dir, exist_ok=True)

    # 1. Generate collector keypairs
    proc_sk = bytes.fromhex("11" * 32)
    proc_pk = crypto_oracle.publickey(proc_sk).hex()

    file_sk = bytes.fromhex("22" * 32)
    file_pk = crypto_oracle.publickey(file_sk).hex()

    run_id = "01HY876543210ABCDEF1234567"

    # Evidence 1: Process (svchost)
    ev1_id = "01HY876543210ABCDEF123456A"
    payload1_bytes = b"process:svchost.exe:pid=1024:ppid=600"
    hash1 = hashlib.sha256(payload1_bytes).hexdigest()
    ev1 = {
        "id": ev1_id,
        "run_id": run_id,
        "step_id": "step_proc_1",
        "collector": "proc_linux",
        "type": "artifact/process",
        "name": "svchost.exe",
        "path": "/proc/1024",
        "size": len(payload1_bytes),
        "hash": hash1,
        "hash_algo": "sha256",
        "metadata": {
            "pid": 1024,
            "ppid": 600,
            "cmdline": "/usr/sbin/svchost -k netsvcs"
        },
        "collected_at": "2026-10-04T12:00:00Z"
    }

    # Receipt 1
    rec1 = {
        "id": "01HY876543210ABCDEF123457A",
        "evidence_id": ev1_id,
        "run_id": run_id,
        "collector": "proc_linux",
        "collector_version": "0.1.0",
        "signature": "",
        "public_key": proc_pk,
        "payload_hash": hash1,
        "payload_hash_algo": "sha256",
        "timestamp": "2026-10-04T12:00:01Z",
        "host_info": {
            "hostname": "forensic-target",
            "os": "linux",
            "kernel": "6.1.0-android",
            "collector_pid": 500
        }
    }
    canon1 = crypto_oracle.canonical_receipt_bytes(rec1)
    rec1["signature"] = crypto_oracle.signature(canon1, proc_sk, bytes.fromhex(proc_pk)).hex()

    # Evidence 2: Child Process (powershell)
    ev2_id = "01HY876543210ABCDEF123456B"
    payload2_bytes = b"process:powershell.exe:pid=2048:ppid=1024"
    hash2 = hashlib.sha256(payload2_bytes).hexdigest()
    ev2 = {
        "id": ev2_id,
        "run_id": run_id,
        "step_id": "step_proc_2",
        "collector": "proc_linux",
        "type": "artifact/process",
        "name": "powershell.exe",
        "path": "/proc/2048",
        "size": len(payload2_bytes),
        "hash": hash2,
        "hash_algo": "sha256",
        "metadata": {
            "pid": 2048,
            "ppid": 1024,
            "cmdline": "powershell.exe -enc aW52b2tlLW1pbWlrYXR6"
        },
        "collected_at": "2026-10-04T12:00:05Z"
    }

    # Receipt 2
    rec2 = {
        "id": "01HY876543210ABCDEF123457B",
        "evidence_id": ev2_id,
        "run_id": run_id,
        "collector": "proc_linux",
        "collector_version": "0.1.0",
        "signature": "",
        "public_key": proc_pk,
        "payload_hash": hash2,
        "payload_hash_algo": "sha256",
        "timestamp": "2026-10-04T12:00:06Z",
        "host_info": {
            "hostname": "forensic-target",
            "os": "linux",
            "kernel": "6.1.0-android",
            "collector_pid": 500
        }
    }
    canon2 = crypto_oracle.canonical_receipt_bytes(rec2)
    rec2["signature"] = crypto_oracle.signature(canon2, proc_sk, bytes.fromhex(proc_pk)).hex()

    # Evidence 3: File (dropped payload)
    ev3_id = "01HY876543210ABCDEF123456C"
    payload3_bytes = b"MZ\x90\x00malicious-trojan-binary-payload"
    hash3 = hashlib.sha256(payload3_bytes).hexdigest()
    ev3 = {
        "id": ev3_id,
        "run_id": run_id,
        "step_id": "step_file_1",
        "collector": "file_linux",
        "type": "artifact/file",
        "name": "updater.bin",
        "path": "/tmp/staging/updater.bin",
        "size": len(payload3_bytes),
        "hash": hash3,
        "hash_algo": "sha256",
        "metadata": {
            "permissions": "0755",
            "file_type": "ELF/binary"
        },
        "collected_at": "2026-10-04T12:00:10Z"
    }

    # Receipt 3
    rec3 = {
        "id": "01HY876543210ABCDEF123457C",
        "evidence_id": ev3_id,
        "run_id": run_id,
        "collector": "file_linux",
        "collector_version": "0.1.0",
        "signature": "",
        "public_key": file_pk,
        "payload_hash": hash3,
        "payload_hash_algo": "sha256",
        "timestamp": "2026-10-04T12:00:11Z",
        "host_info": {
            "hostname": "forensic-target",
            "os": "linux",
            "kernel": "6.1.0-android",
            "collector_pid": 501
        }
    }
    canon3 = crypto_oracle.canonical_receipt_bytes(rec3)
    rec3["signature"] = crypto_oracle.signature(canon3, file_sk, bytes.fromhex(file_pk)).hex()

    # Provenance Chain for Evidence 1 (Root collected -> Transform filtered -> Correlated)
    prov1 = {
        "id": "01HY876543210ABCDEF123458A",
        "evidence_id": ev1_id,
        "receipt_id": rec1["id"],
        "prev_provenance_id": None,
        "action": "collected",
        "actor": "proc_linux",
        "actor_version": "0.1.0",
        "input_hashes": [],
        "output_hashes": [hash1],
        "parameters": {},
        "timestamp": "2026-10-04T12:00:02Z",
        "signature": ""
    }

    prov2 = {
        "id": "01HY876543210ABCDEF123458B",
        "evidence_id": ev1_id,
        "receipt_id": rec1["id"],
        "prev_provenance_id": prov1["id"],
        "action": "filtered",
        "actor": "jockey_filter",
        "actor_version": "0.1.0",
        "input_hashes": [hash1],
        "output_hashes": [hash1],
        "parameters": {"predicate": "name contains svchost"},
        "timestamp": "2026-10-04T12:00:03Z",
        "signature": ""
    }

    prov_chain = [prov1, prov2]

    # Write files
    with open(ev_dir / "evidence_proc_01.json", "w") as f:
        json.dump(ev1, f, indent=2)
    with open(ev_dir / "evidence_proc_02.json", "w") as f:
        json.dump(ev2, f, indent=2)
    with open(ev_dir / "evidence_file_01.json", "w") as f:
        json.dump(ev3, f, indent=2)

    with open(rec_dir / "receipt_proc_01.json", "w") as f:
        json.dump(rec1, f, indent=2)
    with open(rec_dir / "receipt_proc_02.json", "w") as f:
        json.dump(rec2, f, indent=2)
    with open(rec_dir / "receipt_file_01.json", "w") as f:
        json.dump(rec3, f, indent=2)

    with open(prov_dir / "provenance_chain_01.json", "w") as f:
        json.dump(prov_chain, f, indent=2)

    manifest = {
        "case_id": "sample_case_sih26148",
        "run_id": run_id,
        "description": "Synthetic multi-stage malware execution case",
        "evidence_count": 3,
        "receipt_count": 3,
        "provenance_chains": 1,
        "evidence_files": [
            "evidence/evidence_proc_01.json",
            "evidence/evidence_proc_02.json",
            "evidence/evidence_file_01.json"
        ]
    }
    with open(base_dir / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    # Also create test files directory for file collector testing
    test_files_dir = SCRIPT_DIR / "test_files"
    os.makedirs(test_files_dir / "nested", exist_ok=True)
    with open(test_files_dir / "normal.txt", "w") as f:
        f.write("Standard plain text forensic artifact\n")
    with open(test_files_dir / "binary.dat", "wb") as f:
        f.write(b"\x00\x01\x02\x03\xFF\xFE\xFD\xFC" * 64)
    with open(test_files_dir / "nested" / "deep.log", "w") as f:
        f.write("2026-10-04T12:00:00Z [AUTH] User root logon accepted\n")
    with open(test_files_dir / "spaces in name.txt", "w") as f:
        f.write("File with spaces in name\n")

    print("PASS: Generated all sample case and test file fixtures")

if __name__ == "__main__":
    generate_sample_case()
