#!/usr/bin/env bash
# tests/e2e/tier4_realworld/test_realworld_s03_chain_tamper.sh
# Tier 4 Real-World Scenario 3: Forensic Chain Tamper & Rejection
# Features: F3 (Bit-Flip Tamper), F4 (Sig Tamper), F5 (Provenance Chain), F10 (SQLite Storage)
# Flow: Pristine Ingestion -> DB Bit-Flip -> Verification Fail -> DB Sig Tamper -> Fail ->
#       DB Provenance Tamper -> Fail -> Full Restoration -> Verification Pass

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 4 Scenario 3: Forensic Chain Tamper & Rejection"

CASE_DIR="${TEST_TMPDIR}/rw_s03_tamper"
mkdir -p "${CASE_DIR}/evidence" "${CASE_DIR}/receipts" "${CASE_DIR}/provenance"
DB_FILE="${CASE_DIR}/forensics_tamper.db"
RUN_ID="01HY_TAMPER_INVESTIGATION_RUN"

# ---------------------------------------------------------------------------
# Step 1: Initialize Database & Seed Authentic Forensic Artifacts
# ---------------------------------------------------------------------------
log_info "Step 1: Setting up Pristine Forensic Database with Authentic Signatures"

"${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/sqlite_oracle.py" init "${DB_FILE}" >/dev/null

kp_json=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" generate-keypair)
COLLECTOR_SK=$("${PYTHON}" -c "import json; print(json.loads('''${kp_json}''')['secret_key'])")
COLLECTOR_PK=$("${PYTHON}" -c "import json; print(json.loads('''${kp_json}''')['public_key'])")

EV_ID="01HY_S03_EV_ROOT"
EV_HASH=$("${PYTHON}" -c "import hashlib; print(hashlib.sha256(b'SYSTEM_LOG_ENTRY_PRISTINE_RECORD').hexdigest())")
REC_ID="01HY_S03_REC_ROOT"

# Create Authentic Receipt File and Sign
REC_TMP="${CASE_DIR}/receipts/${REC_ID}.json"
cat <<EOF > "${REC_TMP}"
{
  "id": "${REC_ID}",
  "evidence_id": "${EV_ID}",
  "run_id": "${RUN_ID}",
  "collector": "file_linux",
  "collector_version": "0.1.0",
  "public_key": "${COLLECTOR_PK}",
  "payload_hash": "${EV_HASH}",
  "payload_hash_algo": "sha256",
  "timestamp": "2026-10-04T16:00:00Z",
  "host_info": {
    "hostname": "forensics-vm",
    "os": "linux",
    "kernel": "6.1.0",
    "collector_pid": 1234
  }
}
EOF
"${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" sign-receipt --receipt "${REC_TMP}" --sk-hex "${COLLECTOR_SK}" >/dev/null
REC_SIG=$("${PYTHON}" -c "import json; print(json.load(open('${REC_TMP}'))['signature'])")

# Seed SQLite database
"${PYTHON}" -c "
import sqlite3, json
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('PRAGMA foreign_keys = ON;')

# 1. Investigation
cur.execute('''
    INSERT INTO investigations (id, script_hash, ir_json, status, created_at, updated_at)
    VALUES (?, 'script_hash', '{}', 'completed', '2026-10-04', '2026-10-04')
''', ('${RUN_ID}',))

# 2. Evidence
cur.execute('''
    INSERT INTO evidence (id, run_id, step_id, collector, type, name, path, size, hash, hash_algo, metadata, collected_at)
    VALUES (?, ?, 's1', 'file_linux', 'artifact/log', 'auth.log', '/var/log/auth.log', 32, ?, 'sha256', '{}', '2026-10-04T16:00:00Z')
''', ('${EV_ID}', '${RUN_ID}', '${EV_HASH}'))

# 3. Receipt
cur.execute('''
    INSERT INTO receipts (id, evidence_id, run_id, collector, collector_version, signature, public_key, payload_hash, payload_hash_algo, timestamp, host_info)
    VALUES (?, ?, ?, 'file_linux', '0.1.0', ?, ?, ?, 'sha256', '2026-10-04T16:00:00Z', '{\"hostname\": \"forensics-vm\", \"os\": \"linux\", \"kernel\": \"6.1.0\", \"collector_pid\": 1234}')
''', ('${REC_ID}', '${EV_ID}', '${RUN_ID}', '${REC_SIG}', '${COLLECTOR_PK}', '${EV_HASH}'))

# 4. Provenance chain (2 links)
cur.execute('''
    INSERT INTO provenance (id, evidence_id, receipt_id, prev_provenance_id, action, actor, actor_version, input_hashes, output_hashes, parameters, timestamp, signature)
    VALUES ('PROV_S03_01', ?, ?, NULL, 'collected', 'file_linux', '0.1.0', '[]', '[\"${EV_HASH}\"]', '{}', '2026-10-04T16:00:01Z', '')
''', ('${EV_ID}', '${REC_ID}'))

cur.execute('''
    INSERT INTO provenance (id, evidence_id, receipt_id, prev_provenance_id, action, actor, actor_version, input_hashes, output_hashes, parameters, timestamp, signature)
    VALUES ('PROV_S03_02', ?, ?, 'PROV_S03_01', 'hashed', 'jockey_crypto', '0.1.0', '[\"${EV_HASH}\"]', '[\"${EV_HASH}\"]', '{}', '2026-10-04T16:00:02Z', '')
''', ('${EV_ID}', '${REC_ID}'))

conn.commit()
conn.close()
"
assert_exit_code 0 $? "S3.1: Pristine investigation seeded in SQLite"

# Helper function to extract and verify from SQLite
verify_db_evidence() {
    "${PYTHON}" -c "
import sqlite3, json, sys, subprocess

conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()

# Get Evidence
cur.execute('SELECT id, hash, hash_algo, name, path FROM evidence WHERE id = ?', ('${EV_ID}',))
ev_row = cur.fetchone()
ev_data = {
    'id': ev_row[0],
    'hash': ev_row[1],
    'hash_algo': ev_row[2],
    'name': ev_row[3],
    'path': ev_row[4]
}

# Get Receipt
cur.execute('SELECT id, evidence_id, run_id, collector, collector_version, signature, public_key, payload_hash, payload_hash_algo, timestamp, host_info FROM receipts WHERE evidence_id = ?', ('${EV_ID}',))
rec_row = cur.fetchone()
rec_data = {
    'id': rec_row[0],
    'evidence_id': rec_row[1],
    'run_id': rec_row[2],
    'collector': rec_row[3],
    'collector_version': rec_row[4],
    'signature': rec_row[5],
    'public_key': rec_row[6],
    'payload_hash': rec_row[7],
    'payload_hash_algo': rec_row[8],
    'timestamp': rec_row[9],
    'host_info': json.loads(rec_row[10])
}

with open('${CASE_DIR}/ev_check.json', 'w') as f:
    json.dump(ev_data, f)
with open('${CASE_DIR}/rec_check.json', 'w') as f:
    json.dump(rec_data, f)

conn.close()
"
    "${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${CASE_DIR}/ev_check.json" --receipt "${CASE_DIR}/rec_check.json" 2>&1
}

# ---------------------------------------------------------------------------
# Step 2: Pristine State Verification
# ---------------------------------------------------------------------------
log_info "Step 2: Baseline Pristine Verification"
v_pristine=$(verify_db_evidence)
res_pristine=$?
assert_exit_code 0 ${res_pristine} "S3.2: Baseline pristine state verified with exit code 0"
assert_contains "${v_pristine}" "PASS" "S3.2: Pristine verification output confirms PASS"

# ---------------------------------------------------------------------------
# Step 3: Attack Scenario A - In-Database Evidence Payload Bit-Flip
# ---------------------------------------------------------------------------
log_info "Step 3: Attack Scenario A - In-Database Evidence Payload Bit-Flip"

TAMPERED_EV_HASH=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" bitflip "${EV_HASH}" --bit 0)
assert_ne "${EV_HASH}" "${TAMPERED_EV_HASH}" "S3.3: Bit-flip generated different hash"

# Update evidence hash in SQLite database
"${PYTHON}" -c "
import sqlite3
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('UPDATE evidence SET hash = ? WHERE id = ?', ('${TAMPERED_EV_HASH}', '${EV_ID}'))
conn.commit()
conn.close()
"

v_tamper_a=$(verify_db_evidence 2>&1)
res_tamper_a=$?
assert_ne 0 ${res_tamper_a} "S3.3: In-database bit-flipped evidence rejected by verification oracle"
assert_contains "${v_tamper_a}" "Hash mismatch" "S3.3: Rejection explicitly reports Hash mismatch"

# Restore evidence hash
"${PYTHON}" -c "
import sqlite3
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('UPDATE evidence SET hash = ? WHERE id = ?', ('${EV_HASH}', '${EV_ID}'))
conn.commit()
conn.close()
"
v_restore_a=$(verify_db_evidence)
assert_exit_code 0 $? "S3.3: Restoring evidence hash returns to PASS"

# ---------------------------------------------------------------------------
# Step 4: Attack Scenario B - In-Database Receipt Signature Forgery
# ---------------------------------------------------------------------------
log_info "Step 4: Attack Scenario B - In-Database Receipt Signature Forgery"

TAMPERED_SIG=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" bitflip "${REC_SIG}" --bit 7)
assert_ne "${REC_SIG}" "${TAMPERED_SIG}" "S3.4: Altered receipt signature"

# Update receipt signature in SQLite database
"${PYTHON}" -c "
import sqlite3
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('UPDATE receipts SET signature = ? WHERE id = ?', ('${TAMPERED_SIG}', '${REC_ID}'))
conn.commit()
conn.close()
"

v_tamper_b=$(verify_db_evidence 2>&1)
res_tamper_b=$?
assert_ne 0 ${res_tamper_b} "S3.4: In-database forged signature rejected by verification oracle"
assert_contains "${v_tamper_b}" "signature invalid" "S3.4: Rejection explicitly reports signature invalid"

# Restore receipt signature
"${PYTHON}" -c "
import sqlite3
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('UPDATE receipts SET signature = ? WHERE id = ?', ('${REC_SIG}', '${REC_ID}'))
conn.commit()
conn.close()
"
v_restore_b=$(verify_db_evidence)
assert_exit_code 0 $? "S3.4: Restoring receipt signature returns to PASS"

# ---------------------------------------------------------------------------
# Step 5: Attack Scenario C - In-Database Provenance Chain Severing
# ---------------------------------------------------------------------------
log_info "Step 5: Attack Scenario C - In-Database Provenance Chain Severing"

verify_db_provenance() {
    "${PYTHON}" -c "
import sqlite3, json
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('SELECT id, evidence_id, receipt_id, prev_provenance_id, action, actor, actor_version, input_hashes, output_hashes, parameters, timestamp, signature FROM provenance WHERE evidence_id = ? ORDER BY id', ('${EV_ID}',))
rows = cur.fetchall()
chain = [
    {
        'id': r[0],
        'evidence_id': r[1],
        'receipt_id': r[2],
        'prev_provenance_id': r[3],
        'action': r[4],
        'actor': r[5],
        'actor_version': r[6],
        'input_hashes': json.loads(r[7]),
        'output_hashes': json.loads(r[8]),
        'parameters': json.loads(r[9]),
        'timestamp': r[10],
        'signature': r[11]
    }
    for r in rows
]
with open('${CASE_DIR}/prov_check.json', 'w') as f:
    json.dump(chain, f)
conn.close()
"
    "${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${CASE_DIR}/prov_check.json" 2>&1
}

# Baseline provenance check
v_prov_pristine=$(verify_db_provenance)
assert_exit_code 0 $? "S3.5: Baseline provenance chain valid in database"

# Tamper: Sever the chain by pointing prev_provenance_id to an invalid ID
"${PYTHON}" -c "
import sqlite3
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('UPDATE provenance SET prev_provenance_id = \"INVALID_CHAIN_LINK\" WHERE id = \"PROV_S03_02\"')
conn.commit()
conn.close()
"

v_tamper_c=$(verify_db_provenance 2>&1)
res_tamper_c=$?
assert_ne 0 ${res_tamper_c} "S3.5: Severed provenance chain rejected in database"
assert_contains "${v_tamper_c}" "Provenance chain broken" "S3.5: Rejection explicitly reports Provenance chain broken"

# Restore provenance chain link
"${PYTHON}" -c "
import sqlite3
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('UPDATE provenance SET prev_provenance_id = \"PROV_S03_01\" WHERE id = \"PROV_S03_02\"')
conn.commit()
conn.close()
"
v_restore_c=$(verify_db_provenance)
assert_exit_code 0 $? "S3.5: Restoring provenance link returns to PASS"

# ---------------------------------------------------------------------------
# Step 6: Foreign Key Enforcement against DB Inconsistency
# ---------------------------------------------------------------------------
log_info "Step 6: Enforcing SQLite Foreign Key Constraints on Orphan Evidence"

fk_rejection=$("${PYTHON}" -c "
import sqlite3
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('PRAGMA foreign_keys = ON;')
try:
    cur.execute('''
        INSERT INTO receipts (id, evidence_id, run_id, collector, collector_version, signature, public_key, payload_hash, payload_hash_algo, timestamp, host_info)
        VALUES ('orphan_rec', 'NON_EXISTENT_EVIDENCE_ID', '${RUN_ID}', 'c', '1', 'sig', 'pk', 'hash', 'sha256', 'time', '{}')
    ''')
    conn.commit()
    print('ALLOWED')
except sqlite3.IntegrityError:
    print('FOREIGN_KEY_VIOLATION')
conn.close()
")
assert_eq "FOREIGN_KEY_VIOLATION" "${fk_rejection}" "S3.6: SQLite foreign key enforcement blocks orphaned receipts"

test_summary_report "Tier 4 Scenario 3: Forensic Chain Tamper & Rejection"
exit $?
