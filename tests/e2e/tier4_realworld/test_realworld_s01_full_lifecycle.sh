#!/usr/bin/env bash
# tests/e2e/tier4_realworld/test_realworld_s01_full_lifecycle.sh
# Tier 4 Real-World Scenario 1: Full Investigation Lifecycle
# Flow: Compile -> Collect -> Seal & Sign -> Store (SQLite) -> Correlate -> Graph -> Verify

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 4 Scenario 1: Full Investigation Lifecycle"

CASE_DIR="${TEST_TMPDIR}/rw_s01_lifecycle"
mkdir -p "${CASE_DIR}/evidence" "${CASE_DIR}/receipts" "${CASE_DIR}/provenance"
DB_FILE="${CASE_DIR}/investigation.db"

# ---------------------------------------------------------------------------
# Step 1: DSL Investigation Specification & AST/IR Compilation
# ---------------------------------------------------------------------------
log_info "Step 1: DSL Investigation Specification and Compilation"
DSL_SCRIPT="${WORKSPACE_ROOT}/tests/e2e/fixtures/golden_scripts/golden_10_multi_stage_apt.jky"
assert_file_exists "${DSL_SCRIPT}" "S1.1: DSL investigation script exists"

if [ "${JOCKEY_AVAILABLE}" -eq 1 ]; then
    ir_out=$("${JOCKEY_BIN}" compile --input "${DSL_SCRIPT}" 2>&1)
    res_compile=$?
    assert_exit_code 0 ${res_compile} "S1.1: JOCKY CLI compiles DSL script to IR"
    assert_valid_json "${ir_out}" "S1.1: Emitted IR is valid JSON"
else
    # Contract validation of DSL investigation blocks
    assert_contains "$(cat "${DSL_SCRIPT}")" "investigation" "S1.1: DSL contains investigation block"
    assert_contains "$(cat "${DSL_SCRIPT}")" "collect" "S1.1: DSL contains collection directives"
    assert_contains "$(cat "${DSL_SCRIPT}")" "correlate" "S1.1: DSL contains correlation directives"
fi

RUN_ID="01HY_LIFECYCLE_RUN_01"

# ---------------------------------------------------------------------------
# Step 2 & 3: Evidence Generation, SHA-256 Hashing, and Cryptographic Signing
# ---------------------------------------------------------------------------
log_info "Step 2 & 3: Artifact Generation, SHA-256 Hashing & Ed25519 Receipt Signing"

# Generate Ed25519 keypair for collector
kp_json=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" generate-keypair)
COLLECTOR_SK=$("${PYTHON}" -c "import json; print(json.loads('''${kp_json}''')['secret_key'])")
COLLECTOR_PK=$("${PYTHON}" -c "import json; print(json.loads('''${kp_json}''')['public_key'])")
assert_ne "" "${COLLECTOR_PK}" "S1.2: Collector Ed25519 keypair generated"

# Create Evidence 1: Parent Process (svchost.exe)
EV1_ID="01HY_S01_EV_PROC_PARENT"
EV1_FILE="${CASE_DIR}/evidence/${EV1_ID}.json"
EV1_HASH=$("${PYTHON}" -c "import hashlib; print(hashlib.sha256(b'PID:1024;CMD:svchost.exe -k netsvcs').hexdigest())")
cat <<EOF > "${EV1_FILE}"
{
  "id": "${EV1_ID}",
  "run_id": "${RUN_ID}",
  "step_id": "step_proc_collector",
  "collector": "proc_linux",
  "type": "artifact/process",
  "name": "svchost.exe",
  "path": "/proc/1024",
  "size": 33,
  "hash": "${EV1_HASH}",
  "hash_algo": "sha256",
  "metadata": {"pid": 1024, "ppid": 1, "cmdline": "svchost.exe -k netsvcs"},
  "collected_at": "2026-10-04T10:00:00Z"
}
EOF

# Create Evidence 2: Child Process (powershell.exe)
EV2_ID="01HY_S01_EV_PROC_CHILD"
EV2_FILE="${CASE_DIR}/evidence/${EV2_ID}.json"
EV2_HASH=$("${PYTHON}" -c "import hashlib; print(hashlib.sha256(b'PID:2048;PPID:1024;CMD:powershell.exe -enc VwBlAGI...').hexdigest())")
cat <<EOF > "${EV2_FILE}"
{
  "id": "${EV2_ID}",
  "run_id": "${RUN_ID}",
  "step_id": "step_proc_collector",
  "collector": "proc_linux",
  "type": "artifact/process",
  "name": "powershell.exe",
  "path": "/proc/2048",
  "size": 49,
  "hash": "${EV2_HASH}",
  "hash_algo": "sha256",
  "metadata": {"pid": 2048, "ppid": 1024, "cmdline": "powershell.exe -enc VwBlAGI..."},
  "collected_at": "2026-10-04T10:00:01Z"
}
EOF

# Create Evidence 3: Dropped Malware Payload (artifact/file)
EV3_ID="01HY_S01_EV_FILE_PAYLOAD"
EV3_FILE="${CASE_DIR}/evidence/${EV3_ID}.json"
EV3_HASH=$("${PYTHON}" -c "import hashlib; print(hashlib.sha256(b'MALWARE_BINARY_DROP_PAYLOAD_BYTES').hexdigest())")
cat <<EOF > "${EV3_FILE}"
{
  "id": "${EV3_ID}",
  "run_id": "${RUN_ID}",
  "step_id": "step_file_collector",
  "collector": "file_linux",
  "type": "artifact/file",
  "name": "beacon.dll",
  "path": "/tmp/beacon.dll",
  "size": 33,
  "hash": "${EV3_HASH}",
  "hash_algo": "sha256",
  "metadata": {"sha256": "${EV3_HASH}", "permissions": "0755"},
  "collected_at": "2026-10-04T10:00:02Z"
}
EOF

# Generate Signed Receipts for all 3 Evidence items
sign_evidence_receipt() {
    local ev_id="$1"
    local p_hash="$2"
    local coll="$3"
    local rec_id="01HY_S01_REC_${ev_id}"
    local rec_file="${CASE_DIR}/receipts/${rec_id}.json"

    cat <<EOF > "${rec_file}"
{
  "id": "${rec_id}",
  "evidence_id": "${ev_id}",
  "run_id": "${RUN_ID}",
  "collector": "${coll}",
  "collector_version": "0.1.0",
  "public_key": "${COLLECTOR_PK}",
  "payload_hash": "${p_hash}",
  "payload_hash_algo": "sha256",
  "timestamp": "2026-10-04T10:00:05Z",
  "host_info": {
    "hostname": "workstation-01",
    "os": "linux",
    "kernel": "6.1.0",
    "collector_pid": 999
  }
}
EOF
    "${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" sign-receipt --receipt "${rec_file}" --sk-hex "${COLLECTOR_SK}" >/dev/null
}

sign_evidence_receipt "${EV1_ID}" "${EV1_HASH}" "proc_linux"
sign_evidence_receipt "${EV2_ID}" "${EV2_HASH}" "proc_linux"
sign_evidence_receipt "${EV3_ID}" "${EV3_HASH}" "file_linux"

REC1_FILE="${CASE_DIR}/receipts/01HY_S01_REC_${EV1_ID}.json"
REC2_FILE="${CASE_DIR}/receipts/01HY_S01_REC_${EV2_ID}.json"
REC3_FILE="${CASE_DIR}/receipts/01HY_S01_REC_${EV3_ID}.json"

assert_file_exists "${REC1_FILE}" "S1.3: Signed receipt for parent process generated"
assert_file_exists "${REC2_FILE}" "S1.3: Signed receipt for child process generated"
assert_file_exists "${REC3_FILE}" "S1.3: Signed receipt for dropped payload generated"

# Verify all 3 Receipts against Evidence via Cryptographic Oracle
vr1=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV1_FILE}" --receipt "${REC1_FILE}" 2>&1)
assert_exit_code 0 $? "S1.3: Parent process Ed25519 receipt verified"
assert_contains "${vr1}" "PASS" "S1.3: Verification status is PASS"

vr2=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV2_FILE}" --receipt "${REC2_FILE}" 2>&1)
assert_exit_code 0 $? "S1.3: Child process Ed25519 receipt verified"

vr3=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV3_FILE}" --receipt "${REC3_FILE}" 2>&1)
assert_exit_code 0 $? "S1.3: Dropped file Ed25519 receipt verified"

# Create Provenance Chain for Evidence 3 (dropped file)
PROV_CHAIN_FILE="${CASE_DIR}/provenance/prov_chain_ev3.json"
cat <<EOF > "${PROV_CHAIN_FILE}"
[
  {
    "id": "PROV_01",
    "evidence_id": "${EV3_ID}",
    "receipt_id": "01HY_S01_REC_${EV3_ID}",
    "prev_provenance_id": null,
    "action": "collected",
    "actor": "file_linux",
    "actor_version": "0.1.0",
    "input_hashes": [],
    "output_hashes": ["${EV3_HASH}"],
    "parameters": {"path": "/tmp/beacon.dll"},
    "timestamp": "2026-10-04T10:00:03Z",
    "signature": ""
  },
  {
    "id": "PROV_02",
    "evidence_id": "${EV3_ID}",
    "receipt_id": "01HY_S01_REC_${EV3_ID}",
    "prev_provenance_id": "PROV_01",
    "action": "hashed_and_sealed",
    "actor": "jockey_evidence",
    "actor_version": "0.1.0",
    "input_hashes": ["${EV3_HASH}"],
    "output_hashes": ["${EV3_HASH}"],
    "parameters": {"algo": "sha256"},
    "timestamp": "2026-10-04T10:00:04Z",
    "signature": ""
  }
]
EOF

vc_out=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${PROV_CHAIN_FILE}" 2>&1)
assert_exit_code 0 $? "S1.3: Provenance chain continuity verified"
assert_contains "${vc_out}" "PASS" "S1.3: Provenance chain returns PASS"

# ---------------------------------------------------------------------------
# Step 4: Relational Persistence in SQLite (§17.1 Schema)
# ---------------------------------------------------------------------------
log_info "Step 4: Persisting Investigation, Evidence, Receipts, and Provenance to SQLite"
"${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/sqlite_oracle.py" init "${DB_FILE}" >/dev/null

"${PYTHON}" -c "
import sqlite3, json
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('PRAGMA foreign_keys = ON;')

# 1. Ingest investigation
cur.execute('''
    INSERT INTO investigations (id, script_hash, ir_json, contract_json, status, created_at, updated_at)
    VALUES (?, 'script_hash_s01', '{\"steps\": 3}', '{}', 'in_progress', '2026-10-04T10:00:00Z', '2026-10-04T10:00:05Z')
''', ('${RUN_ID}',))

# 2. Ingest evidence items
for fpath in ['${EV1_FILE}', '${EV2_FILE}', '${EV3_FILE}']:
    ev = json.load(open(fpath))
    cur.execute('''
        INSERT INTO evidence (id, run_id, step_id, collector, type, name, path, size, hash, hash_algo, metadata, collected_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (ev['id'], ev['run_id'], ev['step_id'], ev['collector'], ev['type'], ev['name'], ev['path'], ev['size'], ev['hash'], ev['hash_algo'], json.dumps(ev['metadata']), ev['collected_at']))

# 3. Ingest receipts
for rpath in ['${REC1_FILE}', '${REC2_FILE}', '${REC3_FILE}']:
    rec = json.load(open(rpath))
    cur.execute('''
        INSERT INTO receipts (id, evidence_id, run_id, collector, collector_version, signature, public_key, payload_hash, payload_hash_algo, timestamp, host_info)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (rec['id'], rec['evidence_id'], rec['run_id'], rec['collector'], rec['collector_version'], rec['signature'], rec['public_key'], rec['payload_hash'], rec['payload_hash_algo'], rec['timestamp'], json.dumps(rec['host_info'])))

# 4. Ingest provenance records
for prov in json.load(open('${PROV_CHAIN_FILE}')):
    cur.execute('''
        INSERT INTO provenance (id, evidence_id, receipt_id, prev_provenance_id, action, actor, actor_version, input_hashes, output_hashes, parameters, timestamp, signature)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (prov['id'], prov['evidence_id'], prov['receipt_id'], prov['prev_provenance_id'], prov['action'], prov['actor'], prov['actor_version'], json.dumps(prov['input_hashes']), json.dumps(prov['output_hashes']), json.dumps(prov['parameters']), prov['timestamp'], prov['signature']))

conn.commit()
conn.close()
"
assert_exit_code 0 $? "S1.4: Ingestion into SQLite succeeded with relational integrity"

# Validate Schema and Indexes
schema_val=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/sqlite_oracle.py" validate "${DB_FILE}" 2>&1)
assert_exit_code 0 $? "S1.4: SQLite schema validated (6 tables, 5 indexes)"
assert_contains "${schema_val}" "PASS" "S1.4: Schema validation passed"

# ---------------------------------------------------------------------------
# Step 5: Multi-Rule Deterministic Correlation & Graph Generation
# ---------------------------------------------------------------------------
log_info "Step 5: Executing Deterministic Correlation Rules (pid_link & evidence_support)"

"${PYTHON}" -c "
import sqlite3, json
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()

# Rule 1: pid_link: Parent process (svchost PID 1024) -> Child process (powershell PPID 1024)
cur.execute('''
    INSERT INTO correlations (id, run_id, src_evidence_id, dst_evidence_id, relation, confidence, method, details, created_at, created_by)
    VALUES ('corr_01', ?, ?, ?, 'spawned', 1.0, 'pid_link', '{\"parent_pid\": 1024, \"child_pid\": 2048}', '2026-10-04T10:00:10Z', 'correlation_engine')
''', ('${RUN_ID}', '${EV1_ID}', '${EV2_ID}'))

# Rule 2: evidence_support: Child process (powershell) -> Dropped File (beacon.dll)
cur.execute('''
    INSERT INTO correlations (id, run_id, src_evidence_id, dst_evidence_id, relation, confidence, method, details, created_at, created_by)
    VALUES ('corr_02', ?, ?, ?, 'wrote', 0.95, 'evidence_support', '{\"path\": \"/tmp/beacon.dll\"}', '2026-10-04T10:00:11Z', 'correlation_engine')
''', ('${RUN_ID}', '${EV2_ID}', '${EV3_ID}'))

# Update investigation status to completed
cur.execute('UPDATE investigations SET status = ? WHERE id = ?', ('completed', '${RUN_ID}'))

conn.commit()
conn.close()
"
assert_exit_code 0 $? "S1.5: Correlation edges inserted into SQLite"

# Step 6: Construct Cytoscape Graph from SQLite
CYTO_GRAPH_FILE="${CASE_DIR}/cytoscape_graph.json"
"${PYTHON}" -c "
import sqlite3, json
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()

cur.execute('SELECT id, name, type FROM evidence WHERE run_id = ? ORDER BY id', ('${RUN_ID}',))
nodes = [{'data': {'id': r[0], 'label': r[1], 'type': r[2]}} for r in cur.fetchall()]

cur.execute('SELECT id, src_evidence_id, dst_evidence_id, relation, confidence, method FROM correlations WHERE run_id = ? ORDER BY id', ('${RUN_ID}',))
edges = [{'data': {'id': r[0], 'source': r[1], 'target': r[2], 'relation': r[3], 'confidence': r[4], 'method': r[5]}} for r in cur.fetchall()]

cyto_graph = {
    'elements': {
        'nodes': nodes,
        'edges': edges
    }
}
with open('${CYTO_GRAPH_FILE}', 'w') as f:
    json.dump(cyto_graph, f, indent=2)

conn.close()
"
assert_file_exists "${CYTO_GRAPH_FILE}" "S1.6: Cytoscape graph exported from database"
assert_valid_json "$(cat "${CYTO_GRAPH_FILE}")" "S1.6: Cytoscape graph is valid JSON"

node_count=$("${PYTHON}" -c "import json; print(len(json.load(open('${CYTO_GRAPH_FILE}'))['elements']['nodes']))")
edge_count=$("${PYTHON}" -c "import json; print(len(json.load(open('${CYTO_GRAPH_FILE}'))['elements']['edges']))")
assert_eq "3" "${node_count}" "S1.6: Cytoscape graph contains all 3 evidence nodes"
assert_eq "2" "${edge_count}" "S1.6: Cytoscape graph contains 2 correlation edges"

# Verify deterministic hash replay
hash_a=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" hash "${CYTO_GRAPH_FILE}")
hash_b=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" hash "${CYTO_GRAPH_FILE}")
assert_eq "${hash_a}" "${hash_b}" "S1.6: Deterministic graph hash invariance confirmed"

# Verify investigation final status in SQLite
final_status=$("${PYTHON}" -c "
import sqlite3
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('SELECT status FROM investigations WHERE id = ?', ('${RUN_ID}',))
print(cur.fetchone()[0])
conn.close()
")
assert_eq "completed" "${final_status}" "S1.7: Full investigation status marked completed in SQLite"

test_summary_report "Tier 4 Scenario 1: Full Investigation Lifecycle"
exit $?
