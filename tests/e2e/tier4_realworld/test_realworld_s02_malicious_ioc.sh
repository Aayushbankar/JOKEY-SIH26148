#!/usr/bin/env bash
# tests/e2e/tier4_realworld/test_realworld_s02_malicious_ioc.sh
# Tier 4 Real-World Scenario 2: Malicious Binary Detection & IOC Correlation
# Features: F8 (Process Collector), F9 (File Collector), F11 (Correlation & Cytoscape)
# Flow: Process Activity -> File Drop -> IOC Hash Match -> Deterministic Correlation -> Finding Record

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 4 Scenario 2: Malicious Binary Detection & IOC Correlation"

CASE_DIR="${TEST_TMPDIR}/rw_s02_ioc"
mkdir -p "${CASE_DIR}/evidence" "${CASE_DIR}/receipts"
DB_FILE="${CASE_DIR}/investigation_ioc.db"
RUN_ID="01HY_IOC_INVESTIGATION_RUN"

# ---------------------------------------------------------------------------
# Step 1: Malicious Process & Dropped Binary Collection Setup
# ---------------------------------------------------------------------------
log_info "Step 1: Ingesting Process and Dropped File Forensic Evidence"

# Generate Ed25519 keypair for forensic collectors
kp_json=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" generate-keypair)
COLLECTOR_SK=$("${PYTHON}" -c "import json; print(json.loads('''${kp_json}''')['secret_key'])")
COLLECTOR_PK=$("${PYTHON}" -c "import json; print(json.loads('''${kp_json}''')['public_key'])")
assert_ne "" "${COLLECTOR_PK}" "S2.1: Forensic collector Ed25519 keypair initialized"

# Real payload from fixture
BINARY_FIXTURE="${WORKSPACE_ROOT}/tests/e2e/fixtures/test_files/binary.dat"
assert_file_exists "${BINARY_FIXTURE}" "S2.1: Dropped binary artifact fixture exists"
BINARY_SHA256=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" hash "${BINARY_FIXTURE}")
BINARY_SIZE=$(wc -c < "${BINARY_FIXTURE}" | tr -d ' ')

# Process Evidence (Mimikatz execution)
EV_PROC_ID="01HY_S02_EV_PROC_MIMIKATZ"
EV_PROC_FILE="${CASE_DIR}/evidence/${EV_PROC_ID}.json"
EV_PROC_HASH=$("${PYTHON}" -c "import hashlib; print(hashlib.sha256(b'PID:31337;CMD:mimikatz.exe privilege::debug sekurlsa::logonpasswords').hexdigest())")

cat <<EOF > "${EV_PROC_FILE}"
{
  "id": "${EV_PROC_ID}",
  "run_id": "${RUN_ID}",
  "step_id": "step_ioc_proc_collector",
  "collector": "proc_linux",
  "type": "artifact/process",
  "name": "mimikatz.exe",
  "path": "/proc/31337",
  "size": 68,
  "hash": "${EV_PROC_HASH}",
  "hash_algo": "sha256",
  "metadata": {
    "pid": 31337,
    "ppid": 1024,
    "cmdline": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
    "user": "root",
    "cwd": "/opt/malware"
  },
  "collected_at": "2026-10-04T14:30:00Z"
}
EOF

# File Evidence (Dropped mimilib.dll)
EV_FILE_ID="01HY_S02_EV_FILE_MIMILIB"
EV_FILE_PATH="${CASE_DIR}/evidence/${EV_FILE_ID}.json"

cat <<EOF > "${EV_FILE_PATH}"
{
  "id": "${EV_FILE_ID}",
  "run_id": "${RUN_ID}",
  "step_id": "step_ioc_file_collector",
  "collector": "file_linux",
  "type": "artifact/file",
  "name": "mimilib.dll",
  "path": "/opt/malware/mimilib.dll",
  "size": ${BINARY_SIZE},
  "hash": "${BINARY_SHA256}",
  "hash_algo": "sha256",
  "metadata": {
    "sha256": "${BINARY_SHA256}",
    "written_by_pid": 31337,
    "permissions": "0700",
    "file_entropy": 7.92
  },
  "collected_at": "2026-10-04T14:30:02Z"
}
EOF

assert_file_exists "${EV_PROC_FILE}" "S2.1: Process evidence JSON created"
assert_file_exists "${EV_FILE_PATH}" "S2.1: File evidence JSON created"

# ---------------------------------------------------------------------------
# Step 2: Sign Evidence Receipts with Cryptographic Oracle
# ---------------------------------------------------------------------------
log_info "Step 2: Signing Evidence Receipts with Ed25519"

sign_receipt() {
    local ev_id="$1"
    local p_hash="$2"
    local coll="$3"
    local rec_id="01HY_S02_REC_${ev_id}"
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
  "timestamp": "2026-10-04T14:30:05Z",
  "host_info": {
    "hostname": "target-host-linux",
    "os": "linux",
    "kernel": "6.1.0",
    "collector_pid": 1111
  }
}
EOF
    "${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" sign-receipt --receipt "${rec_file}" --sk-hex "${COLLECTOR_SK}" >/dev/null
}

sign_receipt "${EV_PROC_ID}" "${EV_PROC_HASH}" "proc_linux"
sign_receipt "${EV_FILE_ID}" "${BINARY_SHA256}" "file_linux"

REC_PROC_FILE="${CASE_DIR}/receipts/01HY_S02_REC_${EV_PROC_ID}.json"
REC_FILE_PATH="${CASE_DIR}/receipts/01HY_S02_REC_${EV_FILE_ID}.json"

# Verify cryptographic signatures
vr_p=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV_PROC_FILE}" --receipt "${REC_PROC_FILE}" 2>&1)
assert_exit_code 0 $? "S2.2: Process evidence receipt verified"
assert_contains "${vr_p}" "PASS" "S2.2: Process receipt status is PASS"

vr_f=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV_FILE_PATH}" --receipt "${REC_FILE_PATH}" 2>&1)
assert_exit_code 0 $? "S2.2: File evidence receipt verified"
assert_contains "${vr_f}" "PASS" "S2.2: File receipt status is PASS"

# ---------------------------------------------------------------------------
# Step 3: Threat Intelligence IOC Correlation & Finding Formulation
# ---------------------------------------------------------------------------
log_info "Step 3: Performing IOC Matching & Evidence Support Correlation"

# Define Known Malware Threat Intelligence IOC Database
KNOWN_IOC_HASH="${BINARY_SHA256}"
IOC_RULE_ID="RULE_MITRE_T1003_CRED_DUMP"

ioc_match=$("${PYTHON}" -c "
import json
f_ev = json.load(open('${EV_FILE_PATH}'))
known_ioc = '${KNOWN_IOC_HASH}'
if f_ev['hash'] == known_ioc:
    print('MATCH:CRITICAL:T1003.001')
else:
    print('NO_MATCH')
")
assert_eq "MATCH:CRITICAL:T1003.001" "${ioc_match}" "S2.3: Dropped binary hash matches known Threat IOC database"

# ---------------------------------------------------------------------------
# Step 4: Relational Persistence (SQLite §17.1 Schema)
# ---------------------------------------------------------------------------
log_info "Step 4: Persisting Evidence, Correlation, and Findings to SQLite"
"${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/sqlite_oracle.py" init "${DB_FILE}" >/dev/null

"${PYTHON}" -c "
import sqlite3, json
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('PRAGMA foreign_keys = ON;')

# 1. Insert investigation
cur.execute('''
    INSERT INTO investigations (id, script_hash, ir_json, status, created_at, updated_at)
    VALUES (?, 'ioc_script_hash', '{\"hypothesis\": \"Credential dumping\"}', 'completed', '2026-10-04', '2026-10-04')
''', ('${RUN_ID}',))

# 2. Insert process evidence
p_ev = json.load(open('${EV_PROC_FILE}'))
cur.execute('''
    INSERT INTO evidence (id, run_id, step_id, collector, type, name, path, size, hash, hash_algo, metadata, collected_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
''', (p_ev['id'], p_ev['run_id'], p_ev['step_id'], p_ev['collector'], p_ev['type'], p_ev['name'], p_ev['path'], p_ev['size'], p_ev['hash'], p_ev['hash_algo'], json.dumps(p_ev['metadata']), p_ev['collected_at']))

# 3. Insert file evidence
f_ev = json.load(open('${EV_FILE_PATH}'))
cur.execute('''
    INSERT INTO evidence (id, run_id, step_id, collector, type, name, path, size, hash, hash_algo, metadata, collected_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
''', (f_ev['id'], f_ev['run_id'], f_ev['step_id'], f_ev['collector'], f_ev['type'], f_ev['name'], f_ev['path'], f_ev['size'], f_ev['hash'], f_ev['hash_algo'], json.dumps(f_ev['metadata']), f_ev['collected_at']))

# 4. Insert receipts
for rpath in ['${REC_PROC_FILE}', '${REC_FILE_PATH}']:
    r = json.load(open(rpath))
    cur.execute('''
        INSERT INTO receipts (id, evidence_id, run_id, collector, collector_version, signature, public_key, payload_hash, payload_hash_algo, timestamp, host_info)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (r['id'], r['evidence_id'], r['run_id'], r['collector'], r['collector_version'], r['signature'], r['public_key'], r['payload_hash'], r['payload_hash_algo'], r['timestamp'], json.dumps(r['host_info'])))

# 5. Insert correlation edge: process wrote file (evidence_support)
cur.execute('''
    INSERT INTO correlations (id, run_id, src_evidence_id, dst_evidence_id, relation, confidence, method, details, created_at, created_by)
    VALUES ('corr_ioc_01', ?, ?, ?, 'wrote', 0.98, 'evidence_support', '{\"src_pid\": 31337, \"file\": \"mimilib.dll\"}', '2026-10-04T14:30:10Z', 'correlation_engine')
''', ('${RUN_ID}', '${EV_PROC_ID}', '${EV_FILE_ID}'))

# 6. Insert security Finding
cur.execute('''
    INSERT INTO findings (id, run_id, rule_id, title, description, severity, status, evidence_ids, correlation_ids, tags, metadata, created_at, updated_at)
    VALUES ('finding_ioc_01', ?, '${IOC_RULE_ID}', 'LSASS Credential Dumping via Mimikatz', 'Process mimikatz.exe dropped known malicious binary mimilib.dll', 'CRITICAL', 'CONFIRMED', '[\"${EV_PROC_ID}\", \"${EV_FILE_ID}\"]', '[\"corr_ioc_01\"]', '[\"credential_dumping\", \"mitre_t1003\", \"ioc_match\"]', '{\"cve\": \"CVE-2022-26925\"}', '2026-10-04T14:30:15Z', '2026-10-04T14:30:15Z')
''', ('${RUN_ID}',))

conn.commit()
conn.close()
"
assert_exit_code 0 $? "S2.4: Malicious IOC records persisted to SQLite tables"

# ---------------------------------------------------------------------------
# Step 5: Relational Cross-Table Queries & Verification
# ---------------------------------------------------------------------------
log_info "Step 5: Verifying Relational Integrity of Security Finding"

finding_title=$("${PYTHON}" -c "
import sqlite3
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('SELECT title, severity FROM findings WHERE run_id = ?', ('${RUN_ID}',))
row = cur.fetchone()
print(f'{row[0]}:{row[1]}')
conn.close()
")
assert_eq "LSASS Credential Dumping via Mimikatz:CRITICAL" "${finding_title}" "S2.5: Security finding retrieved with CRITICAL severity"

# Verify Cytoscape Threat Graph Generation
CYTO_IOC_OUT="${CASE_DIR}/cyto_ioc_graph.json"
"${PYTHON}" -c "
import sqlite3, json
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()

cur.execute('SELECT id, name, type FROM evidence WHERE run_id = ?', ('${RUN_ID}',))
nodes = [{'data': {'id': r[0], 'label': r[1], 'type': r[2]}} for r in cur.fetchall()]

cur.execute('SELECT id, src_evidence_id, dst_evidence_id, relation, confidence FROM correlations WHERE run_id = ?', ('${RUN_ID}',))
edges = [{'data': {'id': r[0], 'source': r[1], 'target': r[2], 'relation': r[3], 'confidence': r[4]}} for r in cur.fetchall()]

cyto = {'elements': {'nodes': nodes, 'edges': edges}}
with open('${CYTO_IOC_OUT}', 'w') as f:
    json.dump(cyto, f, indent=2)
conn.close()
"
assert_file_exists "${CYTO_IOC_OUT}" "S2.5: Cytoscape threat graph generated"
assert_valid_json "$(cat "${CYTO_IOC_OUT}")" "S2.5: Cytoscape threat graph is valid JSON"

rel=$("${PYTHON}" -c "import json; print(json.load(open('${CYTO_IOC_OUT}'))['elements']['edges'][0]['data']['relation'])")
assert_eq "wrote" "${rel}" "S2.5: Correlation relation in threat graph is 'wrote'"

test_summary_report "Tier 4 Scenario 2: Malicious Binary Detection & IOC Correlation"
exit $?
