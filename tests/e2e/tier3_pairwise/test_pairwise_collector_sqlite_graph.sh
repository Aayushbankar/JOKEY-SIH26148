#!/usr/bin/env bash
# tests/e2e/tier3_pairwise/test_pairwise_collector_sqlite_graph.sh
# Tier 3 Pairwise: Collector -> SQLite Persistence -> Cytoscape Graph

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 3 Pairwise: Collector -> SQLite -> Graph"

DB_FILE="${TEST_TMPDIR}/pairwise_collector_sqlite.db"
"${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/sqlite_oracle.py" init "${DB_FILE}" >/dev/null

# Step 1: Ingest collector evidence into SQLite
run_id="01HY_PAIRWISE_RUN_02"
ev1_id="01HY_EV_PROC_P1"
ev2_id="01HY_EV_PROC_P2"

"${PYTHON}" -c "
import sqlite3
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('PRAGMA foreign_keys = ON;')
cur.execute('''
    INSERT INTO investigations (id, script_hash, ir_json, status, created_at, updated_at)
    VALUES (?, 'hash_ir', '{}', 'completed', '2026-10-04', '2026-10-04')
''', ('${run_id}',))

cur.execute('''
    INSERT INTO evidence (id, run_id, step_id, collector, type, name, path, size, hash, hash_algo, metadata, collected_at)
    VALUES (?, ?, 's1', 'proc_linux', 'artifact/process', 'svchost.exe', '/proc/100', 100, 'h1', 'sha256', '{\"pid\": 100}', '2026')
''', ('${ev1_id}', '${run_id}'))

cur.execute('''
    INSERT INTO evidence (id, run_id, step_id, collector, type, name, path, size, hash, hash_algo, metadata, collected_at)
    VALUES (?, ?, 's2', 'proc_linux', 'artifact/process', 'powershell.exe', '/proc/200', 200, 'h2', 'sha256', '{\"pid\": 200, \"ppid\": 100}', '2026')
''', ('${ev2_id}', '${run_id}'))

# Step 2: Insert correlation edge derived from pid_link
cur.execute('''
    INSERT INTO correlations (id, run_id, src_evidence_id, dst_evidence_id, relation, confidence, method, created_at, created_by)
    VALUES ('edge_01', ?, ?, ?, 'spawned', 1.0, 'pid_link', '2026', 'correlation_engine')
''', ('${run_id}', '${ev1_id}', '${ev2_id}'))

conn.commit()
conn.close()
"
assert_exit_code 0 $? "P2.1: Evidence and correlation edges persisted to SQLite"

# Step 3: Query SQLite and construct Cytoscape graph
CYTO_OUT="${TEST_TMPDIR}/cyto_from_sqlite.json"
"${PYTHON}" -c "
import sqlite3, json
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()

cur.execute('SELECT id, name, type FROM evidence WHERE run_id = ?', ('${run_id}',))
nodes = [{'data': {'id': r[0], 'label': r[1], 'type': r[2]}} for r in cur.fetchall()]

cur.execute('SELECT id, src_evidence_id, dst_evidence_id, relation, confidence FROM correlations WHERE run_id = ?', ('${run_id}',))
edges = [{'data': {'id': r[0], 'source': r[1], 'target': r[2], 'relation': r[3], 'confidence': r[4]}} for r in cur.fetchall()]

graph = {'elements': {'nodes': nodes, 'edges': edges}}
with open('${CYTO_OUT}', 'w') as f:
    json.dump(graph, f, indent=2)
conn.close()
"
assert_file_exists "${CYTO_OUT}" "P2.2: Exported Cytoscape JSON from SQLite exists"
assert_valid_json "$(cat "${CYTO_OUT}")" "P2.2: Cytoscape graph is valid JSON"

nodes_len=$("${PYTHON}" -c "import json; print(len(json.load(open('${CYTO_OUT}'))['elements']['nodes']))")
edges_len=$("${PYTHON}" -c "import json; print(len(json.load(open('${CYTO_OUT}'))['elements']['edges']))")
assert_eq "2" "${nodes_len}" "P2.3: Graph correctly contains 2 evidence nodes"
assert_eq "1" "${edges_len}" "P2.3: Graph correctly contains 1 correlation edge"

test_summary_report "Pairwise: Collector -> SQLite -> Graph"
exit $?
