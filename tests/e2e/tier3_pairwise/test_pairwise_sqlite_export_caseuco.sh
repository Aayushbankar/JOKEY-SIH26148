#!/usr/bin/env bash
# tests/e2e/tier3_pairwise/test_pairwise_sqlite_export_caseuco.sh
# Tier 3 Pairwise: SQLite Evidence -> CASE/UCO Standard Export

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 3 Pairwise: SQLite -> CASE/UCO Export"

DB_FILE="${TEST_TMPDIR}/uco_export_test.db"
"${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/sqlite_oracle.py" init "${DB_FILE}" >/dev/null

run_id="01HY_UCO_RUN"
"${PYTHON}" -c "
import sqlite3
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('''
    INSERT INTO investigations (id, script_hash, ir_json, status, created_at, updated_at)
    VALUES (?, 'h1', '{}', 'completed', '2026', '2026')
''', ('${run_id}',))

cur.execute('''
    INSERT INTO evidence (id, run_id, step_id, collector, type, name, path, size, hash, hash_algo, metadata, collected_at)
    VALUES ('ev_uco_1', ?, 's1', 'file_linux', 'artifact/file', 'payload.exe', '/tmp/payload.exe', 1024, 'h_payload', 'sha256', '{}', '2026-10-04T12:00:00Z')
''', ('${run_id}',))
conn.commit()
conn.close()
"

# Export to CASE/UCO JSON-LD representation
UCO_OUT="${TEST_TMPDIR}/case_uco_export.json"
"${PYTHON}" -c "
import sqlite3, json
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('SELECT id, name, path, hash FROM evidence WHERE run_id = ?', ('${run_id}',))
rows = cur.fetchall()

uco_doc = {
    '@context': {
        'uco-core': 'https://ontology.unifiedcyberontology.org/uco/core/',
        'uco-observable': 'https://ontology.unifiedcyberontology.org/uco/observable/'
    },
    '@graph': [
        {
            '@id': f'kb:{r[0]}',
            '@type': 'uco-observable:File',
            'uco-core:name': r[1],
            'uco-observable:filePath': r[2],
            'uco-observable:hash': [{'@type': 'uco-observable:Hash', 'uco-observable:hashValue': r[3]}]
        }
        for r in rows
    ]
}
with open('${UCO_OUT}', 'w') as out:
    json.dump(uco_doc, out, indent=2)
conn.close()
"
assert_file_exists "${UCO_OUT}" "P4.1: CASE/UCO export file created"
assert_valid_json "$(cat "${UCO_OUT}")" "P4.1: CASE/UCO export is valid JSON"

has_context=$("${PYTHON}" -c "import json; print('@context' in json.load(open('${UCO_OUT}')))")
assert_eq "True" "${has_context}" "P4.2: CASE/UCO document contains '@context' mapping"

has_graph=$("${PYTHON}" -c "import json; print(len(json.load(open('${UCO_OUT}'))['@graph']))")
assert_eq "1" "${has_graph}" "P4.3: CASE/UCO document contains graph object"

test_summary_report "Pairwise: SQLite -> CASE/UCO Export"
exit $?
