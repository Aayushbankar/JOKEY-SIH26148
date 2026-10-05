#!/usr/bin/env bash
# tests/e2e/tier1_feature/test_f10_sqlite_persistence.sh
# Feature 10: SQLite Relational Persistence (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Feature 10: SQLite Relational Persistence"

DB_FILE="${TEST_TMPDIR}/jockey_f10_test.db"

# Test 1: Initialize database schema per §17.1
init_out=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/sqlite_oracle.py" init "${DB_FILE}" 2>&1)
res1=$?
assert_exit_code 0 ${res1} "F10.1: Initialize SQLite schema exits with code 0"

# Test 2: Validate 6 tables and 5 indexes existence
val_out=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/sqlite_oracle.py" validate "${DB_FILE}" 2>&1)
res2=$?
assert_exit_code 0 ${res2} "F10.2: SQLite schema validation succeeds"
assert_contains "${val_out}" "6 tables, 5 indexes" "F10.2: All 6 tables and 5 indexes verified"

# Test 3: Insert investigation record
inv_id="01HY876543210ABCDEF1234567"
"${PYTHON}" -c "
import sqlite3
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('''
    INSERT INTO investigations (id, script_hash, ir_json, contract_json, status, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
''', ('${inv_id}', 'hash123', '{}', '{}', 'completed', '2026-10-04T12:00:00Z', '2026-10-04T12:00:00Z'))
conn.commit()
conn.close()
"
assert_exit_code 0 $? "F10.3: Insert investigation record"

# Test 4: Insert evidence record referencing investigation (FK check)
ev_id="01HY876543210ABCDEF123456A"
"${PYTHON}" -c "
import sqlite3
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('PRAGMA foreign_keys = ON;')
cur.execute('''
    INSERT INTO evidence (id, run_id, step_id, collector, type, name, path, size, hash, hash_algo, metadata, collected_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
''', ('${ev_id}', '${inv_id}', 's1', 'proc_linux', 'artifact/process', 'svchost', '/proc/1024', 100, 'hash_abc', 'sha256', '{}', '2026-10-04T12:00:00Z'))
conn.commit()
conn.close()
"
assert_exit_code 0 $? "F10.4: Insert evidence record with foreign key validation"

# Test 5: Query evidence by run_id
count=$("${PYTHON}" -c "
import sqlite3
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('SELECT COUNT(*) FROM evidence WHERE run_id = ?', ('${inv_id}',))
print(cur.fetchone()[0])
conn.close()
")
assert_eq "1" "${count}" "F10.5: Query evidence by run_id returned 1 record"

test_summary_report "F10: SQLite Relational Persistence"
exit $?
