#!/usr/bin/env bash
# tests/e2e/tier2_boundary/test_boundary_f10_sqlite_storage.sh
# Tier 2 Boundary Tests for Feature 10: SQLite Storage (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 2 Boundary: SQLite Storage Boundaries"

DB_FILE="${TEST_TMPDIR}/bound_db_f10.db"
"${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/sqlite_oracle.py" init "${DB_FILE}" >/dev/null

# Test 1: Foreign key constraint violation
fk_err=$("${PYTHON}" -c "
import sqlite3
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('PRAGMA foreign_keys = ON;')
try:
    cur.execute('''
        INSERT INTO evidence (id, run_id, step_id, collector, type, name, path, size, hash, hash_algo, metadata, collected_at)
        VALUES ('ev_orphan', 'non_existent_run', 's1', 'c1', 'type', 'name', 'path', 1, 'h', 'sha256', '{}', '2026')
    ''')
    conn.commit()
    print('SUCCESS')
except sqlite3.IntegrityError as e:
    print('INTEGRITY_ERROR')
conn.close()
")
assert_eq "INTEGRITY_ERROR" "${fk_err}" "B10.1: Foreign key violation strictly rejected with IntegrityError"

# Test 2: Primary key uniqueness constraint violation
pk_err=$("${PYTHON}" -c "
import sqlite3
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('''
    INSERT INTO investigations (id, script_hash, ir_json, contract_json, status, created_at, updated_at)
    VALUES ('duplicate_pk', 'h1', '{}', '{}', 'pending', '2026', '2026')
''')
conn.commit()
try:
    cur.execute('''
        INSERT INTO investigations (id, script_hash, ir_json, contract_json, status, created_at, updated_at)
        VALUES ('duplicate_pk', 'h2', '{}', '{}', 'pending', '2026', '2026')
    ''')
    conn.commit()
    print('SUCCESS')
except sqlite3.IntegrityError:
    print('DUPLICATE_PK_ERROR')
conn.close()
")
assert_eq "DUPLICATE_PK_ERROR" "${pk_err}" "B10.2: Duplicate primary key rejected with IntegrityError"

# Test 3: Query non-existent run_id returns 0 rows cleanly
zero_rows=$("${PYTHON}" -c "
import sqlite3
conn = sqlite3.connect('${DB_FILE}')
cur = conn.cursor()
cur.execute('SELECT COUNT(*) FROM evidence WHERE run_id = ?', ('non_existent_run_999',))
print(cur.fetchone()[0])
conn.close()
")
assert_eq "0" "${zero_rows}" "B10.3: Query on non-existent run_id cleanly returns 0 rows"

# Test 4: Schema initialization idempotency
init_again=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/sqlite_oracle.py" init "${DB_FILE}" 2>&1)
res4=$?
assert_exit_code 0 ${res4} "B10.4: Re-running schema init on existing database succeeds idempotently"

# Test 5: Corrupted SQLite database detection
CORRUPT_DB="${TEST_TMPDIR}/corrupt.db"
echo "NOT A SQLITE DATABASE HEADER" > "${CORRUPT_DB}"
corrupt_check=$("${PYTHON}" -c "
import sqlite3
try:
    conn = sqlite3.connect('${CORRUPT_DB}')
    conn.execute('SELECT * FROM sqlite_master;')
    print('SUCCESS')
except sqlite3.DatabaseError:
    print('DATABASE_CORRUPT')
" 2>/dev/null || echo "DATABASE_CORRUPT")
assert_eq "DATABASE_CORRUPT" "${corrupt_check}" "B10.5: Corrupted database file detected cleanly"

test_summary_report "B10: SQLite Storage Boundaries"
exit $?
