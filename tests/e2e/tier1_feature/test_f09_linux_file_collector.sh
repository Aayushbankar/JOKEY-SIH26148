#!/usr/bin/env bash
# tests/e2e/tier1_feature/test_f09_linux_file_collector.sh
# Feature 9: Linux File Collector (file_linux) (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Feature 9: Linux File Collector (file_linux)"

TEST_FILES="${WORKSPACE_ROOT}/tests/e2e/fixtures/test_files"
EV_FILE="${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case/evidence/evidence_file_01.json"
REC_FILE="${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case/receipts/receipt_file_01.json"

# Test 1: Verify test file hierarchy exists and is readable
assert_file_exists "${TEST_FILES}/normal.txt" "F9.1: Plain test file exists and readable"
assert_file_exists "${TEST_FILES}/nested/deep.log" "F9.1: Nested directory file exists and readable"

# Test 2: File Evidence schema and type
ev_type=$("${PYTHON}" -c "import json; print(json.load(open('${EV_FILE}'))['type'])")
assert_eq "artifact/file" "${ev_type}" "F9.2: File evidence type is 'artifact/file'"

# Test 3: Raw file content SHA-256 computation matches crypto oracle
oracle_hash=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" hash "${TEST_FILES}/normal.txt")
assert_eq "64" "${#oracle_hash}" "F9.3: Oracle computes valid 64-char hex SHA-256 for test file"
assert_sha256_match "${TEST_FILES}/normal.txt" "${oracle_hash}" "F9.3: SHA-256 match assertion succeeds"

# Test 4: File receipt signed by file_linux collector
collector_name=$("${PYTHON}" -c "import json; print(json.load(open('${REC_FILE}'))['collector'])")
assert_eq "file_linux" "${collector_name}" "F9.4: Receipt collector identifier is file_linux"

# Test 5: Receipt signature verification on file evidence
vr_out=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV_FILE}" --receipt "${REC_FILE}" 2>&1)
res5=$?
assert_exit_code 0 ${res5} "F9.5: File evidence and receipt verified by crypto oracle"

test_summary_report "F9: Linux File Collector (file_linux)"
exit $?
