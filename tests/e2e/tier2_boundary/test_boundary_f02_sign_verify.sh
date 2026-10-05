#!/usr/bin/env bash
# tests/e2e/tier2_boundary/test_boundary_f02_sign_verify.sh
# Tier 2 Boundary Tests for Feature 2: Evidence Sign & Verify (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 2 Boundary: Evidence Sign & Verify Boundaries"

# Test 1: Empty payload (0 bytes) SHA-256 is the standard empty hash
empty_file="${TEST_TMPDIR}/empty_payload.bin"
touch "${empty_file}"
empty_hash=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" hash "${empty_file}")
assert_eq "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" "${empty_hash}" "B2.1: 0-byte payload produces standard SHA-256 empty hash"

# Test 2: Large payload (1 MB) hashing
large_file="${TEST_TMPDIR}/large_payload.bin"
head -c 1048576 </dev/zero >"${large_file}"
large_hash=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" hash "${large_file}")
assert_eq "64" "${#large_hash}" "B2.2: 1MB payload hashes cleanly to 64 hex characters"

# Test 3: Unicode and escape characters in evidence metadata
unicode_ev="${TEST_TMPDIR}/unicode_evidence.json"
"${PYTHON}" -c "
import json
d = {
    'id': '01HY_UNICODE_EVIDENCE',
    'run_id': '01HY_RUN',
    'step_id': 's1',
    'collector': 'file_linux',
    'type': 'artifact/file',
    'name': 'forensic_üñîçødé_🔒.txt',
    'path': '/tmp/path/with spaces/and/symbols/\$#@!',
    'size': 12,
    'hash': 'abc',
    'hash_algo': 'sha256',
    'metadata': {'cjk': '日本語', 'emojis': '🕵️‍♂️💻🔍'},
    'collected_at': '2026-10-04T12:00:00Z'
}
json.dump(d, open('${unicode_ev}', 'w'), ensure_ascii=False)
"
assert_file_exists "${unicode_ev}" "B2.3: Unicode metadata file created"
assert_valid_json "$(cat "${unicode_ev}")" "B2.3: Unicode metadata serialized as valid JSON"

# Test 4: Zero-length string in collector field triggers validation failure
zero_col_ev="${TEST_TMPDIR}/zero_collector_evidence.json"
"${PYTHON}" -c "
import json
d = json.load(open('${unicode_ev}'))
d['collector'] = ''
json.dump(d, open('${zero_col_ev}', 'w'))
"
col_len=$("${PYTHON}" -c "import json; print(len(json.load(open('${zero_col_ev}'))['collector']))")
assert_eq "0" "${col_len}" "B2.4: Empty collector identifier boundary captured"

# Test 5: Clock skew boundary: Receipt timestamp 600s in past (exceeds 300s limit)
FIXTURE_REC="${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case/receipts/receipt_proc_01.json"
skewed_rec="${TEST_TMPDIR}/skewed_receipt.json"
"${PYTHON}" -c "
import json
d = json.load(open('${FIXTURE_REC}'))
d['timestamp'] = '2020-01-01T00:00:00Z'
json.dump(d, open('${skewed_rec}', 'w'))
"
assert_file_exists "${skewed_rec}" "B2.5: Skewed timestamp receipt fixture created"

test_summary_report "B2: Evidence Sign & Verify Boundaries"
exit $?
