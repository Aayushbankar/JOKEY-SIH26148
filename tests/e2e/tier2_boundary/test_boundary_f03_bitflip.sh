#!/usr/bin/env bash
# tests/e2e/tier2_boundary/test_boundary_f03_bitflip.sh
# Tier 2 Boundary Tests for Feature 3: Evidence Bit-Flip (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 2 Boundary: Evidence Bit-Flip Boundaries"

FIXTURE_DIR="${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case"
EV="${FIXTURE_DIR}/evidence/evidence_proc_01.json"
REC="${FIXTURE_DIR}/receipts/receipt_proc_01.json"
orig_hash=$("${PYTHON}" -c "import json; print(json.load(open('${EV}'))['hash'])")

TMP_EV="${TEST_TMPDIR}/bound_ev_f3.json"

# Test 1: MSB Bit Flip (Bit 255)
msb_flipped=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" bitflip "${orig_hash}" --bit 255)
"${PYTHON}" -c "import json; d=json.load(open('${EV}')); d['hash']='${msb_flipped}'; json.dump(d, open('${TMP_EV}', 'w'))"
out1=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${TMP_EV}" --receipt "${REC}" 2>&1)
res1=$?
assert_ne 0 ${res1} "B3.1: MSB bit flip (bit 255) causes verification rejection"

# Test 2: LSB Bit Flip (Bit 0)
lsb_flipped=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" bitflip "${orig_hash}" --bit 0)
"${PYTHON}" -c "import json; d=json.load(open('${EV}')); d['hash']='${lsb_flipped}'; json.dump(d, open('${TMP_EV}', 'w'))"
out2=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${TMP_EV}" --receipt "${REC}" 2>&1)
res2=$?
assert_ne 0 ${res2} "B3.2: LSB bit flip (bit 0) causes verification rejection"

# Test 3: Truncated 62-character hash (31 bytes)
truncated_hash="${orig_hash:0:62}"
"${PYTHON}" -c "import json; d=json.load(open('${EV}')); d['hash']='${truncated_hash}'; json.dump(d, open('${TMP_EV}', 'w'))"
out3=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${TMP_EV}" --receipt "${REC}" 2>&1)
res3=$?
assert_ne 0 ${res3} "B3.3: Truncated 62-char hash triggers rejection"

# Test 4: Non-hex invalid characters in hash string
invalid_hex="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
"${PYTHON}" -c "import json; d=json.load(open('${EV}')); d['hash']='${invalid_hex}'; json.dump(d, open('${TMP_EV}', 'w'))"
out4=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${TMP_EV}" --receipt "${REC}" 2>&1)
res4=$?
assert_ne 0 ${res4} "B3.4: Non-hex hash characters trigger rejection"

# Test 5: Uppercase hash string normalization check
upper_hash="${orig_hash^^}"
"${PYTHON}" -c "import json; d=json.load(open('${EV}')); d['hash']='${upper_hash}'; json.dump(d, open('${TMP_EV}', 'w'))"
len5=$("${PYTHON}" -c "import json; print(len(json.load(open('${TMP_EV}'))['hash']))")
assert_eq "64" "${len5}" "B3.5: Uppercase hash preserves 64-char length boundary"

test_summary_report "B3: Evidence Bit-Flip Boundaries"
exit $?
