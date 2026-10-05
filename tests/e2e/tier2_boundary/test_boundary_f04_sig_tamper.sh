#!/usr/bin/env bash
# tests/e2e/tier2_boundary/test_boundary_f04_sig_tamper.sh
# Tier 2 Boundary Tests for Feature 4: Receipt Signature Tamper (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 2 Boundary: Receipt Signature Tamper Boundaries"

FIXTURE_DIR="${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case"
EV="${FIXTURE_DIR}/evidence/evidence_proc_01.json"
REC="${FIXTURE_DIR}/receipts/receipt_proc_01.json"

TMP_REC="${TEST_TMPDIR}/bound_rec_f4.json"

# Test 1: Signature too short (126 hex chars instead of 128)
short_sig=$(printf 'aa%.0s' {1..63})
"${PYTHON}" -c "import json; d=json.load(open('${REC}')); d['signature']='${short_sig}'; json.dump(d, open('${TMP_REC}', 'w'))"
out1=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV}" --receipt "${TMP_REC}" 2>&1 || true)
res1=$?
assert_ne 0 ${res1} "B4.1: Short 63-byte signature rejected"

# Test 2: Signature too long (130 hex chars)
long_sig=$(printf 'bb%.0s' {1..65})
"${PYTHON}" -c "import json; d=json.load(open('${REC}')); d['signature']='${long_sig}'; json.dump(d, open('${TMP_REC}', 'w'))"
out2=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV}" --receipt "${TMP_REC}" 2>&1 || true)
res2=$?
assert_ne 0 ${res2} "B4.2: Long 65-byte signature rejected"

# Test 3: Non-hex characters in signature
non_hex_sig="xx"$(printf '00%.0s' {1..63})
"${PYTHON}" -c "import json; d=json.load(open('${REC}')); d['signature']='${non_hex_sig}'; json.dump(d, open('${TMP_REC}', 'w'))"
out3=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV}" --receipt "${TMP_REC}" 2>&1 || true)
res3=$?
assert_ne 0 ${res3} "B4.3: Non-hex signature rejected"

# Test 4: All 0xFF signature bytes (invalid Ed25519 point/scalar)
all_ff_sig=$(printf 'ff%.0s' {1..64})
"${PYTHON}" -c "import json; d=json.load(open('${REC}')); d['signature']='${all_ff_sig}'; json.dump(d, open('${TMP_REC}', 'w'))"
out4=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV}" --receipt "${TMP_REC}" 2>&1 || true)
res4=$?
assert_ne 0 ${res4} "B4.4: All-0xFF signature rejected"

# Test 5: Empty signature string
"${PYTHON}" -c "import json; d=json.load(open('${REC}')); d['signature']=''; json.dump(d, open('${TMP_REC}', 'w'))"
out5=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV}" --receipt "${TMP_REC}" 2>&1 || true)
res5=$?
assert_ne 0 ${res5} "B4.5: Empty signature string rejected"

test_summary_report "B4: Receipt Signature Tamper Boundaries"
exit $?
