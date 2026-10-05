#!/usr/bin/env bash
# tests/e2e/tier2_boundary/test_boundary_f13_demo_tamper.sh
# Tier 2 Boundary Tests for Feature 13: Demo Tamper (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 2 Boundary: Demo Tamper Flow Boundaries"

TMP_CASE="${TEST_TMPDIR}/bound_tamper_f13"
mkdir -p "${TMP_CASE}"
cp -r "${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case"/* "${TMP_CASE}/"

EV1="${TMP_CASE}/evidence/evidence_proc_01.json"
REC1="${TMP_CASE}/receipts/receipt_proc_01.json"
EV2="${TMP_CASE}/evidence/evidence_proc_02.json"
REC2="${TMP_CASE}/receipts/receipt_proc_02.json"

# Test 1: Tamper multiple evidence objects simultaneously
"${PYTHON}" -c "
import json
d1 = json.load(open('${EV1}'))
d1['hash'] = '0' * 64
json.dump(d1, open('${EV1}', 'w'))

d2 = json.load(open('${EV2}'))
d2['hash'] = '1' * 64
json.dump(d2, open('${EV2}', 'w'))
"
out1=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV1}" --receipt "${REC1}" 2>&1 || true)
res1=$?
assert_ne 0 ${res1} "B13.1: First tampered evidence rejected"

out2=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV2}" --receipt "${REC2}" 2>&1 || true)
res2=$?
assert_ne 0 ${res2} "B13.2: Second simultaneously tampered evidence also rejected"

# Test 3: Tampering receipt payload_hash without modifying evidence
cp -r "${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case"/* "${TMP_CASE}/"
"${PYTHON}" -c "
import json
d = json.load(open('${REC1}'))
d['payload_hash'] = 'f' * 64
json.dump(d, open('${REC1}', 'w'))
"
out3=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV1}" --receipt "${REC1}" 2>&1 || true)
res3=$?
assert_ne 0 ${res3} "B13.3: Modifying receipt payload_hash alone triggers verification rejection"

# Test 4: Missing receipt file boundary
rm -f "${REC1}"
out4=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV1}" --receipt "${REC1}" 2>&1 || true)
res4=$?
assert_ne 0 ${res4} "B13.4: Missing receipt file triggers non-zero error"

# Test 5: Partial restoration with mismatched hash rejected
echo '{"id": "01HY876543210ABCDEF123456A", "hash": "wrong_hash"}' > "${EV1}"
out5=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV1}" --receipt "${REC2}" 2>&1 || true)
res5=$?
assert_ne 0 ${res5} "B13.5: Partial/mismatched restoration rejected"

test_summary_report "B13: Demo Tamper Flow Boundaries"
exit $?
