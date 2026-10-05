#!/usr/bin/env bash
# tests/e2e/tier1_feature/test_f04_receipt_sig_tamper.sh
# Feature 4: Receipt Signature Tamper Detection (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Feature 4: Receipt Signature Tamper Detection"

FIXTURE_DIR="${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case"
TMP_CASE="${TEST_TMPDIR}/tamper_case_f4"
mkdir -p "${TMP_CASE}"
cp -r "${FIXTURE_DIR}"/* "${TMP_CASE}/"

EV="${TMP_CASE}/evidence/evidence_proc_01.json"
REC="${TMP_CASE}/receipts/receipt_proc_01.json"

orig_sig=$("${PYTHON}" -c "import json; print(json.load(open('${REC}'))['signature'])")

# Test 1: Invert byte 0 of signature hex
corrupt_sig_byte0=$("${PYTHON}" -c "s = list('${orig_sig}'); s[0] = 'f' if s[0] != 'f' else '0'; print(''.join(s))")
"${PYTHON}" -c "import json; d = json.load(open('${REC}')); d['signature'] = '${corrupt_sig_byte0}'; json.dump(d, open('${REC}', 'w'), indent=2)"

vr_out1=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV}" --receipt "${REC}" 2>&1)
res1=$?
assert_ne 0 ${res1} "F4.1: Corrupting signature byte 0 causes verification rejection"
assert_contains "${vr_out1}" "signature invalid" "F4.1: Rejection message reports signature invalid"

# Test 2: Invert byte 63 (last byte) of signature hex
corrupt_sig_last=$("${PYTHON}" -c "s = list('${orig_sig}'); s[-1] = '0' if s[-1] != '0' else '1'; print(''.join(s))")
"${PYTHON}" -c "import json; d = json.load(open('${REC}')); d['signature'] = '${corrupt_sig_last}'; json.dump(d, open('${REC}', 'w'), indent=2)"
vr_out2=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV}" --receipt "${REC}" 2>&1)
res2=$?
assert_ne 0 ${res2} "F4.2: Corrupting last signature byte causes verification rejection"

# Test 3: Replace signature with 64 bytes of zeros (128 '0' chars)
zeros_sig=$(printf '0%.0s' {1..128})
"${PYTHON}" -c "import json; d = json.load(open('${REC}')); d['signature'] = '${zeros_sig}'; json.dump(d, open('${REC}', 'w'), indent=2)"
vr_out3=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV}" --receipt "${REC}" 2>&1)
res3=$?
assert_ne 0 ${res3} "F4.3: Zeroed signature bytes rejected"

# Test 4: Attacker public key substitution with genuine signature
alt_pk=$(printf 'ee%.0s' {1..32})
"${PYTHON}" -c "import json; d = json.load(open('${REC}')); d['signature'] = '${orig_sig}'; d['public_key'] = '${alt_pk}'; json.dump(d, open('${REC}', 'w'), indent=2)"
vr_out4=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV}" --receipt "${REC}" 2>&1)
res4=$?
assert_ne 0 ${res4} "F4.4: Wrong public key causes signature verification rejection"

# Test 5: Restore pristine receipt public key and signature
orig_pk=$("${PYTHON}" -c "import json; print(json.load(open('${FIXTURE_DIR}/receipts/receipt_proc_01.json'))['public_key'])")
"${PYTHON}" -c "import json; d = json.load(open('${REC}')); d['signature'] = '${orig_sig}'; d['public_key'] = '${orig_pk}'; json.dump(d, open('${REC}', 'w'), indent=2)"
vr_out5=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV}" --receipt "${REC}" 2>&1)
res5=$?
assert_exit_code 0 ${res5} "F4.5: Restoring genuine signature and public key passes verification"

test_summary_report "F4: Receipt Signature Tamper Detection"
exit $?
