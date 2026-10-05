#!/usr/bin/env bash
# tests/e2e/tier1_feature/test_f03_evidence_bitflip_tamper.sh
# Feature 3: Evidence Bit-Flip Tamper Detection (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Feature 3: Evidence Bit-Flip Tamper Detection"

FIXTURE_DIR="${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case"
TMP_CASE="${TEST_TMPDIR}/tamper_case_f3"
mkdir -p "${TMP_CASE}"
cp -r "${FIXTURE_DIR}"/* "${TMP_CASE}/"

EV="${TMP_CASE}/evidence/evidence_proc_01.json"
REC="${TMP_CASE}/receipts/receipt_proc_01.json"

# Test 1: Bit flip in evidence.hash
orig_hash=$("${PYTHON}" -c "import json; print(json.load(open('${EV}'))['hash'])")
flipped_hash=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" bitflip "${orig_hash}" --bit 0)

# Modify EV in place with flipped hash
"${PYTHON}" -c "import json; d = json.load(open('${EV}')); d['hash'] = '${flipped_hash}'; json.dump(d, open('${EV}', 'w'), indent=2)"

vr_out=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV}" --receipt "${REC}" 2>&1)
res1=$?

assert_ne 0 ${res1} "F3.1: Verification exits with non-zero error code upon bit flip"
assert_contains "${vr_out}" "Hash mismatch" "F3.1: Error message explicitly reports Hash mismatch"

# Test 2: Verify bitflip detection with a different bit position (bit 127)
flipped_hash_mid=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" bitflip "${orig_hash}" --bit 127)
"${PYTHON}" -c "import json; d = json.load(open('${EV}')); d['hash'] = '${flipped_hash_mid}'; json.dump(d, open('${EV}', 'w'), indent=2)"
vr_out_mid=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV}" --receipt "${REC}" 2>&1)
res2=$?
assert_ne 0 ${res2} "F3.2: Bit flip at bit 127 also triggers verification rejection"

# Test 3: Bit flip in receipt payload_hash while keeping evidence hash intact
# Reset evidence hash
"${PYTHON}" -c "import json; d = json.load(open('${EV}')); d['hash'] = '${orig_hash}'; json.dump(d, open('${EV}', 'w'), indent=2)"
# Flip receipt payload_hash
"${PYTHON}" -c "import json; d = json.load(open('${REC}')); d['payload_hash'] = '${flipped_hash}'; json.dump(d, open('${REC}', 'w'), indent=2)"
vr_out_rec=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV}" --receipt "${REC}" 2>&1)
res3=$?
assert_ne 0 ${res3} "F3.3: Bit flip in receipt payload_hash triggers verification rejection"

# Test 4: Verification output contains FAIL
assert_contains "${vr_out_rec}" "FAIL" "F3.4: Verification outcome contains FAIL"

# Test 5: Reverting bit flip restores PASS
"${PYTHON}" -c "import json; d = json.load(open('${REC}')); d['payload_hash'] = '${orig_hash}'; json.dump(d, open('${REC}', 'w'), indent=2)"
vr_restore=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV}" --receipt "${REC}" 2>&1)
res5=$?
assert_exit_code 0 ${res5} "F3.5: Restoring genuine hash returns PASS"

test_summary_report "F3: Evidence Bit-Flip Tamper Detection"
exit $?
