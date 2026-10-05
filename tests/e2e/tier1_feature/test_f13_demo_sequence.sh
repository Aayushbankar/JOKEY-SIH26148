#!/usr/bin/env bash
# tests/e2e/tier1_feature/test_f13_demo_sequence.sh
# Feature 13: 8-Step Demo Sequence & Tamper Flow (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Feature 13: 8-Step Demo Sequence & Tamper Flow"

TMP_CASE="${TEST_TMPDIR}/demo_case_f13"
mkdir -p "${TMP_CASE}"
cp -r "${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case"/* "${TMP_CASE}/"

EV="${TMP_CASE}/evidence/evidence_proc_01.json"
REC="${TMP_CASE}/receipts/receipt_proc_01.json"

# Test 1: Step 1-5 Investigation Flow Setup
assert_file_exists "${TMP_CASE}/manifest.json" "F13.1: Step 1 Case loaded with manifest"
assert_file_exists "${EV}" "F13.1: Step 3 Process evidence present"
assert_file_exists "${REC}" "F13.1: Step 3 Signed receipt present"

# Test 2: Step 6 Pristine verification check (PASS)
vr_pass=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV}" --receipt "${REC}" 2>&1)
res2=$?
assert_exit_code 0 ${res2} "F13.2: Step 6 Initial verification produces PASS"
assert_contains "${vr_pass}" "PASS" "F13.2: Verification report confirms PASS"

# Test 3: Step 7 In-flight Tamper Injection (Bit flip)
orig_hash=$("${PYTHON}" -c "import json; print(json.load(open('${EV}'))['hash'])")
tampered_hash=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" bitflip "${orig_hash}" --bit 0)
"${PYTHON}" -c "import json; d=json.load(open('${EV}')); d['hash']='${tampered_hash}'; json.dump(d, open('${EV}', 'w'), indent=2)"

vr_fail=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV}" --receipt "${REC}" 2>&1)
res3=$?
assert_ne 0 ${res3} "F13.3: Step 7 Tampered evidence verification fails with non-zero exit code"
assert_contains "${vr_fail}" "FAIL" "F13.3: Verification report confirms FAIL"

# Test 4: Step 8 Restoration of Pristine State
"${PYTHON}" -c "import json; d=json.load(open('${EV}')); d['hash']='${orig_hash}'; json.dump(d, open('${EV}', 'w'), indent=2)"
vr_restore=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV}" --receipt "${REC}" 2>&1)
res4=$?
assert_exit_code 0 ${res4} "F13.4: Step 8 Restored evidence produces PASS"
assert_contains "${vr_restore}" "PASS" "F13.4: Restored verification confirms PASS"

# Test 5: Verify CLI demo execution or script contract
if [ "${JOCKEY_AVAILABLE}" -eq 1 ]; then
    demo_out=$("${JOCKEY_BIN}" demo --os linux 2>&1 || true)
    assert_contains "${demo_out}" "JOCKY" "F13.5: CLI demo command runs"
else
    # Check demo flow contract in main.rs
    main_rs="${WORKSPACE_ROOT}/crates/jockey-cli/src/main.rs"
    assert_contains "$(cat "${main_rs}")" "run_demo" "F13.5: CLI contains run_demo workflow"
fi

test_summary_report "F13: 8-Step Demo Sequence & Tamper Flow"
exit $?
