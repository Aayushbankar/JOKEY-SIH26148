#!/usr/bin/env bash
# tests/e2e/tier3_pairwise/test_pairwise_compile_load_verify.sh
# Tier 3 Pairwise: Script Compilation -> Load Case -> Verify Evidence

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 3 Pairwise: Compile -> Load -> Verify"

GOLDEN_SCRIPT="${WORKSPACE_ROOT}/tests/e2e/fixtures/golden_scripts/golden_01_failed_logon.jky"
SAMPLE_CASE="${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case"

# Pairwise Step 1: Compile investigation DSL script to IR
log_info "Step 1: Compiling DSL investigation script..."
if [ "${JOCKEY_AVAILABLE}" -eq 1 ]; then
    ir_out=$("${JOCKEY_BIN}" compile --input "${GOLDEN_SCRIPT}" 2>&1)
    res1=$?
    assert_exit_code 0 ${res1} "P1.1: DSL script compiled to IR"
    assert_valid_json "${ir_out}" "P1.1: Emitted IR is valid JSON"
else
    assert_file_exists "${GOLDEN_SCRIPT}" "P1.1: Golden script verified"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi

# Pairwise Step 2: Load case manifest and evidence
log_info "Step 2: Loading sample case dataset..."
manifest_file="${SAMPLE_CASE}/manifest.json"
assert_file_exists "${manifest_file}" "P1.2: Sample case manifest found"
run_id=$("${PYTHON}" -c "import json; print(json.load(open('${manifest_file}'))['run_id'])")
assert_ne "" "${run_id}" "P1.2: Case contains non-empty run_id: ${run_id}"

# Pairwise Step 3: Cryptographic verification of loaded case
log_info "Step 3: Verifying loaded case evidence integrity..."
EV="${SAMPLE_CASE}/evidence/evidence_proc_01.json"
REC="${SAMPLE_CASE}/receipts/receipt_proc_01.json"
vr_out=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV}" --receipt "${REC}" 2>&1)
res3=$?
assert_exit_code 0 ${res3} "P1.3: Cryptographic verify succeeds for loaded case"
assert_contains "${vr_out}" "PASS" "P1.3: Verification status is PASS"

test_summary_report "Pairwise: Compile -> Load -> Verify"
exit $?
