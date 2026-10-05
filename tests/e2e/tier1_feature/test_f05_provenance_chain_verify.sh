#!/usr/bin/env bash
# tests/e2e/tier1_feature/test_f05_provenance_chain_verify.sh
# Feature 5: Provenance Chain Link Verification (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Feature 5: Provenance Chain Link Verification"

FIXTURE_CHAIN="${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case/provenance/provenance_chain_01.json"

# Test 1: Verify valid baseline provenance chain
vc_out1=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${FIXTURE_CHAIN}" 2>&1)
res1=$?
assert_exit_code 0 ${res1} "F5.1: Baseline provenance chain verified valid"
assert_contains "${vc_out1}" "PASS" "F5.1: Output status is PASS"

# Test 2: Broken link: mutate prev_provenance_id of step 2
TMP_CHAIN="${TEST_TMPDIR}/broken_chain_f5.json"
"${PYTHON}" -c "
import json
chain = json.load(open('${FIXTURE_CHAIN}'))
chain[1]['prev_provenance_id'] = '01HY_BROKEN_INVALID_PREV_ID'
json.dump(chain, open('${TMP_CHAIN}', 'w'), indent=2)
"
vc_out2=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${TMP_CHAIN}" 2>&1)
res2=$?
assert_ne 0 ${res2} "F5.2: Broken prev_provenance_id link rejected with non-zero exit"
assert_contains "${vc_out2}" "Provenance chain broken" "F5.2: Error message explicitly reports broken chain"

# Test 3: Root provenance record having non-null prev_provenance_id rejected
"${PYTHON}" -c "
import json
chain = json.load(open('${FIXTURE_CHAIN}'))
chain[0]['prev_provenance_id'] = '01HY_NON_NULL_ROOT_PREV_ID'
json.dump(chain, open('${TMP_CHAIN}', 'w'), indent=2)
"
vc_out3=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${TMP_CHAIN}" 2>&1)
res3=$?
assert_ne 0 ${res3} "F5.3: Root provenance with non-null prev_provenance_id rejected"

# Test 4: Extended 3-step valid chain passes
TMP_3STEP="${TEST_TMPDIR}/valid_3step_chain.json"
"${PYTHON}" -c "
import json
chain = json.load(open('${FIXTURE_CHAIN}'))
step3 = {
    'id': '01HY876543210ABCDEF123458C',
    'evidence_id': chain[1]['evidence_id'],
    'receipt_id': chain[1]['receipt_id'],
    'prev_provenance_id': chain[1]['id'],
    'action': 'correlated',
    'actor': 'jockey_correlation',
    'actor_version': '0.1.0',
    'input_hashes': chain[1]['output_hashes'],
    'output_hashes': chain[1]['output_hashes'],
    'parameters': {'rule': 'pid_link'},
    'timestamp': '2026-10-04T12:00:04Z',
    'signature': ''
}
chain.append(step3)
json.dump(chain, open('${TMP_3STEP}', 'w'), indent=2)
"
vc_out4=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${TMP_3STEP}" 2>&1)
res4=$?
assert_exit_code 0 ${res4} "F5.4: Extended 3-step provenance chain verified valid"

# Test 5: Inverted sequence (step 2 placed before step 1) rejected
TMP_INVERT="${TEST_TMPDIR}/inverted_chain.json"
"${PYTHON}" -c "
import json
chain = json.load(open('${FIXTURE_CHAIN}'))
inverted = [chain[1], chain[0]]
json.dump(inverted, open('${TMP_INVERT}', 'w'), indent=2)
"
vc_out5=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${TMP_INVERT}" 2>&1)
res5=$?
assert_ne 0 ${res5} "F5.5: Inverted provenance sequence detected and rejected"

test_summary_report "F5: Provenance Chain Link Verification"
exit $?
