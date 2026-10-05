#!/usr/bin/env bash
# tests/e2e/tier1_feature/test_f06_provenance_output_hash.sh
# Feature 6: Provenance Output Hash Verification (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Feature 6: Provenance Output Hash Verification"

FIXTURE_CHAIN="${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case/provenance/provenance_chain_01.json"
TMP_CHAIN="${TEST_TMPDIR}/hash_chain_f6.json"

# Test 1: Verify output_hash match on pristine chain
out_h0=$("${PYTHON}" -c "import json; print(json.load(open('${FIXTURE_CHAIN}'))[0]['output_hashes'][0])")
in_h1=$("${PYTHON}" -c "import json; print(json.load(open('${FIXTURE_CHAIN}'))[1]['input_hashes'][0])")
assert_eq "${out_h0}" "${in_h1}" "F6.1: Step 1 output_hash strictly equals Step 2 input_hash"

# Test 2: Tamper Step 1 output_hash
"${PYTHON}" -c "
import json
chain = json.load(open('${FIXTURE_CHAIN}'))
chain[0]['output_hashes'] = ['0000000000000000000000000000000000000000000000000000000000000000']
json.dump(chain, open('${TMP_CHAIN}', 'w'), indent=2)
"
vc_out2=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${TMP_CHAIN}" 2>&1)
res2=$?
assert_ne 0 ${res2} "F6.2: Tampered parent output_hash rejected"
assert_contains "${vc_out2}" "Provenance hash mismatch" "F6.2: Reports provenance hash mismatch"

# Test 3: Tamper Step 2 input_hash while leaving Step 1 intact
"${PYTHON}" -c "
import json
chain = json.load(open('${FIXTURE_CHAIN}'))
chain[1]['input_hashes'] = ['ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff']
json.dump(chain, open('${TMP_CHAIN}', 'w'), indent=2)
"
vc_out3=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${TMP_CHAIN}" 2>&1)
res3=$?
assert_ne 0 ${res3} "F6.3: Tampered child input_hash rejected"
assert_contains "${vc_out3}" "Provenance hash mismatch" "F6.3: Reports provenance hash mismatch"

# Test 4: Root record with non-empty input_hashes rejected
"${PYTHON}" -c "
import json
chain = json.load(open('${FIXTURE_CHAIN}'))
chain[0]['input_hashes'] = ['1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef']
json.dump(chain, open('${TMP_CHAIN}', 'w'), indent=2)
"
vc_out4=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${TMP_CHAIN}" 2>&1)
res4=$?
assert_ne 0 ${res4} "F6.4: Root record containing input_hashes rejected"

# Test 5: Multi-output hash array ordering and length mismatch detection
"${PYTHON}" -c "
import json
chain = json.load(open('${FIXTURE_CHAIN}'))
chain[0]['output_hashes'] = ['hash_a', 'hash_b']
chain[1]['input_hashes'] = ['hash_b', 'hash_a'] # reversed order
json.dump(chain, open('${TMP_CHAIN}', 'w'), indent=2)
"
vc_out5=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${TMP_CHAIN}" 2>&1)
res5=$?
assert_ne 0 ${res5} "F6.5: Out-of-order multi-hash provenance links rejected"

test_summary_report "F6: Provenance Output Hash Verification"
exit $?
