#!/usr/bin/env bash
# tests/e2e/tier2_boundary/test_boundary_f06_provenance_hash.sh
# Tier 2 Boundary Tests for Feature 6: Provenance Hash (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 2 Boundary: Provenance Output Hash Boundaries"

FIXTURE_CHAIN="${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case/provenance/provenance_chain_01.json"
TMP_CHAIN="${TEST_TMPDIR}/bound_hash_f6.json"

# Test 1: Intermediate step with empty output_hashes array
"${PYTHON}" -c "
import json
chain = json.load(open('${FIXTURE_CHAIN}'))
chain[0]['output_hashes'] = []
chain[1]['input_hashes'] = ['some_hash']
json.dump(chain, open('${TMP_CHAIN}', 'w'))
"
out1=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${TMP_CHAIN}" 2>&1 || true)
res1=$?
assert_ne 0 ${res1} "B6.1: Empty parent output_hashes rejected when child expects input"

# Test 2: Child having more input hashes than parent outputs
"${PYTHON}" -c "
import json
chain = json.load(open('${FIXTURE_CHAIN}'))
chain[1]['input_hashes'].append('extra_unexpected_hash')
json.dump(chain, open('${TMP_CHAIN}', 'w'))
"
out2=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${TMP_CHAIN}" 2>&1 || true)
res2=$?
assert_ne 0 ${res2} "B6.2: Surplus child input hashes rejected"

# Test 3: Child having fewer input hashes than parent outputs
"${PYTHON}" -c "
import json
chain = json.load(open('${FIXTURE_CHAIN}'))
chain[0]['output_hashes'] = ['h1', 'h2']
chain[1]['input_hashes'] = ['h1']
json.dump(chain, open('${TMP_CHAIN}', 'w'))
"
out3=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${TMP_CHAIN}" 2>&1 || true)
res3=$?
assert_ne 0 ${res3} "B6.3: Deficit child input hashes rejected"

# Test 4: Trailing whitespace in hash string
"${PYTHON}" -c "
import json
chain = json.load(open('${FIXTURE_CHAIN}'))
chain[1]['input_hashes'][0] += ' '
json.dump(chain, open('${TMP_CHAIN}', 'w'))
"
out4=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${TMP_CHAIN}" 2>&1 || true)
res4=$?
assert_ne 0 ${res4} "B6.4: Hash with trailing whitespace rejected"

# Test 5: Exact hash equality requirement (not substring match)
"${PYTHON}" -c "
import json
chain = json.load(open('${FIXTURE_CHAIN}'))
h = chain[0]['output_hashes'][0]
chain[1]['input_hashes'][0] = h[:-1]  # Prefix substring
json.dump(chain, open('${TMP_CHAIN}', 'w'))
"
out5=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${TMP_CHAIN}" 2>&1 || true)
res5=$?
assert_ne 0 ${res5} "B6.5: Substring hash prefix rejected"

test_summary_report "B6: Provenance Output Hash Boundaries"
exit $?
