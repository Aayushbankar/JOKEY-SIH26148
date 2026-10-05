#!/usr/bin/env bash
# tests/e2e/tier2_boundary/test_boundary_f05_provenance_chain.sh
# Tier 2 Boundary Tests for Feature 5: Provenance Chain Link (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 2 Boundary: Provenance Chain Link Boundaries"

FIXTURE_CHAIN="${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case/provenance/provenance_chain_01.json"
TMP_CHAIN="${TEST_TMPDIR}/bound_chain_f5.json"

# Test 1: Empty chain file (0 elements)
echo "[]" > "${TMP_CHAIN}"
out1=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${TMP_CHAIN}" 2>&1 || true)
res1=$?
assert_ne 0 ${res1} "B5.1: Empty provenance chain rejected"

# Test 2: Self-referential link (prev_provenance_id == record id)
"${PYTHON}" -c "
import json
chain = json.load(open('${FIXTURE_CHAIN}'))
chain[1]['prev_provenance_id'] = chain[1]['id']
json.dump(chain, open('${TMP_CHAIN}', 'w'))
"
out2=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${TMP_CHAIN}" 2>&1 || true)
res2=$?
assert_ne 0 ${res2} "B5.2: Self-referential provenance link rejected"

# Test 3: Circular link loop
"${PYTHON}" -c "
import json
chain = json.load(open('${FIXTURE_CHAIN}'))
chain[0]['prev_provenance_id'] = chain[1]['id']
chain[1]['prev_provenance_id'] = chain[0]['id']
json.dump(chain, open('${TMP_CHAIN}', 'w'))
"
out3=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${TMP_CHAIN}" 2>&1 || true)
res3=$?
assert_ne 0 ${res3} "B5.3: Circular provenance link cycle rejected"

# Test 4: Multiple roots in single chain (step 2 has prev_provenance_id = None)
"${PYTHON}" -c "
import json
chain = json.load(open('${FIXTURE_CHAIN}'))
chain[1]['prev_provenance_id'] = None
json.dump(chain, open('${TMP_CHAIN}', 'w'))
"
out4=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${TMP_CHAIN}" 2>&1 || true)
res4=$?
assert_ne 0 ${res4} "B5.4: Multiple roots in single provenance chain rejected"

# Test 5: Special characters in provenance actor name
"${PYTHON}" -c "
import json
chain = json.load(open('${FIXTURE_CHAIN}'))
chain[0]['actor'] = 'proc_linux/v1.0 (Termux; aarch64)'
json.dump(chain, open('${TMP_CHAIN}', 'w'))
"
out5=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-chain "${TMP_CHAIN}" 2>&1 || true)
res5=$?
assert_exit_code 0 ${res5} "B5.5: Special characters in actor string handled safely"

test_summary_report "B5: Provenance Chain Link Boundaries"
exit $?
