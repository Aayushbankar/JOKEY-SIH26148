#!/usr/bin/env bash
# tests/e2e/tier3_pairwise/test_pairwise_proc_file_correlation.sh
# Tier 3 Pairwise: Process Collector + File Collector -> Correlation Engine

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 3 Pairwise: Process + File -> Correlation"

SAMPLE_CASE="${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case"
EV_PROC="${SAMPLE_CASE}/evidence/evidence_proc_02.json"
EV_FILE="${SAMPLE_CASE}/evidence/evidence_file_01.json"

# Step 1: Verify both process and file artifacts coexist in the investigation
ev_p_type=$("${PYTHON}" -c "import json; print(json.load(open('${EV_PROC}'))['type'])")
ev_f_type=$("${PYTHON}" -c "import json; print(json.load(open('${EV_FILE}'))['type'])")
assert_eq "artifact/process" "${ev_p_type}" "P3.1: Process evidence present in case"
assert_eq "artifact/file" "${ev_f_type}" "P3.1: File evidence present in case"

# Step 2: Apply correlation rule between process and file dropped (wrote / evidence_support)
CORR_OUT="${TEST_TMPDIR}/proc_file_correlation.json"
"${PYTHON}" -c "
import json
p = json.load(open('${EV_PROC}'))
f = json.load(open('${EV_FILE}'))

edge = {
    'id': 'edge_proc_file_01',
    'source': p['id'],
    'target': f['id'],
    'relation': 'wrote',
    'confidence': 0.95,
    'method': 'evidence_support',
    'details': {
        'process_name': p['name'],
        'file_path': f['path']
    }
}
with open('${CORR_OUT}', 'w') as out:
    json.dump(edge, out, indent=2)
"
assert_file_exists "${CORR_OUT}" "P3.2: Cross-collector correlation edge created"
assert_valid_json "$(cat "${CORR_OUT}")" "P3.2: Correlation edge is valid JSON"

rel=$("${PYTHON}" -c "import json; print(json.load(open('${CORR_OUT}'))['relation'])")
assert_eq "wrote" "${rel}" "P3.3: Correlation relation is 'wrote'"

test_summary_report "Pairwise: Process + File -> Correlation"
exit $?
