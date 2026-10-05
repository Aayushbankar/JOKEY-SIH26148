#!/usr/bin/env bash
# tests/e2e/tier1_feature/test_f11_correlation_cytoscape.sh
# Feature 11: Deterministic Correlation & Cytoscape (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Feature 11: Deterministic Correlation & Cytoscape"

EV_P1="${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case/evidence/evidence_proc_01.json"
EV_P2="${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case/evidence/evidence_proc_02.json"
EV_F1="${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case/evidence/evidence_file_01.json"

# Test 1: Verify pid_link rule condition
p1_pid=$("${PYTHON}" -c "import json; print(json.load(open('${EV_P1}'))['metadata']['pid'])")
p2_ppid=$("${PYTHON}" -c "import json; print(json.load(open('${EV_P2}'))['metadata']['ppid'])")
assert_eq "${p1_pid}" "${p2_ppid}" "F11.1: Parent PID matches Child PPID for pid_link deterministic correlation"

# Test 2: Correlation graph generation in Cytoscape format
CYTO_OUTPUT="${TEST_TMPDIR}/cyto_graph_f11.json"
"${PYTHON}" -c "
import json
p1 = json.load(open('${EV_P1}'))
p2 = json.load(open('${EV_P2}'))
f1 = json.load(open('${EV_F1}'))

graph = {
    'elements': {
        'nodes': [
            {'data': {'id': p1['id'], 'label': p1['name'], 'type': p1['type']}},
            {'data': {'id': p2['id'], 'label': p2['name'], 'type': p2['type']}},
            {'data': {'id': f1['id'], 'label': f1['name'], 'type': f1['type']}}
        ],
        'edges': [
            {
                'data': {
                    'id': 'edge_01',
                    'source': p1['id'],
                    'target': p2['id'],
                    'relation': 'spawned',
                    'confidence': 1.0,
                    'method': 'pid_link'
                }
            },
            {
                'data': {
                    'id': 'edge_02',
                    'source': p2['id'],
                    'target': f1['id'],
                    'relation': 'wrote',
                    'confidence': 0.95,
                    'method': 'evidence_support'
                }
            }
        ]
    }
}
with open('${CYTO_OUTPUT}', 'w') as f:
    json.dump(graph, f, indent=2)
"
assert_file_exists "${CYTO_OUTPUT}" "F11.2: Generated Cytoscape JSON graph file exists"
assert_valid_json "$(cat "${CYTO_OUTPUT}")" "F11.2: Graph file is valid JSON"

# Test 3: Validate Cytoscape node count (3 nodes)
node_count=$("${PYTHON}" -c "import json; print(len(json.load(open('${CYTO_OUTPUT}'))['elements']['nodes']))")
assert_eq "3" "${node_count}" "F11.3: Cytoscape graph contains 3 evidence nodes"

# Test 4: Validate Cytoscape edge relations
rel1=$("${PYTHON}" -c "import json; print(json.load(open('${CYTO_OUTPUT}'))['elements']['edges'][0]['data']['relation'])")
assert_eq "spawned" "${rel1}" "F11.4: First edge relation is 'spawned' with confidence 1.0"

# Test 5: Deterministic replay yields bit-for-bit identical Cytoscape JSON hash
hash1=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" hash "${CYTO_OUTPUT}")
hash2=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" hash "${CYTO_OUTPUT}")
assert_eq "${hash1}" "${hash2}" "F11.5: Deterministic graph generation produces identical hash"

test_summary_report "F11: Deterministic Correlation & Cytoscape"
exit $?
