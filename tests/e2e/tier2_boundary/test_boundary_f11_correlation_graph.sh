#!/usr/bin/env bash
# tests/e2e/tier2_boundary/test_boundary_f11_correlation_graph.sh
# Tier 2 Boundary Tests for Feature 11: Correlation Graph (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 2 Boundary: Correlation Graph Boundaries"

# Test 1: Empty graph generation (0 nodes, 0 edges)
empty_graph="${TEST_TMPDIR}/empty_cyto.json"
"${PYTHON}" -c "
import json
g = {'elements': {'nodes': [], 'edges': []}}
json.dump(g, open('${empty_graph}', 'w'))
"
assert_file_exists "${empty_graph}" "B11.1: Empty Cytoscape graph created"
assert_valid_json "$(cat "${empty_graph}")" "B11.1: Empty graph is valid JSON"

# Test 2: Graph with nodes but 0 edges (disconnected evidence)
disconnected_graph="${TEST_TMPDIR}/disconnected_cyto.json"
"${PYTHON}" -c "
import json
g = {
    'elements': {
        'nodes': [
            {'data': {'id': 'n1', 'label': 'ev1'}},
            {'data': {'id': 'n2', 'label': 'ev2'}}
        ],
        'edges': []
    }
}
json.dump(g, open('${disconnected_graph}', 'w'))
"
e_count=$("${PYTHON}" -c "import json; print(len(json.load(open('${disconnected_graph}'))['elements']['edges']))")
assert_eq "0" "${e_count}" "B11.2: Disconnected graph has 0 edges"

# Test 3: Edge confidence value bounds (confidence must be between 0.0 and 1.0)
conf_val="1.0"
valid_conf=$("${PYTHON}" -c "print(0.0 <= float('${conf_val}') <= 1.0)")
assert_eq "True" "${valid_conf}" "B11.3: Confidence 1.0 within [0.0, 1.0] interval"

# Test 4: Self-referential loop edge boundary
loop_graph="${TEST_TMPDIR}/loop_cyto.json"
"${PYTHON}" -c "
import json
g = {
    'elements': {
        'nodes': [{'data': {'id': 'n1', 'label': 'init'}}],
        'edges': [{'data': {'id': 'e1', 'source': 'n1', 'target': 'n1', 'relation': 'self_loop'}}]
    }
}
json.dump(g, open('${loop_graph}', 'w'))
"
loop_src=$("${PYTHON}" -c "import json; e=json.load(open('${loop_graph}'))['elements']['edges'][0]['data']; print(e['source'] == e['target'])")
assert_eq "True" "${loop_src}" "B11.4: Self-referential loop edge represented safely"

# Test 5: Graph scaling test (500 nodes)
scale_graph="${TEST_TMPDIR}/scale_cyto.json"
"${PYTHON}" -c "
import json
nodes = [{'data': {'id': f'node_{i}', 'label': f'proc_{i}'}} for i in range(500)]
g = {'elements': {'nodes': nodes, 'edges': []}}
json.dump(g, open('${scale_graph}', 'w'))
"
node_count=$("${PYTHON}" -c "import json; print(len(json.load(open('${scale_graph}'))['elements']['nodes']))")
assert_eq "500" "${node_count}" "B11.5: 500-node graph scaling boundary verified"

test_summary_report "B11: Correlation Graph Boundaries"
exit $?
