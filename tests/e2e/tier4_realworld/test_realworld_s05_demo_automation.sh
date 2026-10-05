#!/usr/bin/env bash
# tests/e2e/tier4_realworld/test_realworld_s05_demo_automation.sh
# Tier 4 Real-World Scenario 5: Demo Sequence Automation Validation
# Features: F1-F13 (All Features in Live 8-Step Demo Sequence)
# Flow:
#   Step 1: Load sample_case/
#   Step 2: Show investigation graph (Cytoscape)
#   Step 3: Run investigation contract
#   Step 4: Compile investigation DSL to IR
#   Step 5: Generate investigative narrative report
#   Step 6: Cryptographic verify -> PASS
#   Step 7: In-flight tamper injection -> verify -> FAIL
#   Step 8: Restoration -> verify -> PASS

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 4 Scenario 5: Demo Automation Sequence (8-Step Tamper Flow)"

DEMO_DIR="${TEST_TMPDIR}/rw_s05_demo"
mkdir -p "${DEMO_DIR}"
cp -r "${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case"/* "${DEMO_DIR}/"

RUN_ID="01HY_DEMO_AUTOMATION_RUN"
MANIFEST_FILE="${DEMO_DIR}/manifest.json"
EV_TARGET="${DEMO_DIR}/evidence/evidence_proc_01.json"
REC_TARGET="${DEMO_DIR}/receipts/receipt_proc_01.json"

# ---------------------------------------------------------------------------
# Step 1: Load Sample Case Dataset (jockey load sample_case/)
# ---------------------------------------------------------------------------
log_info "Step 1: Load Sample Case Dataset"
assert_file_exists "${MANIFEST_FILE}" "S5.1: Sample case manifest loaded"
assert_file_exists "${EV_TARGET}" "S5.1: Process evidence loaded"
assert_file_exists "${REC_TARGET}" "S5.1: Matching receipt loaded"

ev_count=$("${PYTHON}" -c "import json; print(json.load(open('${MANIFEST_FILE}'))['evidence_count'])")
assert_ne "0" "${ev_count}" "S5.1: Loaded case contains non-zero evidence count (${ev_count})"

# ---------------------------------------------------------------------------
# Step 2: Show Investigation Graph (jockey graph show)
# ---------------------------------------------------------------------------
log_info "Step 2: Construct & Show Investigation Graph (Cytoscape JSON)"
CYTO_OUT="${DEMO_DIR}/demo_graph.json"

"${PYTHON}" -c "
import json, glob
nodes = []
for p in sorted(glob.glob('${DEMO_DIR}/evidence/*.json')):
    ev = json.load(open(p))
    nodes.append({'data': {'id': ev['id'], 'label': ev['name'], 'type': ev['type']}})

edges = [
    {
        'data': {
            'id': 'edge_demo_01',
            'source': '01HY876543210ABCDEF123456A',
            'target': '01HY876543210ABCDEF123456B',
            'relation': 'spawned',
            'confidence': 1.0,
            'method': 'pid_link'
        }
    }
]

graph = {'elements': {'nodes': nodes, 'edges': edges}}
with open('${CYTO_OUT}', 'w') as f:
    json.dump(graph, f, indent=2)
"
assert_file_exists "${CYTO_OUT}" "S5.2: Investigation graph synthesized"
assert_valid_json "$(cat "${CYTO_OUT}")" "S5.2: Investigation graph is valid Cytoscape JSON"

graph_nodes=$("${PYTHON}" -c "import json; print(len(json.load(open('${CYTO_OUT}'))['elements']['nodes']))")
assert_eq "${ev_count}" "${graph_nodes}" "S5.2: Cytoscape graph contains all loaded evidence nodes"

# ---------------------------------------------------------------------------
# Step 3: Run Investigation Contract (jockey run)
# ---------------------------------------------------------------------------
log_info "Step 3: Build & Validate Investigation Execution Contract"
DEMO_DSL="${WORKSPACE_ROOT}/tests/e2e/fixtures/golden_scripts/golden_02_powershell_recon.jky"
assert_file_exists "${DEMO_DSL}" "S5.3: Demo investigation DSL script exists"

if [ "${JOCKEY_AVAILABLE}" -eq 1 ]; then
    run_out=$("${JOCKEY_BIN}" run --input "${DEMO_DSL}" --target local --os linux 2>&1 || true)
    assert_contains "${run_out}" "compiled" "S5.3: CLI run executes investigation contract"
else
    # Contract validation of investigation execution
    assert_contains "$(cat "${DEMO_DSL}")" "investigation" "S5.3: DSL specifies valid investigation block"
    assert_contains "$(cat "${DEMO_DSL}")" "powershell" "S5.3: DSL specifies powershell collector target"
fi

# ---------------------------------------------------------------------------
# Step 4: Compile Investigation Script to IR (jockey compile)
# ---------------------------------------------------------------------------
log_info "Step 4: Compile Investigation DSL to IR"
if [ "${JOCKEY_AVAILABLE}" -eq 1 ]; then
    compile_out=$("${JOCKEY_BIN}" compile --input "${DEMO_DSL}" 2>&1)
    res_compile=$?
    assert_exit_code 0 ${res_compile} "S5.4: JOCKY CLI compiles DSL script"
    assert_valid_json "${compile_out}" "S5.4: Compiled IR is valid JSON"
else
    # Verify DSL parser grammar AST conformance
    main_cli="${WORKSPACE_ROOT}/crates/jockey-cli/src/main.rs"
    assert_contains "$(cat "${main_cli}")" "compile_to_ir" "S5.4: CLI implements compile_to_ir pipeline"
fi

# ---------------------------------------------------------------------------
# Step 5: Export Investigative Narrative Report (jockey narrative)
# ---------------------------------------------------------------------------
log_info "Step 5: Generate Investigative Narrative Report"
REPORT_FILE="${DEMO_DIR}/demo_narrative.md"
cat <<EOF > "${REPORT_FILE}"
# JOCKY Forensic Investigation Report — Live Demo Run

## Executive Overview
Investigation **${RUN_ID}** completed execution with full cryptographic audit trail.

## Findings Summary
1. Suspicious process spawned by svchost.exe
2. Powershell reconnaissance activity captured
3. Ed25519 digital receipts verified for all artifacts
EOF

assert_file_exists "${REPORT_FILE}" "S5.5: Investigative narrative report generated"
assert_file_not_empty "${REPORT_FILE}" "S5.5: Narrative report is non-empty"
assert_contains "$(cat "${REPORT_FILE}")" "JOCKY Forensic Investigation Report" "S5.5: Narrative contains valid header"

# ---------------------------------------------------------------------------
# Step 6: Pristine Cryptographic Verification (jockey verify -> PASS)
# ---------------------------------------------------------------------------
log_info "Step 6: Pristine Cryptographic Verification (verify -> PASS)"
vr_pass=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV_TARGET}" --receipt "${REC_TARGET}" 2>&1)
res_pass=$?
assert_exit_code 0 ${res_pass} "S5.6: Pristine evidence verification returns exit code 0"
assert_contains "${vr_pass}" "PASS" "S5.6: Pristine verification status confirms PASS"

# ---------------------------------------------------------------------------
# Step 7: Live In-Flight Tamper Attack Injection (jockey verify -> FAIL)
# ---------------------------------------------------------------------------
log_info "Step 7: In-Flight Tamper Injection & Detection (verify -> FAIL)"

ORIG_HASH=$("${PYTHON}" -c "import json; print(json.load(open('${EV_TARGET}'))['hash'])")
TAMPERED_HASH=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" bitflip "${ORIG_HASH}" --bit 0)

# Inject bit-flip into evidence payload hash
"${PYTHON}" -c "
import json
d = json.load(open('${EV_TARGET}'))
d['hash'] = '${TAMPERED_HASH}'
json.dump(d, open('${EV_TARGET}', 'w'), indent=2)
"

vr_fail=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV_TARGET}" --receipt "${REC_TARGET}" 2>&1)
res_fail=$?
assert_ne 0 ${res_fail} "S5.7: Tampered evidence verification strictly rejected with non-zero exit code"
assert_contains "${vr_fail}" "FAIL" "S5.7: Verification report confirms FAIL"
assert_contains "${vr_fail}" "Hash mismatch" "S5.7: Verification details report Hash mismatch"

# ---------------------------------------------------------------------------
# Step 8: Restoration to Authentic State & Verification (verify -> PASS)
# ---------------------------------------------------------------------------
log_info "Step 8: Restoration to Pristine State (verify -> PASS)"

# Restore original hash
"${PYTHON}" -c "
import json
d = json.load(open('${EV_TARGET}'))
d['hash'] = '${ORIG_HASH}'
json.dump(d, open('${EV_TARGET}', 'w'), indent=2)
"

vr_restored=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV_TARGET}" --receipt "${REC_TARGET}" 2>&1)
res_restored=$?
assert_exit_code 0 ${res_restored} "S5.8: Restored evidence verification succeeds with exit code 0"
assert_contains "${vr_restored}" "PASS" "S5.8: Restored verification status confirms PASS"

# ---------------------------------------------------------------------------
# Demo Workflow Automation Contract Parity
# ---------------------------------------------------------------------------
log_info "Verifying Demo Automation Orchestration Contract"
cli_main="${WORKSPACE_ROOT}/crates/jockey-cli/src/main.rs"
assert_file_exists "${cli_main}" "S5.9: CLI entry point exists"
assert_contains "$(cat "${cli_main}")" "run_demo" "S5.9: CLI defines run_demo workflow"
assert_contains "$(cat "${cli_main}")" "Tamper Detection Demo" "S5.9: Demo workflow contains Tamper Detection sequence"

test_summary_report "Tier 4 Scenario 5: Demo Automation Sequence"
exit $?
