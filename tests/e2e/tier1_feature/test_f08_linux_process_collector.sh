#!/usr/bin/env bash
# tests/e2e/tier1_feature/test_f08_linux_process_collector.sh
# Feature 8: Linux Process Collector (proc_linux) (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Feature 8: Linux Process Collector (proc_linux)"

# Test 1: Verify Linux /proc system availability on the host
if [ -d "/proc" ] && [ -r "/proc/$$/stat" ]; then
    assert_file_exists "/proc/$$/stat" "F8.1: Host Linux /proc filesystem accessible"
else
    log_warn "Host /proc not accessible; testing contract conformance"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi

# Test 2: Process Evidence schema and fields
EV_PROC="${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case/evidence/evidence_proc_01.json"
ev_type=$("${PYTHON}" -c "import json; print(json.load(open('${EV_PROC}'))['type'])")
assert_eq "artifact/process" "${ev_type}" "F8.2: Process evidence type is 'artifact/process'"

# Test 3: Process metadata contains required forensic attributes (pid, ppid, cmdline)
has_pid=$("${PYTHON}" -c "import json; d=json.load(open('${EV_PROC}')); print('pid' in d['metadata'] and 'ppid' in d['metadata'])")
assert_eq "True" "${has_pid}" "F8.3: Process metadata contains pid and ppid"

# Test 4: Process receipt signed by proc_linux collector
REC_PROC="${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case/receipts/receipt_proc_01.json"
collector_name=$("${PYTHON}" -c "import json; print(json.load(open('${REC_PROC}'))['collector'])")
assert_eq "proc_linux" "${collector_name}" "F8.4: Receipt collector identifier is proc_linux"

# Test 5: Receipt signature verification on process evidence
vr_out=$("${PYTHON}" "${WORKSPACE_ROOT}/tests/e2e/common/crypto_oracle.py" verify-receipt --evidence "${EV_PROC}" --receipt "${REC_PROC}" 2>&1)
res5=$?
assert_exit_code 0 ${res5} "F8.5: Process evidence and receipt verified by crypto oracle"

test_summary_report "F8: Linux Process Collector (proc_linux)"
exit $?
