#!/usr/bin/env bash
# tests/e2e/tier1_feature/test_f07_grammar_golden_scripts.sh
# Feature 7: DSL Grammar Parsing (10 Golden Scripts) (10 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Feature 7: DSL Grammar Parsing (10 Golden Scripts)"

GOLDEN_DIR="${WORKSPACE_ROOT}/tests/e2e/fixtures/golden_scripts"

GOLDEN_SCRIPTS=(
    "golden_01_failed_logon.jky"
    "golden_02_powershell_recon.jky"
    "golden_03_smb_lateral.jky"
    "golden_04_ssh_brute_force.jky"
    "golden_05_web_shell.jky"
    "golden_06_dns_exfiltration.jky"
    "golden_07_scheduled_task.jky"
    "golden_08_wmi_persistence.jky"
    "golden_09_credential_dumping.jky"
    "golden_10_multi_stage_apt.jky"
)

test_num=1
for script in "${GOLDEN_SCRIPTS[@]}"; do
    script_path="${GOLDEN_DIR}/${script}"
    assert_file_exists "${script_path}" "F7.${test_num}: Fixture file ${script} exists"
    
    if [ "${JOCKEY_AVAILABLE}" -eq 1 ]; then
        compile_out=$("${JOCKEY_BIN}" compile --input "${script_path}" --format json 2>&1)
        res=$?
        assert_exit_code 0 ${res} "F7.${test_num}: Compile ${script} succeeds"
        assert_valid_json "${compile_out}" "F7.${test_num}: Compile ${script} output is valid IR JSON"
    else
        # When binary is not yet built, verify script structure & keywords
        content=$(cat "${script_path}")
        assert_contains "${content}" "investigation" "F7.${test_num}: Script contains 'investigation' block"
        assert_contains "${content}" "export" "F7.${test_num}: Script contains 'export' statement"
    fi
    test_num=$((test_num + 1))
done

test_summary_report "F7: DSL Grammar Parsing (10 Golden Scripts)"
exit $?
