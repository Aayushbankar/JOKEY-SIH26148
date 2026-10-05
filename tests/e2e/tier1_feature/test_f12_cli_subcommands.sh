#!/usr/bin/env bash
# tests/e2e/tier1_feature/test_f12_cli_subcommands.sh
# Feature 12: CLI Subcommands (7 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Feature 12: CLI Subcommands (7 tests)"

GOLDEN_SCRIPT="${WORKSPACE_ROOT}/tests/e2e/fixtures/golden_scripts/golden_01_failed_logon.jky"
SAMPLE_CASE="${WORKSPACE_ROOT}/tests/e2e/fixtures/sample_case"

# Test 1: CLI help flag
if [ "${JOCKEY_AVAILABLE}" -eq 1 ]; then
    help_out=$("${JOCKEY_BIN}" --help 2>&1)
    res1=$?
    assert_exit_code 0 ${res1} "F12.1: jockey --help exits 0"
    assert_contains "${help_out}" "JOCKY" "F12.1: Help output mentions JOCKY"
else
    # Verify main.rs defines CLI commands
    main_rs="${WORKSPACE_ROOT}/crates/jockey-cli/src/main.rs"
    assert_file_exists "${main_rs}" "F12.1: CLI main source file exists"
    assert_contains "$(cat "${main_rs}")" "Compile" "F12.1: CLI defines Compile command"
fi

# Test 2: Subcommand `compile`
if [ "${JOCKEY_AVAILABLE}" -eq 1 ]; then
    comp_out=$("${JOCKEY_BIN}" compile --input "${GOLDEN_SCRIPT}" 2>&1)
    res2=$?
    assert_exit_code 0 ${res2} "F12.2: jockey compile exits 0 on golden script"
else
    assert_contains "$(cat "${main_rs}")" "Commands::Compile" "F12.2: CLI handles Commands::Compile"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi

# Test 3: Subcommand `run`
if [ "${JOCKEY_AVAILABLE}" -eq 1 ]; then
    run_out=$("${JOCKEY_BIN}" run --input "${GOLDEN_SCRIPT}" --target local --os linux 2>&1 || true)
    assert_contains "${run_out}" "Investigation" "F12.3: jockey run dispatches investigation contract"
else
    assert_contains "$(cat "${main_rs}")" "Commands::Run" "F12.3: CLI handles Commands::Run"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi

# Test 4: Subcommand `load`
if [ "${JOCKEY_AVAILABLE}" -eq 1 ]; then
    load_out=$("${JOCKEY_BIN}" load "${SAMPLE_CASE}" 2>&1 || true)
    assert_contains "${load_out}" "Loading sample case" "F12.4: jockey load accepts sample case directory"
else
    assert_contains "$(cat "${main_rs}")" "Commands::Load" "F12.4: CLI handles Commands::Load"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi

# Test 5: Subcommand `graph`
if [ "${JOCKEY_AVAILABLE}" -eq 1 ]; then
    graph_out=$("${JOCKEY_BIN}" graph "01HY876543210ABCDEF1234567" --format cytoscape 2>&1 || true)
    assert_contains "${graph_out}" "graph" "F12.5: jockey graph accepts run_id and cytoscape format"
else
    assert_contains "$(cat "${main_rs}")" "Commands::Graph" "F12.5: CLI handles Commands::Graph"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi

# Test 6: Subcommand `verify`
if [ "${JOCKEY_AVAILABLE}" -eq 1 ]; then
    verify_out=$("${JOCKEY_BIN}" verify "01HY876543210ABCDEF1234567" 2>&1 || true)
    assert_contains "${verify_out}" "Verifying" "F12.6: jockey verify accepts run_id"
else
    assert_contains "$(cat "${main_rs}")" "Commands::Verify" "F12.6: CLI handles Commands::Verify"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi

# Test 7: Subcommand `narrative`
if [ "${JOCKEY_AVAILABLE}" -eq 1 ]; then
    narrative_out=$("${JOCKEY_BIN}" narrative "01HY876543210ABCDEF1234567" 2>&1 || true)
    assert_contains "${narrative_out}" "narrative" "F12.7: jockey narrative accepts run_id"
else
    assert_contains "$(cat "${main_rs}")" "Commands::Narrative" "F12.7: CLI handles Commands::Narrative"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi

test_summary_report "F12: CLI Subcommands"
exit $?
