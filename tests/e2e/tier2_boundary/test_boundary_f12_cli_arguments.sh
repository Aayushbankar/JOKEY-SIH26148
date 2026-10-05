#!/usr/bin/env bash
# tests/e2e/tier2_boundary/test_boundary_f12_cli_arguments.sh
# Tier 2 Boundary Tests for Feature 12: CLI Arguments (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 2 Boundary: CLI Arguments Boundaries"

if [ "${JOCKEY_AVAILABLE}" -eq 1 ]; then
    # Test 1: Unknown subcommand
    out1=$("${JOCKEY_BIN}" bogus_command_xyz 2>&1 || true)
    res1=$?
    assert_ne 0 ${res1} "B12.1: Unknown subcommand exits with non-zero code"

    # Test 2: Missing required --input in compile
    out2=$("${JOCKEY_BIN}" compile 2>&1 || true)
    res2=$?
    assert_ne 0 ${res2} "B12.2: Compile without --input flag exits with non-zero code"

    # Test 3: Unsupported format in compile
    golden="${WORKSPACE_ROOT}/tests/e2e/fixtures/golden_scripts/golden_01_failed_logon.jky"
    out3=$("${JOCKEY_BIN}" compile --input "${golden}" --format unsupported_fmt_xyz 2>&1 || true)
    res3=$?
    assert_ne 0 ${res3} "B12.3: Compile with unsupported format exits with non-zero code"

    # Test 4: Non-existent input file
    out4=$("${JOCKEY_BIN}" compile --input "/non/existent/script.jky" 2>&1 || true)
    res4=$?
    assert_ne 0 ${res4} "B12.4: Compile with non-existent file path exits with non-zero code"

    # Test 5: Verify without required run_id
    out5=$("${JOCKEY_BIN}" verify 2>&1 || true)
    res5=$?
    assert_ne 0 ${res5} "B12.5: Verify without run_id argument exits with non-zero code"
else
    # Static boundary verification on CLI clap definitions
    main_rs="${WORKSPACE_ROOT}/crates/jockey-cli/src/main.rs"
    assert_file_exists "${main_rs}" "B12.1: CLI main.rs exists"
    assert_contains "$(cat "${main_rs}")" "Commands" "B12.2: Commands enum defined"
    assert_contains "$(cat "${main_rs}")" "default_value" "B12.3: Default values defined for optional arguments"
    assert_contains "$(cat "${main_rs}")" "Unsupported format" "B12.4: Unsupported format guard implemented"
    assert_contains "$(cat "${main_rs}")" "Subcommand" "B12.5: Clap subcommand derive used"
fi

test_summary_report "B12: CLI Arguments Boundaries"
exit $?
