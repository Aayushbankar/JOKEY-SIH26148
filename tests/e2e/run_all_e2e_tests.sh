#!/usr/bin/env bash
# tests/e2e/run_all_e2e_tests.sh
# Master E2E Test Suite Runner for JOCKY Evidence-Contract Forensics Platform
# Orchestrates execution across Tiers 1-4 and reports detailed summary metrics.

set -u

MASTER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WORKSPACE_ROOT="$(cd "${MASTER_DIR}/../.." && pwd)"

source "${MASTER_DIR}/common/env.sh"
source "${MASTER_DIR}/common/logger.sh"

# Default settings
SELECTED_TIERS="1,2,3,4"
FAIL_FAST=0
VERBOSE=0

print_usage() {
    cat <<EOF
JOCKY E2E Master Test Runner
Usage: $(basename "$0") [OPTIONS]

Options:
  -t, --tier <TIER>     Run specific tier(s): 1, 2, 3, 4, or comma-separated list (e.g. "1,4", "all")
                        Default: 1,2,3,4
  -f, --fail-fast       Abort immediately on first failing test suite
  -v, --verbose         Display verbatim test output for passing tests
  -h, --help            Show this help message and exit

Tiers:
  Tier 1: Feature Functionality Verification (13 tests)
  Tier 2: Boundary & Negative Tamper Conditions (13 tests)
  Tier 3: Pairwise Cross-Feature Interactions (4 tests)
  Tier 4: Real-World Forensic Lifecycles & Scenarios (5 tests)
EOF
}

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--tier)
            SELECTED_TIERS="$2"
            shift 2
            ;;
        -f|--fail-fast)
            FAIL_FAST=1
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        tier1|1)
            SELECTED_TIERS="1"
            shift
            ;;
        tier2|2)
            SELECTED_TIERS="2"
            shift
            ;;
        tier3|3)
            SELECTED_TIERS="3"
            shift
            ;;
        tier4|4)
            SELECTED_TIERS="4"
            shift
            ;;
        all)
            SELECTED_TIERS="1,2,3,4"
            shift
            ;;
        *)
            echo "Unknown option: $1" >&2
            print_usage
            exit 2
            ;;
    esac
done

if [ "${SELECTED_TIERS}" == "all" ]; then
    SELECTED_TIERS="1,2,3,4"
fi

# Metrics Tracking
TOTAL_SUITES=0
PASSED_SUITES=0
FAILED_SUITES=0

TIER1_RUN=0; TIER1_PASS=0; TIER1_FAIL=0
TIER2_RUN=0; TIER2_PASS=0; TIER2_FAIL=0
TIER3_RUN=0; TIER3_PASS=0; TIER3_FAIL=0
TIER4_RUN=0; TIER4_PASS=0; TIER4_FAIL=0

FAILED_TEST_NAMES=()

run_tier() {
    local tier_num="$1"
    local tier_dir="$2"
    local tier_title="$3"

    log_tier_header "TIER ${tier_num}: ${tier_title}" "Path: tests/e2e/${tier_dir}"

    local test_scripts=($(find "${MASTER_DIR}/${tier_dir}" -maxdepth 1 -type f -name "*.sh" | sort))

    if [ ${#test_scripts[@]} -eq 0 ]; then
        log_warn "No test scripts found in ${tier_dir}"
        return 0
    fi

    for test_script in "${test_scripts[@]}"; do
        local test_basename
        test_basename=$(basename "${test_script}")
        TOTAL_SUITES=$((TOTAL_SUITES + 1))

        case "${tier_num}" in
            1) TIER1_RUN=$((TIER1_RUN + 1)) ;;
            2) TIER2_RUN=$((TIER2_RUN + 1)) ;;
            3) TIER3_RUN=$((TIER3_RUN + 1)) ;;
            4) TIER4_RUN=$((TIER4_RUN + 1)) ;;
        esac

        local tmp_log
        tmp_log=$(mktemp -t jockey_test_XXXXXX.log)

        # Run test script with fresh isolated temporary environment
        env -u TEST_TMPDIR bash "${test_script}" > "${tmp_log}" 2>&1
        local exit_code=$?

        if [ ${exit_code} -eq 0 ]; then
            PASSED_SUITES=$((PASSED_SUITES + 1))
            case "${tier_num}" in
                1) TIER1_PASS=$((TIER1_PASS + 1)) ;;
                2) TIER2_PASS=$((TIER2_PASS + 1)) ;;
                3) TIER3_PASS=$((TIER3_PASS + 1)) ;;
                4) TIER4_PASS=$((TIER4_PASS + 1)) ;;
            esac
            log_pass "[Tier ${tier_num}] ${test_basename}"
            if [ ${VERBOSE} -eq 1 ]; then
                cat "${tmp_log}"
            fi
        else
            FAILED_SUITES=$((FAILED_SUITES + 1))
            case "${tier_num}" in
                1) TIER1_FAIL=$((TIER1_FAIL + 1)) ;;
                2) TIER2_FAIL=$((TIER2_FAIL + 1)) ;;
                3) TIER3_FAIL=$((TIER3_FAIL + 1)) ;;
                4) TIER4_FAIL=$((TIER4_FAIL + 1)) ;;
            esac
            FAILED_TEST_NAMES+=("Tier ${tier_num}: ${test_basename}")
            log_fail "[Tier ${tier_num}] ${test_basename} (Exit code: ${exit_code})"
            echo "--- Test Output (${test_basename}) ---"
            cat "${tmp_log}"
            echo "---------------------------------------"

            if [ ${FAIL_FAST} -eq 1 ]; then
                rm -f "${tmp_log}"
                echo ""
                log_fail "Fail-fast enabled: Aborting test run after failure in ${test_basename}"
                return 1
            fi
        fi

        rm -f "${tmp_log}"
    done

    return 0
}

START_TIME=$(date +%s)

echo ""
echo -e "${COLOR_BOLD}${COLOR_CYAN}╔══════════════════════════════════════════════════════════════════════════╗${COLOR_RESET}"
echo -e "${COLOR_BOLD}${COLOR_CYAN}║     JOCKY Evidence-Contract Forensics Platform — E2E Master Runner       ║${COLOR_RESET}"
echo -e "${COLOR_BOLD}${COLOR_CYAN}╚══════════════════════════════════════════════════════════════════════════╝${COLOR_RESET}"
echo -e "  Root: ${WORKSPACE_ROOT}"
echo -e "  Date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo -e "  Selected Tiers: ${SELECTED_TIERS}"
echo ""

# Execute selected tiers
if [[ ",${SELECTED_TIERS}," == *",1,"* ]]; then
    run_tier 1 "tier1_feature" "Feature Unit-Integration Tests (F1-F13)" || { [ ${FAIL_FAST} -eq 1 ] && print_summary && exit 1; }
fi

if [[ ",${SELECTED_TIERS}," == *",2,"* ]]; then
    run_tier 2 "tier2_boundary" "Boundary & Tamper Detection Tests (F1-F13)" || { [ ${FAIL_FAST} -eq 1 ] && print_summary && exit 1; }
fi

if [[ ",${SELECTED_TIERS}," == *",3,"* ]]; then
    run_tier 3 "tier3_pairwise" "Pairwise Combinatorial Integration Tests" || { [ ${FAIL_FAST} -eq 1 ] && print_summary && exit 1; }
fi

if [[ ",${SELECTED_TIERS}," == *",4,"* ]]; then
    run_tier 4 "tier4_realworld" "Real-World Multi-Step Forensics Lifecycles" || { [ ${FAIL_FAST} -eq 1 ] && print_summary && exit 1; }
fi

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# ---------------------------------------------------------------------------
# Summary Reporting Table
# ---------------------------------------------------------------------------
print_summary() {
    echo ""
    echo -e "${COLOR_BOLD}======================================================================${COLOR_RESET}"
    echo -e "${COLOR_BOLD}                     E2E TEST EXECUTION SUMMARY                      ${COLOR_RESET}"
    echo -e "${COLOR_BOLD}======================================================================${COLOR_RESET}"
    printf "%-30s | %-8s | %-8s | %-8s | %-8s\n" "Tier / Category" "Suites" "Passed" "Failed" "Rate"
    echo "-------------------------------+----------+----------+----------+---------"

    if [ ${TIER1_RUN} -gt 0 ]; then
        local rate1=$((TIER1_PASS * 100 / TIER1_RUN))
        printf "%-30s | %-8d | %-8d | %-8d | %d%%\n" "Tier 1: Feature Tests" "${TIER1_RUN}" "${TIER1_PASS}" "${TIER1_FAIL}" "${rate1}"
    fi

    if [ ${TIER2_RUN} -gt 0 ]; then
        local rate2=$((TIER2_PASS * 100 / TIER2_RUN))
        printf "%-30s | %-8d | %-8d | %-8d | %d%%\n" "Tier 2: Boundary Tests" "${TIER2_RUN}" "${TIER2_PASS}" "${TIER2_FAIL}" "${rate2}"
    fi

    if [ ${TIER3_RUN} -gt 0 ]; then
        local rate3=$((TIER3_PASS * 100 / TIER3_RUN))
        printf "%-30s | %-8d | %-8d | %-8d | %d%%\n" "Tier 3: Pairwise Tests" "${TIER3_RUN}" "${TIER3_PASS}" "${TIER3_FAIL}" "${rate3}"
    fi

    if [ ${TIER4_RUN} -gt 0 ]; then
        local rate4=$((TIER4_PASS * 100 / TIER4_RUN))
        printf "%-30s | %-8d | %-8d | %-8d | %d%%\n" "Tier 4: Real-World Scenarios" "${TIER4_RUN}" "${TIER4_PASS}" "${TIER4_FAIL}" "${rate4}"
    fi

    echo "-------------------------------+----------+----------+----------+---------"
    local total_rate=0
    if [ ${TOTAL_SUITES} -gt 0 ]; then
        total_rate=$((PASSED_SUITES * 100 / TOTAL_SUITES))
    fi
    printf "${COLOR_BOLD}%-30s | %-8d | %-8d | %-8d | %d%%${COLOR_RESET}\n" "TOTAL" "${TOTAL_SUITES}" "${PASSED_SUITES}" "${FAILED_SUITES}" "${total_rate}"
    echo -e "${COLOR_BOLD}======================================================================${COLOR_RESET}"
    echo "Duration: ${DURATION}s"

    if [ ${FAILED_SUITES} -gt 0 ]; then
        echo ""
        log_fail "Failed Suites (${FAILED_SUITES}):"
        for failed_name in "${FAILED_TEST_NAMES[@]}"; do
            echo -e "  ${COLOR_RED}✗${COLOR_RESET} ${failed_name}"
        done
        echo ""
        return 1
    else
        echo ""
        log_pass "ALL ${PASSED_SUITES} TEST SUITES PASSED CLEANLY!"
        echo ""
        return 0
    fi
}

print_summary
final_exit=$?
exit ${final_exit}
