#!/usr/bin/env bash
# tests/e2e/common/assert.sh
# Standard assertions and test outcome reporting for JOCKY E2E tests

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TEST_FAILURES=()

assert_exit_code() {
    local expected="$1"
    local actual="$2"
    local desc="$3"
    TESTS_RUN=$((TESTS_RUN + 1))

    if [ "${actual}" -eq "${expected}" ]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        log_pass "${desc} (exit code ${actual})"
        return 0
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        local err_msg="${desc} - Expected exit code ${expected}, got ${actual}"
        TEST_FAILURES+=("${err_msg}")
        log_fail "${err_msg}"
        return 1
    fi
}

assert_eq() {
    local expected="$1"
    local actual="$2"
    local desc="$3"
    TESTS_RUN=$((TESTS_RUN + 1))

    if [ "${actual}" == "${expected}" ]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        log_pass "${desc}"
        return 0
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        local err_msg="${desc} - Expected '${expected}', got '${actual}'"
        TEST_FAILURES+=("${err_msg}")
        log_fail "${err_msg}"
        return 1
    fi
}

assert_ne() {
    local unexpected="$1"
    local actual="$2"
    local desc="$3"
    TESTS_RUN=$((TESTS_RUN + 1))

    if [ "${actual}" != "${unexpected}" ]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        log_pass "${desc}"
        return 0
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        local err_msg="${desc} - Expected value NOT equal to '${unexpected}'"
        TEST_FAILURES+=("${err_msg}")
        log_fail "${err_msg}"
        return 1
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local desc="$3"
    TESTS_RUN=$((TESTS_RUN + 1))

    if [[ "${haystack}" == *"${needle}"* ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        log_pass "${desc} (found '${needle}')"
        return 0
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        local err_msg="${desc} - Expected output to contain '${needle}'"
        TEST_FAILURES+=("${err_msg}")
        log_fail "${err_msg}"
        return 1
    fi
}

assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    local desc="$3"
    TESTS_RUN=$((TESTS_RUN + 1))

    if [[ "${haystack}" != *"${needle}"* ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        log_pass "${desc} (correctly absent: '${needle}')"
        return 0
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        local err_msg="${desc} - Expected output NOT to contain '${needle}'"
        TEST_FAILURES+=("${err_msg}")
        log_fail "${err_msg}"
        return 1
    fi
}

assert_file_exists() {
    local file_path="$1"
    local desc="$2"
    TESTS_RUN=$((TESTS_RUN + 1))

    if [ -f "${file_path}" ]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        log_pass "${desc} (file exists: ${file_path})"
        return 0
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        local err_msg="${desc} - File does not exist: ${file_path}"
        TEST_FAILURES+=("${err_msg}")
        log_fail "${err_msg}"
        return 1
    fi
}

assert_file_not_empty() {
    local file_path="$1"
    local desc="$2"
    TESTS_RUN=$((TESTS_RUN + 1))

    if [ -s "${file_path}" ]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        log_pass "${desc} (file not empty: ${file_path})"
        return 0
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        local err_msg="${desc} - File is empty or does not exist: ${file_path}"
        TEST_FAILURES+=("${err_msg}")
        log_fail "${err_msg}"
        return 1
    fi
}

assert_valid_json() {
    local content="$1"
    local desc="$2"
    TESTS_RUN=$((TESTS_RUN + 1))

    if echo "${content}" | "${PYTHON}" -m json.tool >/dev/null 2>&1; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        log_pass "${desc} (valid JSON)"
        return 0
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        local err_msg="${desc} - Content is not valid JSON"
        TEST_FAILURES+=("${err_msg}")
        log_fail "${err_msg}"
        return 1
    fi
}

assert_sha256_match() {
    local file_path="$1"
    local expected_hash="$2"
    local desc="$3"
    TESTS_RUN=$((TESTS_RUN + 1))

    local actual_hash
    actual_hash=$("${PYTHON}" -c "import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], 'rb').read()).hexdigest())" "${file_path}" 2>/dev/null || echo "")

    if [ "${actual_hash}" == "${expected_hash}" ]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        log_pass "${desc} (sha256 matches: ${actual_hash})"
        return 0
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        local err_msg="${desc} - Expected sha256 '${expected_hash}', got '${actual_hash}'"
        TEST_FAILURES+=("${err_msg}")
        log_fail "${err_msg}"
        return 1
    fi
}

test_summary_report() {
    local test_suite_name="$1"
    echo ""
    echo "----------------------------------------------------------------------"
    echo "Suite: ${test_suite_name}"
    echo "Total: ${TESTS_RUN} | Passed: ${TESTS_PASSED} | Failed: ${TESTS_FAILED}"
    if [ ${TESTS_FAILED} -gt 0 ]; then
        echo "Failures:"
        for f in "${TEST_FAILURES[@]}"; do
            echo "  - ${f}"
        done
        echo "----------------------------------------------------------------------"
        return 1
    else
        echo "All assertions passed cleanly."
        echo "----------------------------------------------------------------------"
        return 0
    fi
}
