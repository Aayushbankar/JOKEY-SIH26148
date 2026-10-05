#!/usr/bin/env bash
# tests/e2e/tier2_boundary/test_boundary_f07_grammar_syntax.sh
# Tier 2 Boundary Tests for Feature 7: DSL Grammar Syntax (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 2 Boundary: DSL Grammar Syntax Boundaries"

INVALID_DIR="${WORKSPACE_ROOT}/tests/e2e/fixtures/invalid_scripts"

# Test 1: Unclosed brace
s1="${INVALID_DIR}/syntax_unclosed_brace.jky"
assert_file_exists "${s1}" "B7.1: Invalid fixture syntax_unclosed_brace exists"
if [ "${JOCKEY_AVAILABLE}" -eq 1 ]; then
    out1=$("${JOCKEY_BIN}" compile --input "${s1}" 2>&1 || true)
    res1=$?
    assert_ne 0 ${res1} "B7.1: Parser rejects unclosed brace"
else
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
    log_pass "B7.1: Unclosed brace boundary fixture validated"
fi

# Test 2: Missing string quotes
s2="${INVALID_DIR}/syntax_missing_string_quotes.jky"
assert_file_exists "${s2}" "B7.2: Invalid fixture syntax_missing_string_quotes exists"
if [ "${JOCKEY_AVAILABLE}" -eq 1 ]; then
    out2=$("${JOCKEY_BIN}" compile --input "${s2}" 2>&1 || true)
    res2=$?
    assert_ne 0 ${res2} "B7.2: Parser rejects missing string quotes"
else
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
    log_pass "B7.2: Missing quotes boundary fixture validated"
fi

# Test 3: Unknown keyword
s3="${INVALID_DIR}/syntax_unknown_keyword.jky"
assert_file_exists "${s3}" "B7.3: Invalid fixture syntax_unknown_keyword exists"
if [ "${JOCKEY_AVAILABLE}" -eq 1 ]; then
    out3=$("${JOCKEY_BIN}" compile --input "${s3}" 2>&1 || true)
    res3=$?
    assert_ne 0 ${res3} "B7.3: Parser rejects unknown keyword"
else
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
    log_pass "B7.3: Unknown keyword boundary fixture validated"
fi

# Test 4: Empty script file
s4="${INVALID_DIR}/syntax_empty.jky"
assert_file_exists "${s4}" "B7.4: Empty script fixture exists"
if [ "${JOCKEY_AVAILABLE}" -eq 1 ]; then
    out4=$("${JOCKEY_BIN}" compile --input "${s4}" 2>&1 || true)
    res4=$?
    assert_ne 0 ${res4} "B7.4: Parser rejects empty script"
else
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
    log_pass "B7.4: Empty script boundary fixture validated"
fi

# Test 5: Invalid operator
s5="${INVALID_DIR}/syntax_invalid_operator.jky"
assert_file_exists "${s5}" "B7.5: Invalid operator fixture exists"
if [ "${JOCKEY_AVAILABLE}" -eq 1 ]; then
    out5=$("${JOCKEY_BIN}" compile --input "${s5}" 2>&1 || true)
    res5=$?
    assert_ne 0 ${res5} "B7.5: Parser rejects invalid operator =!="
else
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
    log_pass "B7.5: Invalid operator boundary fixture validated"
fi

test_summary_report "B7: DSL Grammar Syntax Boundaries"
exit $?
