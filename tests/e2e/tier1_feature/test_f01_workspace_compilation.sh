#!/usr/bin/env bash
# tests/e2e/tier1_feature/test_f01_workspace_compilation.sh
# Feature 1: Workspace Compilation Cleanliness (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Feature 1: Workspace Compilation Cleanliness"

cd "${WORKSPACE_ROOT}"

# Test 1: jockey-core crate compilation
log_info "Testing jockey-core compilation..."
out1=$("${CARGO}" check -p jockey-core 2>&1)
res1=$?
assert_exit_code 0 ${res1} "F1.1: jockey-core compiles cleanly"

# Test 2: jockey-evidence crate compilation
log_info "Testing jockey-evidence compilation..."
out2=$("${CARGO}" check -p jockey-evidence 2>&1)
res2=$?
assert_exit_code 0 ${res2} "F1.2: jockey-evidence compiles cleanly"

# Test 3: jockey-language crate compilation
log_info "Testing jockey-language compilation..."
out3=$("${CARGO}" check -p jockey-language 2>&1)
res3=$?
assert_exit_code 0 ${res3} "F1.3: jockey-language compiles cleanly"

# Test 4: collectors and correlation crates compilation
log_info "Testing jockey-collectors and jockey-correlation compilation..."
out4=$("${CARGO}" check -p jockey-collectors -p jockey-correlation 2>&1)
res4=$?
assert_exit_code 0 ${res4} "F1.4: jockey-collectors and jockey-correlation compile"

# Test 5: Full workspace cargo check
log_info "Testing full workspace compilation..."
out5=$("${CARGO}" check --workspace 2>&1)
res5=$?
assert_exit_code 0 ${res5} "F1.5: cargo check --workspace succeeds with code 0"

test_summary_report "F1: Workspace Compilation Cleanliness"
exit $?
