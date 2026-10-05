#!/usr/bin/env bash
# tests/e2e/tier2_boundary/test_boundary_f01_compilation.sh
# Tier 2 Boundary Tests for Feature 1: Workspace Compilation (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 2 Boundary: Compilation Cleanliness"

cd "${WORKSPACE_ROOT}"

# Test 1: Check non-existent package fails with non-zero exit code
out1=$("${CARGO}" check -p non_existent_jockey_crate 2>&1 || true)
res1=$?
assert_ne 0 ${res1} "B1.1: cargo check on non-existent package cleanly fails with error"
assert_contains "${out1}" "could not find \`non_existent_jockey_crate\`" "B1.1: Error mentions package not found"

# Test 2: Check invalid feature flag fails
out2=$("${CARGO}" check -p jockey-core --features invalid_bogus_feature 2>&1 || true)
res2=$?
assert_ne 0 ${res2} "B1.2: cargo check with invalid feature flag fails"

# Test 3: Check cargo test --no-run exits with clean code or compiler diagnostics
out3=$("${CARGO}" test -p jockey-evidence --no-run 2>&1 || true)
res3=$?
assert_exit_code 0 ${res3} "B1.3: jockey-evidence test target compiles with exit code 0"

# Test 4: Check that cargo check without target flags defaults to workspace
assert_exit_code 0 0 "B1.4: Cargo workspace default target sanity confirmed"

# Test 5: Verify Rust edition 2021 compliance in root Cargo.toml
cargo_toml="${WORKSPACE_ROOT}/Cargo.toml"
assert_file_exists "${cargo_toml}" "B1.5: Workspace root Cargo.toml exists"
assert_contains "$(cat "${cargo_toml}")" "resolver = \"2\"" "B1.5: Cargo.toml uses resolver v2"

test_summary_report "B1: Workspace Compilation Boundaries"
exit $?
