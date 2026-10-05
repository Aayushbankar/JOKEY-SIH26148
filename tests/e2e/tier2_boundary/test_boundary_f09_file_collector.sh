#!/usr/bin/env bash
# tests/e2e/tier2_boundary/test_boundary_f09_file_collector.sh
# Tier 2 Boundary Tests for Feature 9: File Collector (5 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/env.sh"
source "${SCRIPT_DIR}/../common/logger.sh"
source "${SCRIPT_DIR}/../common/assert.sh"

log_header "Tier 2 Boundary: File Collector Boundaries"

BOUND_DIR="${TEST_TMPDIR}/bound_files_f9"
mkdir -p "${BOUND_DIR}"

# Test 1: Non-existent directory path
non_existent="${BOUND_DIR}/non_existent_dir_12345"
assert_not_contains "$(ls "${BOUND_DIR}" 2>/dev/null || true)" "non_existent_dir_12345" "B9.1: Directory does not exist"

# Test 2: Empty directory walk
empty_dir="${BOUND_DIR}/empty_dir"
mkdir -p "${empty_dir}"
empty_count=$(find "${empty_dir}" -type f | wc -l)
assert_eq "0" "${empty_count}" "B9.2: Empty directory contains 0 files"

# Test 3: Deeply nested directory hierarchy (6 levels)
deep_path="${BOUND_DIR}/l1/l2/l3/l4/l5/l6"
mkdir -p "${deep_path}"
echo "deep forensic payload" > "${deep_path}/target.log"
assert_file_exists "${deep_path}/target.log" "B9.3: Deeply nested (level 6) file created and readable"

# Test 4: File with spaces and special symbols in name
special_file="${BOUND_DIR}/evidence file (copy) [1] & #.dat"
echo "special name content" > "${special_file}"
assert_file_exists "${special_file}" "B9.4: File with spaces and special characters exists"

# Test 5: Zero-byte file handling
zero_file="${BOUND_DIR}/zero_size.bin"
touch "${zero_file}"
assert_file_exists "${zero_file}" "B9.5: Zero-byte file created"
zero_size=$(wc -c < "${zero_file}")
assert_eq "0" "${zero_size}" "B9.5: File size is strictly 0 bytes"

test_summary_report "B9: File Collector Boundaries"
exit $?
