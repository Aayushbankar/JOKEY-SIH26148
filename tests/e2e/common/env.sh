#!/usr/bin/env bash
# tests/e2e/common/env.sh
# Environment configuration and detection for JOCKY E2E Test Suite

# Determine absolute path of project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# Detect tools
export PYTHON="${PYTHON:-$(command -v python3 || echo "")}"
export JQ="${JQ:-$(command -v jq || echo "")}"
export CARGO="${CARGO:-$(command -v cargo || echo "")}"
export RUSTC="${RUSTC:-$(command -v rustc || echo "")}"

# Detect JOCKY binary
if [ -n "${JOCKEY_BIN:-}" ] && [ -x "${JOCKEY_BIN}" ]; then
    export JOCKEY_AVAILABLE=1
elif [ -x "${WORKSPACE_ROOT}/target/release/jockey" ]; then
    export JOCKEY_BIN="${WORKSPACE_ROOT}/target/release/jockey"
    export JOCKEY_AVAILABLE=1
elif [ -x "${WORKSPACE_ROOT}/target/debug/jockey" ]; then
    export JOCKEY_BIN="${WORKSPACE_ROOT}/target/debug/jockey"
    export JOCKEY_AVAILABLE=1
else
    export JOCKEY_BIN="${WORKSPACE_ROOT}/target/release/jockey"
    export JOCKEY_AVAILABLE=0
fi

# Isolated temporary workspace for testing
if [ -z "${TEST_TMPDIR:-}" ] || [ ! -d "${TEST_TMPDIR}" ]; then
    export TEST_TMPDIR="$(mktemp -d -t jockey_e2e_XXXXXX)"
fi

cleanup_temp() {
    if [ -d "${TEST_TMPDIR}" ] && [[ "${TEST_TMPDIR}" == *"jockey_e2e_"* ]]; then
        rm -rf "${TEST_TMPDIR}"
    fi
}
trap cleanup_temp EXIT
