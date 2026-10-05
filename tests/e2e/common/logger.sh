#!/usr/bin/env bash
# tests/e2e/common/logger.sh
# Formatted logging and reporting helper for JOCKY E2E Test Suite

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    COLOR_RESET="\033[0m"
    COLOR_RED="\033[0;31m"
    COLOR_GREEN="\033[0;32m"
    COLOR_YELLOW="\033[0;33m"
    COLOR_BLUE="\033[0;34m"
    COLOR_MAGENTA="\033[0;35m"
    COLOR_CYAN="\033[0;36m"
    COLOR_BOLD="\033[1m"
else
    COLOR_RESET=""
    COLOR_RED=""
    COLOR_GREEN=""
    COLOR_YELLOW=""
    COLOR_BLUE=""
    COLOR_MAGENTA=""
    COLOR_CYAN=""
    COLOR_BOLD=""
fi

log_info() {
    echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*"
}

log_pass() {
    echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} $*"
}

log_fail() {
    echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} $*"
}

log_warn() {
    echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $*"
}

log_header() {
    echo -e "${COLOR_BOLD}${COLOR_CYAN}======================================================================${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_CYAN}  $*${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_CYAN}======================================================================${COLOR_RESET}"
}

log_tier_header() {
    local tier_name="$1"
    local description="$2"
    echo ""
    echo -e "${COLOR_BOLD}${COLOR_MAGENTA}╔════════════════════════════════════════════════════════════════════╗${COLOR_RESET}"
    printf "${COLOR_BOLD}${COLOR_MAGENTA}║  %-66s║${COLOR_RESET}\n" "${tier_name}"
    printf "${COLOR_BOLD}${COLOR_MAGENTA}║  %-66s║${COLOR_RESET}\n" "${description}"
    echo -e "${COLOR_BOLD}${COLOR_MAGENTA}╚════════════════════════════════════════════════════════════════════╝${COLOR_RESET}"
    echo ""
}
