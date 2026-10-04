#!/bin/bash
# JOCKY SIH 26148 — Quick Start Script
# Run this to begin Phase 0: Compile Fix

set -e

REPO_ROOT="/data/data/com.termux/files/home/workspace/projects/JOKEY---SIH26148"
cd "$REPO_ROOT"

echo "=========================================="
echo "JOCKY SIH 26148 — Phase 0: Compile Fix"
echo "=========================================="
echo ""

# 1. Show current status
echo "📋 Current TODO status:"
grep -A 2 "PHASE 0" TODO.md | head -20
echo ""

# 2. Add hex dependency if missing
echo "🔧 Checking workspace dependencies..."
if ! grep -q 'hex = "0.4"' Cargo.toml; then
    echo "Adding hex=0.4 to workspace dependencies..."
    sed -i '/sha2 = "0.10"/a hex = "0.4"' Cargo.toml
    echo "✅ Added hex=0.4"
else
    echo "✅ hex already present"
fi

# 3. Fix clippy.restriction (already done but verify)
echo "🔧 Verifying Cargo.toml fixes..."
grep -n "clippy.restriction" Cargo.toml
grep -n "config = " Cargo.toml
grep -n "figment = " Cargo.toml
grep -n "pest = " Cargo.toml

# 4. Run cargo check to see current errors
echo ""
echo "🔍 Running cargo check to see current errors..."
cargo check --workspace 2>&1 | head -80

echo ""
echo "=========================================="
echo "Next Steps:"
echo "1. Review errors above"
echo "2. Spawn CryptoAgent to fix jockey-evidence (primary blocker)"
echo "3. Spawn LangAgent to verify parser"
echo "4. Spawn CoreAgent to verify core"
echo "5. Spawn DevOpsAgent to fix CI"
echo ""
echo "Reference: MASTER_PROMPT.md for agent prompts"
echo "Tracking: TODO.md for progress"
echo "Contract: AGENT_CONTRACT.md for full spec"
echo "=========================================="