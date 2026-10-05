#!/bin/bash
# JOCKY Demo Automation Script
# Runs the complete Phase 3A demo workflow

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
OS="${1:-linux}"
EVIDENCE_ROOT="${2:-./evidence}"

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           JOCKY Phase 3A Demo — Evidence Integrity Slice       ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Target OS: ${OS}${NC}"
echo -e "${YELLOW}Evidence Root: ${EVIDENCE_ROOT}${NC}"
echo ""

# Step 1: Build the project
echo -e "${BLUE}Step 1: Building JOCKY...${NC}"
cargo build --release --workspace
echo -e "${GREEN}✓ Build complete${NC}"
echo ""

# Step 2: Run the demo
echo -e "${BLUE}Step 2: Running JOCKY demo (OS: ${OS})...${NC}"
./target/release/jockey demo --os "${OS}" --evidence-root "${EVIDENCE_ROOT}"
echo ""

# Step 3: Show the investigation graph
echo -e "${BLUE}Step 3: Showing investigation graph...${NC}"
./target/release/jockey graph show --format cytoscape
echo ""

# Step 4: Verify evidence integrity
echo -e "${BLUE}Step 4: Verifying evidence integrity...${NC}"
./target/release/jockey verify --evidence-root "${EVIDENCE_ROOT}"
echo ""

# Step 5: Export narrative report
echo -e "${BLUE}Step 5: Generating narrative report...${NC}"
./target/release/jockey narrative --output narrative_report.md
echo -e "${GREEN}✓ Narrative report saved to narrative_report.md${NC}"
echo ""

# Step 6: Export case data
echo -e "${BLUE}Step 6: Exporting case data...${NC}"
./target/release/jockey export --format case_uco --output case_export.json
echo -e "${GREEN}✓ Case export saved to case_export.json${NC}"
echo ""

# Step 7: Load sample case
echo -e "${BLUE}Step 7: Loading sample case...${NC}"
./target/release/jockey load data/samples/sample_case
echo ""

# Step 8: Compile a test script
echo -e "${BLUE}Step 8: Compiling test investigation script...${NC}"
./target/release/jockey compile --input scripts/investigate.jky --output compiled_ir.json
echo -e "${GREEN}✓ Compiled IR saved to compiled_ir.json${NC}"
echo ""

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    DEMO COMPLETE                                ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Summary:${NC}"
echo -e "  • JOCKY DSL script parsed and compiled to IR"
echo -e "  • Execution Contract built with policy validation"
echo -e "  • ${OS} process collector executed (real collection)"
echo -e "  • Evidence objects created with SHA-256 hashes"
echo -e "  • Evidence Receipts generated with Ed25519 signatures"
echo -e "  • Integrity verification: PASS (original), FAIL (tampered)"
echo ""
echo -e "${YELLOW}Artifacts generated in: ${EVIDENCE_ROOT}/<run_id>/${NC}"