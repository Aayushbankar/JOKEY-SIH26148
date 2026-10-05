# E2E Test Infra: JOCKY Evidence-Contract Forensics Platform

## Test Philosophy
- Opaque-box, requirement-driven. No dependency on internal implementation structures.
- Derived directly from `ORIGINAL_REQUEST.md`, `JOCKY_SPEC_SHEET.md`, and acceptance criteria.
- Methodology: Category-Partition, Boundary Value Analysis (BVA), Pairwise Combinatorial Testing, and Real-World Application Workload Testing.

## Feature Inventory & Test Coverage
| # | Feature | Source | Tier 1 (Coverage) | Tier 2 (Boundary) | Tier 3 (Cross-Feature) |
|---|---------|--------|:-----------------:|:-----------------:|:----------------------:|
| 1 | Workspace Compilation Cleanliness | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ |
| 2 | Evidence Sign & Verify Roundtrip | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ |
| 3 | Evidence Bit-Flip Tamper Detection | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ |
| 4 | Receipt Signature Tamper Detection | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ |
| 5 | Provenance Chain Link Verification | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ |
| 6 | Provenance Output Hash Verification | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ |
| 7 | DSL Grammar Parsing (10 Golden Scripts) | ORIGINAL_REQUEST §R3 | 10 | 5 | ✓ |
| 8 | Linux Process Collector (`proc_linux`) | ORIGINAL_REQUEST §R4 | 5 | 5 | ✓ |
| 9 | Linux File Collector (`file_linux`) | ORIGINAL_REQUEST §R4 | 5 | 5 | ✓ |
| 10 | SQLite Relational Persistence | ORIGINAL_REQUEST §R5 | 5 | 5 | ✓ |
| 11 | Deterministic Correlation & Cytoscape | ORIGINAL_REQUEST §R5 | 5 | 5 | ✓ |
| 12 | CLI Subcommands (`run`, `verify`, etc.) | ORIGINAL_REQUEST §R6 | 7 | 5 | ✓ |
| 13 | 8-Step Demo Sequence & Tamper Flow | ORIGINAL_REQUEST §R6 | 5 | 5 | ✓ |

## Test Architecture
- **E2E Test Runner**: `tests/e2e/run_all_e2e_tests.sh` or standalone test binaries.
- **Pass/Fail Semantics**: Clean exit code 0 on valid scenarios; proper non-zero error codes and explicit error messages on negative/tampered test inputs.
- **Directory Layout**:
  - `tests/e2e/tier1_feature/`: Individual feature verification tests.
  - `tests/e2e/tier2_boundary/`: Boundary and negative/tamper test cases.
  - `tests/e2e/tier3_pairwise/`: Cross-feature combinatorial workflows.
  - `tests/e2e/tier4_realworld/`: End-to-end multi-step forensic investigations.

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| 1 | Full Investigation Lifecycle (Compile -> Collect -> Correlate -> Store -> Verify) | F1-F12 | High |
| 2 | Malicious Binary Detection & IOC Correlation (Process + File + Evidence Support) | F8, F9, F11 | High |
| 3 | Forensic Chain Tamper & Rejection (Bit-flip in sqlite -> verify detect failure) | F3, F4, F5, F10, F12 | High |
| 4 | Offline Case Ingestion (`jockey load sample_case/` -> Graph -> Narrative) | F10, F11, F12 | Medium |
| 5 | Live 8-Step Demo Automation Script (`scripts/run_demo.sh`) | F1-F13 | High |

## Coverage Thresholds
- Tier 1: ≥5 test cases per feature
- Tier 2: ≥5 boundary/negative test cases per feature
- Tier 3: Pairwise coverage across major feature interactions
- Tier 4: ≥5 realistic end-to-end investigation scenarios
