# Project: JOCKY Evidence-Contract Forensics Platform

## Architecture
JOCKY is an evidence-contract digital forensics platform built as a Rust workspace with 8 crates:
- `jockey-core`: Core domain model, execution contracts, capabilities, targets, and SQLite storage interface (§17.1).
- `jockey-evidence`: Cryptographic evidence envelopes, SHA-256 payload hashing, Ed25519 receipts, provenance chaining, and verification engine (§10-13).
- `jockey-language`: Pest PEG grammar parser, AST, semantic type-checking, IR lowering, and compiler diagnostics (§4-§9).
- `jockey-correlation`: Deterministic correlation engine, correlation rules (`pid_link`, `temporal_adjacent`, `evidence_support`), `InvestigationGraph` (petgraph), and Cytoscape JSON exporter (§14-§16).
- `jockey-collectors`: Cross-platform forensic collectors (`Collector` trait, `CollectorRegistry`). Linux userspace process (`proc_linux`) and file (`file_linux`) collectors generating authentic signed evidence (§13). Windows mock fallbacks.
- `jockey-runtime`: DAG topological execution engine (`ExecutionContract`), collector dispatcher, SQLite persistence, and execution reporting.
- `jockey-api`: Axum HTTP REST and WebSocket server for investigation state management and streaming.
- `jockey-cli`: Unified command-line interface (`jockey run`, `compile`, `load`, `graph`, `verify`, `narrative`, `export`) and demo runner.

### Data Flow
1. Investigation DSL (`.jky`) -> `jockey-language` (Parser -> Typeck -> IR) -> `ExecutionContract`.
2. `ExecutionContract` -> `jockey-runtime` (Topological DAG Scheduler) -> `jockey-collectors` (Linux Process & File).
3. Collectors -> `jockey-evidence` (Compute SHA-256 payload hash, sign Ed25519 receipt, record provenance).
4. Runtime -> `jockey-core::storage` (Persist Evidence, Receipts, Provenance to SQLite).
5. Evidence -> `jockey-correlation` (Apply correlation rules, construct `InvestigationGraph`, export Cytoscape JSON).
6. Results -> `jockey-cli` (Output verification status, graph visualization, investigative narrative report).

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Workspace Compilation Cleanliness | Fix all 73 compiler errors and 26 latent bugs across 8 crates so `cargo check --workspace` exits 0 | M1 | ORIGINAL_REQUEST §R1 |
| 2 | Pest PEG Grammar String Syntax | Replace invalid PEG difference `(CHAR - "\"")*` with `(!"\"" ~ ANY)*` in `parser.pest` | M1, M3 | ORIGINAL_REQUEST §R1, §R3 |
| 3 | Core Crate Type Re-exports | Export `TargetSpec`, `ExecPolicy`, `ExecutionContract`, `build_contract` from `jockey_core` root | M1 | ORIGINAL_REQUEST §R1 |
| 4 | Correlation Module Deduplication | Clean inline vs file module declarations and unify `CorrelationEdge` struct | M1 | ORIGINAL_REQUEST §R1 |
| 5 | Collectors Manifest & Modules Fix | Clean Cargo manifest target syntax and extract `trait_def`, `registry` modules | M1 | ORIGINAL_REQUEST §R1 |
| 6 | Runtime Imports & Non-Copy Petgraph Fix | Correct crate imports and replace non-Copy `DiGraphMap` with index-based `DiGraph` | M1 | ORIGINAL_REQUEST §R1 |
| 7 | CLI Main Async Runtime Dispatch | Wrap async `run_demo` with Tokio runtime in CLI entry point | M1 | ORIGINAL_REQUEST §R1 |
| 8 | Evidence Sign & Verify Roundtrip | Sign evidence with Ed25519 and verify signature + SHA-256 hash valid | M2 | ORIGINAL_REQUEST §R2 |
| 9 | Evidence Bit-Flip Tamper Detection | Flip bit in payload hash and detect `EvidenceHashMismatch` | M2 | ORIGINAL_REQUEST §R2 |
| 10 | Receipt Signature Tamper Detection | Modify receipt signature bytes and detect `SignatureInvalid` | M2 | ORIGINAL_REQUEST §R2 |
| 11 | Broken Provenance Chain Detection | Modify `prev_provenance_id` and detect `ProvenanceChainBroken` | M2 | ORIGINAL_REQUEST §R2 |
| 12 | Provenance Output Hash Tamper Detection | Modify provenance output hash and detect `ProvenanceHashMismatch` | M2 | ORIGINAL_REQUEST §R2 |
| 13 | Full Investigation Verification Pass | Verify entire valid investigation dataset returning `VerificationReport::Pass` | M2 | ORIGINAL_REQUEST §R2 |
| 14 | Full Investigation Verification Fail | Verify tampered investigation dataset returning `VerificationReport::Fail` | M2 | ORIGINAL_REQUEST §R2 |
| 15 | Pest Grammar Conformance | Complete PEG grammar matching `docs/language/grammar.md` | M3 | ORIGINAL_REQUEST §R3 |
| 16 | Language Golden Test Suite | Extract 10 investigation scripts from `docs/language/examples.md` into `tests/golden/parser/` | M3 | ORIGINAL_REQUEST §R3 |
| 17 | AST & Semantic Type Checker Fixes | Support golden example syntax, correct `SymbolTable`, validate capabilities | M3 | ORIGINAL_REQUEST §R3 |
| 18 | Linux Process Collector (`proc_linux`) | Inspect `/proc/[pid]/stat`, `/proc/[pid]/cmdline`, `/proc/[pid]/exe` to emit `artifact/process` Evidence | M4 | ORIGINAL_REQUEST §R4 |
| 19 | Linux File Collector (`file_linux`) | Recursive directory walk emitting `artifact/file` Evidence with SHA-256 | M4 | ORIGINAL_REQUEST §R4 |
| 20 | Collector Ed25519 Receipt Signing | Sign authentic receipts with Ed25519 keypair during collection | M4 | ORIGINAL_REQUEST §R4 |
| 21 | Windows Collector Mock Fallbacks | Provide stubbed/mock responses on non-Windows platforms | M4 | ORIGINAL_REQUEST §R4 |
| 22 | SQLite Storage Relational Schema | Implement 6 tables and 5 indexes in `jockey-core::storage` per §17.1 | M5 | ORIGINAL_REQUEST §R5 |
| 23 | Runtime Topological DAG Execution | Execute `ExecutionContract` steps in topological order and persist to SQLite | M5 | ORIGINAL_REQUEST §R5 |
| 24 | Deterministic Correlation Rules | Implement `pid_link`, `temporal_adjacent`, `evidence_support` rules | M5 | ORIGINAL_REQUEST §R5 |
| 25 | InvestigationGraph & Cytoscape Export | Build petgraph investigation graph and export Cytoscape-compatible JSON | M5 | ORIGINAL_REQUEST §R5 |
| 26 | CLI Subcommands (`run`, `compile`, etc.) | Implement `run`, `compile`, `load`, `graph`, `verify`, `narrative`, `export` subcommands | M6 | ORIGINAL_REQUEST §R6 |
| 27 | Synthetic Case Dataset (`sample_case/`) | Create `data/samples/sample_case/` with realistic process/file/IOC evidence | M6 | ORIGINAL_REQUEST §R6 |
| 28 | Demo DSL Script (`investigate.jky`) | Write working JOCKY investigation DSL script for demo | M6 | ORIGINAL_REQUEST §R6 |
| 29 | 8-Step Demo Automation (`run_demo.sh`) | Shell script automating 8-step demo with live tamper detection sequence | M6 | ORIGINAL_REQUEST §R6 |
| 30 | Release Binary Compilation | `cargo build --release --workspace` produces `target/release/jockey` | M6 | ORIGINAL_REQUEST §R6 |
| 31 | Full E2E Test Suite Validation | 100% pass across Tier 1-4 tests generated by E2E Testing Track | M7 | Acceptance Criteria |
| 32 | Adversarial Hardening (Tier 5) | White-box adversarial testing and integrity audit validation | M7 | Acceptance Criteria |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | Workspace Compilation (R1) | Fix all 73 compiler errors and 26 latent bugs across 8 crates so `cargo check --workspace` passes cleanly | none | PLANNED |
| 2 | Evidence Crypto & Tamper Tests (R2) | Implement 7+ unit tests in `jockey-evidence` exercising sign, verify, and 5 tamper scenarios | M1 | PLANNED |
| 3 | Language Grammar & Golden Tests (R3) | Implement 10 golden test fixtures, fix PEG grammar and AST/typeck discrepancies | M1 | PLANNED |
| 4 | Linux Collectors & Real Evidence (R4) | Implement `proc_linux` and `file_linux` with SHA-256 and Ed25519 receipts, mock Windows | M1, M2 | PLANNED |
| 5 | Storage, Runtime & Correlation Engine (R5) | Implement SQLite schema (§17.1), DAG runtime executor, 3 correlation rules, Cytoscape JSON | M1, M2, M4 | PLANNED |
| 6 | CLI & Demo Automation (R6) | Complete CLI subcommands, sample case, `investigate.jky`, `run_demo.sh`, release build | M1, M2, M3, M4, M5 | PLANNED |
| 7 | Final E2E Pass & Adversarial Hardening | Pass 100% of E2E test suite (Tiers 1-4) and complete Tier 5 adversarial hardening | M6, E2E Track | PLANNED |

## Interface Contracts

### `jockey-core` ↔ `jockey-language` / `jockey-runtime`
- `TargetSpec`: target specification (host, os, arch, tags). Public from `jockey_core::TargetSpec`.
- `ExecPolicy`: execution constraints (timeout, max_memory, hash_algorithm). Public from `jockey_core::ExecPolicy`.
- `ExecutionContract`: DAG of `ExecStep`, policy, targets, signatures. Public from `jockey_core::ExecutionContract`.
- `build_contract`: constructor for ExecutionContract. Public from `jockey_core::build_contract`.

### `jockey-collectors` ↔ `jockey-evidence`
- `Collector::collect(&self, target: &TargetSpec, context: &ExecutionContext) -> Result<CollectorOutput, CollectorError>`
- Emits `Evidence` with SHA-256 payload hash and signed `EvidenceReceipt`.

### `jockey-core::storage` ↔ `jockey-runtime` / `jockey-cli`
- SQLite database backing investigation runs.
- `Storage::open(path: &Path) -> Result<Storage, StorageError>`
- Tables: `investigations`, `evidence`, `receipts`, `provenance`, `correlations`, `findings`.
- CRUD methods: `insert_investigation`, `insert_evidence`, `insert_receipt`, `insert_provenance`, `insert_correlation`, `get_evidence_by_run`, `get_receipts_by_run`, `get_provenance_by_evidence`.

### `jockey-correlation` ↔ `jockey-runtime` / `jockey-cli`
- `correlate(evidence: &[Evidence]) -> Vec<CorrelationEdge>`
- `InvestigationGraph`: petgraph-based graph with nodes (Evidence) and edges (CorrelationEdge).
- `to_cytoscape_json(&self) -> serde_json::Value`.

## Code Layout
- `crates/jockey-core/`: Core contracts and SQLite storage (`src/storage.rs`).
- `crates/jockey-evidence/`: Cryptographic models, signing, verification, and tests (`src/tests.rs` or `tests/`).
- `crates/jockey-language/`: Pest PEG parser (`src/parser.pest`), AST (`src/ast.rs`), Type checker (`src/typeck.rs`), IR (`src/ir.rs`), golden test fixtures (`tests/golden/parser/`).
- `crates/jockey-collectors/`: Collector traits (`src/trait_def.rs`), registry (`src/registry.rs`), Linux collectors (`src/linux/proc_linux.rs`, `src/linux/file_linux.rs`), Windows mock (`src/windows/proc_windows.rs`).
- `crates/jockey-runtime/`: Topological DAG executor (`src/executor.rs`).
- `crates/jockey-correlation/`: Correlation rules (`src/rules.rs`), graph engine (`src/graph.rs`), Cytoscape exporter.
- `crates/jockey-cli/`: Subcommands and demo runner (`src/main.rs`).
- `scripts/`: `run_demo.sh`, `investigate.jky`.
- `data/samples/sample_case/`: Synthetic forensic test data.
