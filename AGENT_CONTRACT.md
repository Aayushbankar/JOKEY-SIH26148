# JOCKY SIH 26148 — AI Agent Contract & Execution Ledger

**Version:** 1.0 | **Status:** ACTIVE | **Target:** SIH 2026 PS 26148 Win
**Repository:** `/data/data/com.termux/files/home/workspace/projects/JOKEY---SIH26148`
**Environment:** Termux (Android) / Rust 1.99 / aarch64-linux-android

---

## 🎯 MISSION STATEMENT

Build a **complete, working, demo-ready JOCKY Evidence-Contract Forensics Platform** that wins SIH 2026 Problem Statement 26148 by delivering exactly what NTRO researchers value: **security-resilient execution, verifiable evidence provenance, deterministic correlation, and compilation-target unification** — not another forensic query language.

**Winning Criteria (NTRO Rubric):**
1. **Technical Innovation (25%)** — Execution contracts + compilation targets + evidence receipts = genuine novelty
2. **Problem Relevance (20%)** — DFIR fragmentation solved via unified workflow
3. **Feasibility (20%)** — Working end-to-end demo, not slides
4. **Security/Resilience (15%)** — Capability-based, signed receipts, hash-linked provenance = NTRO sweet spot
5. **Presentation/Demo (10%)** — <8 min, tamper detection live, cross-platform
6. **Team Capability (10%)** — Demonstrated Rust/DFIR expertise via code

---

## 📊 CURRENT STATE SNAPSHOT (2026-10-04)

### ✅ Already Implemented (~70% of Spec)
| Crate | Status | Key Assets |
|-------|--------|------------|
| `jockey-language` | 🟢 Advanced | Pest grammar, AST (10 stmts), Typeck w/ capability inference, IR lowering, Tests |
| `jockey-core` | 🟢 Advanced | IR, ExecutionContract, PolicyEngine (7 points), SQLite storage, TargetSpec, Capability |
| `jockey-cli` | 🟢 Advanced | Full subcommands: run, compile, graph, verify, export, load, narrative, serve |
| `jockey-runtime` | 🟡 Partial | Executor, Dispatcher, CollectorRegistry scaffolding |
| `jockey-evidence` | 🟡 Partial | Evidence model, Receipt/Provenance structs, **Crypto BROKEN** (ed25519-dalek 2.x API, missing hex) |
| `jockey-collectors` | 🟡 Skeleton | Collector trait, Manifest schema, Win/Lin dirs — **NO actual collectors** |
| `jockey-correlation` | 🔴 Minimal | lib.rs stub only |
| `jockey-api` | 🔴 Minimal | lib.rs stub only |

### 🔴 Blocking Issues (Fix First)
1. `jockey-evidence` fails compilation: ed25519-dalek 2.x API changes, missing `hex` crate, DateTime abs()
2. Workspace deps need `hex = "0.4"`, `config` without `serde` feature, `figment` without `serde`
3. No golden tests, no synthetic test data, no collector implementations

---

## 🏗️ MASTER ARCHITECTURE (Locked — Do Not Deviate)

```
JOCKY Script (DSL)
       │
       ▼
┌──────────────────┐
│  pest Parser     │ ◀── crates/jockey-language/parser.pest
└────────┬─────────┘
         │ AST
         ▼
┌──────────────────┐
│  Type Checker    │ ◀── Capability inference, semantic validation
└────────┬─────────┘
         │ Typed AST
         ▼
┌──────────────────┐
│  IR Compiler     │ ◀── Platform-agnostic execution plan (ULIDs, deps)
└────────┬─────────┘
         │ IR Module
         ▼
┌──────────────────┐
│  Contract Builder│ ◀── IR + TargetSpec + Policy → ExecutionContract
└────────┬─────────┘
         │ ExecutionContract
         ▼
┌──────────────────┐
│  Policy Engine   │ ◀── 7 enforcement points (allowlist, schema, timeout, root, hash, version, caps)
└────────┬─────────┘
         │ Validated Contract
         ▼
┌──────────────────┐
│  Runtime Engine  │ ◀── Sequential/parallel dispatch, timeout, retry, SQLite persist
└────────┬─────────┘
         │ Evidence Objects
         ▼
┌──────────────────┐
│  Evidence Model  │ ◀── Typed, hashed (blake3), ULID, collected_at
└────────┬─────────┘
         │ Evidence + Receipts
         ▼
┌──────────────────┐
│  Evidence Receipt│ ◀── Ed25519(payload_hash || evidence_id || timestamp), collector key
└────────┬─────────┘
         │ Receipt
         ▼
┌──────────────────┐
│  Provenance Chain│ ◀── Hash-linked, append-only, actor-signed
└────────┬─────────┘
         │ Provenance Records
         ▼
┌──────────────────┐
│  Correlation     │ ◀── 9 deterministic rules → petgraph
└────────┬─────────┘
         │ Investigation Graph
         ▼
┌──────────────────┐
│  Verification    │ ◀── Receipt sigs + provenance hashes → PASS/FAIL
└────────┬─────────┘
         │ Verified Graph
         ▼
┌──────────────────┐
│  Export          │ ◀── CASE/UCO (minimal), Cytoscape, Timesketch CSV, Markdown
└──────────────────┘
```

---

## 📋 PHASE PLAN (10 Weeks → Compressed to 16 Days)

| Phase | Focus | Days | Agents | Deliverable |
|-------|-------|------|--------|-------------|
| **0** | Repo & Compile Fix | 1-2 | 1 | `cargo check --workspace` clean |
| **1** | Language Golden Tests | 2-3 | 1 | 10 scripts → AST → IR golden pass |
| **2** | Evidence Crypto + Verification | 3-5 | 2 | Receipt sign/verify, provenance chain, tamper detection |
| **3** | Minimal Collectors (4) | 5-8 | 3 | proc_win, file_win, proc_lin, file_lin working |
| **4** | Runtime E2E Execution | 8-10 | 2 | Contract → Runtime → SQLite → Evidence+Receipts+Provenance |
| **5** | Correlation + Graph | 10-12 | 2 | 9 rules, petgraph, queries, Cytoscape export |
| **6** | CLI + Demo Automation | 12-14 | 2 | `jockey run` E2E, demo script <8 min, binary <50MB |
| **7** | API + Frontend (STRETCH) | 14-16 | 2 | Axum REST/WS + 8-page dashboard (DROP if behind) |

**Hard Deadline:** Day 14 = Demo Ready | Day 16 = Polish + Backup Video

---

## 🤖 AGENT ROLES & SPAWN STRATEGY

### **Agent Coordinator (You/Primary)**
- Owns this contract, tracks progress, resolves conflicts, merges PRs
- Spawns specialized agents per phase
- Runs quality gates: `cargo check`, `cargo clippy`, `cargo test`, `cargo build --release`

### **Specialized Agent Types**

| Agent Type | Responsibility | Spawn Trigger |
|------------|----------------|---------------|
| **LangAgent** | Parser, AST, Typeck, IR, Diagnostics | Phase 0-1 |
| **CoreAgent** | IR, Contract, Policy, Storage, Target, Capability | Phase 0-1, 4 |
| **CryptoAgent** | Evidence model, Receipts, Provenance, Verification, Crypto primitives | Phase 2 |
| **CollectorAgent-Win** | Windows collectors (proc, file, reg, logs, net) | Phase 3 |
| **CollectorAgent-Lin** | Linux collectors (proc, file, config, logs, net) | Phase 3 |
| **RuntimeAgent** | Executor, Dispatcher, Registry, SQLite persistence | Phase 4 |
| **CorrelationAgent** | Rules engine, Graph, Queries, Hypothesis overlay | Phase 5 |
| **CLIAgent** | CLI commands, Demo script, Binary optimization | Phase 6 |
| **APIAgent** | Axum server, WebSocket, OpenAPI | Phase 7 (optional) |
| **FrontendAgent** | 8 HTML pages, Cytoscape, Chart.js, Markdown render | Phase 7 (optional) |
| **TestAgent** | Golden tests, Property tests, Fuzzing, Integration, Tamper tests | All phases |
| **DevOpsAgent** | CI/CD, Release build, Cross-platform test, Demo recording | Phase 6-7 |

### **Agent Communication Protocol**
- **Shared State:** This `AGENT_CONTRACT.md` + `TODO.md` (updated in real-time)
- **Handoffs:** Each agent writes `HANDOFF_<agent>.md` with decisions, blockers, next steps
- **Quality Gate:** No phase complete without `cargo test -p <crate> -- --nocapture` passing
- **Conflict Resolution:** Coordinator decides; spec (JOCKY_SPEC_SHEET.md) is source of truth

---

## 📝 DETAILED TASK SPECIFICATIONS PER PHASE

### **PHASE 0: COMPILE FIX (Day 1-2)**

#### **LangAgent Tasks**
- [ ] Verify `parser.pest` matches `docs/language/grammar.md` exactly
- [ ] Ensure `build.rs` generates parser correctly
- [ ] Run `cargo test -p jockey-language` — fix any parser/typeck regressions

#### **CoreAgent Tasks**
- [ ] Verify `ir.rs`, `contract.rs`, `policy.rs`, `storage.rs` compile
- [ ] Ensure SQLite schema matches `JOCKY_SPEC_SHEET.md` §17 exactly
- [ ] Fix any `rusqlite` API issues

#### **CryptoAgent Tasks (CRITICAL PATH)**
- [ ] Add `hex = "0.4"` to `Cargo.toml` [workspace.dependencies]
- [ ] Fix `jockey-evidence/src/lib.rs`:
  - `SigningKey::generate(&mut csprng)` → `SigningKey::from_bytes(&random_bytes())`
  - `Signature::from_bytes()` returns `Result` — handle properly
  - `hex::encode/decode` — import `hex` crate
  - `DateTime.abs()` → `signed_duration_since().abs()` or manual
  - `sign_receipt(&EvidenceReceipt)` vs `sign_receipt(&Vec<u8>)` — fix signature
  - `canonicalize.rs` — implement deterministic serialization (serde_json::to_vec with sorted keys)
- [ ] Add unit tests: sign → verify PASS, tamper → verify FAIL

#### **DevOpsAgent Tasks**
- [ ] Fix `.github/workflows/ci.yml` — modern actions (no `actions-rs/cargo@v1`)
- [ ] Ensure `cargo fmt --check`, `cargo clippy --workspace -D warnings` pass

**Phase 0 Exit Criteria:** `cargo check --workspace && cargo clippy --workspace -D warnings && cargo test --workspace` all pass

---

### **PHASE 1: LANGUAGE GOLDEN TESTS (Day 2-3)**

#### **LangAgent Tasks**
- [ ] Create `tests/golden/` structure:
  ```
  tests/golden/
  ├── parser/
  │   ├── 01_basic_investigation.jky
  │   ├── 02_hypothesis_mitre.jky
  │   ├── 03_collect_filter.jky
  │   ├── 04_match_pattern.jky
  │   ├── 05_correlate_pid.jky
  │   ├── 06_timeline_build.jky
  │   ├── 07_bind_hypothesis.jky
  │   ├── 08_export_case.jky
  │   ├── 09_verify_chain.jky
  │   └── 10_complex_full.jky
  ├── ast/
  │   └── *.json (expected AST from each .jky)
  └── ir/
      └── *.json (expected IR from each .jky)
  ```
- [ ] Implement `tests/golden_runner.rs`:
  - Parse each `.jky` → AST → compare with `ast/*.json`
  - Type-check → lower to IR → compare with `ir/*.json`
  - Use `insta` or custom JSON diff for assertions
- [ ] Generate initial golden files from current implementation
- [ ] Fix any parser/typeck bugs revealed

#### **TestAgent Tasks**
- [ ] Add property tests: `proptest` for parser roundtrip (parse → print → parse)
- [ ] Add fuzzing target: `cargo fuzz` for parser input

**Phase 1 Exit Criteria:** `cargo test -p jockey-language` passes 100% with 10 golden tests

---

### **PHASE 2: EVIDENCE CRYPTO + VERIFICATION (Day 3-5)**

#### **CryptoAgent Tasks**
- [ ] **Evidence Model** (`model.rs`): Complete Evidence, EvidenceReceipt, ProvenanceRecord, Finding, CorrelationEdge per spec §10-12
- [ ] **Crypto Primitives** (`crypto.rs`):
  - `blake3_hash(data: &[u8]) -> [u8; 32]`
  - `generate_ed25519_keypair() -> (SigningKey, VerifyingKey)`
  - `sign(signing_key: &SigningKey, payload: &[u8]) -> String` (hex-encoded)
  - `verify(verifying_key: &VerifyingKey, payload: &[u8], sig_hex: &str) -> bool`
  - `generate_ulid() -> String`
- [ ] **Receipts** (`receipt.rs`):
  - `sign_receipt(collector_key: &SigningKey, evidence: &Evidence) -> EvidenceReceipt`
  - `verify_receipt(collector_pubkey: &VerifyingKey, receipt: &EvidenceReceipt, evidence: &Evidence) -> Result<(), VerifyError>`
- [ ] **Provenance** (`provenance.rs`):
  - `build_provenance_chain(evidence: &Evidence, receipt: &EvidenceReceipt, actor_key: &SigningKey, action: &str, params: Value) -> ProvenanceRecord`
  - `verify_provenance_chain(chain: &[ProvenanceRecord]) -> Result<(), VerifyError>`
- [ ] **Verification Engine** (`verify.rs`):
  - `VerificationEngine::verify_run(run_id: &str, db: &Connection) -> VerificationReport`
  - Checks: all receipts valid, all provenance hashes link, no gaps, timestamps ordered

#### **TestAgent Tasks**
- [ ] Golden test: valid evidence chain → `VerificationReport { status: Pass, details: [] }`
- [ ] Tamper test 1: flip 1 bit in evidence file → `status: Fail, details: ["evidence hash mismatch"]`
- [ ] Tamper test 2: modify receipt signature → `status: Fail, details: ["receipt signature invalid"]`
- [ ] Tamper test 3: break provenance link (remove record) → `status: Fail, details: ["provenance chain broken"]`
- [ ] Tamper test 4: modify provenance record → `status: Fail, details: ["provenance hash mismatch"]`

**Phase 2 Exit Criteria:** `cargo test -p jockey-evidence` passes with 5+ tamper detection tests

---

### **PHASE 3: MINIMAL COLLECTORS (Day 5-8) — PARALLEL**

#### **CollectorAgent-Win Tasks** (`crates/jockey-collectors/src/windows/`)
- [ ] `mod.rs` — exports, registry registration
- [ ] `proc_windows.rs`:
  - `Collector::execute("list", params, ctx) → Vec<Evidence>` using `windows-sys::Win32::System::Diagnostics::ToolHelp`
  - Evidence type: `artifact/process`, fields: pid, ppid, name, cmdline, exe_path, username, start_time
  - Manifest: capabilities `["process.list"]`, schema for params (none for list), Ed25519 keypair
- [ ] `file_windows.rs`:
  - `execute("enumerate", params, ctx)` — `FindFirstFileW`/`FindNextFileW` with recursive walk
  - Evidence type: `artifact/file`, fields: path, size, modified, created, hash (blake3)
  - Manifest: capabilities `["file.enumerate", "file.hash"]`, params schema (root_path, pattern, max_depth, hash_algo)

#### **CollectorAgent-Lin Tasks** (`crates/jockey-collectors/src/linux/`)
- [ ] `mod.rs` — exports, registry registration
- [ ] `proc_linux.rs`:
  - `execute("list", params, ctx)` — read `/proc/[0-9]*/stat`, `/proc/[pid]/cmdline`, `/proc/[pid]/exe` (readlink)
  - Evidence type: `artifact/process`, same fields as Windows (cross-platform parity)
  - Manifest: capabilities `["process.list"]`
- [ ] `file_linux.rs`:
  - `execute("enumerate", params, ctx)` — `std::fs::read_dir` recursive, `std::fs::metadata`
  - Evidence type: `artifact/file`, same fields as Windows
  - Manifest: capabilities `["file.enumerate", "file.hash"]`

#### **CoreAgent Tasks** (Registry & Integration)
- [ ] `collector_registry.rs` — load manifests, validate capabilities against policy, store keypairs
- [ ] `manifest.rs` — `CollectorManifest`, `ActionManifest`, `ParamSchema` (JSON Schema)
- [ ] Integration test: spawn mock `ExecutionContext` → call collectors → verify Evidence output matches schema

#### **TestAgent Tasks**
- [ ] Contract tests: each collector implements `Collector` trait correctly
- [ ] Golden tests: collector output → Evidence JSON matches expected structure
- [ ] Synthetic data: create `data/samples/` with known process/file structures for deterministic testing

**Phase 3 Exit Criteria:** `cargo test -p jockey-collectors` passes with 4 collectors producing valid Evidence

---

### **PHASE 4: RUNTIME E2E EXECUTION (Day 8-10)**

#### **RuntimeAgent Tasks**
- [ ] `executor.rs` — `execute(contract: ExecutionContract) -> Result<ExecutionResult, RuntimeError>`
  - Topological sort steps by `depends_on`
  - For each step: lookup collector, validate params, execute with timeout, retry
  - On success: store Evidence + generate Receipt + ProvenanceRecord → SQLite
  - On failure: per policy `continue_on_error` or abort
- [ ] `dispatcher.rs` — async dispatcher with semaphore for `policy.parallelism`
- [ ] `collector_registry.rs` — complete implementation with manifest loading
- [ ] `sandbox.rs` — basic isolation: chroot evidence_root, env sanitization, resource limits (rlimit)

#### **CoreAgent Tasks**
- [ ] `storage.rs` — complete SQLite CRUD for all tables (§17)
- [ ] `contract.rs` — `build_contract(ir, target, policy)` with full validation

#### **TestAgent Tasks**
- [ ] E2E test: Load golden IR → build Contract → execute → verify SQLite has evidence+receipts+provenance
- [ ] Verify `jockey verify` CLI command works on this run

**Phase 4 Exit Criteria:** `cargo test -p jockey-runtime` passes E2E; `jockey run sample.jky` produces valid evidence bundle

---

### **PHASE 5: CORRELATION + GRAPH (Day 10-12)**

#### **CorrelationAgent Tasks**
- [ ] `rules.rs` — 9 deterministic rules from spec §14.1:
  1. `pid_link` (spawned) — pid==ppid, confidence 1.0
  2. `file_write` (wrote) — handle + timestamp, 0.95
  3. `file_read` (read) — handle + timestamp, 0.9
  4. `net_connect` (connected) — pid + 4-tuple, 0.95
  5. `ioc_match` (resolved_to) — IOC match (IP/domain/hash), 1.0
  6. `yara_match` (contains) — YARA/Sigma match, 0.9
  7. `rule_match` (indicates) — rule + evidence IDs, 0.8-1.0
  8. `evidence_support` (supported_by) — explicit citation, 1.0
  9. `temporal_adjacent` (timeline_adjacent) — timestamp window, 0.7
- [ ] Rule config: JSON with condition (expression), confidence, params
- [ ] `engine.rs` — `correlate(evidence: &[Evidence], rules: &[Rule]) -> Vec<CorrelationEdge>`
- [ ] `graph.rs` — `InvestigationGraph` using `petgraph::Graph<EvidenceNode, CorrelationEdge, Directed>`
- [ ] Queries: `path()`, `backward_from()`, `forward_from()`, `hypothesis_support()`, `subgraph()`, `graph_at(timestamp)`
- [ ] `hypothesis.rs` — Hypothesis overlay: MITRE tags, confidence, evidence bindings

#### **TestAgent Tasks**
- [ ] Golden test: synthetic evidence set → expected edges → graph queries return correct results
- [ ] Property test: graph queries invariant (path A→B exists iff backward_from(B) contains A)

**Phase 5 Exit Criteria:** `cargo test -p jockey-correlation` passes; Cytoscape JSON export valid

---

### **PHASE 6: CLI + DEMO AUTOMATION (Day 12-14)**

#### **CLIAgent Tasks**
- [ ] Complete `jockey-cli/src/main.rs` subcommands:
  - `run <script.jky> --target <live|dead|image> --host <HOST> [--policy <file>]`
  - `compile <script.jky> --output-dir <dir>` → VQL, KAPE targets, CASE stubs
  - `graph show --run-id <ID> --format <cytoscape|dot|json>`
  - `verify --run-id <ID> [--evidence <EID>]`
  - `export --run-id <ID> --format <case_uco|cytoscape|timesketch|markdown>`
  - `load <sample_case_dir>`
  - `narrative --run-id <ID>` → Markdown report with evidence citations
  - `serve --addr <ADDR>` → starts API + frontend
- [ ] Error handling: user-friendly messages, exit codes, structured logging

#### **DevOpsAgent Tasks**
- [ ] `scripts/run_demo.sh` — 8-step demo from ROADMAP.md:
  1. `jockey load sample_case/`
  2. `jockey graph show`
  3. `jockey run investigate.jky`
  4. `jockey compile investigate.jky` (show VQL + KAPE + CASE)
  5. `jockey narrative`
  6. `jockey verify`
  7. **TAMPER DEMO**: modify evidence file → `jockey verify` FAIL → restore → `jockey verify` PASS
  8. Close
- [ ] Pre-recorded demo video (asciinema or screen record)
- [ ] Release build: `cargo build --release --workspace` → strip → verify <50MB
- [ ] Cross-platform test: binary runs on Windows 10/11 + Ubuntu 22.04/24.04 (CI or manual)

#### **TestAgent Tasks**
- [ ] Full E2E integration test: script → run → graph → verify → export → narrative

**Phase 6 Exit Criteria:** Demo script runs in <8 min reliably; binary <50MB; tamper demo works

---

### **PHASE 7: API + FRONTEND (Day 14-16) — STRETCH / OPTIONAL**

**ONLY IF PHASES 0-6 COMPLETE AND STABLE**

#### **APIAgent Tasks**
- [ ] `server.rs` — Axum routes per spec §16 (REST + WebSocket)
- [ ] `ws.rs` — WebSocket handler: `step_started`, `evidence_collected`, `correlation_found`, `verification_result`
- [ ] State: `AppState` with DB pool, runtime handle, investigation cache

#### **FrontendAgent Tasks**
- [ ] `frontend/` — 8 static pages (no build step):
  - `index.html` — Dashboard, recent investigations
  - `investigation.html` — Tabs: Graph, Timeline, Evidence, Findings, Export, Verify
  - `graph.html` — Cytoscape.js interactive, filters, hypothesis overlay
  - `timeline.html` — Chart.js zoomable, annotations
  - `evidence.html` — Table + detail pane (receipt/provenance)
  - `findings.html` — Kanban (open/triaged/resolved), citations
  - `verify.html` — Tamper check results, hash chain validation
  - `report.html` — Markdown render with evidence links
- [ ] `frontend/lib/` — Local CDN fallbacks for Cytoscape, Chart.js, marked.js, Lucide
- [ ] `ServeDir` for static assets

**Phase 7 Exit Criteria:** `jockey serve` → browser at localhost:8080 shows working dashboard

---

## ✅ QUALITY GATES (Non-Negotiable)

| Gate | Command | Must Pass |
|------|---------|-----------|
| **Compile** | `cargo check --workspace` | 0 errors |
| **Lint** | `cargo clippy --workspace -D warnings` | 0 warnings |
| **Format** | `cargo fmt --check --workspace` | 0 diffs |
| **Unit Tests** | `cargo test --workspace --lib` | 100% pass |
| **Integration Tests** | `cargo test --workspace --test integration` | 100% pass |
| **Golden Tests** | `cargo test -p jockey-language -- golden` | 10/10 pass |
| **Tamper Tests** | `cargo test -p jockey-evidence -- tamper` | 4/4 detect |
| **E2E Demo** | `scripts/run_demo.sh` | <8 min, all steps PASS |
| **Binary Size** | `ls -lh target/release/jockey` | <50MB |
| **Release Build** | `cargo build --release --workspace` | 0 errors |

---

## 🎪 DEMO SCRIPT (Memorize — Judges Will Ask)

### **8 Steps, 7 Minutes Max**

| Step | Command | Expected Output | Judge Talking Point |
|------|---------|-----------------|---------------------|
| 1 | `jockey load sample_case/` | Loads synthetic evidence bundle | "Pre-loaded case with known attack chain" |
| 2 | `jockey graph show` | Cytoscape JSON → renders in dashboard | "Causal investigation graph, not just timeline" |
| 3 | `jockey run investigate.jky` | Executes DSL → collects evidence → builds graph | "Single script = collection + correlation + timeline" |
| 4 | `jockey compile investigate.jky` | Outputs: `hunt.vql`, `kape_targets.json`, `evidence.case.json` | "Compiles to Velociraptor, KAPE, Volatility, CASE — native backends" |
| 5 | `jockey narrative` | Markdown report with `[Evidence: ULID]` citations | "Verification-backed narrative, clickable evidence" |
| 6 | `jockey verify` | `✅ Verification PASSED — 47 evidence, 12 receipts, 0 tampered` | "Cryptographic proof of integrity" |
| 7 | **TAMPER** `echo "x" >> evidence/...` → `jockey verify` | `❌ FAILED — evidence hash mismatch at ULID...` | "Tamper detection via receipts + provenance" |
| 7b | Restore file → `jockey verify` | `✅ PASSED` | "Recovery proves detection is real" |
| 8 | Close | "Questions?" | — |

### **Judge Q&A Cheat Sheet (Top 10)**

| Question | 30-Second Answer |
|----------|------------------|
| "Why not Velociraptor?" | "Velociraptor is best-in-class for live hunting. JOCKY compiles TO Velociraptor VQL + KAPE targets + Volatility plugins + osquery SQL + CASE/UCO from ONE script. You write once, execute natively everywhere." |
| "Legal admissibility?" | "We produce verification-backed evidence bundles: Ed25519-signed receipts at collection, hash-linked provenance chain through every transform. Admissibility depends on jurisdiction/procedure — we provide the technical chain-of-custody foundation." |
| "Threat model?" | "Compromised collector, malicious script, evidence tampering. Mitigations: capability-based execution contracts (least privilege), per-evidence Ed25519 receipts, hash-linked provenance, verification engine detects any mutation." |
| "Windows/Linux parity?" | "Semantic types (`process`, `file`, `network`) map to platform-specific collectors. Same JOCKY script `collect process as procs` compiles to `proc_windows::list` (Toolhelp32) on Windows and `proc_linux::list` (/proc) on Linux." |
| "Why Rust?" | "Memory safety (no CVE class bugs), performance (parallel collection), WASM target (future sandboxed collectors), growing forensics ecosystem (blake3, ed25519-dalek, pest, petgraph)." |
| "Deterministic correlation?" | "9 rules with explicit conditions (pid_link, timestamp_join, ioc_match) and confidence scores. Edges cite evidence IDs — no ML black boxes. Explainable = legally defensible." |
| "Scale?" | "MVP: single analyst, local execution. Architecture supports: parallel dispatch, SQLite → PostgreSQL, petgraph → persistent graph DB, remote agents (gRPC/mTLS) — all deferred per spec." |
| "Integration with SIEM?" | "Export: CASE/UCO (standard), Timesketch CSV (Plaso-compatible), Cytoscape (graph), Markdown (narrative). Velociraptor/GRR/KAPE artifacts consumed as compilation targets." |
| "Offline/air-gapped?" | "Local execution only for MVP. Script + collectors + evidence bundle = portable. No server required. Offline collector = compile to KAPE targets + run on air-gapped host." |
| "What's next?" | "eBPF collectors (Linux kernel visibility), kernel drivers (Windows ETW/minifilter), remote agent protocol, multi-tenancy, AI assist (local LLM for hypothesis suggestion), formal verification (Prusti/Kani)." |

---

## 📁 FILES TO CREATE / MAINTAIN

### **Agent Handoff Files (Per Phase)**
- `HANDOFF_LANG.md` — Parser decisions, grammar changes, typeck rules
- `HANDOFF_CORE.md` — IR/Contract/Policy changes, storage schema migrations
- `HANDOFF_CRYPTO.md` — Key management, receipt format, provenance chain design
- `HANDOFF_COLLECTORS.md` — Manifest schemas, capability definitions, Windows/Linux API choices
- `HANDOFF_RUNTIME.md` — Executor logic, timeout/retry policies, sandboxing decisions
- `HANDOFF_CORRELATION.md` — Rule configs, graph schema, query API
- `HANDOFF_CLI.md` — Command UX, output formats, demo script
- `HANDOFF_API.md` — REST/WS API contracts, state management
- `HANDOFF_FRONTEND.md` — Page components, data flow, CDN fallbacks

### **Tracking Files**
- `TODO.md` — Real-time task board (update after every agent completion)
- `DECISIONS.md` — Architectural decisions with rationale (immutable log)
- `BLOCKERS.md` — Active blockers, owner, ETA
- `METRICS.md` — Binary size, test count, coverage, demo timing

---

## 🚨 RISK REGISTER & MITIGATIONS

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Collector impl takes 2x estimated | High | Critical | Start Phase 3 Day 5; parallel Win/Lin; `list` action only for MVP |
| ed25519-dalek API changes break crypto | Medium | High | Pin version `ed25519-dalek = "2.2"`; test crypto in isolation first |
| Demo fails live | Medium | Critical | Pre-recorded video backup; synthetic data deterministic; rehearse 5x |
| Binary >50MB | Low | Medium | LTO, strip, `codegen-units=1`, `panic=abort`, audit deps with `cargo bloat` |
| Cross-platform test fails | Medium | High | Test on Windows (VM) + Linux (native) by Day 12; fix before demo |
| Judge asks unimplemented feature | Medium | Medium | Honest: "Deferred per MVP scope (see JOCKY_SPEC_SHEET.md §20)" |
| Time overrun Phase 3-4 | High | Critical | Daily standups; cut scope: drop reg/logs/net collectors, keep proc+file only |

---

## 🏁 DEFINITION OF DONE (SIH Submission)

- [ ] `cargo build --release --workspace` succeeds
- [ ] Binary `target/release/jockey` <50MB, runs on Windows + Ubuntu
- [ ] `scripts/run_demo.sh` executes in <8 min, all 8 steps pass
- [ ] Tamper detection demonstrated live (Step 7)
- [ ] Pre-recorded demo video uploaded
- [ ] `JOCKY_SPEC_SHEET.md` matches implementation (no spec drift)
- [ ] `README.md` updated with actual commands (not "planned")
- [ ] `CHANGELOG.md` updated with v0.1.0 release notes
- [ ] GitHub Release: binary + SHA256 checksums + demo video
- [ ] Judge Q&A doc printed (25 Q&A from `docs/evaluation/judge-questions.md`)
- [ ] Team can explain architecture in 2 min (elevator pitch)

---

## 📞 ESCALATION PATH

1. **Agent Blocked >2 hours** → Post to `BLOCKERS.md`, Coordinator decides
2. **Spec Ambiguity** → Check `JOCKY_SPEC_SHEET.md` first, then `docs/architecture/`, then Coordinator
3. **Dependency Issue** → DevOpsAgent investigates; no new deps without Coordinator approval
4. **Timeline Slip >1 day** → Coordinator cuts scope (see Non-Goals §3, Optional §21)
5. **Critical Bug Day 13-14** → Freeze features, stabilize demo only

---

## 🎖️ SUCCESS METRICS (NTRO-Aligned)

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Compilation Targets** | 5 (VQL, SQL, KAPE, Volatility, CASE) | `jockey compile` outputs all 5 |
| **Evidence Receipts** | 100% of evidence objects | `jockey verify` shows receipt count = evidence count |
| **Provenance Chain** | Hash-linked, no gaps | VerificationReport: `provenance_intact: true` |
| **Deterministic Correlation** | 9 rules, 0 ML | `jockey graph show` edges have `method`, `confidence`, `evidence_ids` |
| **Tamper Detection** | 4/4 attack vectors detected | Tamper test suite passes |
| **Cross-Platform Parity** | `collect process` works Win+Lin | Demo runs on both (or video shows both) |
| **Demo Time** | <8 minutes | Stopwatch |
| **Binary Size** | <50MB | `ls -lh` |

---

## 📜 CONTRACT ACCEPTANCE

By executing this contract, agents acknowledge:

1. **Spec is frozen** — `JOCKY_SPEC_SHEET.md` §20 (MVP Scope) is the contract
2. **No scope creep** — Non-Goals §3 and Optional §21 are explicitly excluded
3. **Quality over features** — Working demo > partial features
4. **NTRO values** — Security-resilient execution, verifiable provenance, deterministic correlation
5. **Honest representation** — No claims of "first", "only", "court-admissible", "100% secure"

**Signed:** _________________________ (Coordinator) | **Date:** 2026-10-04

---

## 📎 APPENDICES

### **A. Key Spec References**
- `JOCKY_SPEC_SHEET.md` — Engineering source of truth (all §1-25)
- `JOCKY_DATA_CONTRACTS.md` — Evidence, Receipt, Provenance, Contract schemas
- `docs/language/grammar.md` — Pest grammar (authoritative)
- `docs/language/examples.md` — 10 example scripts (golden test inputs)
- `docs/architecture/execution-contract.md` — Contract structure
- `docs/architecture/collector-architecture.md` — Collector trait, manifests
- `docs/architecture/correlation-architecture.md` — 9 rules, graph queries
- `docs/evidence/evidence-model.md` — Evidence types, MIME-like schema
- `docs/evidence/evidence-receipt.md` — Receipt structure, verification
- `docs/evidence/provenance.md` — Chain structure, verification
- `ROADMAP.md` — Phase plan, success criteria
- `docs/evaluation/demo-plan.md` — Demo script details
- `docs/evaluation/judge-questions.md` — 25 Q&A
- `docs/evaluation/success-criteria.md` — Measurable targets

### **B. Workspace Dependencies (Final)**
```toml
[workspace.dependencies]
# Core
tokio = { version = "1.38", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "1.0"
anyhow = "1.0"
tracing = { version = "0.1", features = ["std"] }
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt", "json"] }

# Parsing
pest = { version = "2.7" }
pest_derive = "2.7"

# Cryptography
blake3 = "1.5"
ed25519-dalek = "2.2"
rand = "0.8"
zeroize = "1.7"
sha2 = "0.10"
hex = "0.4"

# IDs & Time
ulid = "1.0"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1.7", features = ["v4", "serde", "fast-rng"] }

# Graph
petgraph = { version = "0.6", features = ["serde", "graphmap"] }

# Database
rusqlite = { version = "0.31", features = ["bundled", "chrono", "uuid", "serde_json"] }

# Web
axum = { version = "0.7", features = ["ws"] }
tower = { version = "0.4", features = ["util"] }
tower-http = { version = "0.5", features = ["fs", "trace", "cors"] }
http = "1.0"
mime = "0.3"

# Config
figment = { version = "0.10" }
config = { version = "0.13" }

# CLI
clap = { version = "4.5", features = ["derive", "env", "wrap_help"] }

# Testing
proptest = "1.0"
tempfile = "3.8"
```

### **C. Crate Dependency Graph**
```
jockey-language
    ↓ (uses)
jockey-core ← jockey-evidence
    ↓           ↓
jockey-runtime ← jockey-collectors
    ↓           ↓
jockey-correlation ← jockey-evidence
    ↓
jockey-api ← jockey-core, jockey-runtime, jockey-evidence, jockey-correlation
    ↓
jockey-cli ← jockey-language, jockey-core, jockey-runtime, jockey-evidence, jockey-correlation, jockey-api
```

---

**END OF AGENT CONTRACT**

*This document is the single source of truth for all AI agents working on JOCKY SIH 26148. Any deviation requires Coordinator approval and spec update.*