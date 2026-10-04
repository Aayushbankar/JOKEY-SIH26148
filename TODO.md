# JOCKY SIH 26148 — TODO Tracking Board

**Last Updated:** 2026-10-04 | **Phase:** 0 (Compile Fix) | **Target:** Day 14 Demo Ready

---

## 📋 PHASE 0: COMPILE FIX (Days 1-2)

### CryptoAgent — jockey-evidence Fixes
- [ ] Add `hex = "0.4"` to Cargo.toml [workspace.dependencies]
- [ ] Fix `SigningKey::generate` → `SigningKey::from_bytes(random_bytes())`
- [ ] Fix `Signature::from_bytes` Result handling
- [ ] Add `use hex;` imports for encode/decode
- [ ] Fix `DateTime.abs()` → `signed_duration_since().num_seconds().abs()`
- [ ] Fix `sign_receipt` signature mismatch (Vec<u8> vs EvidenceReceipt)
- [ ] Implement `canonicalize.rs` with deterministic serde_json (sorted keys)
- [ ] Unit test: sign → verify PASS
- [ ] Unit test: tamper evidence → verify FAIL
- [ ] **HANDOFF_CRYPTO.md** written

### LangAgent — Parser Verification
- [ ] Verify `parser.pest` matches `docs/language/grammar.md`
- [ ] Fix any parser regressions
- [ ] **HANDOFF_LANG.md** written

### CoreAgent — Core Verification
- [ ] Verify IR/Contract/Policy/Storage compile
- [ ] Fix any rusqlite API issues
- [ ] **HANDOFF_CORE.md** written

### DevOpsAgent — CI/CD Fix
- [ ] Fix `.github/workflows/ci.yml` (modern actions)
- [ ] Ensure `cargo fmt --check --workspace` passes
- [ ] Ensure `cargo clippy --workspace -D warnings` passes
- [ ] **HANDOFF_DEVOPS.md** written

### Phase 0 Quality Gates
- [ ] `cargo check --workspace` → PASS
- [ ] `cargo clippy --workspace -D warnings` → PASS
- [ ] `cargo fmt --check --workspace` → PASS
- [ ] `cargo test --workspace` → PASS

---

## 📋 PHASE 1: LANGUAGE GOLDEN TESTS (Days 2-3)

### LangAgent — Golden Test Infrastructure
- [ ] Create `tests/golden/parser/*.jky` (10 scripts from `docs/language/examples.md`)
- [ ] Implement `tests/golden_runner.rs` (parse→AST→typecheck→IR→compare)
- [ ] Generate initial golden `ast/*.json` and `ir/*.json`
- [ ] Fix parser/typeck bugs revealed
- [ ] **HANDOFF_LANG.md** updated

### TestAgent — Property Tests
- [ ] Add proptest: parser roundtrip (parse→print→parse)
- [ ] Add fuzzing target for parser input
- [ ] **HANDOFF_TEST.md** written

### Phase 1 Quality Gates
- [ ] `cargo test -p jockey-language` → 10/10 golden tests PASS

---

## 📋 PHASE 2: EVIDENCE CRYPTO + VERIFICATION (Days 3-5)

### CryptoAgent — Complete Implementation
- [ ] `model.rs`: Evidence, EvidenceReceipt, ProvenanceRecord, Finding, CorrelationEdge
- [ ] `crypto.rs`: blake3_hash, generate_ed25519_keypair, sign, verify, generate_ulid
- [ ] `receipt.rs`: sign_receipt, verify_receipt (Ed25519 payload_hash||evidence_id||timestamp)
- [ ] `provenance.rs`: build_provenance_chain, verify_provenance_chain (hash-linked)
- [ ] `verify.rs`: VerificationEngine::verify_run (all receipts + provenance validation)
- [ ] **HANDOFF_CRYPTO.md** updated

### TestAgent — Tamper Detection Tests (CRITICAL)
- [ ] Test 1: Valid chain → VerificationReport { status: Pass }
- [ ] Test 2: Flip 1 evidence bit → Fail: "evidence hash mismatch"
- [ ] Test 3: Modify receipt signature → Fail: "receipt signature invalid"
- [ ] Test 4: Break provenance link → Fail: "provenance chain broken"
- [ ] Test 5: Modify provenance record → Fail: "provenance hash mismatch"
- [ ] **HANDOFF_TEST.md** updated

### Phase 2 Quality Gates
- [ ] `cargo test -p jockey-evidence` → 5+ tamper tests PASS

---

## 📋 PHASE 3: MINIMAL COLLECTORS (Days 5-8) — PARALLEL

### CollectorAgent-Win — Windows Collectors
- [ ] `proc_windows.rs`: Toolhelp32Snapshot → list processes → artifact/process
- [ ] `file_windows.rs`: FindFirstFileW/FindNextFileW → enumerate → artifact/file
- [ ] Manifests: capabilities ["process.list"], ["file.enumerate","file.hash"], Ed25519 keys
- [ ] **HANDOFF_COLLECTORS.md** written

### CollectorAgent-Lin — Linux Collectors
- [ ] `proc_linux.rs`: /proc/[pid]/stat, cmdline, exe → artifact/process (PARITY)
- [ ] `file_linux.rs`: std::fs recursive walk → artifact/file (PARITY)
- [ ] Manifests: same capabilities as Windows
- [ ] **HANDOFF_COLLECTORS.md** updated

### CoreAgent — Registry & Integration
- [ ] `collector_registry.rs`: load manifests, validate capabilities, store keypairs
- [ ] `manifest.rs`: CollectorManifest, ActionManifest, ParamSchema (JSON Schema)
- [ ] **HANDOFF_CORE.md** updated

### TestAgent — Collector Tests
- [ ] Contract tests: each implements Collector trait correctly
- [ ] Golden tests: output Evidence matches schema
- [ ] Synthetic data: `data/samples/` with known process/file structures
- [ ] **HANDOFF_TEST.md** updated

### Phase 3 Quality Gates
- [ ] `cargo test -p jockey-collectors` → 4 collectors PASS
- [ ] Evidence output matches schema on both platforms

---

## 📋 PHASE 4: RUNTIME E2E EXECUTION (Days 8-10)

### RuntimeAgent — Executor Implementation
- [ ] `executor.rs`: execute(contract) → topological sort → dispatch with timeout/retry → store Evidence+Receipt+Provenance
- [ ] `dispatcher.rs`: async with semaphore for policy.parallelism
- [ ] `sandbox.rs`: chroot evidence_root, env sanitize, rlimit
- [ ] **HANDOFF_RUNTIME.md** written

### CoreAgent — Storage & Contract Completion
- [ ] `storage.rs`: complete SQLite CRUD for all tables (§17)
- [ ] `contract.rs`: build_contract(ir, target, policy) with full validation
- [ ] **HANDOFF_CORE.md** updated

### TestAgent — E2E Integration
- [ ] Golden IR → Contract → execute → verify SQLite has evidence+receipts+provenance
- [ ] Verify `jockey verify` CLI works on this run
- [ ] **HANDOFF_TEST.md** updated

### Phase 4 Quality Gates
- [ ] `cargo test -p jockey-runtime` → E2E PASS
- [ ] `jockey run sample.jky` produces valid evidence bundle

---

## 📋 PHASE 5: CORRELATION + GRAPH (Days 10-12)

### CorrelationAgent — Engine & Graph
- [ ] `rules.rs`: 9 deterministic rules (pid_link, file_write, file_read, net_connect, ioc_match, yara_match, rule_match, evidence_support, temporal_adjacent)
- [ ] `engine.rs`: correlate(evidence, rules) → CorrelationEdge
- [ ] `graph.rs`: InvestigationGraph (petgraph), queries: path, backward_from, forward_from, hypothesis_support, subgraph, graph_at
- [ ] `hypothesis.rs`: MITRE tags, confidence, evidence bindings
- [ ] **HANDOFF_CORRELATION.md** written

### TestAgent — Correlation Tests
- [ ] Golden: synthetic evidence → expected edges → queries correct
- [ ] Property: graph query invariants
- [ ] **HANDOFF_TEST.md** updated

### Phase 5 Quality Gates
- [ ] `cargo test -p jockey-correlation` → PASS
- [ ] Cytoscape JSON export valid

---

## 📋 PHASE 6: CLI + DEMO AUTOMATION (Days 12-14) — MAKE OR BREAK

### CLIAgent — Complete CLI
- [ ] `run <script.jky> --target --host --policy`
- [ ] `compile <script.jky> --output-dir` → VQL, KAPE targets, CASE stubs
- [ ] `graph show --run-id --format`
- [ ] `verify --run-id [--evidence]`
- [ ] `export --run-id --format <case_uco|cytoscape|timesketch|markdown>`
- [ ] `load <sample_case_dir>`
- [ ] `narrative --run-id` → Markdown with [Evidence: ULID] citations
- [ ] `serve --addr` → starts API + frontend
- [ ] Error handling: friendly messages, exit codes, structured logging
- [ ] **HANDOFF_CLI.md** written

### DevOpsAgent — Demo Automation (CRITICAL)
- [ ] `scripts/run_demo.sh` — 8 steps from ROADMAP.md
- [ ] Pre-recorded demo video (asciinema)
- [ ] Release build: `cargo build --release --workspace` → strip → verify <50MB
- [ ] Cross-platform test: binary on Windows 10/11 + Ubuntu 22.04/24.04
- [ ] **HANDOFF_DEVOPS.md** updated

### TestAgent — Full E2E
- [ ] Script → run → graph → verify → export → narrative
- [ ] **HANDOFF_TEST.md** updated

### Phase 6 Quality Gates
- [ ] Demo script runs <8 min reliably
- [ ] Binary <50MB
- [ ] Tamper demo works (modify → FAIL → restore → PASS)

---

## 📋 PHASE 7: API + FRONTEND (Days 14-16) — STRETCH

### APIAgent — Axum Server (ONLY IF PHASE 6 COMPLETE)
- [ ] `server.rs`: REST + WS per spec §16
- [ ] `ws.rs`: step_started, evidence_collected, correlation_found, verification_result
- [ ] AppState: DB pool, runtime handle, investigation cache
- [ ] **HANDOFF_API.md** written

### FrontendAgent — 8 Static Pages (ONLY IF PHASE 6 COMPLETE)
- [ ] `frontend/`: index, investigation, graph, timeline, evidence, findings, verify, report
- [ ] Cytoscape.js (graph), Chart.js (timeline), marked.js (report), Lucide icons
- [ ] `frontend/lib/` local CDN fallbacks
- [ ] ServeDir for static assets
- [ ] **HANDOFF_FRONTEND.md** written

### Phase 7 Quality Gates
- [ ] `jockey serve` → browser at localhost:8080 works

---

## 🎯 SIH SUBMISSION CHECKLIST (Day 14-16)

- [ ] `cargo build --release --workspace` succeeds
- [ ] Binary `target/release/jockey` <50MB
- [ ] Binary runs on Windows 10/11 + Ubuntu 22.04/24.04
- [ ] `scripts/run_demo.sh` executes <8 min, all 8 steps pass
- [ ] Tamper detection demonstrated live (Step 7)
- [ ] Pre-recorded demo video uploaded
- [ ] `JOCKY_SPEC_SHEET.md` matches implementation
- [ ] `README.md` updated with actual commands
- [ ] `CHANGELOG.md` updated with v0.1.0 release notes
- [ ] GitHub Release: binary + SHA256 checksums + demo video
- [ ] Judge Q&A doc printed (25 Q&A from `docs/evaluation/judge-questions.md`)
- [ ] Team can explain architecture in 2 min

---

## 🚨 ACTIVE BLOCKERS (Update in Real-Time)

| Blocker | Owner | Since | ETA | Resolution |
|---------|-------|-------|-----|------------|
| jockey-evidence compilation fails | CryptoAgent | Day 0 | Day 1 | In progress |
| No golden test infrastructure | LangAgent | Day 0 | Day 2 | Not started |
| No collector implementations | CollectorAgents | Day 0 | Day 8 | Not started |
| No synthetic test data | TestAgent | Day 0 | Day 5 | Not started |

---

## 📊 METRICS (Track Daily)

| Metric | Target | Current | Date |
|--------|--------|---------|------|
| Binary size (release) | <50MB | — | — |
| Unit test count | >200 | — | — |
| Integration test count | >20 | — | — |
| Golden tests (language) | 10 | 0 | — |
| Tamper detection tests | 5 | 0 | — |
| Working collectors | 4 (proc/file Win+Lin) | 0 | — |
| Demo runtime | <8 min | — | — |
| Compilation targets | 5 | 0 | — |
| Evidence receipts % | 100% | 0% | — |
| Provenance chain integrity | 100% | 0% | — |

---

## 📝 DECISIONS LOG (Immutable)

| Date | Decision | Rationale | Author |
|------|----------|-----------|--------|
| 2026-10-04 | Use ed25519-dalek 2.2 (pinned) | Stable API, avoid breaking changes | Coordinator |
| 2026-10-04 | Only `list`/`enumerate` collectors for MVP | Scope control, timeline | Coordinator |
| 2026-10-04 | Phase 7 (API/Frontend) is stretch | Demo reliability > features | Coordinator |
| 2026-10-04 | Synthetic data only for demo | No real host access in Termux | Coordinator |

---

**Update this file after EVERY agent completion. Post blockers to BLOCKERS.md immediately.**