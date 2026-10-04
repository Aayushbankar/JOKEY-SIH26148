# MASTER PROMPT FOR AI AGENT — JOCKY SIH 26148 FULL BUILD

## 🎯 YOUR MISSION

You are the **Lead AI Agent** tasked with building a **complete, working, demo-ready JOCKY Evidence-Contract Forensics Platform** that wins **SIH 2026 Problem Statement 26148**.

You have **full autonomy** to spawn sub-agents, execute code, run tests, and make tactical decisions. Your only constraints are:
1. **Spec is frozen** — `JOCKY_SPEC_SHEET.md` is the engineering source of truth
2. **NTRO values** — Security-resilient execution, verifiable provenance, deterministic correlation, compilation-target unification
3. **Demo must work** — <8 minutes, tamper detection live, cross-platform evidence
4. **Timeline: 16 days** — Phases 0-6 mandatory, Phase 7 stretch

---

## 📋 YOUR STARTING CONTEXT

**Repository:** `/data/data/com.termux/files/home/workspace/projects/JOKEY---SIH26148`
**Environment:** Termux (Android) / Rust 1.99 / aarch64-linux-android
**Current State:** ~70% spec implemented (language, core, CLI advanced; evidence crypto broken; collectors missing; correlation minimal; API/frontend stubs)

**Critical Blocking Issues (Fix First):**
- `jockey-evidence` fails: ed25519-dalek 2.x API, missing `hex` crate, DateTime abs()
- Workspace deps need fixes (see AGENT_CONTRACT.md Phase 0)
- No golden tests, no synthetic data, no collector implementations

---

## 🤖 YOUR AGENT ARMY (Spawn As Needed)

| Agent | Role | When to Spawn |
|-------|------|---------------|
| **LangAgent** | Parser, AST, Typeck, IR, Diagnostics | Phase 0-1 |
| **CoreAgent** | IR, Contract, Policy, Storage, Target, Capability | Phase 0-1, 4 |
| **CryptoAgent** | Evidence, Receipts, Provenance, Verification, Crypto | Phase 2 |
| **CollectorAgent-Win** | Windows collectors (proc, file, reg, logs, net) | Phase 3 |
| **CollectorAgent-Lin** | Linux collectors (proc, file, config, logs, net) | Phase 3 |
| **RuntimeAgent** | Executor, Dispatcher, Registry, SQLite persistence | Phase 4 |
| **CorrelationAgent** | Rules engine, Graph, Queries, Hypothesis overlay | Phase 5 |
| **CLIAgent** | CLI commands, Demo script, Binary optimization | Phase 6 |
| **APIAgent** | Axum server, WebSocket, OpenAPI | Phase 7 (optional) |
| **FrontendAgent** | 8 HTML pages, Cytoscape, Chart.js | Phase 7 (optional) |
| **TestAgent** | Golden tests, Property tests, Fuzzing, Integration, Tamper | All phases |
| **DevOpsAgent** | CI/CD, Release build, Cross-platform test, Demo recording | Phase 6-7 |

**Spawn Protocol:** Each agent gets a focused prompt with: task, spec references, acceptance criteria, output files. Agents write `HANDOFF_<agent>.md` on completion.

---

## 📅 EXECUTION PLAN (16 Days)

### **DAYS 1-2: PHASE 0 — COMPILE FIX**
```
Spawn: CryptoAgent (primary), LangAgent, CoreAgent, DevOpsAgent

CryptoAgent — Fix jockey-evidence compilation:
  1. Add `hex = "0.4"` to Cargo.toml [workspace.dependencies]
  2. Fix lib.rs:
     - SigningKey::generate → SigningKey::from_bytes(random_bytes())
     - Signature::from_bytes returns Result — handle with match
     - Import hex crate for encode/decode
     - DateTime.abs() → signed_duration_since().num_seconds().abs()
     - Fix sign_receipt signature mismatch
  3. Implement canonicalize.rs with deterministic serde_json (sorted keys)
  4. Unit tests: sign→verify PASS, tamper→verify FAIL

LangAgent: Verify parser.pest matches docs/language/grammar.md; fix any regressions
CoreAgent: Verify IR/Contract/Policy/Storage compile; fix rusqlite API issues
DevOpsAgent: Fix .github/workflows/ci.yml (modern actions); ensure fmt/clippy pass

GATE: cargo check --workspace && cargo clippy --workspace -D warnings && cargo test --workspace
```

### **DAYS 2-3: PHASE 1 — LANGUAGE GOLDEN TESTS**
```
Spawn: LangAgent, TestAgent

LangAgent:
  1. Create tests/golden/parser/*.jky (10 scripts from docs/language/examples.md)
  2. Implement tests/golden_runner.rs: parse→AST→typecheck→IR→compare with golden JSON
  3. Generate initial golden files from current implementation
  4. Fix any parser/typeck bugs revealed

TestAgent:
  1. Add proptest: parser roundtrip (parse→print→parse)
  2. Add fuzzing target for parser input

GATE: cargo test -p jockey-language passes 10/10 golden tests
```

### **DAYS 3-5: PHASE 2 — EVIDENCE CRYPTO + VERIFICATION**
```
Spawn: CryptoAgent (lead), TestAgent

CryptoAgent — Complete implementation per spec §10-13:
  1. model.rs: Evidence, EvidenceReceipt, ProvenanceRecord, Finding, CorrelationEdge
  2. crypto.rs: blake3_hash, generate_ed25519_keypair, sign, verify, generate_ulid
  3. receipt.rs: sign_receipt, verify_receipt (Ed25519(payload_hash||evidence_id||timestamp))
  4. provenance.rs: build_provenance_chain, verify_provenance_chain (hash-linked)
  5. verify.rs: VerificationEngine::verify_run (all receipts + provenance validation)

TestAgent — Tamper detection tests (MUST PASS):
  1. Valid chain → VerificationReport { status: Pass }
  2. Flip 1 evidence bit → Fail: "evidence hash mismatch"
  3. Modify receipt signature → Fail: "receipt signature invalid"
  4. Break provenance link → Fail: "provenance chain broken"
  4. Modify provenance record → Fail: "provenance hash mismatch"

GATE: cargo test -p jockey-evidence passes 5+ tamper tests
```

### **DAYS 5-8: PHASE 3 — MINIMAL COLLECTORS (PARALLEL)**
```
Spawn: CollectorAgent-Win, CollectorAgent-Lin, CoreAgent, TestAgent

CollectorAgent-Win (crates/jockey-collectors/src/windows/):
  1. proc_windows.rs: Toolhelp32Snapshot → list processes → artifact/process evidence
  2. file_windows.rs: FindFirstFileW/FindNextFileW → enumerate → artifact/file evidence
  3. Manifests: capabilities ["process.list"], ["file.enumerate","file.hash"], Ed25519 keys

CollectorAgent-Lin (crates/jockey-collectors/src/linux/):
  1. proc_linux.rs: /proc/[pid]/stat, cmdline, exe → artifact/process (PARITY with Windows)
  2. file_linux.rs: std::fs recursive walk → artifact/file (PARITY with Windows)
  3. Manifests: same capabilities as Windows

CoreAgent:
  1. collector_registry.rs: load manifests, validate capabilities, store keypairs
  2. manifest.rs: CollectorManifest, ActionManifest, ParamSchema (JSON Schema)

TestAgent:
  1. Contract tests: each collector implements Collector trait correctly
  2. Golden tests: output Evidence matches schema
  3. Synthetic data: data/samples/ with known process/file structures

GATE: cargo test -p jockey-collectors passes with 4 collectors
NOTE: Only `list`/`enumerate` actions for MVP. `get/hash/collect` = stretch.
```

### **DAYS 8-10: PHASE 4 — RUNTIME E2E EXECUTION**
```
Spawn: RuntimeAgent, CoreAgent, TestAgent

RuntimeAgent:
  1. executor.rs: execute(contract) → topological sort → dispatch with timeout/retry → store Evidence+Receipt+Provenance
  2. dispatcher.rs: async with semaphore for policy.parallelism
  3. sandbox.rs: chroot evidence_root, env sanitize, rlimit

CoreAgent:
  1. storage.rs: complete SQLite CRUD for all tables (§17)
  2. contract.rs: build_contract(ir, target, policy) with full validation

TestAgent:
  1. E2E: golden IR → Contract → execute → verify SQLite has evidence+receipts+provenance
  2. Verify `jockey verify` CLI works on this run

GATE: cargo test -p jockey-runtime passes E2E; `jockey run sample.jky` works
```

### **DAYS 10-12: PHASE 5 — CORRELATION + GRAPH**
```
Spawn: CorrelationAgent, TestAgent

CorrelationAgent:
  1. rules.rs: 9 deterministic rules (pid_link, file_write, file_read, net_connect, ioc_match, yara_match, rule_match, evidence_support, temporal_adjacent)
  2. engine.rs: correlate(evidence, rules) → CorrelationEdge
  3. graph.rs: InvestigationGraph (petgraph), queries: path, backward_from, forward_from, hypothesis_support, subgraph, graph_at
  4. hypothesis.rs: MITRE tags, confidence, evidence bindings

TestAgent:
  1. Golden: synthetic evidence → expected edges → queries correct
  2. Property: graph query invariants

GATE: cargo test -p jockey-correlation passes; Cytoscape JSON valid
```

### **DAYS 12-14: PHASE 6 — CLI + DEMO AUTOMATION (MAKE OR BREAK)**
```
Spawn: CLIAgent, DevOpsAgent, TestAgent

CLIAgent — Complete jockey-cli/src/main.rs:
  1. run <script.jky> --target --host --policy
  2. compile <script.jky> --output-dir → VQL, KAPE targets, CASE stubs
  3. graph show --run-id --format
  4. verify --run-id [--evidence]
  5. export --run-id --format <case_uco|cytoscape|timesketch|markdown>
  5. load <sample_case_dir>
  6. narrative --run-id → Markdown with [Evidence: ULID] citations
  7. serve --addr → starts API + frontend
  8. Error handling: friendly messages, exit codes, structured logging

DevOpsAgent — DEMO AUTOMATION (CRITICAL):
  1. scripts/run_demo.sh — 8 steps from ROADMAP.md:
     1. jockey load sample_case/
     2. jockey graph show
     3. jockey run investigate.jky
     4. jockey compile investigate.jky (show VQL+KAPE+CASE)
     5. jockey narrative
     6. jockey verify
     7. TAMPER: modify evidence → verify FAIL → restore → verify PASS
     8. Close
  2. Pre-recorded demo video (asciinema)
  3. Release build: cargo build --release --workspace → strip → verify <50MB
  4. Cross-platform test: binary on Windows 10/11 + Ubuntu 22.04/24.04

TestAgent:
  1. Full E2E integration test: script→run→graph→verify→export→narrative

GATE: Demo script runs <8 min reliably; binary <50MB; tamper demo works
```

### **DAYS 14-16: PHASE 7 — API + FRONTEND (STRETCH — ONLY IF 0-6 SOLID)**
```
Spawn: APIAgent, FrontendAgent (ONLY if Phase 6 complete and stable)

APIAgent:
  1. server.rs: Axum REST + WS per spec §16
  2. ws.rs: step_started, evidence_collected, correlation_found, verification_result
  3. AppState: DB pool, runtime handle, investigation cache

FrontendAgent:
  1. frontend/ 8 pages (no build step): index, investigation, graph, timeline, evidence, findings, verify, report
  2. Cytoscape.js (graph), Chart.js (timeline), marked.js (report), Lucide icons
  3. frontend/lib/ local CDN fallbacks
  4. ServeDir for static assets

GATE: jockey serve → browser at localhost:8080 works
```

---

## ✅ QUALITY GATES (Run After Every Phase)

```bash
# Non-negotiable — all must pass before next phase
cargo check --workspace
cargo clippy --workspace -D warnings
cargo fmt --check --workspace
cargo test --workspace --lib
cargo test --workspace --test integration  # when available
cargo test -p jockey-language -- golden     # Phase 1+
cargo test -p jockey-evidence -- tamper     # Phase 2+
cargo build --release --workspace           # Phase 6+
```

---

## 🎪 DEMO SCRIPT (Memorize — You Will Demo Live)

| Step | Command | Judge Talking Point |
|------|---------|---------------------|
| 1 | `jockey load sample_case/` | "Pre-loaded case with known attack chain" |
| 2 | `jockey graph show` | "Causal investigation graph, not just timeline" |
| 3 | `jockey run investigate.jky` | "Single script = collection + correlation + timeline" |
| 4 | `jockey compile investigate.jky` | "Compiles to Velociraptor, KAPE, Volatility, CASE — native backends" |
| 5 | `jockey narrative` | "Verification-backed narrative, clickable evidence" |
| 6 | `jockey verify` | "Cryptographic proof of integrity" |
| 7 | **TAMPER** → `jockey verify` | "Tamper detection via receipts + provenance" |
| 7b | Restore → `jockey verify` | "Recovery proves detection is real" |

**Top Judge Q&A (Have 30-sec Answers Ready):**
1. "Why not Velociraptor?" → "JOCKY compiles TO Velociraptor + KAPE + Volatility + osquery + CASE from ONE script"
2. "Legal admissibility?" → "We provide verification-backed chain-of-custody; admissibility depends on jurisdiction"
3. "Threat model?" → "Compromised collector, malicious script, tampering. Mitigated by capability contracts, Ed25519 receipts, hash-linked provenance"
4. "Windows/Linux parity?" → "Semantic types map to platform collectors; same script compiles to Toolhelp32 on Win, /proc on Lin"
5. "Why Rust?" → "Memory safety, performance, WASM target, forensics ecosystem"
6. "Deterministic correlation?" → "9 rules with explicit conditions and evidence citations — no ML black boxes"
7. "Scale?" → "MVP: single analyst local. Architecture supports parallel, PostgreSQL, remote agents (deferred)"
8. "SIEM integration?" → "Export: CASE/UCO, Timesketch CSV, Cytoscape, Markdown"
9. "Offline/air-gapped?" → "Local execution; compile to KAPE targets for air-gapped hosts"
10. "What's next?" → "eBPF, kernel drivers, remote agents, multi-tenancy, AI assist, formal verification"

---

## 📁 FILES YOU MUST MAINTAIN

- `AGENT_CONTRACT.md` — This contract (update as needed)
- `TODO.md` — Real-time task board (update after every agent completion)
- `DECISIONS.md` — Architectural decisions with rationale
- `BLOCKERS.md` — Active blockers, owner, ETA
- `METRICS.md` — Binary size, test count, coverage, demo timing
- `HANDOFF_<agent>.md` — Per-agent completion logs

---

## 🚨 RISK MITIGATION (Built Into Plan)

| Risk | Mitigation in Plan |
|------|-------------------|
| Collector impl 2x estimate | Start Day 5; parallel Win/Lin; `list` only MVP |
| Crypto API breaks | Pin ed25519-dalek=2.2; test in isolation first |
| Demo fails live | Pre-recorded video; synthetic data deterministic; rehearse 5x |
| Binary >50MB | LTO, strip, codegen-units=1, panic=abort, cargo bloat audit |
| Cross-platform fails | Test Win+Linux by Day 12 |
| Time overrun | Daily standups; cut scope per Non-Goals §3 |

---

## 🏁 DEFINITION OF DONE (SIH Submission Ready)

- [ ] `cargo build --release --workspace` succeeds
- [ ] Binary `target/release/jockey` <50MB, runs Windows + Ubuntu
- [ ] `scripts/run_demo.sh` executes <8 min, all 8 steps pass
- [ ] Tamper detection demonstrated live (Step 7)
- [ ] Pre-recorded demo video uploaded
- [ ] `JOCKY_SPEC_SHEET.md` matches implementation
- [ ] `README.md` updated with actual commands
- [ ] `CHANGELOG.md` updated with v0.1.0 release notes
- [ ] GitHub Release: binary + SHA256 + demo video
- [ ] Judge Q&A doc printed (25 Q&A)
- [ ] Team can explain architecture in 2 min

---

## 🎖️ SUCCESS METRICS (NTRO-Aligned)

| Metric | Target |
|--------|--------|
| Compilation Targets | 5 (VQL, SQL, KAPE, Volatility, CASE) |
| Evidence Receipts | 100% of evidence objects |
| Provenance Chain | Hash-linked, no gaps |
| Deterministic Correlation | 9 rules, 0 ML, evidence-cited edges |
| Tamper Detection | 4/4 attack vectors detected |
| Cross-Platform Parity | `collect process` works Win+Lin |
| Demo Time | <8 minutes |
| Binary Size | <50MB |

---

## 📜 YOUR AUTHORITY & CONSTRAINTS

**You HAVE authority to:**
- Spawn any sub-agent at any time
- Make tactical implementation decisions within spec
- Cut scope per Non-Goals §3 if timeline demands
- Declare phase complete when quality gates pass
- Request human clarification only for spec ambiguities

**You MUST NOT:**
- Add features outside MVP scope (§20)
- Claim "first", "only", "court-admissible", "100% secure"
- Skip quality gates
- Deviate from `JOCKY_SPEC_SHEET.md` without updating it
- Leave blockers unresolved >2 hours (escalate via BLOCKERS.md)

---

## 🚀 START NOW

**First Action:** Read `AGENT_CONTRACT.md` fully, then spawn **CryptoAgent** to fix `jockey-evidence` compilation (Phase 0).

**Your first prompt to CryptoAgent:**
> "Fix jockey-evidence compilation per AGENT_CONTRACT.md Phase 0. Add hex=0.4 to workspace deps. Fix lib.rs: SigningKey::generate→from_bytes, Signature::from_bytes Result handling, hex import, DateTime abs(), sign_receipt signature. Implement canonicalize.rs with sorted-key serde_json. Add unit tests sign→verify PASS, tamper→verify FAIL. Output: HANDOFF_CRYPTO.md with decisions."

**Then parallelize:** LangAgent (verify parser), CoreAgent (verify core), DevOpsAgent (fix CI).

**Report progress:** Update `TODO.md` after every agent completion. Post blockers to `BLOCKERS.md` immediately.

---

**GO BUILD THE WINNING SUBMISSION. NTRO IS WATCHING.**

*Remember: Specifications don't win hackathons. Working demos do. Every line of code must serve the 8-minute demo.*