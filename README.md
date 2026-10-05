# JOCKY — Evidence-Contract Forensics Platform (SIH 26148)

> **Evidence-Contract Forensics Platform** — A Rust-based digital forensics platform for cryptographically verifiable evidence collection, correlation, and investigation.

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)]()
[![SIH](https://img.shields.io/badge/SIH-26148-red)]()

## Overview

JOCKY is a digital forensics platform that provides **cryptographically verifiable evidence collection, correlation, and investigation** capabilities. Built as a Rust workspace with 8 crates, it implements an end-to-end pipeline from DSL-based investigation definitions to cryptographically signed evidence receipts and 3D investigation graphs.

### Key Features

- **🔐 Evidence Integrity** — SHA-256 payload hashing + Ed25519 signed receipts with tamper detection
- **📝 DSL Language** — Pest PEG parser for investigation definitions (hypothesis, collect, correlate, timeline, export)
- **🔗 Deterministic Correlation** — Three rules: `pid_link`, `temporal_adjacent`, `evidence_support`
- **📊 3D Investigation Graphs** — Cytoscape.js compatible JSON with Three.js 3D rendering
- **🗄️ SQLite Storage** — 6-table relational schema with full provenance tracking
- **🖥️ Cross-Platform Collectors** — Linux (`proc_linux`, `file_linux`) and Windows collectors
- **📋 CLI Interface** — 8 subcommands: `compile`, `run`, `load`, `graph`, `verify`, `narrative`, `export`, `demo`

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        JOCKY WORKSPACE (8 crates)                       │
├─────────────────────────────────────────────────────────────────────────┤
│  jockey-language    │  Pest PEG parser → AST → Type-check → IR         │
│  jockey-core        │  IR, ExecutionContract, Policy, Storage, Target  │
│  jockey-evidence    │  Evidence, Receipts, Provenance, Verification    │
│  jockey-collectors  │  Collector trait, Linux/Windows implementations  │
│  jockey-runtime     │  DAG executor, dispatcher, registry, sandbox     │
│  jockey-correlation │  3 rules, InvestigationGraph, Cytoscape export   │
│  jockey-api         │  Axum REST + WebSocket server                    │
│  jockey-cli         │  8 subcommands, demo runner                      │
└─────────────────────────────────────────────────────────────────────────┘

Data Flow:
  1. .jky script → jockey-language → ExecutionContract
  2. ExecutionContract → jockey-runtime (DAG scheduler) → Collectors
  3. Collectors → jockey-evidence (SHA-256 + Ed25519 + Provenance)
  4. Runtime → jockey-core::storage (SQLite persistence)
  5. Evidence → jockey-correlation (rules → InvestigationGraph)
  6. Graph → jockey-cli (Cytoscape JSON → 3D render)
```

---

## Quick Start

### Prerequisites
- Rust 1.75+
- Linux (for `proc_linux`, `file_linux`) or Windows
- SQLite3 (for storage)

### Build
```bash
# Development build
cargo build --workspace

# Release build (optimized)
cargo build --release --workspace

# Run tests
cargo test --workspace

# Generate docs
cargo doc --workspace --no-deps
```

### Run Demo
```bash
# Full demo with evidence collection, receipts, and tamper detection
./target/release/jockey demo --os linux --evidence-root ./evidence

# Quick collect-only demo
./target/release/jockey run --input demo_collect.jky --os linux
```

### CLI Commands
```bash
# Compile investigation script to IR
jockey compile --input investigate.jky --format json --output ir.json

# Run investigation
jockey run --input investigate.jky --target localhost --os linux --evidence-root ./evidence

# Show investigation graph (Cytoscape JSON)
jockey graph show --format cytoscape

# Verify evidence integrity
jockey verify --evidence-root ./evidence

# Generate narrative report
jockey narrative --output report.md

# Export case data
jockey export --format case_uco --output case.json

# Load sample case
jockey load data/samples/sample_case

# Run automated demo
./scripts/run_demo.sh
```

---

## Investigation DSL Syntax

```jocky
investigation "investigation-name" {
    hypothesis "Description of hypothesis" {
        mitre: ["T1059", "T1059.001"]
    }
    
    # Collect evidence
    collect process as procs where name contains "svchost"
    collect file as configs where path matches "/etc/*"
    collect network as conns where destination_port == 443
    
    # Filter & match
    filter procs where cmdline contains "powershell"
    match configs where extension in [".conf", ".cfg"]
    
    # Correlate evidence
    correlate procs -> configs by "pid_link" as proc_config
    correlate procs -> conns by "temporal_adjacent" window 300s as proc_net
    
    # Timeline & binding
    timeline "activity" from proc_config, proc_net
    bind hypothesis "Suspicious activity" to proc_config
    
    # Export
    export case "my-case" format case_uco
    export graph "my-graph" format cytoscape
    export report "my-report" format markdown
}
```

### Supported Evidence Types
- `process` — Process enumeration, metadata, command lines
- `file` — File enumeration, hashing, collection, metadata
- `registry` — Windows registry enumeration
- `network` — Network connections, listeners, captures
- `log` — Event log queries, exports, tailing
- `config` — Configuration file enumeration

### Correlation Methods
| Method | Description | Parameters |
|--------|-------------|------------|
| `pid_link` | Parent-child process relationship | — |
| `temporal_adjacent` | Events within time window | `window <duration>` |
| `evidence_support` | Shared IOCs (IPs, hashes, paths, MITRE tags) | — |

---

## Evidence Integrity

JOCKY provides **cryptographic evidence integrity** with three-layer verification:

1. **SHA-256 Payload Hash** — Each evidence object has a canonical SHA-256 hash
2. **Ed25519 Receipts** — Collector signs receipt with per-collector keypair
3. **Provenance Chains** — Hash-linked records tracking evidence lifecycle

### Tamper Detection (7 Scenarios Tested)
| Scenario | Detection |
|----------|-----------|
| Evidence bit-flip | ✓ Detected via hash mismatch |
| Receipt signature tamper | ✓ Detected via Ed25519 verification |
| Provenance chain break | ✓ Detected via hash linking |
| Provenance output hash tamper | ✓ Detected via chain verification |
| Full investigation verification (valid) | ✓ PASS |
| Full investigation verification (tampered) | ✓ FAIL (detected) |
| Evidence sign/verify roundtrip | ✓ PASS |

---

## 3D Investigation Graphs

JOCKY exports Cytoscape.js-compatible JSON with 3D rendering support:

```bash
# Export graph
jockey graph show --format cytoscape > graph.json

# Open in 3D viewer
open graph_3d.html
```

The included `graph_3d.html` provides a Three.js-based 3D visualization with:
- Force-directed (COSE3D), sphere, grid, and circle layouts
- Real-time particle atmosphere
- Bloom post-processing
- Node/edge hover details
- Layout switching and animation controls

### 3D Rendering (Cytoscape.js)
```javascript
import cytoscape from 'cytoscape';
import cytoscape3d from 'cytoscape-3d';

cytoscape.use(cytoscape3d);

const cy = cytoscape({
  container: document.getElementById('cy'),
  elements: graphJson,
  layout: { name: 'cose3d', animate: true },
  style: [
    { selector: 'node', style: { 'background-color': 'data(type)', 'width': 60, 'height': 60 } },
    { selector: 'edge', style: { 'width': 'mapData(confidence,0,1,1,5)' } }
  ]
});
```

Color mapping: Process=Red, File=Blue, Registry=Orange, Network=Green, Log=Purple

---

## Project Structure

```
JOCKEY-SIH26148/
├── Cargo.toml                 # Workspace manifest
├── README.md                  # This file
├── HANDOFF.md                 # Project handoff document
├── PROJECT.md                 # Project plan & milestones
├── MASTER_PROMPT.md           # Master prompt
├── metrics_report.md          # Performance metrics
├── graph_3d.html              # 3D graph visualization
├── scripts/
│   ├── investigate.jky        # Demo investigation script
│   └── run_demo.sh            # 8-step demo automation
├── data/samples/sample_case/  # Synthetic forensic test data
│   ├── evidence/              # Evidence JSONL files
│   ├── receipts/              # Ed25519 receipts
│   └── provenance/            # Provenance chain records
└── crates/
    ├── jockey-core/           # Core domain model, storage
    ├── jockey-evidence/       # Evidence, receipts, provenance, verification
    ├── jockey-language/       # Parser, AST, typecheck, IR, golden tests
    ├── jockey-collectors/     # Collector trait + Linux/Windows impls
    ├── jockey-runtime/        # DAG executor, dispatcher, registry
    ├── jockey-correlation/    # 3 rules, graph, Cytoscape export
    ├── jockey-api/            # Axum REST/WebSocket server
    └── jockey-cli/            # CLI, demo runner
```

---

## Milestones Completed

| Milestone | Status | Description |
|-----------|--------|-------------|
| M1A | ✅ | Core crates: core, evidence, language |
| M1B | ✅ | Correlation & collectors |
| M1C | ✅ | Runtime, API, CLI compilation fixes |
| M2 | ✅ | 7 Evidence crypto tamper tests |
| M3 | 🔄 | 10 Golden tests (1/10 passing — parser needs `command_line`) |
| M4 | ✅ | Linux collectors (proc_linux, file_linux) |
| M5 | ✅ | SQLite storage, DAG runtime, 3 correlation rules |
| M6 | ✅ | CLI subcommands, demo, sample case |

---

## Performance Metrics (Release Build)

| Metric | Value |
|--------|-------|
| Binary size | 2.08 MB |
| Build time | ~5m 30s |
| Cold start (compile) | ~45ms |
| Evidence collection (187 procs) | ~120ms |
| Verification per evidence | ~11ms |
| Correlation (3 rules) | ~6ms |
| Binary sections | .text: 1.2MB, .rodata: 0.45MB |

---

## Compliance & Standards

| Standard | Implementation |
|----------|----------------|
| CASE/UCO Ontology | JSON-LD export compatible |
| STIX 2.1 | Indicator compatibility |
| MITRE ATT&CK | Full tagging support |
| NIST SP 800-86 | Evidence integrity chain |
| RFC 6920 | Named info hash (SHA-256) |
| RFC 8037 | Ed25519 signatures |

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgments

Built for **Smart India Hackathon 2024 (SIH 26148)** — Evidence-Contract Forensics Platform.

**Key Technologies:** Rust, Pest, Petgraph, Axum, Rusqlite, Ed25519-dalek, Three.js, Cytoscape.js

---

*JOCKY — Where Evidence Meets Integrity*
