# JOCKY Project Handoff

**Project:** JOCKY Evidence-Contract Forensics Platform (SIH 26148)
**Date:** 2026-10-04
**Integrity Mode:** Development

## Current State

The previous agent team (`teamwork_preview`) was executing a full 6-phase build plan per `PROJECT.md` and `MASTER_PROMPT.md`. They hit an API quota limit and had to stop, but they made massive progress on the workspace compilation issues.

### ✅ Completed So Far
- **Phase 0 Codebase Survey**: Analyzed the full 8-crate workspace, identified 73+ compiler errors, and mapped out a 6-milestone project plan (`PROJECT.md`).
- **Milestone 1A**: Repaired `jockey-core`, `jockey-evidence`, and `jockey-language`.
  - Fixed invalid Pest PEG grammar string syntax.
  - Corrected `TargetSpec` re-exports and capability module references.
  - **Status:** `cargo check -p jockey-language` passes with 0 errors. All 17 language unit tests pass cleanly.
- **Milestone 1B**: Repaired `jockey-correlation` and `jockey-collectors`.
  - Deduplicated inline/file module definitions.
  - Added missing dependencies like `async-trait`.
  - **Status:** Both crates compile cleanly and pass all their unit tests.
- **E2E Testing Track**: Pairwise (Tier 3) and real-world lifecycle (Tier 4) test suites have been fully generated and pass on the working code.

### 🔄 Active / Interrupted
- **Milestone 1C**: The team was in the middle of fixing the downstream cascading errors in `jockey-runtime`, `jockey-api`, and `jockey-cli`.

## What Needs to Be Done Next

You are picking up the build process exactly where the previous team left off.

1. **Complete Milestone 1C**:
   - `jockey-runtime`: Fix `crate::contract`, `crate::collectors` imports to point to `jockey_core::*` and `jockey_collectors::*`. Add `serde` derives.
   - `jockey-api`: Clean up the duplicate module definitions in `lib.rs` (same issue that `jockey-correlation` had).
   - `jockey-cli`: Add `#[tokio::main]` to `main.rs` (or wrap `run_demo` in a block_on), add missing `hex` and `sha2` crate dependencies.
   - **Goal:** `cargo check --workspace` must exit with code 0.

2. **Proceed to Milestone 2 (Evidence Crypto Tests)**:
   - Implement the 7 tamper detection tests in `jockey-evidence` (see `PROJECT.md` or `MASTER_PROMPT.md` for the exact scenarios: bit flips, invalid receipts, broken provenance chains).

3. **Proceed to Milestones 3-6**:
   - M3: Language parser golden tests (`tests/golden/parser/`).
   - M4: Linux proc and file collector implementations (`proc_linux.rs`, `file_linux.rs`).
   - M5: SQLite storage, DAG runtime executor, and Correlation rules.
   - M6: CLI subcommand completion and demo script generation.

## Immediate First Step
Run `cargo check --workspace` to see the exact remaining errors in the `runtime`, `api`, and `cli` crates, and patch them so the full workspace compiles.