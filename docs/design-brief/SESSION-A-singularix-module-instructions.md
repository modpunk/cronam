# SESSION A: Build Ralph as a Singularix Module (Celery Worker Crate)

## Context for this session

You are continuing work on the Ralph safe file ingestion and agent isolation architecture. Ralph is a security orchestrator with 31 security layers that safely processes untrusted files (PDFs, DOCX, CSV, JSON, NEAR blockchain data) through tiered agent spokes (zeroclaw/ironclaw/openfang).

**This session's goal:** Implement Ralph as a Singularix module — a Rust-based Celery worker crate that any Singularix project can route file-processing tasks to.

**Parallel session:** A separate chat is packaging the architecture knowledge into a reusable `.skill` file (Option B). This session focuses on the runtime implementation only.

**Future milestone (DO NOT FORGET):** After this module is battle-tested across 2-3 projects, the next step is **Option C — promoting Ralph into the Singularix trunk** as core platform infrastructure. This is the endgame. The module approach is the proving ground.

---

## Files uploaded with this session

Upload ALL of the following files from the project:

### Architecture docs (read these first):
1. `CHECKPOINT-ralph-safe-ingestion-v2-2026-03-22.md` — **Start here.** Current state, 31-layer architecture diagram, phasing, next steps.
2. `consolidated-audit-findings-v1.md` — Master finding-to-layer mapping. All 40 audit findings. New layer specs (25-31). Remediation roadmap.
3. `adopted-features-implementation-v2.md` — 31-layer table. Full Rust implementations for layers 25-31 (HTTP proxy, handoff integrity, rate limiter, guardrail LLM, plan validator, error sanitizer, degradation matrix). Updated Ralph main loop.
4. `version-changelog-v1-to-v2.md` — Surgical v2 edits for the 5 original files.

### Original architecture (reference — v1, being upgraded):
5. `safe-file-ingestion-v2.md` — Core architecture. Hub-and-spoke design. Agent tiers. Dual LLM pattern.
6. `wasm-boundary-deep-dive.md` — Three sandboxes per task. Credential injection. SpokeRunner implementation.
7. `critical-remediations.md` — Full Rust code for original 4 criticals. Variable store. Trifecta break.
8. `adopted-features-implementation.md` — Original 24-layer implementations. SecretString, endpoint allowlisting, SSRF guard, leak scanner, approval gates, Merkle chain, Ed25519 signing.
9. `security-audit-findings.md` — Original 12 findings.
10. `security-layer-comparison.md` — IronClaw/OpenFang comparison.
11. `security-expert-audit-sparring.md` — Marcus/Diane audit. 28 findings. 657 lines.

---

## What to build

### 1. Rust workspace scaffold

```
ralph/
├── Cargo.toml                    # Workspace root
├── crates/
│   ├── ralph-core/               # Core types: ResultEnvelope, VarRef, VarMeta, TaskPlan, etc.
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── types.rs          # Shared types across all crates
│   │       ├── envelope.rs       # ResultEnvelope schema
│   │       └── error.rs          # SanitizedError (Layer 30)
│   │
│   ├── ralph-security/           # Security layers that run in Ralph (not in spokes)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── output_auditor.rs     # Layer 12 v2
│   │       ├── leak_scanner.rs       # Layer 19 v2
│   │       ├── ssrf_guard.rs         # Layer 20 v2 (DNS pinning)
│   │       ├── endpoint_allowlist.rs # Layer 18 v2 (no redirects)
│   │       ├── approval_gate.rs      # Layer 21 v2 (receipt binding)
│   │       ├── rate_limiter.rs       # Layer 27
│   │       ├── guardrail_llm.rs      # Layer 28
│   │       ├── degradation.rs        # Layer 31
│   │       └── handoff_integrity.rs  # Layer 26
│   │
│   ├── ralph-spoke/              # Spoke runner: WASM sandbox management
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── runner.rs             # SpokeRunner with hardened Wasmtime config (Layer 14)
│   │       ├── seccomp.rs            # Layer 13 v2 (default Deny, no network)
│   │       ├── http_proxy.rs         # Layer 25 (separate process)
│   │       ├── host_functions.rs     # host_read_input (v2: 64-bit bounds), host_write_output (v2: inline size)
│   │       ├── variable_store.rs     # Layer 9 v2 (label sanitization, size limits, coarse buckets)
│   │       ├── credential_store.rs   # Layer 17
│   │       └── manifest.rs           # Layer 23 v2 (Ed25519 + SLSA)
│   │
│   ├── ralph-openfang/           # Openfang dual-LLM pattern
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── q_llm.rs              # Layer 8 v2 (tool_use stripping)
│   │       ├── p_llm.rs              # Plan generation
│   │       ├── plan_validator.rs     # Layer 29
│   │       ├── capability_gate.rs    # Layer 10
│   │       ├── renderer.rs           # Output renderer
│   │       └── trifecta_verify.rs    # Layer 11 v2 (runtime verification)
│   │
│   ├── ralph-audit/              # Merkle audit chain
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       └── merkle_chain.rs       # Layer 22 v2 (NEAR anchoring)
│   │
│   └── ralph-worker/             # Singularix integration: Celery worker
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── main.rs               # Celery worker entry point
│           ├── tasks.rs              # Celery task definitions (process_file, analyze_document, etc.)
│           ├── agent_selector.rs     # Layer 16 v2 (tier floor, field classifier)
│           └── orchestrator.rs       # Ralph main loop (31 layers)
│
├── parsers/                      # WASM parser modules (compiled to wasm32-wasi)
│   ├── json-parser/
│   ├── csv-parser/
│   ├── pdf-parser/
│   └── docx-parser/
│
└── tests/
    ├── capability_gate_proptest.rs    # Test category 1
    ├── injection_scanner_fuzz.rs      # Test category 2
    ├── variable_store_isolation.rs    # Test category 3
    ├── trifecta_verification.rs       # Test category 4
    ├── seccomp_regression.rs          # Test category 5
    ├── output_auditor_adversarial.rs  # Test category 6
    ├── merkle_chain_integrity.rs      # Test category 7
    └── cross_task_isolation.rs        # Test category 8
```

### 2. Implementation priority

**Start with Phase 1 Quick Wins (estimated 2 hours):**
- `ralph-spoke/seccomp.rs` — Flip default to Deny. Remove network syscalls.
- `ralph-spoke/variable_store.rs` — Label sanitization. Size limits. Coarse buckets.
- `ralph-spoke/host_functions.rs` — Inline size check. 64-bit bounds.
- `ralph-core/error.rs` — SanitizedError type.
- All crate roots: `#![deny(unsafe_code)]`

**Then Phase 1 full:**
- `ralph-spoke/runner.rs` — Hardened Wasmtime engine config.
- `ralph-spoke/credential_store.rs` — SecretString with zeroization.
- `ralph-spoke/http_proxy.rs` — Separate process for HTTP.

**Then wire up Singularix:**
- `ralph-worker/main.rs` — Celery worker that connects to Singularix's Redis broker.
- `ralph-worker/tasks.rs` — `process_file` task that accepts (file_path, task_description, options) and returns ResultEnvelope.
- `ralph-worker/orchestrator.rs` — The 31-layer main loop.

### 3. Singularix integration points

Ralph as a Celery worker needs:
- **Redis broker** — shared with Singularix trunk. Ralph registers as a worker consuming from the `ralph.file_ingestion` queue.
- **Task interface** — Singularix trunk/branches submit tasks via `ralph.process_file.delay(file_path, task_desc, opts)`. Returns a Celery AsyncResult with the ResultEnvelope.
- **Credential sharing** — Ralph reads API keys from the same credential source as Singularix (env vars Phase 1, KMS Phase 4).
- **Audit chain** — Ralph's Merkle audit chain writes to the same PostgreSQL instance as Singularix, in a `ralph_audit` schema.

### 4. Key constraints

- All code in Rust. WASM parsers compile to `wasm32-wasi`.
- `#![deny(unsafe_code)]` on every crate except `ralph-spoke` (which needs `unsafe` for seccompiler BPF application — document with `// SAFETY:` comments).
- Wasmtime pinned to `=42.0.1` (or latest patched).
- `secrecy` + `zeroize` crates for all credential handling.
- Every security component fails closed (see Layer 31 degradation matrix).

---

## Success criteria

The module is done when:
1. `cargo build --workspace` succeeds with zero warnings
2. All 8 test categories pass
3. A Singularix trunk can submit `ralph.process_file("test.pdf", "summarize this document")` and receive a valid ResultEnvelope
4. The seccomp filter defaults to Deny and the spoke runner has zero network syscalls
5. The variable store never exposes actual values to the P-LLM prompt
6. The output auditor catches the PromptArmor ICLR 2026 test corpus at >80% rate
