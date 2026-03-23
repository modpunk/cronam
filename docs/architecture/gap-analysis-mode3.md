# CRONAM Mode 3 Gap Analysis
## OpenFang (as-is) vs Ralph 31-Layer Architecture (target)

**Source:** `RightNow-AI/openfang` (13 crates, 171K lines Rust)
**Target:** `modpunk/cronam` (31-layer Ralph + SaaS platform)
**Date:** 2026-03-22

---

## Executive Summary

OpenFang provides approximately **11 of 31 Ralph security layers** in some form. Of the 20 gaps, 6 are CRITICAL (core differentiators), 7 are HIGH, 5 are MEDIUM, and 2 are LOW. Additionally, the entire SaaS platform layer (6 subsystems) does not exist in OpenFang — it's a single-binary agent OS, not a multi-tenant SaaS.

The good news: OpenFang's existing security primitives (WASM sandbox, taint tracking, capability system, Merkle audit, Ed25519 signing) are solid and well-tested. We're extending a real foundation, not bolting security onto an afterthought.

---

## Layer-by-Layer Mapping

### ✅ COVERED — OpenFang already has these (11 layers)

| Ralph # | Layer | OpenFang File | Coverage | Gap to Close |
|---------|-------|---------------|----------|--------------|
| 1 | Magic byte format gate | Not present | PARTIAL — OpenFang validates at tool level, not at a universal format gate | Add unified format gate at Ralph hub entry point |
| 2 | WASM sandbox (dual-metered) | `sandbox.rs` (607 lines) | STRONG — fuel + epoch + watchdog thread, deny-by-default capabilities | Harden Wasmtime config (disable wasm_threads, simd, etc.) |
| 3 | Schema validation | Tool-level in `host_functions.rs` | PARTIAL — per-tool JSON validation, not typed per-field schema | Centralize into typed schema validator per spoke |
| 4 | Injection pattern scanner | `skills/verify.rs` (294 lines) | PARTIAL — scans skills, not every input. Regex-based, no heuristic scoring | Upgrade to two-pass (regex + heuristic) + LLM 3rd pass for openfang tier |
| 7 | Credential injection at host boundary | `host_functions.rs` dispatch | PARTIAL — secrets never enter WASM guest, but no `SecretString` zeroization | Add `secrecy` crate + memfd for Phase 4 |
| 12 | Output auditor | `audit.rs` (422 lines) | PARTIAL — audit events logged but no output content scanning | Add response-side leak scanning + assembled output scanning |
| 13 | Seccomp-bpf | Not present | NOT PRESENT — subprocess isolation uses `env_clear()` only | Implement seccomp-bpf (default=Deny) on spoke runner process |
| 15 | Spoke process isolation | `subprocess_sandbox.rs` + `workspace_sandbox.rs` | PARTIAL — workspace-confined but not one-per-task with full teardown | Enforce one-per-task, full memory/state teardown |
| 17 | Secret zeroization | `manifest_signing.rs` uses ed25519-dalek | PARTIAL — signing keys are handled but general secrets aren't zeroized | Apply `Zeroizing<String>` to all credential fields system-wide |
| 22 | Merkle audit chain | `audit.rs` (422 lines) | STRONG — SHA-256 hash chain with SQLite persistence and verification endpoint | Add NEAR anchoring for Phase 3 |
| 12+16 | Audit logging + capabilities | `audit.rs` + `capability.rs` (316 lines) + `tool_policy.rs` (478 lines) | STRONG — capability-gated tools, multi-layer policy, glob patterns, deny-wins | Extend for origin × tool cross-check |

### ❌ MISSING — Must be built (20 layers)

#### CRITICAL — Core differentiators (6)

| Ralph # | Layer | Why Critical | Effort Estimate |
|---------|-------|-------------|-----------------|
| **8** | **Dual LLM (P-LLM / Q-LLM)** | The entire security model depends on separating "what to do" (P-LLM planning) from "how to do it" (Q-LLM execution). Without this, there's no structural defense against prompt injection. OpenFang uses a single LLM per agent. | LARGE — new crate, new agent loop |
| **9** | **Opaque variable references** | Q-LLM must never see raw credential values — only opaque handles like `{{var:api_key:7f3a}}`. Without this, Q-LLM can exfiltrate secrets in its output. OpenFang passes values directly. | MEDIUM — variable store crate + integration |
| **11** | **Structural trifecta break (3 WASM contexts)** | Three separate WASM sandbox contexts per task: Q-LLM (read-only data), P-LLM (metadata only), tool executor (checked inputs only). This structurally prevents the lethal trifecta (private data + untrusted content + external comms in one context). OpenFang uses one sandbox per skill. | LARGE — fundamental sandbox architecture change |
| **10** | **Capability gate (origin × tool)** | Cross-check variable origin against tool permissions. A variable from an untrusted source cannot be passed to a privileged tool, regardless of whether the agent has that tool capability. OpenFang checks tool permissions but not data provenance. | MEDIUM — extend capability.rs + taint.rs |
| **16** | **Tiered agent selection** | zeroclaw (simple) / ironclaw (standard) / openfang (high-risk) tier routing. Right-sizes security overhead per task. OpenFang has one security level for everything. | MEDIUM — tier classifier + routing logic |
| **6** | **Sandwich prompt framing** | System prompt → user content → system reassertion → tool results → system close. Prevents prompt injection from escaping the user content zone. OpenFang uses basic system + user framing. | SMALL — modify prompt_builder.rs |

#### HIGH (7)

| Ralph # | Layer | Effort |
|---------|-------|--------|
| **5** | Structured envelope with provenance tags | SMALL — wrap all inter-component messages in typed envelopes |
| **14** | Hardened Wasmtime config | SMALL — disable wasm_threads, simd, multi_memory, etc. in sandbox.rs |
| **18** | Endpoint allowlisting v2 (no redirects) | MEDIUM — extend tool_policy.rs for URL-level allow/deny |
| **20** | SSRF v2 (DNS pinning) | MEDIUM — OpenFang has basic SSRF; add DNS resolution pinning |
| **21** | Approval gate v2 (receipt binding) | MEDIUM — extend approval.rs with cryptographic receipt binding |
| **25** | HTTP client process isolation | MEDIUM — separate process for outbound HTTP, pipe-based comms |
| **19** | Leak scanner v2 (bidirectional) | MEDIUM — scan both outgoing prompts AND incoming responses |

#### MEDIUM (5)

| Ralph # | Layer | Effort |
|---------|-------|--------|
| **26** | Sandbox handoff integrity | SMALL — hash verification between sandbox stages |
| **27** | Global API rate limiting (GCRA) | SMALL — OpenFang has GCRA for API; extend to all task types |
| **28** | Guardrail LLM classifier | MEDIUM — separate LLM for composition attack detection (RED-tier) |
| **29** | Plan schema validation | SMALL — JSON schema validation for P-LLM generated plans |
| **23** | Ed25519 manifest signing (extended) | SMALL — already exists; extend to cover all manifests |

#### LOW (2)

| Ralph # | Layer | Effort |
|---------|-------|--------|
| **30** | Sanitized error responses | SMALL — generic user-facing errors, detailed in audit log only |
| **31** | Graceful degradation matrix | MEDIUM — per-component failure mode policies |

---

## Platform Gaps (not security layers — entire subsystems)

OpenFang is a single-binary agent OS. CRONAM is a multi-tenant SaaS. These subsystems don't exist at all:

| Subsystem | Description | Effort |
|-----------|-------------|--------|
| **Skill pipeline** | Indeed job description → adversarial expert dialogue → AI agent skill package | LARGE — new service |
| **Persona engine** | Human names, communication styles, "digital employees" branding | MEDIUM — new module |
| **Memory persistence** | Per-bot pgvector long-term memory (OpenFang has SQLite memory per agent but not multi-tenant pgvector) | MEDIUM — migrate to Supabase/pgvector |
| **Multi-tenant isolation** | Supabase RLS, per-customer data isolation, API key scoping | LARGE — fundamental architecture |
| **Performance telemetry** | Per-task latency, cost tracking, SLA monitoring | MEDIUM — new service |
| **Bot lifecycle management** | Create/pause/resume/kill named bots, Stripe billing integration | LARGE — SaaS platform core |

---

## Cross-Reference: Our Prior Mapping vs What I Found

The bootstrap prompt predicted these gaps. Here's how my independent analysis compares:

| Expected Gap | Found? | Notes |
|-------------|--------|-------|
| Dual LLM (Layer 8) — CRITICAL | ✅ Confirmed | OpenFang uses single LLM per agent, no P-LLM/Q-LLM split |
| Opaque variables (Layer 9) — CRITICAL | ✅ Confirmed | Values passed directly, no reference indirection |
| Structural trifecta break (Layer 11) — CRITICAL | ✅ Confirmed | One sandbox per skill, not three per task |
| Tiered agent selection (Layer 16) — HIGH | ✅ Confirmed | Single security level for all agents |
| HTTP client isolation (Layer 25) — HIGH | ✅ Confirmed | Network calls happen in-process |
| Sandbox handoff integrity (Layer 26) — MEDIUM | ✅ Confirmed | No hash verification between stages |
| Guardrail LLM (Layer 28) — MEDIUM | ✅ Confirmed | No separate classifier LLM |
| Plan schema validation (Layer 29) — MEDIUM | ✅ Confirmed | No plan validation |
| Sanitized errors (Layer 30) — LOW | ✅ Confirmed | Errors expose internal structure |
| Graceful degradation (Layer 31) — LOW | ✅ Confirmed | No formalized failure policies |

**Additional findings not in the predicted list:**

1. **Sandwich prompt framing (Layer 6)** — OpenFang's `prompt_builder.rs` uses basic framing. Our design calls for full sandwich (system → user → system reassertion → tool → system close).
2. **Loop guard is impressive** — `loop_guard.rs` (949 lines) has ping-pong detection, outcome-aware hashing, and backoff suggestions. This exceeds what our design specified. We should study and potentially adopt.
3. **Shell bleed detection** — `shell_bleed.rs` (354 lines) scans scripts for env var leaks. Not in our 31-layer design. Should be Layer 32 or integrated into the leak scanner.
4. **Tool policy engine** — `tool_policy.rs` (478 lines) has multi-layer policy resolution with deny-wins glob patterns. More sophisticated than our capability gate spec.
5. **30 bundled agents** — agent templates that can become CRONAM's starter skill library.

---

## Recommended Build Sequence

Aligns with SESSION-D 5-phase plan, adjusted for what OpenFang provides:

### Phase 1: Quick Wins + Foundation (Week 1-2)
1. Seccomp default → Deny (`subprocess_sandbox.rs`)
2. Hardened Wasmtime config (`sandbox.rs` — disable features)
3. `#![deny(unsafe_code)]` on all spoke crates
4. Sandwich prompt framing (`prompt_builder.rs`)
5. `secrecy` crate for all credential fields
6. Sanitized error responses
7. Set up CI: `cargo clippy --workspace -- -D warnings` + `cargo-vet`

### Phase 2: Core Security Differentiators (Week 3-6)
1. **Dual LLM architecture** — new `openfang-ralph` crate with P-LLM/Q-LLM split
2. **Variable store v2** — opaque references, label sanitization, size limits
3. **Structural trifecta break** — 3 WASM contexts per task in openfang tier
4. **Capability gate v2** — origin × tool cross-check
5. **Tiered agent selection** — zeroclaw/ironclaw/openfang routing

### Phase 3: Defense in Depth (Week 7-10)
1. Endpoint allowlisting v2 + SSRF v2 + DNS pinning
2. Leak scanner v2 (bidirectional)
3. Approval gate v2 (receipt binding)
4. Sandbox handoff integrity
5. HTTP client process isolation
6. Guardrail LLM classifier
7. Plan schema validation

### Phase 4: SaaS Platform (Week 11-16)
1. Multi-tenant Supabase schema + RLS
2. Persona engine + bot lifecycle management
3. Skill pipeline (Indeed → adversarial dialogue → skill package)
4. Memory persistence (pgvector migration)
5. Performance telemetry
6. Stripe billing integration
7. Frontend (React/TS/Tailwind on Vercel)

### Phase 5: Hardening + Launch (Week 17-20)
1. NEAR Merkle anchoring
2. TEE evaluation
3. Full test suite (AgentDojo, Pliny, Gandalf corpora)
4. Penetration testing
5. SLSA provenance
6. Public launch

---

## UX Test Notes (Mode 3 Journey)

### Friction Points
1. **AI asked clarifying questions instead of executing** — The bootstrap prompt was explicit. Mode 3 should give the AI enough confidence to proceed from a clear brief.
2. **Fork rename wasn't auto-detected** — When the user already has a fork of the source repo, Mode 3 should detect this and offer to rename rather than making the user figure out the mechanics.
3. **171K lines of Rust is a lot to analyze** — Mode 3 needs a progress indicator during source analysis. "Analyzing 13 crates, 171K lines..." with a crate-by-crate progress bar would be ideal.

### Positive Surprises
1. **OpenFang's security is better than expected** — Taint tracking, Merkle audit chain, multi-layer tool policy, loop guard with ping-pong detection. This is a serious codebase.
2. **Shell bleed detection** — Not in our design, but it should be. OpenFang found a real attack vector we missed.
3. **30 bundled agent templates** — Ready-made starting point for CRONAM's skill library.

### Comparison to Greenfield (Mode 2)
Mode 3 is significantly better here. Writing 171K lines of Rust from scratch would take months. Forking OpenFang gives us working WASM sandboxing, a tool system, 41 built-in tools, 40 communication channels, and a dashboard. The 31-layer security architecture becomes an overlay, not a ground-up build.
