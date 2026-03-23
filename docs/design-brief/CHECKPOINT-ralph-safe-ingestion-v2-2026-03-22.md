# CHECKPOINT: Ralph Safe File Ingestion & Agent Isolation Architecture
## Session date: March 22, 2026 (v2 — post-audit consolidation)
## Context window at checkpoint: ~95% of 200K


## What was built (cumulative)

### Documents delivered (all in /mnt/user-data/outputs/):

**Original architecture (v1):**
1. **safe-file-ingestion-v2.md** → **v3 pending** — Core architecture. Ralph = hub. zeroclaw/ironclaw/openfang spokes. Tiered agent selection.
2. **wasm-boundary-deep-dive.md** → **v2 pending** — Three sandboxes per task. Credential injection model. SpokeRunner implementation.
3. **security-audit-findings.md** → **v2 pending** — Original 12 findings (4 CRITICAL, 4 HIGH, 4 MEDIUM).
4. **critical-remediations.md** → **v2 pending** — Full Rust implementation for original 4 criticals. Phases 1–3.
5. **security-layer-comparison.md** → **v2 pending** — Layer-by-layer vs IronClaw (7 layers) and OpenFang (16 layers).
6. **adopted-features-implementation.md** → **v2 delivered** — Expanded from 24 to 31 layers. All new layer implementations.

**Post-audit consolidation (v2):**
7. **consolidated-audit-findings-v1.md** — **NEW.** Maps all 40 findings from both security audits to the 31-layer architecture. Finding-to-layer mapping, new layer specifications, prioritized remediation roadmap, expert disagreements, test suite requirements.
8. **adopted-features-implementation-v2.md** — **NEW.** Updated layer table (24 → 31). Implementations for 7 new layers: HTTP client process isolation, sandbox handoff integrity, global API rate limiting, guardrail LLM classifier, plan schema validation, sanitized error responses, graceful degradation matrix. Updated Ralph main loop with all 31 layers.
9. **security-expert-audit-sparring.md** — Marcus Reinhardt & Diane Kowalski sparring match. 28 findings. 657 lines, 8,767 words.
10. **CHECKPOINT-ralph-safe-ingestion-v2-2026-03-22.md** — This file.

### Audit coverage:
- **Original audit**: 12 findings (4C, 4H, 4M) — all remediated in spec/code
- **Audit A** (Mara Vasquez & Dex Okonkwo): 23 findings (A1–A23), 3 expert disagreements
- **Audit B** (Marcus Reinhardt & Diane Kowalski): 28 findings (C1–C11, H1–H9, M1–M10), 5 expert disagreements
- **Total unique findings after deduplication: 40**
- **Total combined expert disagreements: 8** (all resolved with recommended approaches)


## Architecture summary (v2 — 31 layers)

```
Ralph hub (31 security layers)
├── Agent selector v2 (#16: tier floor, field classifier, never-downgrade)
├── Sanitized error responses (#30: generic user-facing, detailed audit-only)
├── Global API rate limiting (#27: GCRA across all tasks)
├── Secret zeroization (#17: secrecy crate, memfd Phase 4)
├── Merkle audit chain v2 (#22: tamper-evident + NEAR anchoring)
├── Output auditor v2 (#12: individual + assembled scanning)
├── Guardrail LLM (#28: RED-tier composition attack defense)
├── Approval gate v2 (#21: receipt binding, fatigue escalation)
├── Leak scanner v2 (#19: bidirectional, context-aware)
├── Graceful degradation matrix (#31: per-component fail policies)
│
├── Spoke: zeroclaw (simple tasks)
│   Format gate → schema validation → field classifier check
│   → direct LLM call (freetext auto-elevates to ironclaw)
│
├── Spoke: ironclaw (crypto/NEAR tasks)
│   Format gate → WASM parser (#2 v2: inline size + 64-bit bounds)
│   → typed schema → sandwich frame (documented limitations)
│   → WASM-sandboxed LLM call (credential injected at host)
│   Endpoint allowlisting v2 (#18: no redirects), SSRF v2 (#20: DNS pinning)
│
└── Spoke: openfang (default, high-risk tasks)
    Format gate → WASM parser → schema + injection scan v2 (#4: LLM 3rd pass)
    → Sandbox handoff integrity (#26: hash verification between sandboxes)
    → Variable store v2 (#9: label sanitization, size limits, no char_count)
    → Context A: Q-LLM (#8 v2: tool_use stripped, 0 tools, 0 network)
    → Context B: P-LLM (metadata only, plan schema validated #29)
    → Capability gate (origin × tool permissions)
    → Context C: Tool executor (checked inputs only)
    → HTTP client isolation (#25: separate process, pipe comms)
    → Endpoint allowlisting v2 + SSRF v2 + DNS pinning
    → Output auditor v2 → Guardrail LLM (RED-tier) → Approval gate v2
    → Merkle audit v2 (NEAR-anchored)
```

**Layer evolution:** 16 original + 8 IronClaw/OpenFang adopted + 7 audit-consolidated = **31 layers**
- 22 existing layers hardened with audit findings
- 7 genuinely new layers added
- All 40 audit findings mapped to specific layers


## Implementation phasing (updated)

| Phase | What | Status |
|-------|------|--------|
| Phase 1 Quick Wins | Seccomp flip to Deny, label sanitization, inline size check, 64-bit bounds, error sanitization, deny(unsafe_code), HTTP client isolation | Spec complete, code written, NOT deployed |
| Phase 1 | Wasmtime hardening, secret zeroization, seccomp-bpf | Spec complete, code written, NOT deployed |
| Phase 2 | Agent selector hardening, variable store v2, guardrail LLM, LLM injection classifier, DNS pinning, redirect blocking, rate limiting, handoff integrity, degradation matrix, Q-LLM tool_use stripping | Spec complete, code written, NOT deployed |
| Phase 3 | SLSA provenance, NEAR anchoring, min_tier config, plan schema validation, full test suite, runtime trifecta verification | Spec complete, partial code |
| Phase 4 | TEE deployment, memfd credentials, latency padding, approval receipt binding, Firecracker vsock auth | Spec outlined, no code |


## Key research references
- CaMeL (Google DeepMind, arXiv:2503.18813) — capability-based dual LLM
- Operationalizing CaMeL (Tallam, arXiv:2505.22852) — critique + enterprise extensions
- IsolateGPT/SecGPT (NDSS 2025) — hub-and-spoke execution isolation
- Simon Willison's Lethal Trifecta (June 2025) — private data + untrusted content + external comms
- PromptArmor (ICLR 2026) — LLM-as-guardrail, <5% FNR with reasoning models
- Wasmtime CVEs: CVE-2026-24116, CVE-2026-27572, CVE-2026-27204, CVE-2026-27195
- OWASP Top 10 for LLM Applications 2025 + Agentic Applications 2026
- AgentDojo, Pliny, Gandalf (Lakera) — injection benchmark corpora


## Cost model (updated)
- Claude.ai Pro sessions: $0 marginal cost beyond subscription
- API blended rate: ~$0.006/1K tokens
- Per-task estimates:
  - zeroclaw: ~$0.016
  - ironclaw: ~$0.020
  - openfang: ~$0.039
  - openfang + guardrail LLM (RED-tier): ~$0.055
- 10K tasks/day on blended rate: ~$400/day (~$12K/month)
- 10K RED-tier tasks/day with guardrail: ~$550/day (~$16.5K/month)


## File version registry

| File | Current Version | Lines | Description |
|------|----------------|-------|-------------|
| safe-file-ingestion-v2.md | v2 (rename to v3 pending) | 380 | Core architecture |
| wasm-boundary-deep-dive.md | v1 (v2 pending) | 809 | WASM boundary spec |
| security-audit-findings.md | v1 (v2 pending) | 275 | Original 12 findings |
| critical-remediations.md | v1 (v2 pending) | 1,171 | Critical finding implementations |
| security-layer-comparison.md | v1 (v2 pending) | 217 | IronClaw/OpenFang comparison |
| adopted-features-implementation.md | **v2** | ~800 | 31-layer table + new implementations |
| consolidated-audit-findings-v1.md | **v1 (NEW)** | ~350 | All 40 findings mapped to layers |
| security-expert-audit-sparring.md | v1 | 657 | Marcus/Diane sparring match |
| CHECKPOINT (this file) | **v2** | ~140 | Session state |

### Pending v2 updates for remaining files:
The v2 changes for the remaining 5 original files are **documented in consolidated-audit-findings-v1.md** as specific line-item fixes. Each file needs surgical edits, not full rewrites:
- **safe-file-ingestion**: Update tier selection table, zeroclaw spec (add field classifier), openfang spec (variable store v2, Q-LLM stripping)
- **wasm-boundary-deep-dive**: Fix host_read_input (64-bit bounds), host_write_output (inline size), add handoff integrity section
- **security-audit-findings**: Add appendix referencing post-audits (40 total findings)
- **critical-remediations**: Fix seccomp default, add label sanitization code, HTTP client separation
- **security-layer-comparison**: Update layer count 24→31, add new layers to comparison table


## Next steps for pickup
1. Apply surgical v2 edits to the 5 remaining original files (changes documented in consolidated-audit-findings-v1.md)
2. Scaffold the Rust crate workspace structure for ralph/spoke_runner
3. Implement Phase 1 Quick Wins (seccomp flip, label sanitization, inline size check — estimated 2 hours)
4. Set up CI with cargo-vet + `#![deny(unsafe_code)]`
5. Or pivot to another project
