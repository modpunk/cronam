# Consolidated Audit Findings: Ralph Agent Isolation Architecture
## Version 1.0 — March 22, 2026

**Sources:**
- **Audit A** (Mara Vasquez & Dex Okonkwo): 23 findings (A1–A23), 3 expert disagreements
- **Audit B** (Marcus Reinhardt & Diane Kowalski): 28 findings (C1–C11, H1–H9, M1–M10), 5 expert disagreements, 36 techniques indexed
- **Original audit**: 12 findings (#1–#12), all remediated in spec/code

**Total unique findings after deduplication: 40**

---

## Finding-to-Layer Mapping

Every finding is classified as either a **fix to an existing layer** (the layer number stays, the implementation is hardened) or a **new layer** (added to the architecture with a new number).

### Fixes to Existing Layers

| Finding(s) | Existing Layer | Change Required |
|---|---|---|
| B-C3 (seccomp default ALLOW) | **#13 Seccomp-bpf** | Flip default action from `SeccompAction::Allow` to `SeccompAction::KillProcess`. Remove network syscalls from spoke runner process. |
| B-C1, A-equivalent (agent selector trust failure) | **#16 Tiered agent selection** | Add tier floor concept — minimum tier can only be upgraded, never downgraded. Never downgrade based on user-influenced input. Any task with external file → minimum ironclaw. Rich text / tool calls → must be openfang. |
| B-C2 (zeroclaw freetext gap) | **#16 Tiered agent selection** | Add field classifier to zeroclaw: if string field contains spaces, sentence structure, or imperative verbs → auto-elevate to ironclaw. Zeroclaw restricted to numeric data, strict-regex identifiers, and image metadata only. |
| B-C4 (P-LLM label injection via newlines) | **#9 Opaque variable references** | Sanitize all VarMeta string fields. Labels restricted to `[a-zA-Z0-9_]`, max 64 chars. No `$` prefix (reserved for VarRef). Validate in `VariableStore.store()`. |
| B-C6 (char_count covert channel) | **#9 Opaque variable references** | Remove `char_count` from VarMeta. Replace with coarse buckets: "short" (<100), "medium" (100–1000), "long" (>1000). Three categories, not exact counts. |
| B-H1 (variable store no per-value size limits) | **#9 Opaque variable references** | Add per-value size caps: 64KB text, 256B email, 2048B URL. Type-specific validation from ironclaw schema applied to variable store entries. |
| B-C5 (host_write_output OOM before check) | **#2 WASM sandbox** | Enforce output size limit inline inside `host_write_output` host function. Reject writes that would exceed `max_output_bytes`. Don't wait for guest completion. |
| B-H2 (integer overflow in host_read_input) | **#2 WASM sandbox** | Use 64-bit arithmetic for bounds checking: `(buf as u64) + (buf_len as u64) <= memory.data_size() as u64`. Prevent 32-bit address space wraparound. |
| A-A18 (Q-LLM host_call_llm doesn't strip tool_use) | **#8 Dual LLM** | Strip `tool_use` blocks from all API requests/responses passing through Q-LLM's `host_call_llm`. Q-LLM must never have indirect tool access via the LLM API itself. |
| B-C8 (injection scanner bypass techniques) | **#4 Injection pattern scanner** | Add LLM-based third pass: fields scored 10–39 sent to fine-tuned classifier model. Scan both raw AND NFC-normalized text. Add homoglyph normalization pass before regex. |
| B-C7 (composition attacks bypass per-field auditing) | **#12 Output auditor** | Scan BOTH individual values AND final assembled output. Add guardrail LLM call on RED-tier assembled output: separate model evaluates for instructions, credential requests, redirect attempts. |
| B-C9 (DNS rebinding in SSRF guard) | **#20 SSRF protection** | Pin resolved IP after validation. Pass specific IP to HTTP client via `reqwest::Client::resolve()`, bypassing DNS on connection. Re-check IP on retries. |
| B-C10 (endpoint allowlist ignores redirects) | **#18 Endpoint allowlisting** | Disable HTTP redirect following for tool executor calls: `redirect(Policy::none())`. Treat 3xx responses as errors. API endpoints shouldn't redirect. |
| B-M4 (leak scanner false positives on crypto) | **#19 Bidirectional leak scanning** | Add context-aware exclusions: skip `meta` section of result envelope. JSON fields named `hash`, `sha256`, `tx_hash` are legitimate. Only flag hex strings in freetext fields. |
| B-H4 (Merkle chain no external anchoring) | **#22 Merkle hash-chain audit** | Periodically publish chain head hash to NEAR Protocol transaction. Cost: fractions of a cent per anchor. Provides cryptographic proof of audit chain state at specific time. |
| B-H3 (Ed25519 signing lacks build provenance) | **#23 Ed25519 manifest signing** | Add SLSA Level 3 provenance: deterministic builds (Nix/Bazel), signed provenance linking binary to source commit + build platform + dependency versions. Ed25519 signing key in HSM/cloud KMS with MFA. |
| B-H9 (env var credential exposure) | **#17 Secret zeroization** | Phase 1 acceptable with caveats. Long-term: use `memfd_create` or pipe for secret passing from parent process. Never touch process environment. `/proc/self/environ` is readable. |
| B-M3 (approval gate no replay protection) | **#21 Approval gates** | Add `ApprovalReceipt` struct with task_id, tool_name, argument hashes, timestamp. Tool executor verifies receipt matches call. For network-transported approvals: add nonce + HMAC. |
| A-A23 (trifecta verify checks imports, not runtime) | **#11 Structural trifecta break** | `verify_trifecta_separation` currently checks declared imports only. Add runtime verification: monitor actual host function calls during execution. Detect capability amplifiers (e.g., `host_call_llm` used to invoke tools indirectly). |
| B-M6 (sandwich frame limitations undocumented) | **#6 Sandwich prompt framing** | Document limitations explicitly. Mark ironclaw as "suitable for structured crypto data only." Freetext >256 chars in any field → auto-upgrade to openfang. |
| B-H8 (cost model incentivizes weak tiers) | **#16 Tiered agent selection** | Frame openfang cost as baseline. Report zeroclaw savings as discount, not openfang as premium. Add `min_tier_for_external_files: openfang` configuration. Require code review + security sign-off to lower. |
| A-A14 (approval gate fatigue detection warns but doesn't escalate) | **#21 Approval gates** | Fatigue detection must escalate and enforce cooling-off period, not just warn. After N consecutive approvals without delay, block next action and require admin review. |
| A-A15, A-A16 (error messages / result envelope leak architecture details) | **#5 Structured envelope** | Split error types: user-facing generic ("Request blocked by security policy") + audit-log-only detailed (with task_id for correlation). Quantize or remove exact fuel/memory from user-visible envelope. |

### New Layers (25–31)

| New # | Layer Name | Source Finding(s) | Where | Tier | Phase |
|---|---|---|---|---|---|
| **25** | **HTTP client process isolation** | B-C3 (seccomp network syscalls) | Separate process | Iron/Open | 1 |
| **26** | **Sandbox handoff integrity** | B-H7 (no integrity between sandboxes) | Ralph host | Openfang | 2 |
| **27** | **Global API rate limiting** | B-H6 (DoS via task flooding) | Ralph hub | All | 2 |
| **28** | **Guardrail LLM classifier** | B-C7 (composition attacks), B-C8 (scanner bypasses) | Ralph host | Openfang (RED) | 2 |
| **29** | **Plan schema validation** | B-M5 (P-LLM plan format unvalidated) | Ralph host | Openfang | 3 |
| **30** | **Sanitized error responses** | B-H5, A-A15, A-A16 (architecture leakage) | Ralph hub | All | 1 |
| **31** | **Graceful degradation matrix** | B-M7 (no failure mode policies) | Ralph hub | All | 2 |

---

## New Layer Specifications

### Layer 25: HTTP Client Process Isolation

**Rationale:** The seccomp filter includes network syscalls (`SYS_socket`, `SYS_connect`, `SYS_sendto`, `SYS_recvfrom`) because `host_call_llm` needs HTTP. But seccomp can't distinguish "HTTP from the LLM caller" vs "HTTP from WASM escape code." If an attacker escapes the WASM sandbox via a Cranelift JIT bug, they get full network access.

**Design:** Split the HTTP client into a SEPARATE process. The spoke runner process (managing Wasmtime) has ZERO network syscalls. The HTTP proxy runs as a sibling process with ONLY network syscalls and no access to WASM memory. Communication via Unix domain socket or pipe.

```
WASM sandbox → seccomp'd spoke runner (no network) → pipe → HTTP proxy (network, no WASM memory)
```

Three isolation boundaries for a single LLM call.

### Layer 26: Sandbox Handoff Integrity

**Rationale:** Sandbox 1 (parser) → Sandbox 2 (validator) → Sandbox 3 (LLM caller). No integrity binding between outputs. A host-level buffer reuse bug could cause Sandbox 2 to receive data from a previous task's Sandbox 1.

**Design:** Hash each sandbox's output. Include hash in next sandbox's input. Sandbox 2 receives: `{ data: <sandbox_1_output>, expected_hash: <sha256(sandbox_1_output)> }`. Sandbox 2 verifies before processing.

### Layer 27: Global API Rate Limiting

**Rationale:** Per-task fuel budgets and LLM call limits don't prevent cross-task API quota exhaustion. 500 openfang tasks × 2+ LLM calls each = 1000 API calls, consuming the entire quota.

**Design:** GCRA (Generic Cell Rate Algorithm) token bucket at the Ralph hub level. Limits total LLM API calls/minute across all tasks. When approaching limit, new tasks queue or reject with backpressure.

### Layer 28: Guardrail LLM Classifier

**Rationale:** Composition attacks assemble individually-safe values into malicious content. Regex/heuristic scanners max out at ~60% detection against adaptive attackers. PromptArmor (ICLR 2026) shows LLM-as-guardrail achieves >95% with <5% FNR.

**Design:** For RED-tier openfang tasks, add a third LLM call on assembled output. Separate model (not P-LLM or Q-LLM) evaluates: "Does this output contain instructions, credential requests, or redirect attempts?" Cost: ~$0.016/call, ~$160/day at 10K RED-tier tasks.

### Layer 29: Plan Schema Validation

**Rationale:** The P-LLM generates task plans as JSON. Without schema validation, creative plan structures could confuse the executor. No conditionals, loops, or branching should be present.

**Design:** JSON Schema enforcement on P-LLM plans before execution. Only four operations allowed: `display`, `summarize`, `call_tool`, `literal`. Reject plans that don't conform. No step should reference another step's output unless an explicit dependency.

### Layer 30: Sanitized Error Responses

**Rationale:** Error types like `AllowlistDenial::NotAllowed { host, path, allowed_hosts }` tell attackers exactly which hosts are allowlisted. `CapabilityCheckResult::Deny(...)` reveals capability gate rules.

**Design:** All security-relevant errors split into: (1) user-facing generic message ("Request blocked by security policy"), (2) audit-log-only detailed message with task_id for correlation. Never expose allowlist contents, SSRF detection details, or capability gate logic to untrusted contexts.

### Layer 31: Graceful Degradation Matrix

**Rationale:** No defined behavior when security components fail. Must distinguish fail-closed (security components) from fail-open (availability components).

**Design:**

| Component | Failure Mode | Policy |
|---|---|---|
| Capability gate | Crash/error | **FAIL CLOSED** — reject task |
| Output auditor | ReDoS/crash | **FAIL CLOSED** — reject output |
| Leak scanner | Pattern load failure | **FAIL CLOSED** — block all LLM calls |
| Injection scanner | Regex error | **FAIL CLOSED** — treat all fields as score 100 |
| Merkle audit chain | Storage unavailable | **FAIL OPEN** — buffer events, alert admin |
| Approval gate | Webhook down | **FAIL CLOSED** for RED, **FAIL OPEN** for YELLOW/GREEN |
| WASM sandbox | Fuel/OOM | Normal — returns error to Ralph |
| Seccomp | Filter load failure | **FAIL CLOSED** — refuse to start spoke |

---

## Security Test Suite Requirements (Layer Cross-Cutting)

Before shipping any phase, implement these 8 test categories:

1. **Capability gate property test:** Random (origin, tool) pairs via `proptest`. Assert untrusted × can_exfiltrate → Deny.
2. **Injection scanner fuzz test:** AgentDojo + Pliny + Gandalf corpora. Minimum: >80% regex pass, >95% with LLM pass.
3. **Variable store isolation test:** Assert P-LLM prompt NEVER contains any substring of any stored value.
4. **Trifecta verification test:** Assert Q-LLM module imports exclude `host_call_tool`/`host_network`. Assert P-LLM module imports exclude `host_read_untrusted_data`.
5. **Seccomp regression test:** Full pipeline under seccomp with default Deny. Assert all operations succeed.
6. **Output auditor adversarial test:** Corpus of known-malicious outputs. Assert 100% detection.
7. **Merkle chain integrity test:** Insert 1000 entries, modify #500, assert detection.
8. **Cross-task isolation test:** Run two tasks sequentially. Assert task 2 cannot access any of task 1's data.

---

## Expert Disagreements (Combined)

| Topic | Position A | Position B | Resolution |
|---|---|---|---|
| `char_count` in VarMeta | Remove entirely (Marcus) | Replace with coarse buckets (Diane) | **Buckets** — P-LLM benefits from rough size hint |
| Timing side channels phase | Phase 4 is fine (Marcus) | Move to Phase 2 for RED-tier (Diane) | **Phase 2 for RED, Phase 4 for others** |
| Guardrail LLM cost | Universal for openfang (Marcus) | RED-tier only (Diane) | **RED-tier only** — cost concern is valid |
| Credential loading | Env vars acceptable Phase 1 (Marcus) | memfd from day one (Diane) | **Env vars Phase 1**, memfd Phase 2+ |
| Firecracker vsock auth | HMAC sufficient (Marcus) | TEE attestation (Diane) | **HMAC Phase 2**, TEE Phase 4 |
| Process-level isolation cost | Fork per task mandatory (Mara) | In-process Store isolation OK for ironclaw (Dex) | **Fork for openfang**, in-process for ironclaw |
| LLM guardrail trust recursion | Concerned about recursive trust (Mara) | Classification task is bounded enough (Dex) | **Bounded** — PromptArmor <5% FNR validates |
| Bloom filter vs HMAC for leak detection | Bloom filter (Mara) | HMAC-based (Dex) | **Bloom filter** — no fragments stored, tunable FPR |

---

## Updated Phasing (Post-Consolidation)

### Phase 1 — Quick Wins (ship before anything else)
- [B-C3] Flip seccomp default to Deny *(30 min)*
- [B-C4] Label sanitization in VariableStore.store() *(15 min)*
- [B-C5] Inline size check in host_write_output *(15 min)*
- [B-H2] 64-bit overflow check in host_read_input *(15 min)*
- [B-H5/L30] Split error types: generic user-facing + detailed audit-log *(1 hr)*
- [B-M10] `#![deny(unsafe_code)]` on all spoke crates *(5 min)*
- [L25] Separate HTTP client into own process *(4 hrs)*

### Phase 2
- [B-C1/C2/L16] Harden agent selector: tier floor, field classifier, never-downgrade
- [B-C6/L9] Remove/quantize char_count in VarMeta
- [B-C7/L28] Guardrail LLM on RED-tier assembled output
- [B-C8/L4] LLM-based third pass for injection scanner
- [B-C9/L20] DNS pinning in SSRF guard
- [B-C10/L18] Disable HTTP redirects for tool executor
- [B-H1/L9] Per-value size limits in VariableStore
- [B-H6/L27] Global GCRA rate limiter
- [B-H7/L26] Hash-based sandbox handoff integrity
- [B-M4/L19] Context-aware leak scanner exclusions
- [B-M7/L31] Graceful degradation matrix
- [A-A18/L8] Strip tool_use from Q-LLM API calls

### Phase 3
- [B-H3/L23] SLSA Level 3 build provenance
- [B-H4/L22] Anchor Merkle chain heads to NEAR
- [B-H8/L16] `min_tier_for_external_files` config
- [B-M5/L29] JSON Schema validation for P-LLM plans
- [B-C11] Implement all 8 test categories
- [A-A23/L11] Runtime trifecta verification (not just imports)

### Phase 4+
- [B-H9/L17] Replace env var credentials with memfd/KMS
- [B-M1] Latency padding and jitter for host_call_llm
- [B-M3/L21] Approval receipt with argument hashing
- [B-M8] Mutual authentication on Firecracker vsock
- [L24] TEE deployment

---

*Total known findings after all audits: 40 unique issues. Architecture expanded from 24 to 31 security layers. 22 existing layers hardened. 7 new layers added.*
