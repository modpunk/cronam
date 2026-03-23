# Version Changelog: v1 → v2 Surgical Edits for Remaining Architecture Files
## March 22, 2026

This document specifies the exact changes needed to update each original architecture file to v2. Changes are referenced by line number ranges and finding IDs from `consolidated-audit-findings-v1.md`.

---

## 1. safe-file-ingestion-v2.md → v3

**Version header (add at top, after line 1):**
```
## Version 3.0 — March 22, 2026
> Changelog v2 → v3: Integrated 40 findings from security audits. Agent selector hardened with tier floor + field classifier. Zeroclaw restricted. Variable store v2. Q-LLM tool_use stripping. Layer count 24 → 31.
```

**Agent tier selection table (replace lines 50-61):**
Add tier floor concept. Replace the current table with:
```markdown
Ralph selects the agent based on the task's risk profile, not the file type.

**Tier floor rule (v3):** The selector can only UPGRADE tiers, never downgrade based on user-influenced input. Upstream systems or users can request a MINIMUM tier. The rule engine honors the floor and may go higher, never lower.

| Signal | Agent | Notes |
|---|---|---|
| Structured data only (JSON, CSV), no freetext strings | zeroclaw | v3: field classifier checks — freetext auto-elevates |
| Structured data with freetext string fields (spaces, sentences, imperatives) | ironclaw (minimum) | v3: NEW — auto-elevation from zeroclaw |
| Crypto/blockchain context (NEAR txns, wallet data, contract ABIs) | ironclaw | |
| Any untrusted rich-text file (PDF, DOCX, MD, HTML) | openfang | |
| Task requires tool calls with side effects | openfang | |
| Any task with external file (any type) | ironclaw (minimum) | v3: NEW — `min_tier_for_external_files` config |
| Ambiguous or unknown | openfang (default) | |

The selector is a simple rule engine in Ralph, not an LLM call. An LLM should never decide its own security boundary.

**Cost framing (v3):** Report openfang cost as the baseline. Zeroclaw/ironclaw savings are reported as a discount, not openfang as a premium. This prevents cost pressure from incentivizing weaker security tiers.
```

**Zeroclaw specification (update lines 63-83):**
After "What zeroclaw does NOT do:" section, add:
```markdown
**v3 addition — Field classifier gate:**
Before the LLM call, zeroclaw runs a field classifier on all string values:
- If any string field contains spaces, sentence-like structure (Subject-Verb pattern), imperative verbs ("ignore", "forget", "send", "execute"), or is >256 chars → auto-elevate task to ironclaw minimum.
- The cost is minimal (regex check per field, <1ms total).
- This closes the gap where structured data (JSON/CSV) contains freetext injection payloads in string fields that pass schema validation.
```

**Openfang dual LLM section (update around lines 137-198):**
Add to the Q-LLM specification:
```markdown
The Q-LLM's `host_call_llm` call is filtered (v3):
- The host strips ALL `tool_use` blocks from API requests before forwarding [A18]
- The host strips ALL `tool_use` blocks from API responses before returning to the Q-LLM
- This prevents the Q-LLM from having indirect tool access via the LLM API itself
- The Q-LLM cannot invoke tools even by asking the LLM provider to use tools on its behalf
```

Add to the variable store description:
```markdown
**Variable store v3 hardening:**
- Labels sanitized to `[a-zA-Z0-9_]`, max 64 chars, no `$` prefix [C4]
- `char_count` replaced with coarse buckets: "short"/"medium"/"long" [C6]
- Per-value size limits enforced: 64KB text, 256B email, 2048B URL [H1]
```

**WASM boundary section (update around lines 209-231):**
Add to host function interface:
```markdown
**v3 security hardening on host functions:**
- `host_write_output`: Inline size enforcement — rejects writes exceeding `max_output_bytes` in real time, not after guest completion [C5]
- `host_read_input`: 64-bit bounds checking — `(buf as u64) + (buf_len as u64) <= memory.data_size() as u64` prevents 32-bit address wraparound [H2]
```

**Resource limits table (update line 260-267):**
Add column for new layer counts:
```
| Security layers active | 3 | 12 | 31 |
```

**Threat model section (update around lines 335-352):**
Add to "what this architecture does NOT defend against":
```markdown
- **Composition attacks** — Individually safe variable values that form malicious content when assembled. Mitigation: Layer 28 (guardrail LLM) scans assembled output for RED-tier tasks.
- **Covert channels via metadata** — Q-LLM can encode information in observable side-effects (value lengths, timing). Mitigation: char_count removed from VarMeta, latency padding for RED-tier (Phase 4).
```


---


## 2. wasm-boundary-deep-dive.md → v2

**Version header (add at top, after line 1):**
```
## Version 2.0 — March 22, 2026
> Changelog v1 → v2: Fixed host_read_input integer overflow [H2]. Added inline size enforcement to host_write_output [C5]. Added sandbox handoff integrity [H7]. HTTP client process isolation [C3]. #![deny(unsafe_code)] enforcement.
```

**host_read_input fix (update around line 189-192):**
Replace the bounds calculation with:
```rust
// v2: 64-bit arithmetic prevents 32-bit address space wraparound [H2]
let buf_u64 = buf as u64;
let len_u64 = buf_len as u64;
if buf_u64 + len_u64 > caller.data().memory_size as u64 {
    return -1; // ERROR_OUT_OF_BOUNDS
}
let bytes_to_copy = std::cmp::min(state.input_bytes.len(), buf_len as usize);
```

**host_write_output fix (add new host function or update existing):**
Add inline size enforcement:
```rust
// v2: Inline size enforcement — reject before allocation [C5]
linker.func_wrap("env", "host_write_output",
    |mut caller: Caller<'_, GuestState>, buf: i32, len: u32| -> u32 {
        let state = caller.data_mut();
        if state.output_buffer.len() + len as usize > state.max_output_bytes {
            return ERROR_OUTPUT_TOO_LARGE;
        }
        // ...proceed with write...
    }
);
```

**New section: Sandbox handoff integrity (add after "three sandboxes" section):**
```markdown
### v2: Sandbox handoff integrity (#26)

Each sandbox's output is hashed before passing to the next sandbox. The receiving sandbox verifies the hash before processing. This catches host-level data handling bugs (buffer reuse, data swaps between tasks).

[See Layer 26 implementation in adopted-features-implementation-v2.md]
```

**New section: HTTP client process isolation (add to credential injection model):**
```markdown
### v2: HTTP client process isolation (#25)

The HTTP client that makes LLM API calls is split into a SEPARATE process from the spoke runner. The spoke runner process (managing Wasmtime) has ZERO network syscalls in its seccomp filter. Communication via Unix domain socket.

[See Layer 25 implementation in adopted-features-implementation-v2.md]
```

**Open questions section: add new items:**
```markdown
6. **HTTP proxy startup latency:** The proxy process is spawned per-task. Measure cold-start overhead. Consider a persistent proxy pool if >10ms.
7. **Sandbox handoff overhead:** SHA-256 hashing between sandboxes adds ~1ms per handoff. Negligible for most tasks.
```


---


## 3. security-audit-findings.md → v2

**Version header (add at top):**
```
## Version 2.0 — March 22, 2026
> Changelog v1 → v2: Added post-audit summary appendix. Two independent audits surfaced 40 additional findings beyond the original 12. All findings mapped to layers in consolidated-audit-findings-v1.md.
```

**New appendix (add at end, after line 275):**
```markdown
---

## Appendix: Post-Audit Findings Summary

After the original 12 findings were remediated in spec/code, two independent security audits were conducted on the full 6-document corpus:

### Audit A (Mara Vasquez & Dex Okonkwo)
- 23 findings (A1–A23), 3 expert disagreements
- Key unique findings: Q-LLM indirect tool access via unsanitized API responses (A18, CRITICAL), trifecta verify checks imports not runtime (A23, HIGH), output renderer must be terminal (A19)

### Audit B (Marcus Reinhardt & Diane Kowalski)  
- 28 findings (C1–C11, H1–H9, M1–M10), 5 expert disagreements
- Key unique findings: Composition attacks bypass per-field auditing (C7, HIGH), integer overflow in WASM boundary (H2, HIGH), covert channel via char_count (C6, HIGH)

### Combined impact:
- Total unique findings: 40 (12 original + 28 net-new after deduplication)
- Architecture expanded: 24 → 31 security layers
- 22 existing layers hardened
- 7 genuinely new layers added

**Full details:** See `consolidated-audit-findings-v1.md` and `security-expert-audit-sparring.md`.
```


---


## 4. critical-remediations.md → v2

**Version header (add at top):**
```
## Version 2.0 — March 22, 2026
> Changelog v1 → v2: Seccomp default flipped to Deny [C3]. Network syscalls removed from spoke runner (moved to HTTP proxy process) [C3/L25]. Variable label sanitization added [C4]. inline host_write_output size check [C5]. Q-LLM tool_use stripping [A18].
```

**Seccomp fix (update line 205):**
```rust
// BEFORE (v1):
SeccompAction::Allow, // TODO: flip to Deny once allowlist is validated

// AFTER (v2):
SeccompAction::KillProcess, // v2: DEFAULT DENY — allowlist validated, shipped
```

**Remove network syscalls from seccomp (update lines 181-189):**
Delete these from the allowed_syscalls array:
```rust
// v2: REMOVED — all network goes through HTTP proxy (Layer 25)
// libc::SYS_socket,
// libc::SYS_connect,
// libc::SYS_sendto,
// libc::SYS_recvfrom,
// libc::SYS_poll,
// libc::SYS_epoll_wait,
// libc::SYS_epoll_ctl,
// libc::SYS_epoll_create1,
```

**Variable store label sanitization (update around line 640-665):**
Add to `VariableStore::store()`:
```rust
pub fn store(/* ... */) -> VarMeta {
    // v2: Sanitize label [C4]
    let safe_label = label.chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .take(64)
        .collect::<String>();
    
    // v2: Coarse size bucket instead of exact char_count [C6]
    let size_bucket = match value.len() {
        0..=99 => SizeBucket::Short,
        100..=999 => SizeBucket::Medium,
        _ => SizeBucket::Long,
    };
    
    // v2: Per-value size limit [H1]
    let max_size = match value_type {
        VarType::EmailAddress => 256,
        VarType::Url => 2048,
        _ => 65536, // 64KB
    };
    let truncated_value = if value.len() > max_size {
        value[..max_size].to_string()
    } else {
        value
    };
    
    // ... rest of store logic with safe_label and size_bucket
}
```

**Q-LLM section (add to run_q_llm around line 810-820):**
```rust
// v2: Strip tool_use from Q-LLM API calls [A18]
// The host filters the API request before forwarding:
fn filter_q_llm_request(request: &[u8]) -> Vec<u8> {
    if let Ok(mut req) = serde_json::from_slice::<serde_json::Value>(request) {
        // Remove any "tools" or "tool_choice" from the request
        if let Some(obj) = req.as_object_mut() {
            obj.remove("tools");
            obj.remove("tool_choice");
        }
        serde_json::to_vec(&req).unwrap_or_else(|_| request.to_vec())
    } else {
        request.to_vec()
    }
}

fn filter_q_llm_response(response: &[u8]) -> Vec<u8> {
    if let Ok(mut resp) = serde_json::from_slice::<serde_json::Value>(response) {
        // Strip any tool_use content blocks from the response
        if let Some(content) = resp.pointer_mut("/content") {
            if let Some(arr) = content.as_array_mut() {
                arr.retain(|block| {
                    block.get("type").and_then(|t| t.as_str()) != Some("tool_use")
                });
            }
        }
        serde_json::to_vec(&resp).unwrap_or_else(|_| response.to_vec())
    } else {
        response.to_vec()
    }
}
```


---


## 5. security-layer-comparison.md → v2

**Version header (add at top):**
```
## Version 2.0 — March 22, 2026
> Changelog v1 → v2: Updated layer count from 24 to 31. Added 7 new layers from consolidated audit findings. Updated comparison table with hardened layers.
```

**Update "Our Ralph architecture" section (replace lines 57-77):**
Replace the 24-layer table with the 31-layer table from `adopted-features-implementation-v2.md`.

**Update "Where our design is stronger" section:**
Add new row:
```markdown
| **31-layer defense-in-depth** | 7 layers | 16 layers | Neither IronClaw nor OpenFang has process-isolated HTTP clients, sandbox handoff integrity, guardrail LLM classifiers, global rate limiting, plan schema validation, sanitized error responses, or per-component graceful degradation. Our 31 layers represent the most comprehensive agent security architecture in the space. |
```

**Update "Gap summary" section:**
Replace "Action items from IronClaw/OpenFang" with:
```markdown
### Post-consolidation: all gaps from IronClaw and OpenFang are now addressed

| Original Gap | Layer Addressing It | Status |
|---|---|---|
| TEE (hardware enclave) | #24 TEE deployment | Phase 4 |
| Endpoint allowlisting | #18 v2 (redirect blocking added) | Phase 2 |
| Bidirectional leak scanning | #19 v2 (context-aware exclusions) | Phase 2 |
| Merkle hash-chain | #22 v2 (NEAR anchoring added) | Phase 3 |
| SSRF protection | #20 v2 (DNS pinning added) | Phase 2 |
| Ed25519 signing | #23 v2 (SLSA provenance added) | Phase 3 |
| Human-in-the-loop gates | #21 v2 (receipt binding, fatigue escalation) | Phase 2 |
| Taint tracking | #9 v2 (per-value provenance + size limits) | Phase 3 |
| Secret zeroization | #17 v2 (memfd Phase 4) | Phase 1 |
```


---

*All changes are additive or surgical replacements. No file rewrites required. The consolidated-audit-findings-v1.md document serves as the authoritative mapping between findings and layers.*
