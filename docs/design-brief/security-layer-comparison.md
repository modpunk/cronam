# Security layer comparison: our Ralph design vs IronClaw (7 layers) vs OpenFang (16 layers)


## IronClaw's 7 security layers (NEAR AI)

Sourced from the IronClaw GitHub repo and ironclaw.com.

IronClaw's model is a single pipeline that every tool invocation passes through:

```
WASM ──► Allowlist ──► Leak Scan ──► Credential ──► Execute ──► Leak Scan ──► WASM
         Validator     (request)     Injector      Request     (response)
```

| # | Layer | What it does |
|---|-------|--------------|
| 1 | WASM sandbox | Each tool runs in an isolated WebAssembly container with capability-based permissions. Explicit opt-in for HTTP, secrets, tool invocation. |
| 2 | Endpoint allowlisting | HTTP requests only to pre-approved hosts/paths. No wildcard network access. |
| 3 | Credential injection | Secrets injected at the host network boundary. The LLM and WASM guest never see raw API keys. Uses Rust `Secret<String>` with ZeroOnDrop. |
| 4 | Leak detection (bidirectional) | Scans both outgoing requests AND incoming responses for patterns matching secrets. Blocks exfiltration attempts. |
| 5 | Rate limiting | Per-tool request limits. Prevents abuse via rapid-fire tool calls. |
| 6 | Resource limits | Memory, CPU, and execution time constraints on each WASM instance. |
| 7 | TEE (Trusted Execution Environment) | Hardware-level encrypted enclaves on NEAR AI Cloud. Memory encrypted from boot to shutdown. Even the cloud provider cannot inspect runtime state. |

**Plus (not numbered but documented):**
- Prompt injection defense (pattern detection, content sanitization, policy enforcement)
- Encrypted vault for credential storage (AES-256-GCM)
- Comprehensive audit log of all tool activity
- No telemetry/analytics data collection
- pgvector-backed local PostgreSQL storage


## OpenFang's 16 security layers (RightNow AI)

Sourced from the OpenFang GitHub repo, openfang.sh, and documentation.

| # | Layer | What it does |
|---|-------|--------------|
| 1 | WASM dual-metered sandbox | Fuel metering (instruction count) + epoch interruption (wall-clock timeout). Watchdog thread kills runaway code. |
| 2 | Ed25519 manifest signing | Every agent identity and capability set is cryptographically signed. Tampered manifests are rejected. |
| 3 | Merkle hash-chain audit trail | Every action is cryptographically linked to the previous one. Tamper with one entry and the entire chain breaks. |
| 4 | Taint tracking | Labels propagate through execution — secrets are tracked from source to sink. Data provenance is maintained across the full execution path. |
| 5 | SSRF protection | Blocks requests to private IPs, cloud metadata endpoints (169.254.x.x), and DNS rebinding attacks. |
| 6 | Secret zeroization | `Zeroizing<String>` auto-wipes API keys from memory the instant they're no longer needed. |
| 7 | HMAC-SHA256 mutual auth | Constant-time verification for P2P networking between OpenFang instances. Nonce-based to prevent replay. |
| 8 | GCRA rate limiter | Generic Cell Rate Algorithm — smoother than token bucket, prevents burst abuse. |
| 9 | Subprocess isolation | Subprocesses (e.g., FFmpeg) execute with cleared environments and enforced timeouts. |
| 10 | Prompt injection scanner | Pattern-based detection of injection attempts in agent inputs. |
| 11 | Path traversal prevention | File operations are strictly workspace-confined. No `../` escapes. |
| 12 | Capability-based access control | Agents declare required tools. The kernel enforces the declared set. No privilege escalation via prompt manipulation. Immutable after agent creation. |
| 13 | HTTP security headers | CSP, X-Frame-Options, HSTS, X-Content-Type-Options on every response. |
| 14 | Workspace-confined file operations | Agents can only read/write within their designated workspace directory. |
| 15 | Human-in-the-loop approval gates | Mandatory approval for sensitive actions (e.g., Browser Hand requires approval before purchases). |
| 16 | Comprehensive audit logging | Full activity log for all agent operations, tools, and channel interactions. |


## Our Ralph architecture (4 critical remediations applied)

| # | Layer | Where it lives | Tier |
|---|-------|---------------|------|
| 1 | Magic byte format gate | Ralph hub | All |
| 2 | WASM sandbox (dual-metered: fuel + epoch) | Spoke sandbox 1 | Iron/Open |
| 3 | Schema validation (typed, per-field) | Spoke sandbox 2 | All |
| 4 | Injection pattern scanner | Spoke sandbox 2 | Openfang |
| 5 | Structured envelope with provenance tags | Spoke → Ralph | All |
| 6 | Sandwich prompt framing | Spoke sandbox 3 | Iron/Open |
| 7 | Credential injection at host boundary | Ralph host | Iron/Open |
| 8 | Dual LLM (P-LLM / Q-LLM) | Spoke sandbox 3 | Openfang |
| 9 | Opaque variable references (Q-LLM → store) | Ralph host | Openfang |
| 10 | Capability gate (origin × tool permissions) | Ralph host | Openfang |
| 11 | Structural trifecta break (3 WASM contexts) | Spoke sandbox 3 | Openfang |
| 12 | Output auditor | Ralph host | All |
| 13 | Seccomp-bpf secondary containment | Ralph host process | Iron/Open |
| 14 | Hardened Wasmtime config (features disabled) | Ralph host | Iron/Open |
| 15 | Spoke process isolation (one-per-task, teardown) | Ralph hub | All |
| 16 | Audit log (result envelope + security events) | Ralph hub | Openfang |


## Layer-by-layer comparison

### Where all three overlap (strong consensus)

| Capability | IronClaw | OpenFang | Our design |
|-----------|----------|----------|-----------|
| WASM sandbox | ✓ Single-metered | ✓ Dual-metered (fuel + epoch) | ✓ Dual-metered (fuel + epoch) |
| Credential injection | ✓ Host boundary | ✓ Secret zeroization | ✓ Host boundary + never enters WASM memory |
| Rate limiting | ✓ Per-tool | ✓ GCRA | ✓ Fuel budget + LLM call budget per task |
| Resource limits | ✓ Memory/CPU/time | ✓ Via WASM metering | ✓ StoreLimits + fuel + wall-clock |
| Prompt injection defense | ✓ Pattern detection | ✓ Scanner | ✓ Two-pass scanner (regex + heuristic scoring) |
| Audit logging | ✓ Comprehensive | ✓ Merkle chain | ✓ Result envelope logging (not yet Merkle) |
| Capability-based access | ✓ Explicit opt-in | ✓ Kernel-enforced | ✓ Per-variable origin + tool permission gate |

**Assessment:** These are table stakes. Every serious agent framework has them. Our implementation is comparable. The dual-metering (fuel + epoch) matches OpenFang and exceeds IronClaw's single-metered approach.


### Where IronClaw is stronger than our design

| IronClaw layer | Our equivalent | Gap |
|---------------|---------------|-----|
| **TEE (hardware enclave)** | Seccomp-bpf + optional Firecracker | **SIGNIFICANT.** TEEs provide hardware-rooted trust. Even if the host OS is compromised, the enclave remains secure. Our seccomp-bpf is software-only. Firecracker microVMs are closer but still rely on KVM, not hardware attestation. |
| **Endpoint allowlisting** | Not implemented | **MODERATE.** IronClaw restricts HTTP to pre-approved hosts/paths. Our design controls tool calls via the capability gate, but doesn't allowlist specific network endpoints. A compromised tool executor could contact any host. |
| **Bidirectional leak detection** | Output auditor (response-side only) | **MODERATE.** IronClaw scans BOTH outgoing requests AND incoming responses for secret patterns. Our output auditor only checks the final response. We don't scan the outgoing LLM API call prompt for accidentally included secrets. |
| **Encrypted vault with ZeroOnDrop** | Environment variables / credential store | **MINOR.** IronClaw uses Rust `Secret<String>` with automatic memory zeroization. Our spec mentions credential stores but doesn't specify zeroization. Easy fix — use the `secrecy` crate. |

**Action items from IronClaw:**
1. Add endpoint allowlisting to the tool executor. Every tool declares which hosts it may contact. The capability gate enforces this.
2. Add bidirectional leak scanning — scan the OUTGOING prompt to the LLM API for secret patterns before it leaves the host.
3. Use the `secrecy` crate (`Secret<String>`, `Zeroizing<String>`) for all credential handling.
4. Long-term: evaluate TEE deployment on NEAR AI Cloud for the highest-security tier, or investigate Intel TDX / AMD SEV for self-hosted TEE.


### Where OpenFang is stronger than our design

| OpenFang layer | Our equivalent | Gap |
|---------------|---------------|-----|
| **Merkle hash-chain audit trail** | Flat audit log | **MODERATE.** OpenFang's Merkle chain is tamper-evident — altering one entry breaks the chain. Our audit log is append-only but not cryptographically linked. An attacker with database access could modify logs undetected. |
| **Taint tracking (source to sink)** | Provenance tags on variables | **MINOR overlap.** OpenFang propagates taint labels through the entire execution path. Our variable store tracks origin per-value, which is similar but not as granular — we don't track taint through intermediate computations. |
| **Ed25519 manifest signing** | Hash-pinned WASM modules | **MINOR.** OpenFang signs agent identities and capabilities. We pin WASM module hashes but don't cryptographically sign the manifest (who created it, what it's authorized to do). |
| **SSRF protection** | Not implemented | **MODERATE.** OpenFang blocks private IPs, cloud metadata (169.254.x.x), and DNS rebinding. Our design doesn't address this — a tool could be tricked into fetching internal network resources. |
| **Path traversal prevention** | WASM has no filesystem access | **MINIMAL.** Our WASM sandbox simply has no filesystem access, which is a stronger guarantee than preventing path traversal. But for any file operations outside WASM (e.g., Ralph writing results), we don't have explicit path traversal guards. |
| **HTTP security headers** | Not applicable (no web UI) | **N/A.** OpenFang serves a web dashboard. We don't (yet). If Ralph gets a web interface, add CSP/HSTS/etc. |
| **HMAC-SHA256 mutual auth** | Not applicable (no P2P) | **N/A.** OpenFang supports P2P networking between instances. Our agents don't communicate peer-to-peer. |
| **Subprocess isolation** | Not addressed | **MINOR.** If any tool spawns subprocesses (e.g., FFmpeg for media processing), they should run with cleared environments. Our WASM sandbox prevents subprocess spawning entirely, but if we add subprocess tools, we need this. |
| **Human-in-the-loop gates** | Mentioned but not specified | **MODERATE.** OpenFang has mandatory approval gates for sensitive actions. Our spec mentions human review for quarantined outputs but doesn't formalize approval workflows. |

**Action items from OpenFang:**
1. Upgrade audit log to Merkle hash-chain. Each entry includes `hash(previous_entry + current_entry)`. Tamper-evident by construction.
2. Add SSRF protection to the tool executor's HTTP client. Block private IP ranges, link-local addresses, and cloud metadata endpoints.
3. Sign WASM modules with Ed25519 (not just hash-pin). Include the signer identity and authorized capabilities in the signed manifest.
4. Formalize human-in-the-loop approval gates as a first-class concept in the capability gate, not an afterthought.


### Where our design is stronger than both

| Our layer | IronClaw equivalent | OpenFang equivalent | Why ours is stronger |
|----------|-------------------|--------------------|--------------------|
| **Dual LLM (P-LLM / Q-LLM)** | None | None | Neither IronClaw nor OpenFang separates the LLM into privileged and quarantined instances. They both run a single LLM that sees both trusted instructions and untrusted content in the same context window. Our CaMeL-inspired split means the planning LLM never ingests untrusted tokens. |
| **Opaque variable references** | None | None | Neither project prevents the LLM from seeing extracted values. IronClaw's credential injection protects secrets, but extracted file content (which may contain injection payloads) still reaches the LLM directly. Our variable store ensures the P-LLM operates on metadata only. |
| **Structural trifecta break** | Partial (no exfiltration from WASM) | Partial (taint tracking) | IronClaw limits network access per-tool. OpenFang tracks taint. But neither STRUCTURALLY ensures that no single execution context possesses all three trifecta legs simultaneously. Our three-context split (Q-LLM / P-LLM / tool executor) provides this guarantee by construction, not by policy. |
| **Hub-and-spoke with per-task teardown** | Persistent agent | Persistent Hands | IronClaw and OpenFang both run persistent agents with memory across sessions. Our spokes are ephemeral — one per task, torn down after completion. A compromised task cannot contaminate the next. This eliminates the cross-task gossip vector. |
| **Three-sandbox pipeline** | Single WASM per tool | Single WASM per tool | IronClaw and OpenFang sandbox each TOOL. We sandbox each PHASE (parsing, validation, LLM calling) as separate WASM instances with different capability profiles. The parser has zero capabilities; the LLM caller has one (host_call_llm). More granular least-privilege. |
| **Output auditing** | Leak detection (partial) | None specified | IronClaw scans for secret leakage. OpenFang doesn't specify output scanning. Our output auditor checks for instruction smuggling, credential phishing, URL abuse, and contradiction detection — a broader scope than leak detection alone. |
| **Schema validation with injection scoring** | Prompt injection defense | Prompt injection scanner | IronClaw and OpenFang both scan for injection patterns. Our two-pass approach (regex + heuristic scoring with a 0-100 suspicion scale) allows graduated responses (warn/quarantine/reject) instead of binary pass/fail. |
| **Agent tier selection** | N/A (single runtime) | N/A (single runtime) | Neither project offers tiered security. Every task gets the same security stack. Our zeroclaw/ironclaw/openfang tier selection means simple tasks get fast execution (zeroclaw: no WASM, no dual LLM) while high-risk tasks get the full stack. This is a practical advantage — over-securing every task creates performance overhead and prompt fatigue. |


## The fundamental architectural difference

IronClaw and OpenFang both treat security as a **pipeline of filters** applied to a single agent with a single LLM:

```
IronClaw / OpenFang model:

  Input → [filters] → Single LLM (sees everything) → [filters] → Tool → [filters] → Output
```

Our model treats security as **structural separation** between execution contexts:

```
Our model:

  Input → [Parser WASM (0 caps)] → [Validator WASM (0 caps)]
                                           ↓
                                    Variable Store (locked)
                                     ↙              ↘
              Q-LLM WASM (untrusted data, 0 tools)    P-LLM WASM (no untrusted data, plans tools)
                    ↓                                          ↓
              $var bindings                              Task plan ($var refs)
                    ↓                                          ↓
                                  Capability Gate (in Ralph)
                                           ↓
                                  Tool Executor WASM (checked inputs only)
                                           ↓
                                    Output Auditor (in Ralph)
                                           ↓
                                        Result
```

The key insight: **IronClaw and OpenFang assume the LLM will be exposed to untrusted content and try to filter around it. We assume the planning LLM will NOT be exposed to untrusted content — by construction.**

This is the CaMeL innovation. Neither IronClaw nor OpenFang implements it. It's the single biggest differentiator.

But the tradeoff is real: our openfang tier makes at minimum 2 LLM calls per task (P-LLM + Q-LLM), sometimes more. IronClaw and OpenFang make 1. For high-volume, low-risk tasks, our design is more expensive. That's why we have the tier system — zeroclaw skips all of this overhead for structured-data-only tasks.


## Gap summary: what we should adopt from each

### From IronClaw (add to our design):

| Priority | Item | Phase |
|----------|------|-------|
| HIGH | Endpoint allowlisting on tool executor | Phase 2 |
| HIGH | Bidirectional leak scanning (outgoing + incoming) | Phase 2 |
| MEDIUM | `secrecy` crate for credential zeroization | Phase 1 |
| LOW | TEE deployment option (NEAR AI Cloud or Intel TDX) | Phase 4 |

### From OpenFang (add to our design):

| Priority | Item | Phase |
|----------|------|-------|
| HIGH | Merkle hash-chain audit trail | Phase 3 |
| HIGH | SSRF protection (block private IPs, metadata endpoints) | Phase 2 |
| MEDIUM | Ed25519 manifest signing for WASM modules | Phase 3 |
| MEDIUM | Formalized human-in-the-loop approval gates | Phase 2 |
| LOW | Subprocess isolation (if we add subprocess tools) | Phase 4 |

### Already stronger in our design (maintain):

| Item | Why it matters |
|------|---------------|
| Dual LLM pattern | Planning LLM never touches untrusted content |
| Opaque variable references | Smuggling attack structurally neutralized |
| Structural trifecta break | No single context has all 3 legs |
| Per-task spoke teardown | No cross-task contamination |
| Three-sandbox pipeline | Least privilege per phase, not per tool |
| Tiered agent selection | Right-sized security for each task |
