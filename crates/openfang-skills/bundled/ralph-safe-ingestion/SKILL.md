---
name: ralph-safe-ingestion
description: >-
  31-layer security architecture for AI agents processing untrusted files.
  Hub-and-spoke model with three tiers: zeroclaw (minimal), ironclaw (WASM
  sandbox), openfang (dual LLM + capability gates). Consult for WASM
  sandboxing, dual LLM patterns, prompt injection defense, agent isolation,
  seccomp hardening, capability gates, output auditing, leak scanning, SSRF
  protection. Based on CaMeL, IsolateGPT, and PromptArmor research.
---

# Ralph Safe File Ingestion & Agent Isolation

## Architecture
Ralph is a hub-and-spoke security orchestrator with 31 defense layers across three agent tiers:
- **zeroclaw**: Structured data only (JSON/CSV). Schema validation is the defense. No sandbox.
- **ironclaw**: WASM-sandboxed parsing and LLM calls. Host-injected credentials. Crypto-aware.
- **openfang**: Dual LLM (CaMeL pattern). Q-LLM quarantined (zero tools/network). P-LLM sees only opaque variable references. Three WASM contexts break the lethal trifecta.

Default routing: ambiguous or unknown → openfang. Tier floor: once classified, never downgraded.

## Key Patterns
- **Variable store**: Q-LLM output stored as opaque refs ($var_xxxx). P-LLM never sees actual values. Label sanitization, size limits, coarse buckets.
- **Capability gate**: Origin × tool permission matrix. Immutable after spoke creation. Deny-by-default.
- **Seccomp-bpf**: Default Deny. Zero network syscalls (HTTP via Layer 25 proxy process).
- **Output auditor**: Individual + assembled output scanning. Guardrail LLM for RED-tier tasks.
- **Trifecta break**: No single WASM context has private data + untrusted content + external comms.

## When to Consult
- Designing file processing for untrusted inputs
- Implementing WASM sandbox isolation
- Building dual LLM architectures
- Defending against prompt injection in agentic systems
- Reviewing agent security architecture
- Implementing approval gates, audit chains, or capability controls
