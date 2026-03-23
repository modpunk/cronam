# SESSION B: Package Ralph Architecture as a Reusable Skill

## Context for this session

You are packaging the Ralph safe file ingestion and agent isolation architecture (31 security layers) into a reusable `.skill` file that any Claude session or AI agent can consult when building security-sensitive file-handling systems.

**This session's goal:** Convert the architecture docs into a callable skill package using the skill-creator toolchain. The skill should be invocable as "consult with the security experts on safe file ingestion" or "audit this code for Ralph-pattern security compliance."

**Parallel session:** A separate chat is building the actual Rust implementation as a Singularix module (Option A). This session focuses on the knowledge artifact only.

**Future milestone (DO NOT FORGET):** After the Singularix module (Option A) is battle-tested across 2-3 projects, the next step is **Option C — promoting Ralph into the Singularix trunk** as core platform infrastructure. This skill should be updated at that point to reflect production learnings.

---

## Files uploaded with this session

Upload ALL of the following files from the project:

### Post-consolidation docs (primary source material):
1. `CHECKPOINT-ralph-safe-ingestion-v2-2026-03-22.md` — Current state, 31-layer architecture, phasing.
2. `consolidated-audit-findings-v1.md` — All 40 findings mapped to layers. New layer specs. Test suite. Disagreements.
3. `adopted-features-implementation-v2.md` — 31-layer table. Rust implementations for layers 25-31. Updated main loop.
4. `security-expert-audit-sparring.md` — Marcus/Diane audit. 28 findings. 657 lines. Techniques list.

### Original architecture (reference):
5. `safe-file-ingestion-v2.md` — Core architecture. Hub-and-spoke. Dual LLM.
6. `wasm-boundary-deep-dive.md` — Three sandboxes. Credential injection. SpokeRunner.
7. `critical-remediations.md` — Variable store. Trifecta break. Output auditor. Seccomp.
8. `adopted-features-implementation.md` — Original 24-layer implementations.
9. `security-audit-findings.md` — Original 12 findings.
10. `security-layer-comparison.md` — IronClaw/OpenFang comparison.
11. `version-changelog-v1-to-v2.md` — Surgical edits for v2 updates.

### Skill tooling:
12. Read the skill-creator SKILL.md at `/mnt/skills/examples/skill-creator/SKILL.md` before starting.

---

## What to build

### Skill structure

```
ralph-safe-ingestion/
├── SKILL.md                          # Main orchestration file (~150 lines)
│                                     # - Trigger description
│                                     # - Domain map (which ref to read for which task)
│                                     # - Quick-start decision tree
│                                     # - 31-layer summary table
│
├── references/
│   ├── architecture-overview.md      # Hub-and-spoke model, agent tiers, tier selection rules
│   │                                 # Source: safe-file-ingestion-v2.md (condensed)
│   │
│   ├── wasm-boundary.md              # Three sandboxes, host functions, credential injection
│   │                                 # Source: wasm-boundary-deep-dive.md (condensed)
│   │
│   ├── dual-llm-pattern.md           # P-LLM / Q-LLM split, variable store, capability gate
│   │                                 # Source: critical-remediations.md openfang sections
│   │
│   ├── security-layers-1-16.md       # Original 16 layers with v2 hardening notes
│   │                                 # Source: adopted-features-implementation-v2.md layers 1-16
│   │
│   ├── security-layers-17-24.md      # IronClaw/OpenFang adopted layers with v2 hardening
│   │                                 # Source: adopted-features-implementation-v2.md layers 17-24
│   │
│   ├── security-layers-25-31.md      # New audit-consolidated layers with full implementations
│   │                                 # Source: adopted-features-implementation-v2.md layers 25-31
│   │
│   ├── audit-findings.md             # Condensed 40-finding table with remediation status
│   │                                 # Source: consolidated-audit-findings-v1.md (table only)
│   │
│   ├── threat-model.md               # What the architecture defends against / doesn't
│   │                                 # Attack scenarios, known limitations, honest assessment
│   │                                 # Source: safe-file-ingestion-v2.md threat model section
│   │
│   ├── test-suite.md                 # 8 test categories with specific tools and thresholds
│   │                                 # Source: consolidated-audit-findings-v1.md test section
│   │
│   └── rust-patterns.md              # Key Rust code patterns: SpokeRunner, VariableStore,
│                                     # OutputAuditor, CapabilityGate, SeccompFilter
│                                     # Source: critical-remediations.md + adopted-features code
```

### SKILL.md design

The SKILL.md should use **progressive disclosure** — agents load only the reference files relevant to their current task:

```markdown
## When to use this skill

Trigger on ANY of these:
- "safe file ingestion", "process untrusted files", "file parsing security"
- "WASM sandbox", "sandbox escape", "Wasmtime hardening"
- "dual LLM", "P-LLM", "Q-LLM", "quarantined LLM"
- "prompt injection defense", "injection scanning"
- "lethal trifecta", "capability gate", "variable store"
- "agent isolation", "spoke isolation", "hub and spoke"
- "Ralph security", "31 security layers", "openfang", "ironclaw", "zeroclaw"
- "output auditing", "leak scanning", "SSRF protection"
- "seccomp", "credential injection", "secret zeroization"
- Code review of file-handling, LLM-calling, or tool-executing code
- Architecture review of any agentic AI system

## Quick domain map

| If you're working on... | Read these references |
|---|---|
| Overall architecture decisions | `architecture-overview.md` |
| WASM sandbox implementation | `wasm-boundary.md` |
| Dual LLM / variable store / capability gate | `dual-llm-pattern.md` |
| Hardening existing layers (1-16) | `security-layers-1-16.md` |
| Adding IronClaw/OpenFang features (17-24) | `security-layers-17-24.md` |
| New audit-driven layers (25-31) | `security-layers-25-31.md` |
| Understanding the threat model | `threat-model.md` |
| Writing security tests | `test-suite.md` |
| Rust implementation patterns | `rust-patterns.md` |
| Reviewing audit findings | `audit-findings.md` |
```

### Key principles for the skill

1. **Nothing left out.** Every one of the 31 layers, all 40 findings, all 8 test categories, all expert disagreements, and all Rust code patterns must be present in the skill. Condensed for progressive loading, but complete.

2. **The skill is a security immune system.** It should trigger automatically whenever an agent is writing code that touches files, makes LLM calls, executes tools, or handles credentials. The trigger description should be broad enough to catch all of these.

3. **Ironclaw/Singularix-specific context preserved.** The skill should retain all references to Rust, Wasmtime, pgvector, NEAR Protocol, Celery/Redis, and the modpunk project ecosystem. This isn't a generic security guide — it's the Ralph architecture.

4. **Actionable, not advisory.** Every reference file should include concrete Rust code, specific crate versions, exact regex patterns, and named tools. An agent consulting this skill should be able to write production code, not just understand the concepts.

### Packaging

After building all files, package using the skill-creator toolchain:

```bash
cd /mnt/skills/examples/skill-creator
python -m scripts.package_skill /home/claude/ralph-safe-ingestion /mnt/user-data/outputs/ralph-safe-ingestion.skill
```

Also deliver the raw files in case the .skill packaging has issues — the raw directory is usable directly.

---

## Quality checklist before delivery

- [ ] SKILL.md trigger description covers all 31 layers by keyword
- [ ] Domain map routes to correct reference files
- [ ] 31-layer table present with v2 hardening column
- [ ] All 40 audit findings present (at minimum as a summary table)
- [ ] All 8 test categories with named tools and thresholds
- [ ] All 8 expert disagreements with resolutions
- [ ] Rust code for: SpokeRunner, VariableStore, OutputAuditor, CapabilityGate, SeccompFilter, HttpProxy, HandoffIntegrity, RateLimiter, GuardrailClassifier, PlanValidator, SanitizedError, DegradationMatrix
- [ ] Phased remediation roadmap with time estimates
- [ ] Threat model (defends against / doesn't defend against)
- [ ] Cost model per tier
- [ ] `#![deny(unsafe_code)]` noted as mandatory
- [ ] Wasmtime `=42.0.1` pinning noted
- [ ] `secrecy` + `zeroize` crate usage documented
- [ ] Progressive disclosure works — agents don't load all 10 reference files for a simple question

---

## Success criteria

The skill is done when:
1. `package_skill` produces a valid `.skill` file
2. A fresh Claude session can load the skill and correctly answer: "What are the 7 new layers added from the audit consolidation?"
3. A fresh Claude session can load the skill and write a correct `apply_spoke_seccomp()` function with default Deny and no network syscalls
4. The SKILL.md alone (without reference files) gives enough context to route to the right reference
5. No information from the source docs is missing — verify the 31-layer table, 40 findings, 8 tests, and all Rust patterns are present
