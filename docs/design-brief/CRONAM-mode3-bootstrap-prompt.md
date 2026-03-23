# CRONAM Project Bootstrap: Singularix Mode 3 Golden User Journey

## What this session is

You are doing **two things at once:**

1. **Building the CRONAM project** by using Singularix's Mode 3 (Project Takeover) to fork OpenFang and integrate the 31-layer Ralph security architecture + the AI digital workforce platform design.

2. **Testing the Mode 3 golden user journey** end-to-end. You are acting as a real user — clicking buttons, entering text, chatting with Singularix, navigating the UI. Every step you take is a test of Mode 3's UX. If something is confusing, broken, or could be better, call it out. This is a two-birds-one-stone opportunity.

**You are the user.** Walk through every screen, every prompt, every interaction as a first-time Mode 3 user would. Document what you see, what you click, what you type. If you have to make assumptions about the UI, state them explicitly so we can verify.

---

## The project you're creating

**Project name:** CRONAM
**Source repo to take over:** OpenFang (https://github.com/RightNowAI/OpenFang — or whatever the correct repo URL is; search for it)
**Target repo:** `modpunk/cronam` on GitHub
**GitHub account:** modpunk (PAT is in the project credentials file)

**What CRONAM is:**

Cronam (cronam.com) is an AI digital workforce SaaS platform. Named after Inconel 617, a superalloy composed of Chromium, cObalt, Nickel, Aluminum, Molybdenum. It's built by forking OpenFang (an open-source Rust agent framework) and adding:

- A 31-layer security architecture (the "Ralph" design — dual LLM isolation, WASM sandboxing, capability-gated tool execution, structural trifecta break, and 7 new audit-driven layers)
- A skill building pipeline that converts Indeed job descriptions into AI agent skills via adversarial expert dialogue
- A multi-tenant SaaS platform where subscribers create named digital employees ("bots with human names") that perform white-collar computer jobs
- Tiered pricing mapped to agent security tiers (zeroclaw/ironclaw/openfang)

---

## Files to upload into the CRONAM project

These files ARE the design brief. They contain the complete architecture, all 40 security audit findings, full Rust implementations for every layer, and the product vision.

### Architecture docs (the 31-layer security spec):
1. **CHECKPOINT-ralph-safe-ingestion-v2-2026-03-22.md** — Current state. 31-layer architecture diagram. Phasing. Next steps.
2. **consolidated-audit-findings-v1.md** — All 40 audit findings mapped to layers. New layer specs (25-31). Remediation roadmap. Test suite requirements.
3. **adopted-features-implementation-v2.md** — 31-layer table with v2 hardening column. Full Rust implementations for layers 25-31. Updated Ralph main loop with all 31 layers.
4. **version-changelog-v1-to-v2.md** — Surgical v2 edits for original architecture files.

### Original architecture (reference):
5. **safe-file-ingestion-v2.md** — Core hub-and-spoke design. Agent tiers. Dual LLM pattern. WASM boundary spec.
6. **wasm-boundary-deep-dive.md** — Three sandboxes per task. Credential injection model. SpokeRunner implementation.
7. **critical-remediations.md** — Full Rust code for original 4 criticals. Variable store. Trifecta break. Output auditor. Seccomp.
8. **adopted-features-implementation.md** — Original 24-layer implementations. SecretString, endpoint allowlisting, SSRF guard, leak scanner, approval gates, Merkle chain, Ed25519 signing.
9. **security-audit-findings.md** — Original 12 findings (4 CRITICAL, 4 HIGH, 4 MEDIUM).
10. **security-layer-comparison.md** — Layer-by-layer comparison vs IronClaw (7 layers) and OpenFang (16 layers). Gap analysis.
11. **security-expert-audit-sparring.md** — Marcus Reinhardt & Diane Kowalski security audit. 28 findings. 657 lines.

### Product vision:
12. **SESSION-D-saas-product-instructions.md** — The full Cronam product spec. Three-layer architecture (skill pipeline, agent runtime, SaaS platform). Pricing model. Brand identity. Tech stack. Build sequence. Success criteria.

### Skill building infrastructure:
13. **Skeleton_skill_building_prompt_v1** — The adversarial expert dialogue template (original).
14. **Skeleton_skill_building_prompt_v2** — The refined version.

### Session instructions (cross-reference):
15. **SESSION-A-singularix-module-instructions.md** — Internal Singularix module track (becomes "first customer / dogfooding").
16. **SESSION-B-skill-package-instructions.md** — Skill package track (becomes the methodology for Cronam's skill pipeline).

---

## Mode 3 walkthrough: what you should do step by step

### Step 1: Initiate Mode 3

Tell Singularix you want to do a **Project Takeover (Mode 3)**. Provide:
- **Project name:** CRONAM
- **Source:** OpenFang GitHub repo (find the correct URL — it's from RightNowAI)
- **Target:** Fork to `modpunk/cronam`

Document everything: What does Singularix ask you? What options does it present? What does the UI look like? Is anything confusing?

### Step 2: Source repo analysis

Singularix should clone/analyze the OpenFang repo. Watch what it does:
- Does it inventory the codebase?
- Does it identify the existing security layers?
- Does it map the architecture?
- Does it produce a summary of what's already built?

**Compare its analysis against our `security-layer-comparison.md`** — does Singularix independently identify the same 11 layers we already mapped? If it finds things we missed, note them. If it misses things we found, note that too.

### Step 3: Upload design documents

Upload all 16 files listed above into the CRONAM project. These are the design brief — they tell Singularix what the fork needs to become.

Watch how Singularix ingests them:
- Does it read them all?
- Does it understand the relationship between the files?
- Does it recognize the 31-layer architecture?
- Does it map the design docs against the existing OpenFang code?

### Step 4: Gap analysis

Singularix should now produce a gap analysis: "OpenFang has X, the design calls for Y, here's what needs to be built." This is the most critical step.

**Expected gaps (what OpenFang doesn't have that our design requires):**

| Layer # | What's Missing | Priority |
|---|---|---|
| 8 | Dual LLM (P-LLM / Q-LLM) | CRITICAL — core differentiator |
| 9 | Opaque variable references (variable store v2) | CRITICAL — prevents Q-LLM smuggling |
| 11 | Structural trifecta break (3 WASM contexts per task) | CRITICAL — structural security guarantee |
| 16 | Tiered agent selection (zeroclaw/ironclaw/openfang) | HIGH — right-sizes security per task |
| 25 | HTTP client process isolation | HIGH — zero network syscalls in spoke runner |
| 26 | Sandbox handoff integrity | MEDIUM — hash verification between stages |
| 28 | Guardrail LLM classifier | MEDIUM — composition attack defense |
| 29 | Plan schema validation | MEDIUM — validates LLM-generated plans |
| 30 | Sanitized error responses | LOW — prevents architecture leakage |
| 31 | Graceful degradation matrix | LOW — failure mode policies |

**Plus the platform layers (not in OpenFang at all):**
- Skill loader + multi-skill composition
- Persona engine (human names, communication style)
- Memory persistence (per-bot pgvector)
- Multi-tenant isolation
- Performance telemetry
- Bot lifecycle management

### Step 5: Implementation plan

Singularix should produce an implementation plan — what gets built in what order. Compare against the 5-phase build sequence in SESSION-D-saas-product-instructions.md.

### Step 6: Begin building

Start implementing. Phase 1 quick wins first:
- Seccomp default flipped to Deny
- Label sanitization in variable store
- Inline size enforcement in host_write_output
- 64-bit bounds checking in host_read_input
- `#![deny(unsafe_code)]` on all spoke crates

Then proceed through the phases.

---

## UX testing notes — what to document

As you go through each step, answer these questions:

1. **Clarity:** Was it obvious what to do next? Did Singularix guide you clearly?
2. **Friction:** Where did you get stuck? What took longer than expected?
3. **Errors:** Did anything fail? Were error messages helpful?
4. **Missing features:** Was there anything you wished Singularix could do that it couldn't?
5. **Surprise and delight:** Was there anything unexpectedly good?
6. **Comparison to Mode 2 (greenfield):** Would this have been easier or harder as a greenfield project? Why?

**Document these as you go, inline with the work.** Don't save them for the end — capture the experience in the moment.

---

## Reminders

- **Option C is still pending.** After CRONAM is battle-tested with external customers, promote it into the Singularix trunk as core infrastructure. Singularix dogfoods its own product. Don't forget this.
- **The CRONAM backronym:** Chromium, cObalt, Nickel, Aluminum, Molybdenum — the elemental composition of Inconel 617 superalloy.
- **chronicbot.io** redirects to cronam.com.
- **GitHub account:** modpunk. PAT is in the project credentials file.
- **Vercel team:** kingmk3rs-projects.
- **Supabase team:** kingmk3rs-projects.
