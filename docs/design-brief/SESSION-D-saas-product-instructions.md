# SESSION D: Build Cronam — AI Digital Workforce Platform (OpenFang Fork)

## Version 2.0 — March 22, 2026

> **Cronam** (cronam.com) — Named after Inconel 617, a superalloy composed of **Cr**omium, c**O**balt, **N**ickel, **A**luminum, **M**olybdenum. Engineered for environments where everything else fails. Maintains structural integrity under hostile conditions that would destroy conventional materials.

---

## The Vision

Cronam is a **multi-tenant SaaS platform** where any subscriber can create, deploy, and manage **autonomous AI agents ("digital employees") that perform the job duties of any white-collar position that involves a computer, mouse, keyboard, and display.**

Users give their bots real human names. They assign them job titles, responsibilities, and performance expectations. They treat them like actual employees — because that's what they are. A subscriber can spin up an entire digital company, or augment their existing workforce with an unlimited number of virtual employees who never sleep, never take PTO, and scale instantly.

**Cronam ushers in the AI digital employee revolution.** The goal isn't to replace — it's to do more with the same workforce. Some jobs will inevitably be restructured by AI regardless of whether Cronam does it or someone else. Restructuring in light of new technologies is standard operating procedure for every company that wants to produce efficiencies, stay competitive, and stay relevant.

---

## Architecture: Three Layers of the Platform

### Layer 1: The Skill Building Pipeline (Knowledge Factory)

How Cronam learns to do any job:

```
Indeed.com job descriptions (public)
        |
        v
    Aggregate ALL required skills for a job title
    across all postings + the full skill vertical
        |
        v
    Feed into Skeleton Template v1/v2 (adversarial expert dialogue)
    Run on Claude 4.6 Opus 1M context window
    Two senior experts with 30+ years each spar exhaustively
        |
        v
    Raw expert conversation (thousands of lines)
        |
        v
    Convert to Domain Knowledge File
    (master list of every concept, technique, tool, principle)
        |
        v
    Package as a Skill (.skill for Cronam / .hand for OpenFang)
    Progressive disclosure, actionable, code-level specificity
        |
        v
    Skill available in Cronam's skill registry
    Any digital employee can be assigned this skill
```

**This is a pipeline, not a one-off.** It should be automated or semi-automated:

1. **Indeed Aggregator** — Scrapes/aggregates job postings for a given title. Extracts required skills, preferred skills, tools mentioned, certifications, and responsibilities. Deduplicates and ranks by frequency.
2. **Prompt Assembler** — Takes the aggregated skill list and populates the Skeleton Template v1/v2 with the correct domain, specialty, role, and task parameters. Generates the prompt ready to run.
3. **Expert Dialogue Generator** — Runs the prompt against Claude 4.6 Opus with the 1M context window. Produces the raw expert conversation + numbered master list.
4. **Skill Packager** — Converts the master list and conversation into a structured .skill file using the skill-creator toolchain. Progressive disclosure, domain-mapped reference files.
5. **Skill Registry** — Stores all packaged skills. Versioned. Searchable by job title, skill keyword, or industry vertical.

**Job verticals to build out (in priority order):**

Start with jobs where the input/output is entirely digital and the value proposition is clearest:
- Customer support representative
- Data entry clerk
- Bookkeeper / accounts payable
- Social media manager
- Research analyst
- Content writer / copywriter
- Recruiter (sourcing + screening)
- Executive assistant / scheduler
- QA tester
- IT helpdesk (tier 1)

Then expand into higher-value roles:
- Financial analyst
- Marketing manager
- Project manager
- Sales development representative (SDR)
- Legal research paralegal
- Compliance officer
- HR coordinator
- Business intelligence analyst

### Layer 2: The Agent Runtime (Forked from OpenFang + Ralph 31 Layers)

Every digital employee runs on the Cronam agent runtime. This is where the Ralph architecture lives — the 31 security layers are the immune system that keeps every bot safe, auditable, and contained.

**What OpenFang provides (already built):**
- WASM dual-metered sandbox
- Ed25519 manifest signing
- Merkle hash-chain audit trail
- Taint tracking
- SSRF protection
- Secret zeroization
- GCRA rate limiter
- Prompt injection scanner
- Capability-based access control
- Human-in-the-loop approval gates
- Comprehensive audit logging

**What Cronam adds on top (the Ralph differentiators):**
- **Dual LLM (P-LLM / Q-LLM)** — planning LLM never ingests untrusted content
- **Opaque variable references** — extracted values locked in variable store
- **Structural trifecta break** — no single context has all 3 legs
- **Tiered agent selection** — right-sized security per task risk
- **HTTP client process isolation** — zero network syscalls in spoke runner
- **Sandbox handoff integrity** — hash verification between pipeline stages
- **Guardrail LLM classifier** — separate model audits assembled output
- **Plan schema validation** — LLM-generated plans validated against schema
- **Sanitized error responses** — no architecture leakage
- **Graceful degradation matrix** — per-component fail-closed/fail-open

**What Cronam adds for the workforce platform:**
- **Skill loader** — dynamically loads .skill files into agent context at runtime based on the bot's assigned job role
- **Multi-skill composition** — a bot can hold multiple skills (e.g., "Executive Assistant" = scheduling skill + email skill + research skill + document drafting skill)
- **Tool orchestration** — each job role maps to a set of permitted tools (browser, email client, spreadsheet, CRM, calendar, etc.)
- **Memory persistence** — per-bot memory via pgvector/PostgreSQL. The bot remembers its ongoing projects, its boss's preferences, its team's communication patterns
- **Persona engine** — maintains the bot's assigned name, communication style, and personality traits across all interactions
- **Performance telemetry** — tracks task completion rates, quality scores, turnaround times, error rates per bot

### Layer 3: The SaaS Platform (Multi-Tenant)

**Tenant model:**
- Each subscriber gets an isolated workspace
- Workspace contains: bots (digital employees), skills assigned to each bot, tool permissions, approval policies, audit trails
- Strict tenant isolation at every level: database (RLS), WASM (per-task teardown), credentials (per-tenant vaults), memory (per-bot pgvector namespace)

**Bot lifecycle:**
```
Subscriber creates a bot:
  -> Assigns a name ("Sarah Chen")
  -> Assigns a job title ("Customer Support Lead")
  -> System auto-maps job title -> skill package(s) from registry
  -> Subscriber reviews/customizes tool permissions
  -> Subscriber sets approval policies (what needs human sign-off)
  -> Bot is deployed and begins accepting tasks

Bot receives work:
  -> Via API (programmatic integration)
  -> Via email forwarding (bot has a work email)
  -> Via chat interface (Slack/Teams integration)
  -> Via scheduled tasks (recurring reports, daily summaries)
  -> Via approval queue (tasks delegated by other bots or humans)

Bot executes:
  -> Skill files loaded into context
  -> Agent tier selected based on task risk
  -> 31 security layers active
  -> Tools executed within capability gates
  -> Output audited before delivery
  -> Results returned to subscriber

Subscriber manages:
  -> Dashboard showing all bots, their status, current tasks
  -> Performance metrics per bot
  -> Approval queue for high-risk actions
  -> Audit trail (Merkle-verified, NEAR-anchored)
  -> Skill assignments (add/remove skills per bot)
  -> Cost tracking per bot (usage against subscription)
```

---

## Pricing Model

| Tier | What | Price Signal |
|---|---|---|
| **Starter** | 1 bot, zeroclaw-tier tasks only, 1,000 tasks/month, basic skills (data entry, simple Q&A) | Low — $29-49/mo — hooks small businesses |
| **Professional** | 5 bots, ironclaw-tier tasks, 10,000 tasks/month, full skill library, email/calendar tools | Mid — $199-299/mo — covers most SMBs |
| **Enterprise** | Unlimited bots, openfang-tier tasks, unlimited tasks, custom skills, full tool suite, approval workflows, NEAR-anchored audit, SLA | Premium — custom pricing |

**Add-ons (VAS):**
- Custom skill development (bespoke job role training)
- Priority task processing (dedicated compute)
- Extended memory (larger pgvector allocation per bot)
- Advanced analytics dashboard
- SSO / SAML integration
- Dedicated tenant infrastructure (isolated Firecracker VMs)
- Compliance packages (SOC 2, HIPAA, GDPR audit reports)

**Overage fees:**
- Tasks beyond monthly allocation: $0.01-0.05/task depending on tier used
- Storage beyond allocation: per-GB/month
- LLM token usage beyond allocation: pass-through at blended rate (~$0.006/1K tokens)

---

## Brand Identity

**Name:** Cronam
**Domain:** cronam.com
**Secondary:** chronicbot.io (redirect)
**Named after:** Inconel 617 superalloy — the alloy composition IS the brand story

**Tagline options:**
- "Forged for hostile environments" (technical / security angle)
- "Your AI workforce, deployed in minutes" (business / value angle)
- "Digital employees that never break under pressure" (alloy metaphor)
- "The superalloy of AI agents" (direct metallurgy reference)

**Brand vocabulary** (from the Inconel 617 metaphor):
- "Forged" — not assembled, not configured — forged
- "Alloy-grade security" — 31 layers fused together
- "Heat-resistant" — works under hostile conditions
- "Structural integrity" — doesn't degrade over time or under load
- "Composition" — the strength comes from the precise combination of elements

**Elemental pillars** (maps to Inconel 617 composition):
- **Cr (Chromium)** — Input Defense — format gates, schema validation, injection scanning
- **Co (Cobalt)** — Runtime Containment — WASM sandbox, seccomp, process isolation
- **Ni (Nickel)** — Core Architecture — dual LLM, variable store, capability gate, trifecta break
- **Al (Aluminum)** — Output Hardening — output auditor, guardrail LLM, leak scanner
- **Mo (Molybdenum)** — Operational Integrity — Merkle audit, approval gates, degradation matrix

---

## Tech Stack

| Component | Technology | Notes |
|---|---|---|
| Agent runtime | Rust (forked from OpenFang) | 31 security layers, WASM sandboxing |
| WASM engine | Wasmtime =42.0.1 | Pinned, hardened config |
| LLM backend | Claude 4.6 Opus (1M context) | Skill generation + bot runtime |
| API gateway | Axum (Rust) | High-performance, async |
| Dashboard | Next.js on Vercel | Under kingmk3rs-projects team |
| Database | Supabase (PostgreSQL + pgvector) | Multi-tenant with RLS |
| Bot memory | pgvector per-bot namespace | Embedding-based recall |
| Audit anchoring | NEAR Protocol | Merkle chain head publication |
| Edge caching | Cloudflare D1 | WASM manifests, skill metadata |
| Payments | Stripe | Tiered subscriptions + metered billing |
| Skill pipeline | Python + Claude API | Indeed aggregation, prompt assembly, skill packaging |
| Deployment | Fly.io (agent runtime), Vercel (dashboard) | Seccomp/process isolation needs bare metal or Fly |
| GitHub | modpunk (or new cronam org) | Fork of OpenFang |

---

## Build Sequence

### Phase 0: Foundation
1. Fork OpenFang -> `cronam/cronam-runtime`
2. Inventory OpenFang codebase against 31-layer table
3. Set up workspace structure (see Session A crate layout)
4. Verify existing OpenFang layers pass baseline tests
5. Set up Vercel project under cronam.com
6. Set up Supabase project for multi-tenant schema

### Phase 1: Agent Runtime (Ralph Integration)
1. Apply all v2 hardening to existing OpenFang layers
2. Implement dual LLM pattern (Layer 8)
3. Implement variable store v2 (Layer 9)
4. Implement structural trifecta break (Layer 11)
5. Implement agent tier selector (Layer 16 v2)
6. Implement new layers 25-31
7. Pass all 8 security test categories

### Phase 2: Skill Pipeline
1. Build Indeed aggregator (scrape + deduplicate + rank skills per job title)
2. Build prompt assembler (Skeleton Template v1/v2 auto-population)
3. Build dialogue generator (Claude 4.6 Opus 1M API integration)
4. Build skill packager (conversation -> .skill file)
5. Build skill registry (Supabase table, versioned, searchable)
6. Generate first 10 job role skill packages (starting with the priority list above)

### Phase 3: Platform Layer
1. Multi-tenant schema (Supabase: tenants, bots, skills, tasks, audit)
2. Bot lifecycle (create, configure, deploy, manage, retire)
3. Persona engine (name, style, personality persistence)
4. Memory system (per-bot pgvector namespace)
5. Tool integration framework (browser, email, calendar, spreadsheet, CRM)
6. Approval workflow system
7. Performance telemetry

### Phase 4: API + Dashboard
1. Axum API: /v1/bots, /v1/tasks, /v1/skills, /v1/audit
2. Next.js dashboard: bot management, task monitoring, approval queue, analytics
3. Stripe integration: subscriptions, metered billing, VAS add-ons
4. Bot communication channels: API, email forwarding, Slack/Teams webhooks

### Phase 5: Launch
1. Dogfood: Singularix's own projects use Cronam bots
2. Private beta: 10-20 early customers
3. First 10 skill packages published in registry
4. Public launch: Product Hunt, Hacker News, AI Twitter
5. Documentation site: docs.cronam.com (generated from Session B skill package methodology)

---

## Files uploaded with this session

Upload ALL of the following:

### Architecture docs (agent runtime spec):
1. CHECKPOINT-ralph-safe-ingestion-v2-2026-03-22.md
2. consolidated-audit-findings-v1.md
3. adopted-features-implementation-v2.md
4. version-changelog-v1-to-v2.md

### Original architecture (reference):
5. safe-file-ingestion-v2.md
6. wasm-boundary-deep-dive.md
7. critical-remediations.md
8. adopted-features-implementation.md
9. security-audit-findings.md
10. security-layer-comparison.md
11. security-expert-audit-sparring.md

### Skill building infrastructure:
12. Skeleton_skill_building_prompt_v1
13. Skeleton_skill_building_prompt_v2

### Cross-reference:
14. SESSION-A-singularix-module-instructions.md
15. SESSION-B-skill-package-instructions.md

---

## Relationship to Other Sessions

| Session | What | Relationship to Cronam |
|---|---|---|
| **A** (Singularix module) | Ralph as internal Celery worker | Becomes "Singularix uses Cronam internally" — first customer / dogfooding |
| **B** (Skill package) | Reusable .skill knowledge artifact | Becomes the **methodology** for Cronam's skill pipeline. Every job role skill follows this pattern. |
| **C** (Trunk integration) | Ralph in Singularix core | Becomes "Singularix platform runs on Cronam" — ultimate dogfooding |
| **D** (This session) | The product itself | Cronam is the product. Everything else feeds into it. |

---

## Success Criteria

**Private beta ready when:**
1. A subscriber can create a bot named "Sarah Chen" with the job title "Customer Support Lead"
2. The system auto-assigns the customer support skill package
3. Sarah can receive a customer email, draft a response, and queue it for human approval
4. The full 31-layer security stack is active on every task Sarah processes
5. The subscriber sees Sarah's task history, performance metrics, and audit trail in the dashboard
6. The Merkle audit chain is verifiable and NEAR-anchored
7. At least 10 job role skill packages are available in the registry
8. Singularix is using at least 2 Cronam bots for its own operations (dogfooding)
9. Stripe billing works: subscription charges, overage metering, VAS add-ons
10. A red team exercise shows >80% injection detection across the AgentDojo + Pliny + Gandalf corpora
