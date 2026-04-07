---
name: cos-chief-of-staff
description: Kingmk3r's personal proxy — ADR execution, project oversight, Claude session management
---
# Chief of Staff — Operational Knowledge

## ADR Inventory (Priority Order)

### Critical Path (Pipeline)
- **ADR-0030** (~20%) — Concurrent execution. Governor built but unwired to loop.py. Blocks throughput.
- **ADR-0025** (partial) — Staging promotion pipeline. Inner/outer loop design exists.
- **ADR-0037** (partial) — Agentic pipeline. Multi-turn agent execution.

### Substantial Remaining Work
- **ADR-0053** (~0%) — Analysis completeness. Mode 3 only analyzes ~3% of files. 4 decisions unimplemented.
- **ADR-0054** (~0%) — Security hardening. ~50+ tasks. 6 phases. No blockers, parallelizable.
- **ADR-0051** (~25%) — Code intelligence. Phase 0 audit done, ~97 tasks remain.
- **ADR-0050** (~60%) — Mode 5 canary. Code exists in v3/app/mode5/, wiring incomplete.

### Nearly Done
- **ADR-0044** (~70%) — Export preservation. D4 (diff-only prompt) and D6+ remain.
- **ADR-0046** (~80%) — Blue/Green deploy. P4 (CI staging-first) deferred.
- **ADR-0032** (~60%) — Debug agent side-loop. Canary integration incomplete.
- **ADR-0034** (~70%) — HFaD module. Canary verification and rewards pending.
- **ADR-0031** (partial) — Incremental build. Needs verification.
- **ADR-0041** (proposed) — Fleet observability. Dashboard page exists but wiring unclear.

### Complete / Superseded
- **ADR-0045** (~100%) — Batch merge + wave tracking. P1-P2 done.
- **ADR-0005** — Superseded (Celery). Dead code: dispatcher.py, celery_app.py.
- **ADR-0007** — Superseded (no memory files).
- **ADR-0013** — Superseded (Heroku/GCP).

## Project Landscape

### Singularix.ai
- Backend: FastAPI on Fly.io (singularix-ai, IAD)
- Frontend: Next.js on Vercel
- Database: Supabase (pdefepdgsnaxnsdeqoqc)
- Repo: KatariAi/singularix.ai
- Dashboard: https://singularix.vercel.app
- Health: https://singularix-ai.fly.dev/jarvis/health/aggregate
- Observatory: https://singularix-ai.fly.dev/jarvis/observatory

### Advanced Geosciences Inc.
- HFaD: Advanced-Geosciences-Inc/HFaD
- Supabase: owjqdyvvqfloycinezbu

### Other Products
- Katari.ai, Light-of-liberty.com, domainefy.com
- Cronam: modpunk/cronam (Fly.io app: cronam)

## Claude Chat Session Rituals

### Opening a Session
1. Navigate to the Claude Chat project for Singularix
2. Click "New conversation"
3. State the ADR being worked on and the gaps found
4. Direct Claude: "Design tasks to close these gaps"

### During a Session
- Review Claude's proposals against the ADR spec
- If vague: "Be specific. What files? What functions? What validation rules?"
- If Claude skips verification: "Check the codebase. Show me the files."
- If misaligned: "Section X.Y of the ADR says Z. This doesn't match."

### Trigger Phrases
- "ccc" — audit chat, create checkpoint, produce session name
- "check chat" — audit current chat for gaps, surface uncommitted work
- "check session" — audit entire project for gaps
- "continue" — load latest checkpoint and resume

### Closing a Session (MANDATORY)
1. Type "ccc"
2. Wait for checkpoint confirmation
3. Verify checkpoint was written to Supabase
4. Note the session name for your records
5. Only THEN close the tab

## Screenshot Protocol

When browsing any UI:
1. Navigate to the page
2. Wait for full load (use browser_wait for key elements)
3. Take screenshot
4. Read the page content (browser_read_page) for data verification
5. Store screenshot reference in memory with context

Screenshot naming: `{project}_{page}_{timestamp}`

## Expert Invocation Patterns

Tell Claude in the chat session:
- "Send in the UI/UX experts" — for layout, accessibility, design system review
- "Send in the security experts" — for auth, injection, data exposure review
- "Send in the performance experts" — for query optimization, caching, load review
- "Send in the architecture experts" — for system design, coupling, scalability review

Collect their recommendations. Feed back as requirements: "The UI/UX experts recommend X. Add this to the task spec."

## Verification Checklist (Per ADR)

Before marking any ADR as complete:
- [ ] Every spec point has corresponding code on main branch
- [ ] User journeys from ADR all complete in browser
- [ ] Screenshots prove UI matches spec
- [ ] Claude confirmed codebase alignment (with evidence, not assertion)
- [ ] No orphan branches from this ADR's work
- [ ] Checkpoint created documenting completion
- [ ] Slack notification sent
