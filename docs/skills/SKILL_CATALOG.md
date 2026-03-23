# Skill Catalog — skills-and-agents

> Auto-generated during Project Canon bootstrap on 2026-03-22.
> Skills are loaded from the project's Supabase `skill_library` table.

## How to Use

In any Claude session connected to this project's Supabase:

- `load skill [name]` — Load a skill for the current session
- `show skills` — List all available skills
- `find skill for [topic]` — Search by keyword

## Available Skills

### Debugging (8 skills)

| Skill | Description |
|---|---|
| `saas-debug` | Master-level SaaS debugging. 10-step workflow, suspect list, 8 isolation techniques, 20-category taxonomy. Routes to 7 sub-modules. |
| `debug-bug-taxonomy` | Complete taxonomy of 20 SaaS bug categories with causes, detection, and prevention. |
| `debug-tooling` | Log analysis, metrics/observability (RED/USE), distributed tracing, profiling, system-level tracing. |
| `debug-database` | PostgreSQL, MySQL, Redis debugging. Active queries, locks, bloat, indexes, ORM debugging. |
| `debug-network-infra` | DNS, TLS/SSL, TCP, HTTP/proxy, cloud infrastructure, Kubernetes debugging. |
| `debug-concurrency-perf` | Race conditions, performance methodology, distributed systems, data issues. |
| `debug-security-frontend` | Security bug checklist, SaaS security, frontend/DevTools debugging. |
| `debug-process-wisdom` | Incident response, reproduction techniques, language-specific tips, debugging zen. |

### Security (5 skills)

| Skill | Description |
|---|---|
| `security-audit` | 221+ concepts across 27 domains. Domain map routes to 4 sub-modules. Includes Ironclaw/Singularix concerns. |
| `security-auth` | Password hashing, timing attacks, credential stuffing, sessions, JWT, MFA. |
| `security-injection` | SQL/NoSQL/command/template/code injection, SSRF, XXE. |
| `security-ai-emerging` | LLM vulnerabilities, AI supply chain, WASM security, assume-breach architecture. |
| `security-checklists-tools` | Code review checklist, entry point enumeration, tools catalog (SAST/DAST/SCA/fuzzing), zero trust. |

## Supabase Source of Truth

```sql
SELECT name, display_name, description, category, version
FROM skill_library WHERE active = true
ORDER BY category, name;
```

This file is a convenience reference. The `skill_library` table is the authoritative source.
