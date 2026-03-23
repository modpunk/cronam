# First Prompt Templates for CRONAM

## Session Start Prompt (use this every new chat)

```
continue
```

Claude will automatically:
1. Connect to CRONAM's Supabase
2. Query session_memory for behavioral instructions
3. Query the latest checkpoint
4. Read the handoff, present state, suggest priorities

## Trigger Phrases

- "create checkpoint" — Save progress to Supabase
- "check chat" — Audit current chat for gaps
- "check session" — Audit entire project state
- "load skill [name]" — Load a skill from the skill library
- "show skills" — List all available skills
- "status" — Report state without executing
