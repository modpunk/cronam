---
name: workstation-provisioner
description: Ephemeral Claude Code environments on Fly.io for agent-driven development sessions
---
# Workstation Provisioner

Provisions and manages ephemeral Fly.io machines running Claude Code CLI.

## Key Concepts

- Each workstation is a Fly machine with Claude Code, Git, and SSH
- Agents SSH in and run `claude` commands as a human would
- Workstations are org-scoped — each org's credentials are isolated
- Auto-destroyed after idle timeout (default 30 minutes)
- Cost: ~$0.002 per 30-minute session (shared-cpu-1x)

## Provisioning Flow

1. Agent requests workstation via Singularix API
2. Provisioner creates Fly machine with org credentials
3. Machine clones repo, configures Claude Code
4. Returns SSH endpoint on Fly internal network
5. Agent SSH's in, runs Claude Code sessions
6. Machine auto-destroys on idle timeout

## Multi-Tenancy

- Org A's workstation has only Org A's API keys and PATs
- Credential injection via env vars (never written to disk)
- Each org tracked separately in v3_workstations table
- Concurrent limit enforced per org
