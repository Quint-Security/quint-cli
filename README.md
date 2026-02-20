# Quint

Local security proxy for AI agent tool calls.

Quint sits between AI agents (Claude Code, Cursor, Cline) and their MCP tool servers, enforcing permissions and producing a signed, tamper-evident audit trail of every action.

## The problem

AI agents have no granular permissions, no audit trail, and no way to prove a human authorized a specific action. As agents go autonomous, this is a real security gap.

## How it works

```
Claude Code                    Quint                     Real MCP Server
    |                            |                            |
    |---- JSON-RPC request ----->|                            |
    |                            | parse, check policy,       |
    |                            | sign, log to SQLite        |
    |                            |                            |
    |                            |-- if allowed, forward ---->|
    |                            |<-- response ---------------|
    |<--- forward response ------|                            |
```

If a tool is **denied**, Quint never forwards to the real server. It returns a JSON-RPC error and the agent never executes the action.

## Setup (one line change)

```json
// Before:
{ "command": "builder-mcp", "args": [] }

// After:
{ "command": "quint", "args": ["proxy", "--name", "builder-mcp", "--", "builder-mcp"] }
```

Restart your agent. Every tool call now flows through Quint.

## Install

```bash
git clone <repo-url> && cd quint
npm install
npm run build
npm link
```

## Quick start

```bash
# Generate signing keys
quint keys generate

# Create default policy
quint policy init

# Edit policy to deny dangerous tools
vim ~/.quint/policy.json

# Check everything is configured
quint status
```

## Policy

`~/.quint/policy.json` controls what's allowed:

```json
{
  "version": 1,
  "data_dir": "~/.quint",
  "log_level": "info",
  "servers": [
    {
      "server": "builder-mcp",
      "default_action": "allow",
      "tools": [
        { "tool": "MechanicRunTool", "action": "deny" },
        { "tool": "TicketingWriteActions", "action": "deny" }
      ]
    },
    { "server": "*", "default_action": "allow", "tools": [] }
  ]
}
```

First matching tool rule wins. No server match = deny (fail-closed).

Only `tools/call` messages are policy-checked. Everything else (`initialize`, `tools/list`, notifications) passes through.

## Audit trail

Every action is logged to SQLite with an Ed25519 signature and hash chain:

```bash
# View recent logs
quint logs

# Filter by server, tool, or verdict
quint logs --server builder-mcp --tool MechanicRunTool
quint logs --denied

# Verify signatures
quint verify --last 20

# Verify signatures + hash chain integrity
quint verify --all --chain
```

Each entry includes:
- Timestamp, server, tool name, arguments, response
- Policy verdict (allow / deny / passthrough)
- SHA-256 hash of the active policy (proves what rules were in effect)
- SHA-256 hash of the previous entry's signature (tamper-evident chain)
- Ed25519 signature over all fields

Delete or modify any row and the chain breaks. `quint verify --chain` catches it.

## Commands

| Command | Purpose |
|---------|---------|
| `quint proxy --name <n> -- <cmd> [args]` | Run as MCP stdio proxy |
| `quint logs [--server X] [--tool Y] [--denied]` | Search audit log |
| `quint keys generate\|show\|export` | Manage signing keys |
| `quint verify [--last N] [--all] [--chain]` | Verify signatures and chain |
| `quint policy init\|validate\|show` | Manage policy |
| `quint status` | Config summary |

## Security model

**What Quint guarantees:**
- Tool actions that go through the proxy are enforced and logged
- Receipts are tamper-evident (hash chain + Ed25519 signatures)
- Third parties can verify receipts given the public key and exported log

**What Quint does not claim:**
- Preventing a local admin from disabling Quint
- Capturing actions that bypass the MCP protocol

Quint secures the agent tool boundary you configure it to mediate.

## Architecture

```
packages/
  core/    - types, Ed25519 crypto, SQLite database, policy engine
  proxy/   - stdio relay, message interceptor, audit logger
  cli/     - CLI entry point and 6 commands
test/      - 39 tests (crypto, db, policy, interceptor, chain, integration)
```

Two runtime dependencies: `better-sqlite3`, `commander`.

Crypto is `node:crypto` built-in (Ed25519 + SHA-256). No external crypto deps.

## Tests

```bash
npm test    # 39 tests, ~10s
```

## License

MIT
