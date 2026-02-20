# Quint — Architecture Decisions & Build Plan

## My Decisions (And Why)

### Decision 1: Skip Tauri. Use Node.js + Electron (later).

You don't know Rust. Learning Rust while shipping a product is a trap. Here's what I found:

- **Tauri's WebAuthn/passkey support is broken for this use case.** The WebView uses `tauri://localhost` as its origin, which doesn't satisfy WebAuthn's relying party checks. You'd need to write Rust FFI bridges to Apple's native AuthenticationServices framework. That's weeks of work for someone who doesn't know Rust.
- **Tauri sidecars require compiling Node.js into standalone binaries** (`pkg` or Node SEA) with platform-specific suffixes. More packaging headaches.
- **The MCP proxy IS the product.** It's a Node.js HTTP server. The desktop UI is a nice-to-have management layer. Build the core first, wrap it in Electron (or Tauri) later.

**Architecture:**
```
┌─────────────────────────────────────────┐
│  Quint Proxy (Node.js HTTP server)      │
│  - Intercepts MCP JSON-RPC calls        │
│  - Enforces permissions per agent       │
│  - Signs every action with Ed25519      │
│  - Logs to SQLite                       │
│  - Serves web dashboard on localhost    │
└──────────┬──────────────┬───────────────┘
           │              │
     ┌─────┴─────┐  ┌────┴────────────┐
     │ Claude    │  │ Real MCP        │
     │ Code /    │  │ Servers         │
     │ Cursor    │  │ (filesystem,    │
     │ etc.      │  │  github, etc.)  │
     └───────────┘  └─────────────────┘

User configures Claude Code:
  "type": "http", "url": "http://localhost:9120/mcp/filesystem"
Instead of running the MCP server directly.
```

### Decision 2: MCP Proxy approach is validated and correct.

Research confirmed:
- Claude Code supports `"type": "http"` MCP servers pointed at any URL
- MCP is JSON-RPC 2.0 — tool calls are simple `{"method": "tools/call", "params": {"name": "...", "arguments": {...}}}`
- The proxy receives every message, can inspect/log/sign/reject, then forwards to the real server
- An existing `mcp-proxy` npm package proves this pattern works
- Config change for users is one line in `~/.claude.json`

### Decision 3: Skip passkeys for MVP. Use Touch ID directly.

WebAuthn passkeys are designed for web authentication between a browser and a remote server. You don't have a remote server. You don't need one. What you actually need is:

- **Local user verification** — "prove you're the human at the keyboard"
- **Gate access to signing keys** — "unlock the key store"

For MVP: prompt for Touch ID via the system (macOS `LocalAuthentication` framework, accessible via a small native Node addon or the `security` CLI), or fall back to a passphrase that encrypts the key store. Full WebAuthn passkeys can come in v2 when you add a cloud sync / multi-device story.

### Decision 4: Simple random keypairs, not BIP-32 HD derivation.

Each agent gets a random Ed25519 keypair. Stored in an encrypted SQLite database (AES-256-GCM, key derived from user passphrase via scrypt). No master seed, no derivation paths. If you need key rotation, generate a new keypair and re-register.

BIP-32 HD derivation adds complexity for a feature (deterministic backup/recovery) you don't need yet.

### Decision 5: Crypto stack.

- `@noble/curves` — Ed25519 signing/verification (audited, zero deps, pure JS)
- `@noble/hashes` — SHA-256, scrypt for key derivation (audited)
- `canonicalize` — RFC 8785 JSON Canonicalization for deterministic signing
- Node.js built-in `crypto` — AES-256-GCM for encrypting the key store

### Decision 6: Start with CLI + web dashboard, not desktop app.

The fastest path to a usable product:

1. `npm install -g @quint/cli`
2. `quint init` — set up passphrase, create key store
3. `quint add-agent claude-code` — generate keypair, print MCP config snippet
4. `quint start` — start the proxy daemon
5. Open `http://localhost:9120` — web dashboard for monitoring

Desktop app (Electron wrapper with system tray, auto-launch) is Phase 4, after the core works.

---

## Tech Stack (Final)

| Component | Technology | Why |
|-----------|-----------|-----|
| MCP Proxy | Node.js + Express/Fastify | JSON-RPC handling, HTTP server, team knows it |
| CLI | Node.js + Commander.js | Setup, agent management |
| Dashboard | React + TypeScript + Vite | Agent monitoring, audit log viewer, permissions editor |
| Database | better-sqlite3 | Sync SQLite from Node.js, fast, no ORM overhead |
| Crypto | @noble/curves + @noble/hashes | Ed25519 signing, scrypt key derivation |
| Signing | canonicalize (RFC 8785) | Deterministic JSON serialization for signatures |
| Auth (MVP) | Passphrase → scrypt → AES-256-GCM | Encrypts the key store locally |
| Auth (v2) | Touch ID / Electron safeStorage | Native biometric unlock |
| Desktop (v2) | Electron | System tray, auto-launch, native feel |

---

## Build Plan

### Phase 1: Project scaffolding + data layer
- Initialize monorepo (pnpm workspaces): `packages/proxy`, `packages/cli`, `packages/dashboard`
- Set up TypeScript, ESLint, build tooling
- Design and implement SQLite schema:
  - `agents` table (id, name, public_key, permissions_json, created_at)
  - `audit_log` table (id, agent_id, timestamp, method, tool_name, arguments_hash, signature, result_status)
  - `settings` table (key, value)
- Implement encrypted key store (scrypt + AES-256-GCM for secret keys)
- Implement AgentKeyManager (create keypair, sign, verify, list agents)

### Phase 2: MCP Proxy (the core product)
- Build HTTP server that accepts MCP JSON-RPC requests
- Implement proxy routing: receive request → check permissions → forward to real MCP server → return response
- Support two modes for connecting to real MCP servers:
  - **HTTP forwarding**: proxy to another HTTP MCP server
  - **stdio spawning**: proxy spawns a local MCP server process and bridges stdio ↔ HTTP
- Implement permission checking on `tools/call`:
  - Allow-list of tool names per agent
  - Deny by default
- Sign every `tools/call` with the agent's Ed25519 key
- Log every action to SQLite audit trail
- Agent identification via URL path or auth token (e.g., `localhost:9120/mcp/agent-name/server-name`)

### Phase 3: CLI
- `quint init` — create config directory, set passphrase, initialize database
- `quint add-agent <name>` — generate keypair, set default permissions, output MCP config snippet for Claude Code / Cursor
- `quint remove-agent <name>` — revoke keypair
- `quint list-agents` — show all agents and their permissions
- `quint set-permissions <agent> <rules>` — update allow/deny lists
- `quint start` — start proxy daemon (foreground, or background with `--daemon`)
- `quint stop` — stop proxy daemon
- `quint logs [--agent <name>] [--tail]` — query audit log

### Phase 4: Web Dashboard
- React app served by the proxy at `http://localhost:9120`
- Pages:
  - **Activity Feed**: real-time stream of agent actions (WebSocket from proxy)
  - **Agents**: list agents, create/delete, edit permissions
  - **Audit Log**: searchable/filterable log of all actions with signatures
  - **Settings**: proxy config, port, passphrase management
- Simple, clean UI — this isn't the selling point, the proxy is

### Phase 5 (later): Desktop wrapper + Touch ID
- Electron shell around the web dashboard
- System tray icon showing proxy status
- Auto-launch on login
- Touch ID integration for unlocking the key store
- macOS DMG packaging

---

## What a User's Setup Looks Like (End State)

```bash
# Install
npm install -g @quint/cli

# Initialize
quint init
# → Enter a passphrase to protect your agent keys
# → Created config at ~/.quint/

# Add an agent
quint add-agent claude-code
# → Generated keypair for "claude-code"
# → Add this to your Claude Code MCP config:
# →   "quint-filesystem": {
# →     "type": "http",
# →     "url": "http://localhost:9120/mcp/claude-code/filesystem"
# →   }

# Start the proxy
quint start
# → Quint proxy running on http://localhost:9120
# → Dashboard: http://localhost:9120/dashboard

# Now Claude Code's MCP calls flow through Quint:
# Claude Code → Quint Proxy (check permissions, sign, log) → Real MCP Server
```

---

## What Gets Cut (Explicitly)

- Shell wrapper / terminal interceptor — too many edge cases, MCP proxy is the right chokepoint
- BIP-32 HD key derivation — random keypairs are simpler and sufficient
- WebAuthn/passkeys — passphrase for MVP, Touch ID for v2
- Spending limits — no payment APIs in MVP
- Cross-platform — macOS first (and Linux for free since it's Node.js)
- Tamper-evident chain (Merkle tree) — simple signed log entries are enough for MVP
- Custom RBAC — preset allow/deny lists per agent, not a full role engine
- Multi-user — single user, single machine for MVP
