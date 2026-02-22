# Quint CLI

Local security proxy for AI agent MCP tool calls. Monorepo with three packages: `core`, `proxy`, `cli`.

## Workflow

- Never push directly to `main`. Branch protection is enabled.
- Create a feature branch, push it, and open a PR.
- CI (`test` job) must pass before merging.
- Claude Code Review and Claude PR Description workflows run automatically on PRs.

## Build & Test

```bash
npm ci
npm run build
npm test
```

## Project Structure

```
packages/
  core/   - types, Ed25519 crypto, SQLite database, policy engine
  proxy/  - stdio relay, message interceptor, audit logger
  cli/    - CLI entry point (commander)
test/     - node:test based tests
```

## Publishing

Packages publish to GitHub Packages (`@quint-security/*`) on `v*` tags. Version is derived from the git tag automatically.

## Key Conventions

- TypeScript, Node 20+
- Two runtime deps: `better-sqlite3`, `commander`
- Crypto uses `node:crypto` built-ins (Ed25519 + SHA-256)
- Registry: `https://npm.pkg.github.com`
