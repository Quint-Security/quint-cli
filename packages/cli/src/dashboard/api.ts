import type { IncomingMessage, ServerResponse } from "node:http";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { AuditDb } from "@quint-security/core";
import {
  loadPolicy,
  resolveDataDir,
  publicKeyFingerprint,
  isKeyEncrypted,
} from "@quint-security/core";
import type { AuditEntry, PolicyConfig } from "@quint-security/core";

export interface DashboardDeps {
  db: AuditDb;
  dataDir: string;
  policy: PolicyConfig;
}

function json(res: ServerResponse, data: unknown, status = 200): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

// GET /api/status
export function handleStatus(deps: DashboardDeps, _req: IncomingMessage, res: ServerResponse): void {
  const pubPath = join(deps.dataDir, "keys", "quint.pub");
  let fingerprint = "no key";
  if (existsSync(pubPath)) {
    const pub = readFileSync(pubPath, "utf-8");
    fingerprint = publicKeyFingerprint(pub);
  }

  json(res, {
    fingerprint,
    encrypted: isKeyEncrypted(deps.dataDir),
    entries: deps.db.count(),
    data_dir: deps.dataDir,
  });
}

// GET /api/policy
export function handlePolicy(deps: DashboardDeps, _req: IncomingMessage, res: ServerResponse): void {
  // Reload from disk so dashboard shows latest
  const fresh = loadPolicy(deps.dataDir);
  json(res, fresh);
}

// GET /api/logs?server=&tool=&verdict=&limit=50
export function handleLogs(deps: DashboardDeps, req: IncomingMessage, res: ServerResponse): void {
  const url = new URL(req.url ?? "/", "http://localhost");
  const server = url.searchParams.get("server") || undefined;
  const tool = url.searchParams.get("tool") || undefined;
  const verdict = url.searchParams.get("verdict") || undefined;
  const limit = parseInt(url.searchParams.get("limit") ?? "50", 10);

  const entries = deps.db.query({ server, tool, verdict, limit });
  json(res, { entries, total: deps.db.count() });
}

// GET /api/logs/:id
export function handleLogById(deps: DashboardDeps, id: number, _req: IncomingMessage, res: ServerResponse): void {
  const entry = deps.db.getById(id);
  if (!entry) {
    json(res, { error: "Entry not found" }, 404);
    return;
  }
  json(res, entry);
}

// GET /api/stats
export function handleStats(deps: DashboardDeps, _req: IncomingMessage, res: ServerResponse): void {
  const all = deps.db.query({ limit: 10000 });
  const total = deps.db.count();

  // Verdict counts
  const verdicts: Record<string, number> = { allow: 0, deny: 0, passthrough: 0, rate_limited: 0 };
  const riskLevels: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  const toolCounts: Record<string, number> = {};
  const serverCounts: Record<string, number> = {};

  for (const e of all) {
    verdicts[e.verdict] = (verdicts[e.verdict] ?? 0) + 1;
    if (e.risk_level) {
      riskLevels[e.risk_level] = (riskLevels[e.risk_level] ?? 0) + 1;
    }
    if (e.tool_name) {
      toolCounts[e.tool_name] = (toolCounts[e.tool_name] ?? 0) + 1;
    }
    serverCounts[e.server_name] = (serverCounts[e.server_name] ?? 0) + 1;
  }

  // Top 10 tools
  const topTools = Object.entries(toolCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name, count]) => ({ name, count }));

  // Top 10 servers
  const topServers = Object.entries(serverCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name, count]) => ({ name, count }));

  json(res, { total, verdicts, riskLevels, topTools, topServers });
}
