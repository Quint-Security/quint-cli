import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import type { AuditDb } from "@quint-security/core";
import type { PolicyConfig } from "@quint-security/core";
import {
  handleStatus,
  handlePolicy,
  handleLogs,
  handleLogById,
  handleStats,
  type DashboardDeps,
} from "./api.js";
import { dashboardHtml } from "./html.js";

export interface DashboardServerOpts {
  port: number;
  db: AuditDb;
  dataDir: string;
  policy: PolicyConfig;
}

export function startDashboardServer(opts: DashboardServerOpts): Promise<Server> {
  const deps: DashboardDeps = {
    db: opts.db,
    dataDir: opts.dataDir,
    policy: opts.policy,
  };

  const sseClients = new Set<ServerResponse>();
  let lastCount = opts.db.count();

  // Poll DB for new entries every 2 seconds
  const pollInterval = setInterval(() => {
    const currentCount = opts.db.count();
    if (currentCount > lastCount) {
      const delta = currentCount - lastCount;
      const newEntries = opts.db.getLast(delta);
      lastCount = currentCount;

      const payload = `data: ${JSON.stringify({ type: "new_entries", entries: newEntries, total: currentCount })}\n\n`;
      for (const client of sseClients) {
        try {
          client.write(payload);
        } catch {
          sseClients.delete(client);
        }
      }
    }
  }, 2000);

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;

    // CORS headers for local dev
    res.setHeader("Access-Control-Allow-Origin", "*");

    try {
      // Static routes
      if (path === "/" && req.method === "GET") {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(dashboardHtml());
        return;
      }

      if (path === "/api/status" && req.method === "GET") {
        handleStatus(deps, req, res);
        return;
      }

      if (path === "/api/policy" && req.method === "GET") {
        handlePolicy(deps, req, res);
        return;
      }

      if (path === "/api/logs" && req.method === "GET") {
        handleLogs(deps, req, res);
        return;
      }

      // /api/logs/:id
      const logMatch = path.match(/^\/api\/logs\/(\d+)$/);
      if (logMatch && req.method === "GET") {
        handleLogById(deps, parseInt(logMatch[1], 10), req, res);
        return;
      }

      if (path === "/api/stats" && req.method === "GET") {
        handleStats(deps, req, res);
        return;
      }

      // SSE endpoint
      if (path === "/api/events" && req.method === "GET") {
        res.writeHead(200, {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          "Connection": "keep-alive",
        });
        res.write(`data: ${JSON.stringify({ type: "connected", total: opts.db.count() })}\n\n`);
        sseClients.add(res);

        req.on("close", () => {
          sseClients.delete(res);
        });
        return;
      }

      // 404
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found" }));
    } catch (err) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: String(err) }));
    }
  });

  // Cleanup on server close
  server.on("close", () => {
    clearInterval(pollInterval);
    for (const client of sseClients) {
      client.end();
    }
    sseClients.clear();
  });

  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(opts.port, () => {
      resolve(server);
    });
  });
}
