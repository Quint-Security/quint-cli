import {
  type PolicyConfig,
  ensureKeyPair,
  openAuditDb,
  openAuthDb,
  authenticateBearer,
  resolveDataDir,
} from "@quint/core";
import { HttpRelay } from "./http-relay.js";
import { inspectRequest, inspectResponse, buildDenyResponse } from "./interceptor.js";
import { AuditLogger } from "./logger.js";

export interface HttpProxyOptions {
  serverName: string;
  port: number;
  targetUrl: string;
  policy: PolicyConfig;
  requireAuth?: boolean;
}

/**
 * Start the HTTP proxy: run a local HTTP server, intercept all JSON-RPC
 * requests, enforce policy, sign and log everything, forward to remote.
 */
export async function startHttpProxy(opts: HttpProxyOptions): Promise<void> {
  const dataDir = resolveDataDir(opts.policy.data_dir);

  // Ensure signing keys exist
  const kp = ensureKeyPair(dataDir);

  // Open audit database
  const db = openAuditDb(dataDir);

  // Create audit logger
  const logger = new AuditLogger(db, kp.privateKey, kp.publicKey, opts.policy);

  // Create HTTP relay (with optional auth)
  const authDb = opts.requireAuth ? openAuthDb(dataDir) : null;
  const relay = new HttpRelay(opts.port, opts.targetUrl, opts.requireAuth ? (req) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return "Quint: missing or invalid Authorization header. Use: Bearer <api-key>";
    }
    const token = authHeader.slice(7);
    const result = authenticateBearer(authDb!, token);
    if (!result) {
      return "Quint: invalid or expired API key";
    }
    return null;
  } : undefined);

  // ── Handle requests from agent → remote MCP server ──

  relay.on("request", (line: string, requestKey: string) => {
    const result = inspectRequest(line, opts.serverName, opts.policy);

    // Log the request
    logger.log({
      serverName: opts.serverName,
      direction: "request",
      method: result.method,
      messageId: result.messageId,
      toolName: result.toolName,
      argumentsJson: result.argumentsJson,
      responseJson: null,
      verdict: result.verdict,
    });

    if (result.verdict === "deny") {
      // Send error response back to agent
      const reqId = result.message && "id" in result.message ? result.message.id : null;
      const errorResponse = buildDenyResponse(reqId ?? null);
      relay.respondToClient(requestKey, errorResponse);

      // Log the synthetic deny response
      logger.log({
        serverName: opts.serverName,
        direction: "response",
        method: result.method,
        messageId: result.messageId,
        toolName: result.toolName,
        argumentsJson: null,
        responseJson: errorResponse,
        verdict: "deny",
      });
    } else {
      // Forward to remote server
      relay.forwardToRemote(requestKey);
    }
  });

  // ── Handle responses from remote MCP server ──

  relay.on("response", (line: string) => {
    const result = inspectResponse(line);

    // Log the response
    logger.log({
      serverName: opts.serverName,
      direction: "response",
      method: result.method,
      messageId: result.messageId,
      toolName: null,
      argumentsJson: null,
      responseJson: result.responseJson,
      verdict: "passthrough",
    });
  });

  // ── Handle errors ──

  relay.on("error", (err: Error) => {
    process.stderr.write(`quint: http-proxy error: ${err.message}\n`);
  });

  // Handle shutdown
  const shutdown = () => {
    relay.stop();
    db.close();
    authDb?.close();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  // Start listening
  await relay.start();
  process.stderr.write(
    `quint: HTTP proxy listening on http://localhost:${opts.port} → ${opts.targetUrl}\n`,
  );
}
