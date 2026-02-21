import {
  type PolicyConfig,
  ensureKeyPair,
  openAuditDb,
  openAuthDb,
  authenticateBearer,
  resolveDataDir,
  setLogLevel,
  logDebug,
  logInfo,
  logWarn,
  logError,
  RiskEngine,
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
  setLogLevel(opts.policy.log_level);
  const dataDir = resolveDataDir(opts.policy.data_dir);

  // Ensure signing keys exist
  const kp = ensureKeyPair(dataDir);

  // Open audit database
  const db = openAuditDb(dataDir);

  // Create audit logger
  const logger = new AuditLogger(db, kp.privateKey, kp.publicKey, opts.policy);

  // Create risk engine
  const riskEngine = new RiskEngine();

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
      logInfo(`denied ${result.toolName} on ${opts.serverName}`);

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
    } else if (result.toolName) {
      // Run risk scoring on tool calls that passed policy
      const risk = riskEngine.score(result.toolName, result.argumentsJson, "anonymous");
      const riskAction = riskEngine.evaluate(risk);

      if (riskAction === "deny") {
        // Risk score too high — auto-deny
        const reqId = result.message && "id" in result.message ? result.message.id : null;
        const errorResponse = buildDenyResponse(reqId ?? null);
        relay.respondToClient(requestKey, errorResponse);
        logWarn(`risk-denied ${result.toolName} (score=${risk.score}, level=${risk.level}): ${risk.reasons.join("; ")}`);

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
        if (riskAction === "flag") {
          logWarn(`high-risk ${result.toolName} (score=${risk.score}, level=${risk.level}): ${risk.reasons.join("; ")}`);
        }
        logDebug(`forwarding ${result.method} (risk=${risk.score}) to remote`);
        relay.forwardToRemote(requestKey);
      }

      // Check for revocation threshold
      if (riskEngine.shouldRevoke("anonymous")) {
        logWarn(`repeated high-risk actions detected — consider revoking agent credentials`);
      }
    } else {
      // Non-tool-call (initialize, tools/list, etc.) — forward directly
      logDebug(`forwarding ${result.method} (${result.verdict}) to remote`);
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
    logError(`http-proxy error: ${err.message}`);
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
  logInfo(`HTTP proxy listening on http://localhost:${opts.port} → ${opts.targetUrl}`);
}
