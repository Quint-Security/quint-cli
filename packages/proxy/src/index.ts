import {
  type PolicyConfig,
  ensureKeyPair,
  openAuditDb,
  openBehaviorDb,
  resolveDataDir,
  setLogLevel,
  logDebug,
  logInfo,
  logWarn,
  logError,
  RiskEngine,
} from "@quint-security/core";
import { Relay } from "./relay.js";
import { inspectRequest, inspectResponse, buildDenyResponse } from "./interceptor.js";
import { AuditLogger } from "./logger.js";

export { Relay } from "./relay.js";
export { HttpRelay } from "./http-relay.js";
export { inspectRequest, inspectResponse, buildDenyResponse } from "./interceptor.js";
export { AuditLogger } from "./logger.js";
export { startHttpProxy } from "./http-proxy.js";

export interface ProxyOptions {
  serverName: string;
  command: string;
  args: string[];
  policy: PolicyConfig;
}

/**
 * Start the proxy: spawn child MCP server, intercept all JSON-RPC
 * messages, enforce policy, sign and log everything.
 */
export function startProxy(opts: ProxyOptions): void {
  setLogLevel(opts.policy.log_level);
  const dataDir = resolveDataDir(opts.policy.data_dir);

  // Ensure signing keys exist
  const passphrase = process.env.QUINT_PASSPHRASE;
  const kp = ensureKeyPair(dataDir, passphrase);

  // Open audit database
  const db = openAuditDb(dataDir);

  // Create audit logger
  const logger = new AuditLogger(db, kp.privateKey, kp.publicKey, opts.policy);

  // Create risk engine with persistent behavior tracking
  const behaviorDb = openBehaviorDb(dataDir);
  const riskEngine = new RiskEngine({ behaviorDb });

  // Create relay
  const relay = new Relay(opts.command, opts.args);

  // ── Handle messages from parent (AI agent) → child (MCP server) ──

  relay.on("parentMessage", (line: string) => {
    try {
      const result = inspectRequest(line, opts.serverName, opts.policy);

      // For non-tool-call requests, log immediately. Tool calls get logged after risk scoring.
      if (!result.toolName || result.verdict === "deny") {
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
      }

      if (result.verdict === "deny") {
        const reqId = result.message && "id" in result.message ? result.message.id : null;
        const errorResponse = buildDenyResponse(reqId ?? null);
        relay.sendToParent(errorResponse);
        logInfo(`denied ${result.toolName} on ${opts.serverName}`);

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
        const risk = riskEngine.score(result.toolName, result.argumentsJson, "anonymous");
        const riskAction = riskEngine.evaluate(risk);

        // Log the request with risk score attached
        logger.log({
          serverName: opts.serverName,
          direction: "request",
          method: result.method,
          messageId: result.messageId,
          toolName: result.toolName,
          argumentsJson: result.argumentsJson,
          responseJson: null,
          verdict: result.verdict,
          riskScore: risk.score,
          riskLevel: risk.level,
        });

        if (riskAction === "deny") {
          const reqId = result.message && "id" in result.message ? result.message.id : null;
          const errorResponse = buildDenyResponse(reqId ?? null);
          relay.sendToParent(errorResponse);
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
            riskScore: risk.score,
            riskLevel: risk.level,
          });
        } else {
          if (riskAction === "flag") {
            logWarn(`high-risk ${result.toolName} (score=${risk.score}, level=${risk.level}): ${risk.reasons.join("; ")}`);
          }
          logDebug(`forwarding ${result.method} (risk=${risk.score}) to child`);
          relay.sendToChild(line);
        }

        if (riskEngine.shouldRevoke("anonymous")) {
          logWarn(`repeated high-risk actions detected — consider revoking agent credentials`);
        }
      } else {
        // Non-tool-call — forward directly
        logDebug(`forwarding ${result.method} (${result.verdict}) to child`);
        relay.sendToChild(line);
      }
    } catch (err) {
      // Fail-open: if Quint's own processing throws, forward the message
      // rather than silently dropping it. Log the error but don't break the pipe.
      logError(`error processing request: ${err instanceof Error ? err.message : err}`);
      relay.sendToChild(line);
    }
  });

  // ── Handle messages from child (MCP server) → parent (AI agent) ──

  relay.on("childMessage", (line: string) => {
    try {
      const result = inspectResponse(line);

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
    } catch (err) {
      // Don't let logging failures block responses from reaching the agent
      logError(`error processing response: ${err instanceof Error ? err.message : err}`);
    }

    // Always forward responses to parent — even if logging failed
    relay.sendToParent(line);
  });

  // ── Handle child exit ──

  relay.on("childExit", (code: number | null) => {
    db.close();
    behaviorDb.close();
    process.exit(code ?? 0);
  });

  relay.on("error", (err: Error) => {
    logError(`relay error: ${err.message}`);
    db.close();
    behaviorDb.close();
    process.exit(1);
  });

  // Ensure DBs close on unexpected termination
  const cleanup = () => {
    try { db.close(); } catch { /* already closed */ }
    try { behaviorDb.close(); } catch { /* already closed */ }
  };
  process.on("uncaughtException", (err) => {
    logError(`uncaught exception: ${err.message}`);
    cleanup();
    process.exit(1);
  });
  process.on("SIGTERM", () => { cleanup(); process.exit(0); });
  process.on("SIGINT", () => { cleanup(); process.exit(0); });

  // Start
  relay.start();
}
