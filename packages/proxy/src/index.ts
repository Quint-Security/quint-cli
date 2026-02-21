import {
  type PolicyConfig,
  ensureKeyPair,
  openAuditDb,
  resolveDataDir,
  setLogLevel,
  logDebug,
  logInfo,
  logError,
} from "@quint/core";
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
  const kp = ensureKeyPair(dataDir);

  // Open audit database
  const db = openAuditDb(dataDir);

  // Create audit logger
  const logger = new AuditLogger(db, kp.privateKey, kp.publicKey, opts.policy);

  // Create relay
  const relay = new Relay(opts.command, opts.args);

  // ── Handle messages from parent (AI agent) → child (MCP server) ──

  relay.on("parentMessage", (line: string) => {
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
      // Send error response back to parent
      const reqId = result.message && "id" in result.message ? result.message.id : null;
      const errorResponse = buildDenyResponse(reqId ?? null);
      relay.sendToParent(errorResponse);
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
    } else {
      // Forward to child
      logDebug(`forwarding ${result.method} (${result.verdict}) to child`);
      relay.sendToChild(line);
    }
  });

  // ── Handle messages from child (MCP server) → parent (AI agent) ──

  relay.on("childMessage", (line: string) => {
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

    // Always forward responses to parent
    relay.sendToParent(line);
  });

  // ── Handle child exit ──

  relay.on("childExit", (code: number | null) => {
    db.close();
    process.exit(code ?? 0);
  });

  relay.on("error", (err: Error) => {
    logError(`relay error: ${err.message}`);
    db.close();
    process.exit(1);
  });

  // Start
  relay.start();
}
