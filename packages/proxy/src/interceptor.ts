import {
  type JsonRpcRequest,
  type JsonRpcMessage,
  type Verdict,
  type PolicyConfig,
  isJsonRpcRequest,
  isToolCallRequest,
  extractToolInfo,
  evaluatePolicy,
} from "@quint-security/core";

export interface InspectionResult {
  /** The parsed JSON-RPC message (null if line is not valid JSON-RPC) */
  message: JsonRpcMessage | null;
  /** Policy verdict */
  verdict: Verdict;
  /** Extracted tool name (for tools/call requests) */
  toolName: string | null;
  /** Extracted tool arguments as JSON string */
  argumentsJson: string | null;
  /** JSON-RPC method */
  method: string;
  /** JSON-RPC id */
  messageId: string | null;
}

/**
 * Try to parse a line as JSON-RPC and determine the policy verdict.
 * Non-parseable lines or non-tools/call methods get "passthrough".
 */
export function inspectRequest(
  line: string,
  serverName: string,
  policy: PolicyConfig,
): InspectionResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return {
      message: null,
      verdict: "passthrough",
      toolName: null,
      argumentsJson: null,
      method: "unknown",
      messageId: null,
    };
  }

  if (!isJsonRpcRequest(parsed)) {
    return {
      message: parsed as JsonRpcMessage,
      verdict: "passthrough",
      toolName: null,
      argumentsJson: null,
      method: "unknown",
      messageId: extractId(parsed),
    };
  }

  const req = parsed as JsonRpcRequest;
  const toolInfo = extractToolInfo(req);
  const toolName = toolInfo?.name ?? null;
  const argumentsJson = toolInfo ? JSON.stringify(toolInfo.args) : null;

  // Only policy-check tools/call; everything else is passthrough
  let verdict: Verdict;
  if (isToolCallRequest(req)) {
    verdict = evaluatePolicy(policy, serverName, toolName);
  } else {
    verdict = "passthrough";
  }

  return {
    message: req,
    verdict,
    toolName,
    argumentsJson,
    method: req.method,
    messageId: req.id != null ? String(req.id) : null,
  };
}

/**
 * Inspect a response line from the child (just for logging purposes — responses always pass through).
 */
export function inspectResponse(line: string): {
  method: string;
  messageId: string | null;
  responseJson: string | null;
} {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return { method: "unknown", messageId: null, responseJson: null };
  }

  return {
    method: "response",
    messageId: extractId(parsed),
    responseJson: line,
  };
}

/**
 * Build a JSON-RPC error response for a denied tool call.
 */
export function buildDenyResponse(requestId: string | number | null): string {
  const response = {
    jsonrpc: "2.0" as const,
    id: requestId,
    error: {
      code: -32600,
      message: "Quint: tool call denied by policy",
    },
  };
  return JSON.stringify(response);
}

function extractId(obj: unknown): string | null {
  if (typeof obj === "object" && obj !== null && "id" in obj) {
    const id = (obj as Record<string, unknown>).id;
    return id != null ? String(id) : null;
  }
  return null;
}
