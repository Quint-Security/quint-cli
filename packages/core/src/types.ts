// ── JSON-RPC types ──────────────────────────────────────────────

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: JsonRpcError;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export type JsonRpcMessage = JsonRpcRequest | JsonRpcResponse;

// ── MCP-specific helpers ────────────────────────────────────────

export interface McpToolCallParams {
  name: string;
  arguments?: Record<string, unknown>;
}

// ── Policy types ────────────────────────────────────────────────

export type Action = "allow" | "deny";
export type Verdict = "allow" | "deny" | "passthrough";

export interface ToolRule {
  tool: string;
  action: Action;
}

export interface ServerPolicy {
  server: string;
  default_action: Action;
  tools: ToolRule[];
}

export interface PolicyConfig {
  version: number;
  data_dir: string;
  log_level: "debug" | "info" | "warn" | "error";
  servers: ServerPolicy[];
}

// ── Audit log types ─────────────────────────────────────────────

export interface AuditEntry {
  id?: number;
  timestamp: string;
  server_name: string;
  direction: "request" | "response";
  method: string;
  message_id: string | null;
  tool_name: string | null;
  arguments_json: string | null;
  response_json: string | null;
  verdict: Verdict;
  signature: string;
  public_key: string;
}

// ── Crypto types ────────────────────────────────────────────────

export interface KeyPair {
  publicKey: string;   // SPKI PEM
  privateKey: string;  // PKCS8 PEM
}

// ── Helper: check if message is a JSON-RPC request ──────────────

export function isJsonRpcRequest(msg: unknown): msg is JsonRpcRequest {
  if (typeof msg !== "object" || msg === null) return false;
  const obj = msg as Record<string, unknown>;
  return obj.jsonrpc === "2.0" && typeof obj.method === "string";
}

export function isJsonRpcResponse(msg: unknown): msg is JsonRpcResponse {
  if (typeof msg !== "object" || msg === null) return false;
  const obj = msg as Record<string, unknown>;
  return obj.jsonrpc === "2.0" && ("result" in obj || "error" in obj);
}

export function isToolCallRequest(msg: JsonRpcRequest): boolean {
  return msg.method === "tools/call";
}

export function extractToolInfo(msg: JsonRpcRequest): { name: string; args: Record<string, unknown> } | null {
  if (!isToolCallRequest(msg)) return null;
  const params = msg.params as McpToolCallParams | undefined;
  if (!params?.name) return null;
  return {
    name: params.name,
    args: params.arguments ?? {},
  };
}
