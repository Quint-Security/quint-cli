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
export type Verdict = "allow" | "deny" | "passthrough" | "rate_limited";

export interface ToolRule {
  tool: string;
  action: Action;
}

export interface ServerPolicy {
  server: string;
  default_action: Action;
  tools: ToolRule[];
}

export interface RateLimitConfig {
  /** Requests per minute (default: 60) */
  rpm: number;
  /** Burst allowance — extra requests allowed in short bursts (default: 10) */
  burst: number;
}

export interface PolicyConfig {
  version: number;
  data_dir: string;
  log_level: "debug" | "info" | "warn" | "error";
  servers: ServerPolicy[];
  /** Global rate limit defaults. Per-key overrides live in the auth DB. */
  rate_limit?: RateLimitConfig;
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
  risk_score: number | null;
  risk_level: string | null;
  policy_hash: string;
  prev_hash: string;
  nonce: string;
  signature: string;
  public_key: string;
}

// ── Auth types ──────────────────────────────────────────────────

export interface ApiKey {
  id: string;           // Public identifier (prefix: qk_)
  key_hash: string;     // SHA-256 hex of the raw key
  owner_id: string;     // Who created it
  label: string;        // Human-readable name
  scopes: string;       // Comma-separated scopes (e.g. "proxy:read,audit:write")
  created_at: string;   // ISO-8601
  expires_at: string | null;  // ISO-8601 or null for no expiry
  revoked: boolean;
  rate_limit_rpm: number | null;  // Per-key requests-per-minute override (null = use global default)
}

export interface Session {
  id: string;           // Opaque session token (UUID v4)
  subject_id: string;   // API key ID or user ID
  auth_method: string;  // "api_key" | "passkey"
  scopes: string;       // Inherited from credential
  issued_at: string;    // ISO-8601
  expires_at: string;   // ISO-8601 (default: issued_at + 24h)
  revoked: boolean;
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
