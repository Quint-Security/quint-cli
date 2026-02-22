import { randomUUID, createHash, randomBytes } from "node:crypto";
import type { ApiKey, Session } from "./types.js";
import type { AuthDb } from "./auth-db.js";

const API_KEY_PREFIX = "qk_";
const DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// ── API Key management ──────────────────────────────────────────

function hashKey(rawKey: string): string {
  return createHash("sha256").update(rawKey, "utf-8").digest("hex");
}

/**
 * Generate a new API key. Returns the raw key (shown once) and the stored record.
 */
export function generateApiKey(
  db: AuthDb,
  opts: { label: string; ownerId?: string; scopes?: string[]; ttlSeconds?: number },
): { rawKey: string; apiKey: ApiKey } {
  const rawKey = API_KEY_PREFIX + randomBytes(32).toString("hex");
  const id = API_KEY_PREFIX + randomUUID().replace(/-/g, "").substring(0, 16);
  const now = new Date().toISOString();
  const expiresAt = opts.ttlSeconds && opts.ttlSeconds > 0
    ? new Date(Date.now() + opts.ttlSeconds * 1000).toISOString()
    : null;

  const apiKey: ApiKey = {
    id,
    key_hash: hashKey(rawKey),
    owner_id: opts.ownerId ?? "local",
    label: opts.label,
    scopes: (opts.scopes ?? []).join(","),
    created_at: now,
    expires_at: expiresAt,
    revoked: false,
    rate_limit_rpm: null,
  };

  db.insertApiKey(apiKey);
  return { rawKey, apiKey };
}

/**
 * Verify a raw API key. Returns the key record if valid, undefined otherwise.
 */
export function verifyApiKey(db: AuthDb, rawKey: string): ApiKey | undefined {
  const hash = hashKey(rawKey);
  const key = db.getApiKeyByHash(hash);
  if (!key) return undefined;
  if (key.revoked) return undefined;
  if (key.expires_at && new Date(key.expires_at) < new Date()) return undefined;
  return key;
}

// ── Session management ──────────────────────────────────────────

/**
 * Create a session after successful authentication.
 */
export function createSession(
  db: AuthDb,
  opts: { subjectId: string; authMethod: string; scopes?: string; ttlMs?: number },
): Session {
  const now = new Date();
  const ttl = opts.ttlMs ?? DEFAULT_SESSION_TTL_MS;

  const session: Session = {
    id: randomUUID(),
    subject_id: opts.subjectId,
    auth_method: opts.authMethod,
    scopes: opts.scopes ?? "",
    issued_at: now.toISOString(),
    expires_at: new Date(now.getTime() + ttl).toISOString(),
    revoked: false,
  };

  db.insertSession(session);
  return session;
}

/**
 * Validate a session token. Returns the session if valid, undefined otherwise.
 */
export function validateSession(db: AuthDb, token: string): Session | undefined {
  const session = db.getSession(token);
  if (!session) return undefined;
  if (session.revoked) return undefined;
  if (new Date(session.expires_at) < new Date()) return undefined;
  return session;
}

/**
 * Authenticate a bearer token — could be a raw API key or a session token.
 * Returns { type, subject, scopes } if valid, undefined otherwise.
 */
export function authenticateBearer(
  db: AuthDb,
  token: string,
): { type: "api_key" | "session"; subjectId: string; scopes: string; rateLimitRpm: number | null } | undefined {
  // Try as session first (UUIDs are shorter, faster lookup)
  const session = validateSession(db, token);
  if (session) {
    // Look up the originating API key to inherit its rate limit
    const originKey = db.getApiKeyById(session.subject_id);
    return {
      type: "session",
      subjectId: session.subject_id,
      scopes: session.scopes,
      rateLimitRpm: originKey?.rate_limit_rpm ?? null,
    };
  }

  // Try as raw API key
  const key = verifyApiKey(db, token);
  if (key) {
    return {
      type: "api_key",
      subjectId: key.id,
      scopes: key.scopes,
      rateLimitRpm: key.rate_limit_rpm,
    };
  }

  return undefined;
}
