import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import type { PolicyConfig, ServerPolicy, Action, Verdict } from "./types.js";

const DEFAULT_DATA_DIR = join(homedir(), ".quint");

const DEFAULT_POLICY: PolicyConfig = {
  version: 1,
  data_dir: "~/.quint",
  log_level: "info",
  servers: [
    { server: "*", default_action: "allow", tools: [] },
  ],
};

// ── Resolve ~ in paths ──────────────────────────────────────────

export function resolveDataDir(raw: string): string {
  if (raw.startsWith("~/")) {
    return join(homedir(), raw.slice(2));
  }
  return raw;
}

// ── Load policy ─────────────────────────────────────────────────

/**
 * Load policy from either:
 *   - a direct file path ending in .json
 *   - a data directory containing policy.json
 *   - QUINT_DATA_DIR env var
 *   - default ~/.quint
 */
export function loadPolicy(pathOrDir?: string): PolicyConfig {
  const envDir = process.env.QUINT_DATA_DIR;

  let policyPath: string;
  let dir: string;

  if (pathOrDir && pathOrDir.endsWith(".json")) {
    // Direct path to a policy file
    policyPath = pathOrDir;
    dir = dirname(policyPath);
  } else {
    dir = pathOrDir ?? envDir ?? DEFAULT_DATA_DIR;
    policyPath = join(dir, "policy.json");
  }

  if (!existsSync(policyPath)) {
    return { ...DEFAULT_POLICY, data_dir: dir };
  }

  const raw = readFileSync(policyPath, "utf-8");
  const parsed = JSON.parse(raw) as PolicyConfig;
  return {
    ...parsed,
    data_dir: resolveDataDir(parsed.data_dir ?? dir),
  };
}

// ── Save/init policy ────────────────────────────────────────────

export function initPolicy(dataDir?: string): string {
  const dir = dataDir ?? DEFAULT_DATA_DIR;
  mkdirSync(dir, { recursive: true });
  const policyPath = join(dir, "policy.json");

  if (existsSync(policyPath)) {
    return policyPath;
  }

  writeFileSync(policyPath, JSON.stringify(DEFAULT_POLICY, null, 2) + "\n");
  return policyPath;
}

// ── Validate policy ─────────────────────────────────────────────

export function validatePolicy(config: PolicyConfig): string[] {
  const errors: string[] = [];

  if (config.version !== 1) {
    errors.push(`Unsupported policy version: ${config.version}`);
  }
  if (!Array.isArray(config.servers)) {
    errors.push("'servers' must be an array");
    return errors;
  }

  for (const srv of config.servers) {
    if (!srv.server || typeof srv.server !== "string") {
      errors.push("Each server entry must have a 'server' name string");
    }
    if (!["allow", "deny"].includes(srv.default_action)) {
      errors.push(`Invalid default_action '${srv.default_action}' for server '${srv.server}'`);
    }
    if (!Array.isArray(srv.tools)) {
      errors.push(`'tools' must be an array for server '${srv.server}'`);
      continue;
    }
    for (const rule of srv.tools) {
      if (!rule.tool || typeof rule.tool !== "string") {
        errors.push(`Tool rule missing 'tool' name in server '${srv.server}'`);
      }
      if (!["allow", "deny"].includes(rule.action)) {
        errors.push(`Invalid action '${rule.action}' for tool '${rule.tool}' in server '${srv.server}'`);
      }
    }
  }

  return errors;
}

// ── Evaluate policy for a tool call ─────────────────────────────

export function evaluatePolicy(
  config: PolicyConfig,
  serverName: string,
  toolName: string | null,
): Verdict {
  // Find matching server policy (first match wins, * is wildcard)
  let serverPolicy: ServerPolicy | undefined;
  for (const sp of config.servers) {
    if (sp.server === serverName || sp.server === "*") {
      serverPolicy = sp;
      break;
    }
  }

  // No server match = fail closed
  if (!serverPolicy) return "deny";

  // If no tool name (not a tools/call), passthrough
  if (!toolName) return "passthrough";

  // Check tool-specific rules (first match wins)
  for (const rule of serverPolicy.tools) {
    if (rule.tool === toolName || rule.tool === "*") {
      return rule.action;
    }
  }

  // Fall back to server default
  return serverPolicy.default_action;
}
