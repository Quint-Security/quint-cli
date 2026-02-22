import { Command } from "commander";
import {
  loadPolicy,
  resolveDataDir,
  openAuthDb,
  generateApiKey,
} from "@quint-security/core";

export const authCommand = new Command("auth")
  .description("Manage authentication (API keys and sessions)");

authCommand
  .command("create-key")
  .description("Create a new API key")
  .requiredOption("--label <name>", "Human-readable label for the key")
  .option("--scopes <scopes>", "Comma-separated scopes (e.g. proxy:read,audit:write)")
  .option("--ttl <seconds>", "Time-to-live in seconds (0 = no expiry)", "0")
  .action((opts: { label: string; scopes?: string; ttl: string }) => {
    const policy = loadPolicy();
    const dataDir = resolveDataDir(policy.data_dir);
    const db = openAuthDb(dataDir);

    const scopes = opts.scopes ? opts.scopes.split(",").map((s) => s.trim()) : [];
    const ttl = parseInt(opts.ttl, 10);

    const { rawKey, apiKey } = generateApiKey(db, {
      label: opts.label,
      scopes,
      ttlSeconds: ttl > 0 ? ttl : undefined,
    });

    console.log(`API key created.\n`);
    console.log(`  ID:      ${apiKey.id}`);
    console.log(`  Label:   ${apiKey.label}`);
    console.log(`  Scopes:  ${apiKey.scopes || "(all)"}`);
    console.log(`  Expires: ${apiKey.expires_at ?? "never"}`);
    console.log(`\n  Raw key (SAVE THIS — shown only once):\n`);
    console.log(`  ${rawKey}\n`);

    db.close();
  });

authCommand
  .command("list-keys")
  .description("List all API keys")
  .action(() => {
    const policy = loadPolicy();
    const dataDir = resolveDataDir(policy.data_dir);
    const db = openAuthDb(dataDir);

    const keys = db.listApiKeys();
    if (keys.length === 0) {
      console.log("No API keys found. Create one with `quint auth create-key`.");
      db.close();
      return;
    }

    console.log(`${keys.length} API key(s):\n`);
    for (const key of keys) {
      const status = key.revoked
        ? "REVOKED"
        : key.expires_at && new Date(key.expires_at) < new Date()
          ? "EXPIRED"
          : "active";
      const icon = status === "active" ? "●" : "○";
      console.log(`  ${icon} ${key.id}  ${key.label}  [${status}]  scopes=${key.scopes || "*"}  created=${key.created_at}`);
    }

    db.close();
  });

authCommand
  .command("revoke-key")
  .description("Revoke an API key")
  .requiredOption("--id <id>", "API key ID to revoke")
  .action((opts: { id: string }) => {
    const policy = loadPolicy();
    const dataDir = resolveDataDir(policy.data_dir);
    const db = openAuthDb(dataDir);

    const key = db.getApiKeyById(opts.id);
    if (!key) {
      console.error(`API key not found: ${opts.id}`);
      db.close();
      process.exit(1);
    }

    if (key.revoked) {
      console.log(`Key ${opts.id} is already revoked.`);
      db.close();
      return;
    }

    db.revokeApiKey(opts.id);
    // Also revoke any sessions issued to this key
    const revoked = db.revokeSessionsBySubject(opts.id);
    console.log(`Revoked key ${opts.id} (${key.label}).`);
    if (revoked > 0) {
      console.log(`  Also revoked ${revoked} active session(s).`);
    }

    db.close();
  });

authCommand
  .command("set-rate-limit")
  .description("Set a per-key rate limit (requests per minute)")
  .requiredOption("--id <id>", "API key ID")
  .requiredOption("--rpm <number>", "Requests per minute (0 = use global default)")
  .action((opts: { id: string; rpm: string }) => {
    const policy = loadPolicy();
    const dataDir = resolveDataDir(policy.data_dir);
    const db = openAuthDb(dataDir);

    const key = db.getApiKeyById(opts.id);
    if (!key) {
      console.error(`API key not found: ${opts.id}`);
      db.close();
      process.exit(1);
    }

    const rpm = parseInt(opts.rpm, 10);
    if (isNaN(rpm) || rpm < 0) {
      console.error(`Invalid RPM value: ${opts.rpm}. Must be a non-negative integer.`);
      db.close();
      process.exit(1);
    }

    const effectiveRpm = rpm === 0 ? null : rpm;
    db.setRateLimit(opts.id, effectiveRpm);

    if (effectiveRpm === null) {
      console.log(`Cleared per-key rate limit for ${opts.id} (${key.label}). Will use global default.`);
    } else {
      console.log(`Set rate limit for ${opts.id} (${key.label}) to ${effectiveRpm} requests/minute.`);
    }

    db.close();
  });
