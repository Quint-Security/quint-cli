import { Command } from "commander";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { loadPolicy, resolveDataDir, openAuditDb, type AuditEntry } from "@quint-security/core";

interface SyncState {
  last_synced_id: number;
  last_synced_at: string | null;
}

interface SyncConfig {
  api_url?: string;
  api_key?: string;
}

const BATCH_SIZE = 500;
const WATCH_INTERVAL_MS = 30_000;

function getQuintDir(): string {
  return join(homedir(), ".quint");
}

function loadSyncState(): SyncState {
  const path = join(getQuintDir(), "sync.json");
  if (existsSync(path)) {
    try {
      return JSON.parse(readFileSync(path, "utf-8"));
    } catch {
      // Corrupted file, start fresh
    }
  }
  return { last_synced_id: 0, last_synced_at: null };
}

function saveSyncState(state: SyncState): void {
  const dir = getQuintDir();
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "sync.json"), JSON.stringify(state, null, 2));
}

function loadSyncConfig(): SyncConfig {
  const configPath = join(getQuintDir(), "config.json");
  if (existsSync(configPath)) {
    try {
      return JSON.parse(readFileSync(configPath, "utf-8"));
    } catch {
      // Ignore
    }
  }
  return {};
}

function getApiUrl(opts: { apiUrl?: string }): string {
  if (opts.apiUrl) return opts.apiUrl;
  const envUrl = process.env.QUINT_API_URL;
  if (envUrl) return envUrl;
  const config = loadSyncConfig();
  if (config.api_url) return config.api_url;
  throw new Error(
    "API URL not configured. Set QUINT_API_URL env var, pass --api-url, or add api_url to ~/.quint/config.json"
  );
}

function getApiKey(opts: { apiKey?: string }): string {
  if (opts.apiKey) return opts.apiKey;
  const envKey = process.env.QUINT_API_KEY;
  if (envKey) return envKey;
  const config = loadSyncConfig();
  if (config.api_key) return config.api_key;
  throw new Error(
    "API key not configured. Set QUINT_API_KEY env var, pass --api-key, or add api_key to ~/.quint/config.json"
  );
}

function formatEntry(e: AuditEntry) {
  return {
    timestamp: e.timestamp,
    server_name: e.server_name,
    direction: e.direction,
    method: e.method,
    message_id: e.message_id,
    tool_name: e.tool_name,
    arguments_json: e.arguments_json,
    response_json: e.response_json,
    verdict: e.verdict,
    risk_score: e.risk_score,
    risk_level: e.risk_level,
    policy_hash: e.policy_hash,
    prev_hash: e.prev_hash,
    nonce: e.nonce,
    signature: e.signature,
    public_key: e.public_key,
  };
}

async function syncBatch(
  apiUrl: string,
  apiKey: string,
  entries: AuditEntry[],
  verbose?: boolean,
): Promise<{ ingested: number; skipped: number }> {
  const url = `${apiUrl.replace(/\/$/, "")}/v1/audit/entries`;
  let totalIngested = 0;
  let totalSkipped = 0;
  let remaining = [...entries];

  while (remaining.length > 0) {
    const body = JSON.stringify({ entries: remaining.map(formatEntry) });

    const resp = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body,
    });

    if (resp.ok) {
      const result = (await resp.json()) as { ingested: number; ids: number[] };
      totalIngested += result.ingested;
      break;
    }

    const result = await resp.json() as { error: string; index?: number; nonce?: string };

    // If a specific entry failed, split: ingest everything before it, skip it, continue
    if (resp.status === 400 && typeof result.index === "number") {
      const badIndex = result.index;
      const badEntry = remaining[badIndex];

      // Ingest entries before the bad one
      if (badIndex > 0) {
        const before = remaining.slice(0, badIndex);
        const beforeResp = await fetch(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${apiKey}`,
          },
          body: JSON.stringify({ entries: before.map(formatEntry) }),
        });
        if (beforeResp.ok) {
          const beforeResult = (await beforeResp.json()) as { ingested: number };
          totalIngested += beforeResult.ingested;
        }
      }

      // Skip the bad entry
      if (verbose) {
        console.warn(`  Skipping entry id=${badEntry.id}: ${result.error}`);
      }
      totalSkipped++;
      remaining = remaining.slice(badIndex + 1);
      continue;
    }

    // Duplicate nonce — skip that entry
    if (resp.status === 409 && typeof result.index === "number") {
      const badIndex = result.index;
      if (badIndex > 0) {
        const before = remaining.slice(0, badIndex);
        const beforeResp = await fetch(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${apiKey}`,
          },
          body: JSON.stringify({ entries: before.map(formatEntry) }),
        });
        if (beforeResp.ok) {
          const beforeResult = (await beforeResp.json()) as { ingested: number };
          totalIngested += beforeResult.ingested;
        }
      }
      totalSkipped++;
      remaining = remaining.slice(badIndex + 1);
      continue;
    }

    // Unknown error — throw
    throw new Error(`API returned ${resp.status}: ${JSON.stringify(result)}`);
  }

  return { ingested: totalIngested, skipped: totalSkipped };
}

async function pullPolicy(apiUrl: string, apiKey: string): Promise<boolean> {
  const url = `${apiUrl.replace(/\/$/, "")}/v1/policies/active`;

  // Read current ETag if we have one
  const etagPath = join(getQuintDir(), "policy_etag.txt");
  let currentEtag: string | undefined;
  if (existsSync(etagPath)) {
    currentEtag = readFileSync(etagPath, "utf-8").trim();
  }

  const headers: Record<string, string> = {
    Authorization: `Bearer ${apiKey}`,
  };
  if (currentEtag) {
    headers["If-None-Match"] = currentEtag;
  }

  const resp = await fetch(url, { headers });

  if (resp.status === 304) {
    return false; // Not modified
  }

  if (resp.status === 404) {
    console.log("  No active policy on server");
    return false;
  }

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`API returned ${resp.status}: ${text}`);
  }

  const policy = await resp.json();
  const etag = resp.headers.get("ETag");

  // Write policy to local file
  const policyPath = join(getQuintDir(), "policy.json");
  writeFileSync(policyPath, JSON.stringify(policy.config_json, null, 2));
  console.log(`  Policy updated: ${policy.name} v${policy.version}`);

  // Save ETag
  if (etag) {
    writeFileSync(etagPath, etag);
  }

  return true;
}

async function runSync(opts: {
  apiUrl?: string;
  apiKey?: string;
  pullPolicy?: boolean;
  verbose?: boolean;
}): Promise<void> {
  const apiUrl = getApiUrl(opts);
  const apiKey = getApiKey(opts);

  let policy;
  try {
    policy = loadPolicy();
  } catch {
    policy = { data_dir: "~/.quint" };
  }

  const dataDir = resolveDataDir(policy.data_dir);
  const db = openAuditDb(dataDir);

  try {
    const state = loadSyncState();
    const totalLocal = db.count();

    if (opts.verbose) {
      console.log(`Local entries: ${totalLocal}`);
      console.log(`Last synced ID: ${state.last_synced_id}`);
    }

    let synced = 0;

    // Sync entries in batches
    while (true) {
      const entries = db.getAfterId(state.last_synced_id, BATCH_SIZE);
      if (entries.length === 0) break;

      if (opts.verbose) {
        console.log(`  Syncing batch of ${entries.length} entries (IDs ${entries[0].id}-${entries[entries.length - 1].id})...`);
      }

      const result = await syncBatch(apiUrl, apiKey, entries, opts.verbose);
      synced += result.ingested;

      if (result.skipped > 0 && opts.verbose) {
        console.log(`  Skipped ${result.skipped} entries with invalid signatures`);
      }

      // Update state with the last entry's ID
      const lastEntry = entries[entries.length - 1];
      state.last_synced_id = lastEntry.id!;
      state.last_synced_at = new Date().toISOString();
      saveSyncState(state);
    }

    if (synced > 0) {
      console.log(`Synced ${synced} entries to ${apiUrl}`);
    } else {
      console.log("Already up to date");
    }

    // Pull policy if requested
    if (opts.pullPolicy) {
      console.log("Checking for policy updates...");
      try {
        await pullPolicy(apiUrl, apiKey);
      } catch (err) {
        console.error(`  Failed to pull policy: ${err instanceof Error ? err.message : err}`);
      }
    }
  } finally {
    db.close();
  }
}

export const syncCommand = new Command("sync")
  .description("Sync local audit entries to the Quint control plane API")
  .option("--api-url <url>", "API base URL (or set QUINT_API_URL)")
  .option("--api-key <key>", "API key (or set QUINT_API_KEY)")
  .option("--watch", "Continuously sync every 30 seconds")
  .option("--pull-policy", "Pull active policy from the API after syncing")
  .option("-v, --verbose", "Show detailed sync progress")
  .action(async (opts: {
    apiUrl?: string;
    apiKey?: string;
    watch?: boolean;
    pullPolicy?: boolean;
    verbose?: boolean;
  }) => {
    try {
      if (opts.watch) {
        console.log("Starting sync watch mode (Ctrl+C to stop)...");
        // Run once immediately
        await runSync(opts);

        // Then run on interval
        const interval = setInterval(async () => {
          try {
            await runSync(opts);
          } catch (err) {
            console.error(`Sync error: ${err instanceof Error ? err.message : err}`);
          }
        }, WATCH_INTERVAL_MS);

        // Keep process running
        process.on("SIGINT", () => {
          clearInterval(interval);
          console.log("\nSync watch stopped");
          process.exit(0);
        });
      } else {
        await runSync(opts);
      }
    } catch (err) {
      console.error(`Error: ${err instanceof Error ? err.message : err}`);
      process.exit(1);
    }
  });
