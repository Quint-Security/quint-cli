import { Command } from "commander";
import {
  loadPolicy,
  resolveDataDir,
  loadKeyPair,
  publicKeyFingerprint,
  openAuditDb,
} from "@quint/core";
import { existsSync } from "node:fs";
import { join } from "node:path";

export const statusCommand = new Command("status")
  .description("Show Quint configuration summary")
  .action(() => {
    const policy = loadPolicy();
    const dataDir = resolveDataDir(policy.data_dir);

    console.log("Quint Status");
    console.log("============");
    console.log(`  Data dir:    ${dataDir}`);
    console.log(`  Policy:      ${join(dataDir, "policy.json")} ${existsSync(join(dataDir, "policy.json")) ? "(found)" : "(not found)"}`);
    console.log(`  Log level:   ${policy.log_level}`);

    // Keys
    const kp = loadKeyPair(dataDir);
    if (kp) {
      console.log(`  Keys:        ${publicKeyFingerprint(kp.publicKey)} (loaded)`);
    } else {
      console.log(`  Keys:        not generated (run \`quint keys generate\`)`);
    }

    // Database
    const dbPath = join(dataDir, "quint.db");
    if (existsSync(dbPath)) {
      const db = openAuditDb(dataDir);
      const count = db.count();
      db.close();
      console.log(`  Database:    ${dbPath} (${count} entries)`);
    } else {
      console.log(`  Database:    not created yet`);
    }

    // Servers
    console.log(`\n  Servers (${policy.servers.length}):`);
    for (const srv of policy.servers) {
      const toolRules = srv.tools.length > 0
        ? srv.tools.map(t => `${t.tool}:${t.action}`).join(", ")
        : "no tool-specific rules";
      console.log(`    ${srv.server} → default:${srv.default_action} [${toolRules}]`);
    }
  });
