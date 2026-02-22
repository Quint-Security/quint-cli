import { Command } from "commander";
import { loadPolicy, resolveDataDir, openAuditDb } from "@quint-security/core";
import { startDashboardServer } from "../dashboard/server.js";

export const dashboardCommand = new Command("dashboard")
  .description("Launch the web dashboard for audit logs and policy overview")
  .option("-p, --port <port>", "Port to listen on", "3000")
  .option("--policy <path>", "Path to policy.json or data directory")
  .action(async (opts) => {
    const port = parseInt(opts.port, 10);
    if (isNaN(port) || port < 1 || port > 65535) {
      console.error("Error: invalid port number");
      process.exit(1);
    }

    const policy = loadPolicy(opts.policy);
    const dataDir = resolveDataDir(policy.data_dir);
    const db = openAuditDb(dataDir);

    const server = await startDashboardServer({ port, db, dataDir, policy });

    console.log(`Quint dashboard running at http://localhost:${port}`);

    const shutdown = () => {
      server.close();
      db.close();
      process.exit(0);
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  });
