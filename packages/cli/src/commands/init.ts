import { Command } from "commander";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import {
  ensureKeyPair,
  resolveDataDir,
  initPolicy,
  publicKeyFingerprint,
  type PolicyConfig,
  type ServerPolicy,
} from "@quint-security/core";

// ── Role presets ────────────────────────────────────────────────

interface RolePreset {
  name: string;
  description: string;
  defaultAction: "allow" | "deny";
  tools: Array<{ tool: string; action: "allow" | "deny" }>;
}

const ROLE_PRESETS: Record<string, RolePreset> = {
  "coding-assistant": {
    name: "Coding Assistant",
    description: "Read/write project files, run builds and tests. Block destructive ops, shell access outside project, and sensitive file access.",
    defaultAction: "allow",
    tools: [
      { tool: "Delete*", action: "deny" },
      { tool: "Remove*", action: "deny" },
      { tool: "Drop*", action: "deny" },
      { tool: "MechanicRun*", action: "deny" },
      { tool: "TicketingWrite*", action: "deny" },
    ],
  },
  "research-agent": {
    name: "Research Agent",
    description: "Read-only access. Can fetch web pages and search. All write/execute operations denied.",
    defaultAction: "deny",
    tools: [
      { tool: "Read*", action: "allow" },
      { tool: "Get*", action: "allow" },
      { tool: "List*", action: "allow" },
      { tool: "Search*", action: "allow" },
      { tool: "Fetch*", action: "allow" },
      { tool: "ReadInternalWebsites", action: "allow" },
      { tool: "MechanicDiscoverTools", action: "allow" },
      { tool: "MechanicDescribeTool", action: "allow" },
    ],
  },
  "strict": {
    name: "Strict",
    description: "Deny everything by default. Manually allowlist tools as needed.",
    defaultAction: "deny",
    tools: [],
  },
  "permissive": {
    name: "Permissive",
    description: "Allow everything, deny only known-dangerous operations. Good for trusted environments.",
    defaultAction: "allow",
    tools: [
      { tool: "Delete*", action: "deny" },
      { tool: "Remove*", action: "deny" },
      { tool: "Drop*", action: "deny" },
    ],
  },
};

// ── Detect MCP servers from Claude Code config ──────────────────

interface ClaudeMcpServer {
  type: "stdio" | "http";
  command?: string;
  args?: string[];
  url?: string;
  env?: Record<string, string>;
}

interface DetectedServer {
  name: string;
  config: ClaudeMcpServer;
  source: "global" | "project";
  alreadyProxied: boolean;
}

function detectMcpServers(): DetectedServer[] {
  const claudeConfigPath = join(homedir(), ".claude.json");
  if (!existsSync(claudeConfigPath)) {
    return [];
  }

  const raw = readFileSync(claudeConfigPath, "utf-8");
  let config: Record<string, unknown>;
  try {
    config = JSON.parse(raw);
  } catch {
    return [];
  }

  const servers: DetectedServer[] = [];
  const seen = new Set<string>();

  // Global MCP servers
  const globalServers = config.mcpServers as Record<string, ClaudeMcpServer> | undefined;
  if (globalServers && typeof globalServers === "object") {
    for (const [name, srv] of Object.entries(globalServers)) {
      if (!seen.has(name)) {
        seen.add(name);
        servers.push({
          name,
          config: srv,
          source: "global",
          alreadyProxied: isAlreadyProxied(srv),
        });
      }
    }
  }

  // Project-level MCP servers (current working directory)
  const projects = config.projects as Record<string, { mcpServers?: Record<string, ClaudeMcpServer> }> | undefined;
  if (projects) {
    const cwd = process.cwd();
    for (const [projectPath, proj] of Object.entries(projects)) {
      if (cwd.startsWith(projectPath) && proj.mcpServers) {
        for (const [name, srv] of Object.entries(proj.mcpServers)) {
          if (!seen.has(name)) {
            seen.add(name);
            servers.push({
              name,
              config: srv,
              source: "project",
              alreadyProxied: isAlreadyProxied(srv),
            });
          }
        }
      }
    }
  }

  return servers;
}

function isAlreadyProxied(srv: ClaudeMcpServer): boolean {
  return srv.command === "quint" || srv.command === "node" && (srv.args ?? []).some(a => a.includes("quint"));
}

// ── Generate wrapped config ─────────────────────────────────────

function generateWrappedConfig(server: DetectedServer): ClaudeMcpServer | null {
  if (server.alreadyProxied) return null;

  if (server.config.type === "stdio") {
    return {
      type: "stdio",
      command: "quint",
      args: [
        "proxy",
        "--name", server.name,
        "--",
        server.config.command!,
        ...(server.config.args ?? []),
      ],
      env: server.config.env ?? {},
    };
  }

  if (server.config.type === "http" && server.config.url) {
    return {
      type: "stdio",
      command: "quint",
      args: [
        "http-proxy",
        "--name", server.name,
        "--target", server.config.url,
      ],
      env: server.config.env ?? {},
    };
  }

  return null;
}

// ── Apply changes to claude.json ────────────────────────────────

function applyToClaudeConfig(servers: DetectedServer[]): { applied: number; path: string } {
  const claudeConfigPath = join(homedir(), ".claude.json");
  const raw = readFileSync(claudeConfigPath, "utf-8");
  const config = JSON.parse(raw);

  let applied = 0;

  for (const server of servers) {
    if (server.alreadyProxied) continue;

    const wrapped = generateWrappedConfig(server);
    if (!wrapped) continue;

    if (server.source === "global" && config.mcpServers?.[server.name]) {
      config.mcpServers[server.name] = wrapped;
      applied++;
    } else if (server.source === "project") {
      // Find the project entry
      for (const [projectPath, proj] of Object.entries(config.projects as Record<string, { mcpServers?: Record<string, ClaudeMcpServer> }>)) {
        if (proj.mcpServers?.[server.name]) {
          proj.mcpServers[server.name] = wrapped;
          applied++;
          break;
        }
      }
    }
  }

  writeFileSync(claudeConfigPath, JSON.stringify(config, null, 2) + "\n");
  return { applied, path: claudeConfigPath };
}

// ── The init command ────────────────────────────────────────────

export const initCommand = new Command("init")
  .description("Set up Quint: detect MCP servers, generate keys, create policy, and optionally wrap your config")
  .option("--role <role>", "Use a pre-built role preset (coding-assistant, research-agent, strict, permissive)")
  .option("--apply", "Apply changes to ~/.claude.json (wraps MCP servers through Quint)")
  .option("--revert", "Revert all Quint-proxied MCP servers back to direct connections")
  .option("--dry-run", "Show what would change without modifying anything")
  .option("--list-roles", "Show available role presets")
  .action((opts: { role?: string; apply?: boolean; revert?: boolean; dryRun?: boolean; listRoles?: boolean }) => {

    // ── List roles ──
    if (opts.listRoles) {
      console.log("Available role presets:\n");
      for (const [id, preset] of Object.entries(ROLE_PRESETS)) {
        console.log(`  ${id}`);
        console.log(`    ${preset.description}`);
        console.log(`    Default: ${preset.defaultAction}, ${preset.tools.length} tool rules`);
        console.log("");
      }
      return;
    }

    // ── Revert ──
    if (opts.revert) {
      const servers = detectMcpServers();
      const proxied = servers.filter(s => s.alreadyProxied);

      if (proxied.length === 0) {
        console.log("No Quint-proxied servers found. Nothing to revert.");
        return;
      }

      if (opts.dryRun) {
        console.log("Would revert these servers to direct connections:\n");
        for (const s of proxied) {
          // Extract the original command from quint proxy args
          const args = s.config.args ?? [];
          const dashDashIdx = args.indexOf("--");
          if (dashDashIdx >= 0) {
            const origCmd = args[dashDashIdx + 1];
            const origArgs = args.slice(dashDashIdx + 2);
            console.log(`  ${s.name}: quint proxy → ${origCmd} ${origArgs.join(" ")}`);
          }
        }
        return;
      }

      const claudeConfigPath = join(homedir(), ".claude.json");
      const raw = readFileSync(claudeConfigPath, "utf-8");
      const config = JSON.parse(raw);

      let reverted = 0;
      for (const s of proxied) {
        const args = s.config.args ?? [];
        const dashDashIdx = args.indexOf("--");
        if (dashDashIdx < 0) continue;

        const origCmd = args[dashDashIdx + 1];
        const origArgs = args.slice(dashDashIdx + 2);
        const restored = {
          type: "stdio" as const,
          command: origCmd,
          args: origArgs,
          env: s.config.env ?? {},
        };

        // Restore in the correct location
        if (s.source === "global" && config.mcpServers?.[s.name]) {
          config.mcpServers[s.name] = restored;
          reverted++;
        } else if (s.source === "project" && config.projects) {
          for (const proj of Object.values(config.projects as Record<string, { mcpServers?: Record<string, ClaudeMcpServer> }>)) {
            if (proj.mcpServers?.[s.name]) {
              proj.mcpServers[s.name] = restored;
              reverted++;
              break;
            }
          }
        }
      }

      writeFileSync(claudeConfigPath, JSON.stringify(config, null, 2) + "\n");
      console.log(`Reverted ${reverted} server(s) to direct connections.`);
      console.log("Restart Claude Code for changes to take effect.");
      return;
    }

    // ── Normal init flow ──

    console.log("Quint Setup\n");

    // Step 1: Detect MCP servers
    const servers = detectMcpServers();
    if (servers.length === 0) {
      console.log("  No MCP servers found in ~/.claude.json");
      console.log("  Quint works by wrapping existing MCP servers.");
      console.log("  Add MCP servers to Claude Code first, then run quint init again.");
      return;
    }

    console.log(`  Found ${servers.length} MCP server(s):\n`);
    for (const s of servers) {
      const status = s.alreadyProxied ? " (already proxied)" : "";
      const type = s.config.type === "http" ? ` [HTTP: ${s.config.url}]` : ` [stdio: ${s.config.command}]`;
      console.log(`    ${s.name}${type} (${s.source})${status}`);
    }

    const toWrap = servers.filter(s => !s.alreadyProxied);
    if (toWrap.length === 0) {
      console.log("\n  All servers are already proxied through Quint.");
    }

    // Step 2: Generate keys
    console.log("");
    const dataDir = resolveDataDir("~/.quint");
    const kp = ensureKeyPair(dataDir);
    console.log(`  Keys:   ${publicKeyFingerprint(kp.publicKey)} (ready)`);

    // Step 3: Generate policy
    const role = opts.role ? ROLE_PRESETS[opts.role] : undefined;
    if (opts.role && !role) {
      console.error(`\n  Unknown role: ${opts.role}`);
      console.error(`  Available: ${Object.keys(ROLE_PRESETS).join(", ")}`);
      process.exit(1);
    }

    const serverPolicies: ServerPolicy[] = [];

    for (const s of servers) {
      if (role) {
        serverPolicies.push({
          server: s.name,
          default_action: role.defaultAction,
          tools: [...role.tools],
        });
      } else {
        serverPolicies.push({
          server: s.name,
          default_action: "allow",
          tools: [],
        });
      }
    }

    // Always add wildcard fallback
    serverPolicies.push({ server: "*", default_action: "allow", tools: [] });

    const policy: PolicyConfig = {
      version: 1,
      data_dir: "~/.quint",
      log_level: "info",
      servers: serverPolicies,
    };

    const policyPath = join(dataDir, "policy.json");
    if (!existsSync(policyPath)) {
      writeFileSync(policyPath, JSON.stringify(policy, null, 2) + "\n");
      console.log(`  Policy: ${policyPath} (created${role ? `, role: ${role.name}` : ""})`);
    } else {
      console.log(`  Policy: ${policyPath} (exists, not overwritten)`);
    }

    // Step 4: Show or apply config changes
    if (toWrap.length > 0) {
      console.log(`\n  Config changes needed for ${toWrap.length} server(s):\n`);

      for (const s of toWrap) {
        const wrapped = generateWrappedConfig(s);
        if (!wrapped) continue;

        console.log(`    ${s.name}:`);
        console.log(`      before: ${JSON.stringify({ command: s.config.command, args: s.config.args ?? [] })}`);
        console.log(`      after:  ${JSON.stringify({ command: wrapped.command, args: wrapped.args })}`);
        console.log("");
      }

      if (opts.apply && !opts.dryRun) {
        const result = applyToClaudeConfig(toWrap);
        console.log(`  Applied ${result.applied} change(s) to ${result.path}`);
        console.log("  Restart Claude Code for changes to take effect.");
      } else if (opts.dryRun) {
        console.log("  (dry run — no changes made)");
      } else {
        console.log("  Run with --apply to modify ~/.claude.json automatically.");
        console.log("  Run with --dry-run to preview without changes.");
        console.log("  Run with --revert to undo Quint proxying.");
      }
    }

    console.log("\n  Setup complete. Run `quint status` to verify.");
  });
