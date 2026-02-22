import { Command } from "commander";
import {
  loadPolicy,
  resolveDataDir,
  ensureKeyPair,
  openCredentialStore,
  deriveCredentialKey,
} from "@quint-security/core";
import { getProvider, PROVIDERS } from "../connect/providers.js";
import { runOAuthFlow } from "../connect/oauth.js";

function getEncryptionKey(dataDir: string): string {
  const passphrase = process.env.QUINT_PASSPHRASE;
  const kp = ensureKeyPair(dataDir, passphrase);
  return deriveCredentialKey(passphrase, kp.privateKey);
}

export const connectCommand = new Command("connect")
  .description("Manage OAuth credentials for remote MCP servers");

// ── quint connect <service> ──────────────────────────────────

connectCommand
  .command("add <service>")
  .description("Store a credential for a service (token or OAuth flow)")
  .option("--token <token>", "Store a pre-existing token directly")
  .option("--client-id <id>", "Start OAuth PKCE flow with this client ID")
  .option("--client-secret <secret>", "OAuth client secret (required by some providers)")
  .option("--scopes <scopes>", "Override default scopes (comma-separated)")
  .option("--auth-url <url>", "Custom OAuth authorization URL")
  .option("--token-url <url>", "Custom OAuth token URL")
  .option("--callback-port <port>", "Fixed port for OAuth callback (default: random)", parseInt)
  .action(async (service: string, opts: {
    token?: string;
    clientId?: string;
    clientSecret?: string;
    scopes?: string;
    authUrl?: string;
    tokenUrl?: string;
    callbackPort?: number;
  }) => {
    const policy = loadPolicy();
    const dataDir = resolveDataDir(policy.data_dir);
    const encKey = getEncryptionKey(dataDir);
    const store = openCredentialStore(dataDir, encKey);

    try {
      if (opts.token) {
        // Direct token storage
        const provider = getProvider(service);
        store.store(service, {
          provider: provider ? service : "custom",
          accessToken: opts.token,
          scopes: opts.scopes ?? "",
        });
        console.log(`Credential stored for "${service}".`);
      } else if (opts.clientId) {
        // OAuth PKCE flow
        const provider = getProvider(service);
        const authUrl = opts.authUrl ?? provider?.authUrl;
        const tokenUrl = opts.tokenUrl ?? provider?.tokenUrl;

        if (!authUrl || !tokenUrl) {
          console.error(
            `Unknown provider "${service}". Specify --auth-url and --token-url for custom providers.`
          );
          process.exit(1);
        }

        const defaultScopes = provider?.defaultScopes ?? [];
        const scopes = opts.scopes
          ? opts.scopes.split(",").map((s) => s.trim())
          : defaultScopes;

        const result = await runOAuthFlow({
          clientId: opts.clientId,
          clientSecret: opts.clientSecret,
          authUrl,
          tokenUrl,
          scopes,
          callbackPort: opts.callbackPort,
        });

        const expiresAt = result.expires_in
          ? new Date(Date.now() + result.expires_in * 1000).toISOString()
          : undefined;

        store.store(service, {
          provider: provider ? service : "custom",
          accessToken: result.access_token,
          refreshToken: result.refresh_token,
          tokenType: result.token_type ?? "bearer",
          scopes: result.scope ?? scopes.join(","),
          expiresAt,
          metadata: {
            client_id: opts.clientId,
            token_url: tokenUrl,
          },
        });

        console.log(`\nOAuth credential stored for "${service}".`);
        if (result.scope) {
          console.log(`  Scopes: ${result.scope}`);
        }
        if (expiresAt) {
          console.log(`  Expires: ${expiresAt}`);
        }
      } else {
        console.error(
          `Specify --token <token> or --client-id <id> to store a credential.\n` +
          `  quint connect add ${service} --token <your-token>\n` +
          `  quint connect add ${service} --client-id <oauth-app-id>`
        );
        process.exit(1);
      }
    } finally {
      store.close();
    }
  });

// ── quint connect list ───────────────────────────────────────

connectCommand
  .command("list")
  .description("List stored credentials (tokens not shown)")
  .action(() => {
    const policy = loadPolicy();
    const dataDir = resolveDataDir(policy.data_dir);
    const encKey = getEncryptionKey(dataDir);
    const store = openCredentialStore(dataDir, encKey);

    const creds = store.list();
    if (creds.length === 0) {
      console.log("No stored credentials. Use `quint connect add <service>` to add one.");
      store.close();
      return;
    }

    console.log(`${creds.length} stored credential(s):\n`);
    for (const c of creds) {
      const expired = c.expires_at && new Date(c.expires_at) < new Date();
      const status = expired ? "EXPIRED" : "active";
      const icon = expired ? "○" : "●";
      console.log(`  ${icon} ${c.id}  provider=${c.provider}  [${status}]  scopes=${c.scopes || "*"}  updated=${c.updated_at}`);
    }

    store.close();
  });

// ── quint connect remove <service> ───────────────────────────

connectCommand
  .command("remove <service>")
  .description("Delete a stored credential")
  .action((service: string) => {
    const policy = loadPolicy();
    const dataDir = resolveDataDir(policy.data_dir);
    const encKey = getEncryptionKey(dataDir);
    const store = openCredentialStore(dataDir, encKey);

    const removed = store.remove(service);
    if (removed) {
      console.log(`Credential for "${service}" removed.`);
    } else {
      console.log(`No credential found for "${service}".`);
    }

    store.close();
  });

// ── quint connect status <service> ───────────────────────────

connectCommand
  .command("status <service>")
  .description("Check if a stored credential is valid/expired")
  .action((service: string) => {
    const policy = loadPolicy();
    const dataDir = resolveDataDir(policy.data_dir);
    const encKey = getEncryptionKey(dataDir);
    const store = openCredentialStore(dataDir, encKey);

    const cred = store.get(service);
    if (!cred) {
      console.log(`No credential found for "${service}".`);
      store.close();
      return;
    }

    const expired = store.isExpired(service);
    console.log(`Credential: ${service}`);
    console.log(`  Provider:  ${cred.provider}`);
    console.log(`  Type:      ${cred.token_type}`);
    console.log(`  Scopes:    ${cred.scopes || "(all)"}`);
    console.log(`  Status:    ${expired ? "EXPIRED" : "active"}`);
    console.log(`  Expires:   ${cred.expires_at ?? "never"}`);
    console.log(`  Created:   ${cred.created_at}`);
    console.log(`  Updated:   ${cred.updated_at}`);

    store.close();
  });

// ── quint connect providers ──────────────────────────────────

connectCommand
  .command("providers")
  .description("List known OAuth providers")
  .action(() => {
    console.log("Known OAuth providers:\n");
    for (const [key, provider] of Object.entries(PROVIDERS)) {
      console.log(`  ${key}`);
      console.log(`    Name:   ${provider.name}`);
      console.log(`    Scopes: ${provider.defaultScopes.join(", ") || "(none)"}`);
      console.log(`    Docs:   ${provider.docs}`);
      console.log();
    }
    console.log("For unlisted providers, use --auth-url and --token-url with `quint connect add`.");
  });
