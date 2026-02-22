import { createServer, type Server } from "node:http";
import { randomBytes, createHash } from "node:crypto";
import { execSync } from "node:child_process";
import { URL } from "node:url";

export interface OAuthTokenResult {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  token_type?: string;
}

export interface OAuthFlowOpts {
  clientId: string;
  clientSecret?: string;
  authUrl: string;
  tokenUrl: string;
  scopes: string[];
  redirectUri?: string;
  callbackPort?: number;
}

function base64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function openBrowser(url: string): void {
  const platform = process.platform;
  try {
    if (platform === "darwin") {
      execSync(`open "${url}"`, { stdio: "ignore" });
    } else if (platform === "win32") {
      execSync(`start "" "${url}"`, { stdio: "ignore" });
    } else {
      execSync(`xdg-open "${url}"`, { stdio: "ignore" });
    }
  } catch {
    // If browser open fails, user can manually copy the URL
  }
}

/**
 * Run a full OAuth 2.0 PKCE authorization code flow.
 *
 * 1. Generate code_verifier + code_challenge
 * 2. Start a temporary HTTP server for the callback
 * 3. Open the browser to the authorization URL
 * 4. Wait for the callback with the authorization code
 * 5. Exchange code for tokens
 * 6. Return the token result
 */
export async function runOAuthFlow(opts: OAuthFlowOpts): Promise<OAuthTokenResult> {
  // Generate PKCE values
  const codeVerifier = base64url(randomBytes(64));
  const codeChallenge = base64url(
    createHash("sha256").update(codeVerifier).digest()
  );
  const state = randomBytes(32).toString("hex");

  // Start temporary server (fixed port if specified, otherwise random)
  const { server, port } = await startCallbackServer(opts.callbackPort);
  const redirectUri = opts.redirectUri ?? `http://localhost:${port}/callback`;

  // Build authorization URL
  const authUrl = new URL(opts.authUrl);
  authUrl.searchParams.set("client_id", opts.clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  authUrl.searchParams.set("state", state);
  if (opts.scopes.length > 0) {
    authUrl.searchParams.set("scope", opts.scopes.join(" "));
  }

  console.log(`\nOpening browser for authorization...`);
  console.log(`If the browser doesn't open, visit:\n  ${authUrl.toString()}\n`);
  openBrowser(authUrl.toString());

  // Wait for the callback
  const { code, receivedState } = await waitForCallback(server, port);

  // Verify state
  if (receivedState !== state) {
    throw new Error("OAuth state mismatch — possible CSRF attack. Aborting.");
  }

  // Exchange code for tokens
  console.log("Exchanging authorization code for tokens...");
  const tokenResult = await exchangeCode({
    tokenUrl: opts.tokenUrl,
    code,
    codeVerifier,
    redirectUri,
    clientId: opts.clientId,
    clientSecret: opts.clientSecret,
  });

  return tokenResult;
}

function startCallbackServer(fixedPort?: number): Promise<{ server: Server; port: number }> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.on("error", reject);
    server.listen(fixedPort ?? 0, () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("Failed to get server address"));
        return;
      }
      resolve({ server, port: addr.port });
    });
  });
}

function waitForCallback(server: Server, port: number): Promise<{ code: string; receivedState: string }> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      server.close();
      reject(new Error("OAuth callback timed out after 5 minutes."));
    }, 5 * 60 * 1000);

    server.on("request", (req, res) => {
      const url = new URL(req.url ?? "/", `http://localhost:${port}`);

      if (url.pathname !== "/callback") {
        res.writeHead(404);
        res.end("Not found");
        return;
      }

      const code = url.searchParams.get("code");
      const receivedState = url.searchParams.get("state");
      const error = url.searchParams.get("error");

      if (error) {
        const desc = url.searchParams.get("error_description") ?? error;
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(`<html><body><h2>Authorization failed</h2><p>${desc}</p><p>You can close this tab.</p></body></html>`);
        clearTimeout(timeout);
        server.close();
        reject(new Error(`OAuth authorization failed: ${desc}`));
        return;
      }

      if (!code || !receivedState) {
        res.writeHead(400, { "Content-Type": "text/html" });
        res.end(`<html><body><h2>Missing parameters</h2><p>Expected code and state parameters.</p></body></html>`);
        return;
      }

      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(`<html><body><h2>Authorization successful!</h2><p>You can close this tab and return to the terminal.</p></body></html>`);
      clearTimeout(timeout);
      server.close();
      resolve({ code, receivedState });
    });
  });
}

async function exchangeCode(opts: {
  tokenUrl: string;
  code: string;
  codeVerifier: string;
  redirectUri: string;
  clientId: string;
  clientSecret?: string;
}): Promise<OAuthTokenResult> {
  const params: Record<string, string> = {
    grant_type: "authorization_code",
    code: opts.code,
    code_verifier: opts.codeVerifier,
    redirect_uri: opts.redirectUri,
    client_id: opts.clientId,
  };
  if (opts.clientSecret) {
    params.client_secret = opts.clientSecret;
  }
  const body = new URLSearchParams(params);

  const res = await fetch(opts.tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: body.toString(),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Token exchange failed (${res.status}): ${text}`);
  }

  const contentType = res.headers.get("content-type") ?? "";
  let data: Record<string, unknown>;

  if (contentType.includes("application/x-www-form-urlencoded")) {
    // GitHub returns form-encoded by default
    const text = await res.text();
    const params = new URLSearchParams(text);
    data = Object.fromEntries(params.entries());
  } else {
    data = await res.json() as Record<string, unknown>;
  }

  if (data.error) {
    throw new Error(`Token exchange error: ${data.error_description ?? data.error}`);
  }

  return {
    access_token: data.access_token as string,
    refresh_token: data.refresh_token as string | undefined,
    expires_in: data.expires_in ? Number(data.expires_in) : undefined,
    scope: data.scope as string | undefined,
    token_type: (data.token_type as string | undefined) ?? "bearer",
  };
}
