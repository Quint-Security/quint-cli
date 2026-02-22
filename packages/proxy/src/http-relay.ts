import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { EventEmitter } from "node:events";

export interface HttpRelayEvents {
  /** Fired for every JSON-RPC request received from the agent via HTTP */
  request: (line: string) => void;
  /** Fired for every JSON-RPC response received from the remote server */
  response: (line: string) => void;
  /** Unrecoverable error */
  error: (err: Error) => void;
}

interface PendingRequest {
  res: ServerResponse;
  body: string;
  headers: Record<string, string>;
  subjectId: string;
}

/**
 * Auth check result. Return an object with error to reject (401),
 * or with subjectId/rateLimitRpm to attach metadata to the request.
 * Returning null/undefined means auth passed with no metadata.
 */
export interface AuthCheckResult {
  error?: string;
  subjectId?: string;
  rateLimitRpm?: number | null;
}

/**
 * Optional auth check function. Return null/undefined if auth passes,
 * a string error message to reject with 401, or an AuthCheckResult object.
 */
export type AuthCheckFn = (req: IncomingMessage) => string | AuthCheckResult | undefined | null;

/**
 * HttpRelay manages:
 *  - Running a local HTTP server that accepts JSON-RPC POST requests
 *  - Forwarding allowed requests to a remote MCP server via fetch()
 *  - Streaming SSE responses back when the remote uses text/event-stream
 *
 * The interceptor hooks into request/response events to inspect,
 * allow, deny, or modify messages before they are forwarded.
 */
export class HttpRelay extends EventEmitter {
  private server: Server | null = null;
  private port: number;
  private targetUrl: string;
  private pending: Map<string, PendingRequest> = new Map();
  private requestCounter = 0;
  private authCheck: AuthCheckFn | null = null;

  constructor(port: number, targetUrl: string, authCheck?: AuthCheckFn) {
    super();
    this.port = port;
    this.targetUrl = targetUrl;
    this.authCheck = authCheck ?? null;
  }

  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = createServer((req, res) => {
        this.handleRequest(req, res);
      });

      this.server.on("error", (err) => {
        this.emit("error", err);
        reject(err);
      });

      this.server.listen(this.port, () => {
        resolve();
      });
    });
  }

  stop(): void {
    this.server?.close();
  }

  /**
   * Send a deny response back to the HTTP client for a given pending request.
   */
  respondToClient(requestKey: string, body: string): void {
    const pending = this.pending.get(requestKey);
    if (!pending) return;
    this.pending.delete(requestKey);

    pending.res.writeHead(200, { "Content-Type": "application/json" });
    pending.res.end(body);
  }

  /**
   * Send a response with a custom HTTP status code and headers.
   */
  respondWithStatus(requestKey: string, statusCode: number, headers: Record<string, string>, body: string): void {
    const pending = this.pending.get(requestKey);
    if (!pending) return;
    this.pending.delete(requestKey);

    pending.res.writeHead(statusCode, { "Content-Type": "application/json", ...headers });
    pending.res.end(body);
  }

  /**
   * Forward the original request to the remote MCP server and relay the response.
   */
  async forwardToRemote(requestKey: string): Promise<void> {
    const pending = this.pending.get(requestKey);
    if (!pending) return;
    this.pending.delete(requestKey);

    try {
      // Forward relevant headers from the original request to the remote server
      const forwardHeaders: Record<string, string> = {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
      };
      if (pending.headers.authorization) {
        forwardHeaders["Authorization"] = pending.headers.authorization;
      }

      const remoteRes = await fetch(this.targetUrl, {
        method: "POST",
        headers: forwardHeaders,
        body: pending.body,
      });

      const contentType = remoteRes.headers.get("content-type") ?? "";

      if (contentType.includes("text/event-stream") && remoteRes.body) {
        // SSE streaming — relay each event back to the client
        pending.res.writeHead(remoteRes.status, {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
        });

        const reader = remoteRes.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            const chunk = decoder.decode(value, { stream: true });
            buffer += chunk;
            pending.res.write(chunk);

            // Extract complete SSE data lines for logging
            const lines = buffer.split("\n");
            buffer = lines.pop() ?? "";
            for (const line of lines) {
              if (line.startsWith("data: ")) {
                const data = line.slice(6).trim();
                if (data) {
                  this.emit("response", data);
                }
              }
            }
          }
        } finally {
          // Flush remaining buffer
          if (buffer.startsWith("data: ")) {
            const data = buffer.slice(6).trim();
            if (data) {
              this.emit("response", data);
            }
          }
          pending.res.end();
        }
      } else {
        // Standard JSON response
        const responseBody = await remoteRes.text();
        this.emit("response", responseBody);

        pending.res.writeHead(remoteRes.status, {
          "Content-Type": contentType || "application/json",
        });
        pending.res.end(responseBody);
      }
    } catch (err) {
      const errorBody = JSON.stringify({
        jsonrpc: "2.0",
        id: null,
        error: {
          code: -32603,
          message: `Quint: failed to reach remote server: ${(err as Error).message}`,
        },
      });
      this.emit("response", errorBody);
      pending.res.writeHead(502, { "Content-Type": "application/json" });
      pending.res.end(errorBody);
    }
  }

  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
    // Only handle POST requests
    if (req.method !== "POST") {
      res.writeHead(405, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Method not allowed. Use POST." }));
      return;
    }

    // CORS preflight support
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    // Auth check (if configured)
    let authSubjectId = "anonymous";
    if (this.authCheck) {
      const authResult = this.authCheck(req);
      const authError = typeof authResult === "string"
        ? authResult
        : authResult?.error ?? null;
      if (authError) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32600, message: authError },
        }));
        return;
      }
      if (typeof authResult === "object" && authResult) {
        if (authResult.subjectId) authSubjectId = authResult.subjectId;
      }
    }

    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf-8");
      const requestKey = String(++this.requestCounter);

      // Capture headers to forward to remote server
      const headers: Record<string, string> = {};
      for (const key of ["authorization", "content-type", "accept"]) {
        const val = req.headers[key];
        if (typeof val === "string") headers[key] = val;
      }

      this.pending.set(requestKey, { res, body, headers, subjectId: authSubjectId });

      // Emit the request for the interceptor to inspect.
      // The interceptor will call respondToClient() for denials
      // or forwardToRemote() for allowed requests.
      // Third argument is the authenticated subject ID (for rate limiting).
      this.emit("request", body, requestKey, authSubjectId);
    });

    req.on("error", (err) => {
      this.emit("error", err);
    });
  }
}
