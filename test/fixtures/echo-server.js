#!/usr/bin/env node
// Tiny HTTP server that echoes back request headers as a JSON-RPC response.
// Usage: node echo-server.js [port]

const http = require("node:http");
const port = parseInt(process.argv[2] || "0", 10);

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks).toString("utf-8");
    let parsed;
    try { parsed = JSON.parse(body); } catch { parsed = null; }

    const response = {
      jsonrpc: "2.0",
      id: parsed?.id ?? null,
      result: {
        echo: true,
        method: parsed?.method ?? "unknown",
        receivedHeaders: req.headers,
        hasAuthorization: !!req.headers.authorization,
        authorizationPreview: req.headers.authorization
          ? req.headers.authorization.substring(0, 20) + "..."
          : null,
      },
    };

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(response, null, 2));
  });
});

server.listen(port, () => {
  const addr = server.address();
  console.log(addr.port);
  console.error(`Echo server listening on http://localhost:${addr.port}`);
});
