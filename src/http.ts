import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createServer as createMcpServer } from "./server.js";
import { info, warn, error as logError, audit } from "./governance/logger.js";
import { checkAccess, getClientIp } from "./governance/access.js";
import { setNetworkMode, enforceStartupPolicy, checkBrowserSafety } from "./governance/policy.js";

const PORT = parseInt(process.env["PORT"] ?? "3001", 10);
const HOST = process.env["HOST"] ?? "127.0.0.1";
const API_VERSION = "v1";

setNetworkMode(HOST);
try {
  enforceStartupPolicy(HOST);
} catch (err) {
  console.error(`Refusing to start: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}

const transports = new Map<string, StreamableHTTPServerTransport>();

function json(res: import("node:http").ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

const httpServer = createServer(async (req, res) => {
  const clientIp = getClientIp(req);
  const start = performance.now();

  // ── Browser and DNS rebinding protection ────────────────────────
  const browser = checkBrowserSafety(req);
  if (!browser.allowed) {
    json(res, browser.reason?.startsWith("Content-Type") ? 415 : 403, { error: browser.reason });
    return;
  }

  // ── Health (no auth required) ───────────────────────────────────
  if (req.method === "GET" && (req.url === "/health" || req.url === `/${API_VERSION}/health`)) {
    json(res, 200, {
      status: "ok",
      name: "safe-mcp-skill",
      version: "1.0.0",
      apiVersion: API_VERSION,
    });
    return;
  }

  // ── Version info (no auth required) ─────────────────────────────
  if (req.method === "GET" && req.url === "/version") {
    json(res, 200, {
      name: "safe-mcp-skill",
      version: "1.0.0",
      apiVersion: API_VERSION,
      framework: "SAFE-MCP",
    });
    return;
  }

  // ── Access control ──────────────────────────────────────────────
  const access = checkAccess(req);
  if (!access.allowed) {
    json(res, 403, { error: access.reason });
    return;
  }

  // ── Versioned + unversioned MCP endpoint ────────────────────────
  const mcpPaths = ["/mcp", `/${API_VERSION}/mcp`];
  const url = req.url?.split("?")[0];
  if (url && mcpPaths.includes(url)) {
    try {
      if (req.method === "POST") {
        const chunks: Buffer[] = [];
        for await (const chunk of req) {
          chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
        }
        const body = JSON.parse(Buffer.concat(chunks).toString("utf-8")) as unknown;

        const sessionId = req.headers["mcp-session-id"] as string | undefined;
        let transport = sessionId ? transports.get(sessionId) : undefined;

        if (!transport) {
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: (id) => {
              info("session_created", { sessionId: id, clientIp });
              transports.set(id, transport!);
            },
          });
          const srv = createMcpServer();
          await srv.connect(transport as unknown as Transport);
        }

        await transport.handleRequest(req, res, body);
        audit("http_request", {
          clientIp,
          detail: { method: "POST", path: url, sessionId, durationMs: Math.round(performance.now() - start) },
        });
        return;
      }

      if (req.method === "GET" || req.method === "DELETE") {
        const sessionId = req.headers["mcp-session-id"] as string | undefined;
        const transport = sessionId ? transports.get(sessionId) : undefined;
        if (!transport) {
          json(res, 400, { error: "No active session" });
          return;
        }
        if (req.method === "DELETE") {
          info("session_closed", { sessionId, clientIp });
        }
        await transport.handleRequest(req, res);
        return;
      }

      res.writeHead(405).end();
      return;
    } catch (err) {
      logError("http_error", { clientIp, detail: err instanceof Error ? err.message : String(err) });
      json(res, 500, { error: "Internal server error" });
      return;
    }
  }

  json(res, 404, { error: "Not found", availableEndpoints: [`/${API_VERSION}/mcp`, "/health", "/version"] });
});

httpServer.listen(PORT, HOST, () => {
  info("server_started", { detail: { host: HOST, port: PORT, apiVersion: API_VERSION } });
  console.error(`SAFE-MCP Skill ${API_VERSION} listening on http://${HOST}:${PORT}/${API_VERSION}/mcp`);
  console.error(`Health: http://${HOST}:${PORT}/health | Version: http://${HOST}:${PORT}/version`);
});
