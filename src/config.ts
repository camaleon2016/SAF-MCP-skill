/**
 * Static analysis of MCP client configs (Claude Desktop, VS Code).
 *
 * Unlike discovery, this starts nothing and connects to nothing: it reads the
 * config and checks how each server would be launched. Tools are not known,
 * so tool level rules stay quiet; launch, container, secret, and naming rules
 * apply. Environment values and arguments are never echoed back, because they
 * often hold secrets.
 */
import { analyzeArchitecture, type AgentArchitecture, type AnalysisResult, type ServerDefinition } from "./engine/rules.js";

export interface ClientConfigEntry {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  type?: string;
  headers?: Record<string, string>;
}

export interface ConfigAnalysisResult {
  servers: Array<{
    configName: string;
    transport: string;
    command?: string | undefined;
    url?: string | undefined;
    envVars: number;
  }>;
  analysis: AnalysisResult;
}

/** Server entries from any of the config shapes in use. */
export function parseClientConfig(config: string | Record<string, unknown>): Record<string, ClientConfigEntry> {
  let parsed: unknown = config;
  if (typeof config === "string") {
    try {
      parsed = JSON.parse(config);
    } catch {
      throw new Error("The config is not valid JSON.");
    }
  }
  if (!parsed || typeof parsed !== "object") throw new Error("The config must be a JSON object.");
  const root = parsed as Record<string, unknown>;
  const mcp = root["mcp"] as Record<string, unknown> | undefined;
  const entries = (root["mcpServers"] ?? mcp?.["servers"] ?? root["servers"]) as Record<string, ClientConfigEntry> | undefined;
  if (!entries || typeof entries !== "object") {
    throw new Error('No servers found. Expected "mcpServers" (Claude Desktop), "mcp.servers" (VS Code settings), or "servers" (VS Code mcp.json).');
  }
  return entries;
}

const AUTH_HEADER = /^(authorization|x-api-key|api-key|x-auth-token)$/i;

/** One server definition per config entry, labeled by its config key. */
export function serversFromConfig(entries: Record<string, ClientConfigEntry>): ServerDefinition[] {
  return Object.entries(entries).map(([name, e]) => {
    if (e.url) {
      const hasAuthHeader = Object.keys(e.headers ?? {}).some((h) => AUTH_HEADER.test(h));
      return {
        name,
        transport: e.type === "sse" ? "sse" : "http",
        // A remote server's auth usually lives in the client's OAuth flow, not the file.
        authentication: hasAuthHeader ? "token" : "unknown",
        exposedEndpoints: [e.url],
      };
    }
    return {
      name,
      transport: "stdio",
      ...(e.command ? { launch: { command: e.command, args: e.args ?? [], env: e.env ?? {} } } : {}),
    };
  });
}

export function analyzeConfig(config: string | Record<string, unknown>): ConfigAnalysisResult {
  const entries = parseClientConfig(config);
  const servers = serversFromConfig(entries);
  const architecture: AgentArchitecture = { name: "client-config", servers };
  return {
    servers: Object.entries(entries).map(([configName, e]) => ({
      configName,
      transport: e.url ? (e.type === "sse" ? "sse" : "http") : "stdio",
      command: e.command,
      url: e.url,
      envVars: Object.keys(e.env ?? {}).length,
    })),
    analysis: analyzeArchitecture(architecture),
  };
}
