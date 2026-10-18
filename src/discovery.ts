import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import {
  analyzeServer,
  analyzeArchitecture,
} from "./engine/rules.js";
import type {
  ToolDefinition,
  ServerDefinition,
  AgentArchitecture,
  AnalysisResult,
} from "./engine/rules.js";
import { assertCommandDiscoveryAllowed, assertUrlAllowed } from "./governance/policy.js";
import { VERSION } from "./version.js";

// ── Shared Helpers ──────────────────────────────────────────────────

const CONNECT_TIMEOUT = 30_000;

/** Convert Git-Bash / MSYS2 POSIX paths (e.g. /c/Users/…) to Windows paths. */
function normalizeCwd(cwd: string): string {
  if (process.platform === "win32") {
    const m = /^\/([a-zA-Z])(\/.*)?$/.exec(cwd);
    if (m) {
      const drive = m[1]!.toUpperCase();
      const rest = (m[2] ?? "/").replace(/\//g, "\\");
      return `${drive}:${rest}`;
    }
  }
  return cwd;
}

interface DiscoveredServer {
  name: string;
  transport: string;
  tools: ToolDefinition[];
  serverInfo: { name: string; version: string } | undefined;
}

async function discoverViaClient(
  client: Client,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  transport: any,
): Promise<DiscoveredServer> {
  const timeout = AbortSignal.timeout(CONNECT_TIMEOUT);
  await client.connect(transport, { signal: timeout });

  const serverInfo = client.getServerVersion();
  const { tools } = await client.listTools();

  const mapped: ToolDefinition[] = tools.map((t) => ({
    name: t.name,
    description: t.description ?? "",
    inputSchema: t.inputSchema as Record<string, unknown> | undefined,
    annotations: t.annotations as Record<string, unknown> | undefined,
  }));

  const name = serverInfo?.name ?? "unknown-server";

  await client.close();

  return {
    name,
    transport: "unknown",
    tools: mapped,
    serverInfo: serverInfo ? { name: serverInfo.name, version: serverInfo.version } : undefined,
  };
}

function buildServerDef(
  discovered: DiscoveredServer,
  overrides: Partial<ServerDefinition>,
): ServerDefinition {
  return {
    name: discovered.name,
    transport: discovered.transport,
    tools: discovered.tools,
    ...overrides,
  };
}

// ── Discover via Stdio ──────────────────────────────────────────────

export interface StdioDiscoveryInput {
  command: string;
  args?: string[] | undefined;
  env?: Record<string, string> | undefined;
  cwd?: string | undefined;
}

export interface DiscoveryResult {
  discovered: {
    serverName: string;
    serverVersion: string | undefined;
    toolCount: number;
    tools: ToolDefinition[];
  };
  analysis: AnalysisResult;
}

export async function discoverAndAnalyzeStdio(
  input: StdioDiscoveryInput,
): Promise<DiscoveryResult> {
  assertCommandDiscoveryAllowed();
  const client = new Client({ name: "saf-mcp-discovery", version: VERSION });
  const stdioParams: Record<string, unknown> = { command: input.command, stderr: "pipe" };
  if (input.args) stdioParams.args = input.args;
  if (input.env) stdioParams.env = input.env;
  if (input.cwd) stdioParams.cwd = normalizeCwd(input.cwd);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const transport = new StdioClientTransport(stdioParams as any);

  const discovered = await discoverViaClient(client, transport);
  discovered.transport = "stdio";

  const serverDef = buildServerDef(discovered, { transport: "stdio" });
  const analysis = analyzeServer(serverDef);

  return {
    discovered: {
      serverName: discovered.name,
      serverVersion: discovered.serverInfo?.version,
      toolCount: discovered.tools.length,
      tools: discovered.tools,
    },
    analysis,
  };
}

// ── Discover via HTTP / SSE ─────────────────────────────────────────

export interface HttpDiscoveryInput {
  url: string;
  headers?: Record<string, string> | undefined;
}

export async function discoverAndAnalyzeHttp(
  input: HttpDiscoveryInput,
): Promise<DiscoveryResult> {
  const url = await assertUrlAllowed(input.url);
  const client = new Client({ name: "saf-mcp-discovery", version: VERSION });

  const opts = input.headers
    ? { requestInit: { headers: input.headers } }
    : undefined;

  // Try StreamableHTTP first, fall back to SSE
  let discovered: DiscoveredServer;
  try {
    const transport = opts
      ? new StreamableHTTPClientTransport(url, opts)
      : new StreamableHTTPClientTransport(url);
    discovered = await discoverViaClient(client, transport);
    discovered.transport = "http";
  } catch {
    const sseClient = new Client({ name: "saf-mcp-discovery", version: VERSION });
    const sseTransport = opts
      ? new SSEClientTransport(url, opts)
      : new SSEClientTransport(url);
    discovered = await discoverViaClient(sseClient, sseTransport);
    discovered.transport = "sse";
  }

  const serverDef = buildServerDef(discovered, {
    transport: discovered.transport,
    exposedEndpoints: [input.url],
  });
  const analysis = analyzeServer(serverDef);

  return {
    discovered: {
      serverName: discovered.name,
      serverVersion: discovered.serverInfo?.version,
      toolCount: discovered.tools.length,
      tools: discovered.tools,
    },
    analysis,
  };
}

// ── Discover via Config File ────────────────────────────────────────

interface McpServerConfig {
  command?: string | undefined;
  args?: string[] | undefined;
  env?: Record<string, string> | undefined;
  url?: string | undefined;
}

interface McpConfigFile {
  mcpServers?: Record<string, McpServerConfig> | undefined;
  mcp?: { servers?: Record<string, McpServerConfig> | undefined } | undefined;
}

export interface ConfigDiscoveryInput {
  configJson: string;
}

export interface ConfigDiscoveryResult {
  discovered: {
    serversFound: number;
    servers: Array<{
      configName: string;
      serverName: string;
      serverVersion: string | undefined;
      toolCount: number;
      tools: ToolDefinition[];
      transport: string;
      error: string | undefined;
    }>;
  };
  analysis: AnalysisResult;
}

export async function discoverAndAnalyzeConfig(
  input: ConfigDiscoveryInput,
): Promise<ConfigDiscoveryResult> {
  const config = JSON.parse(input.configJson) as McpConfigFile;

  // Support both { mcpServers: {...} } (Claude Desktop) and { mcp: { servers: {...} } } (VS Code)
  const serverEntries =
    config.mcpServers ?? config.mcp?.servers ?? {};

  const discoveredServers: ConfigDiscoveryResult["discovered"]["servers"] = [];
  const serverDefs: ServerDefinition[] = [];

  for (const [configName, entry] of Object.entries(serverEntries)) {
    try {
      let discovered: DiscoveredServer;

      if (entry.url) {
        // HTTP/SSE server
        const url = await assertUrlAllowed(entry.url);
        const client = new Client({ name: "saf-mcp-discovery", version: VERSION });
        try {
          const transport = new StreamableHTTPClientTransport(url);
          discovered = await discoverViaClient(client, transport);
          discovered.transport = "http";
        } catch {
          const sseClient = new Client({ name: "saf-mcp-discovery", version: VERSION });
          const sseTransport = new SSEClientTransport(url);
          discovered = await discoverViaClient(sseClient, sseTransport);
          discovered.transport = "sse";
        }

        serverDefs.push(
          buildServerDef(discovered, {
            // Label servers by their config key: unique, and the name the user knows.
            name: configName,
            transport: discovered.transport,
            exposedEndpoints: [entry.url],
          }),
        );
      } else if (entry.command) {
        // Stdio server: spawns a process, so it obeys the command discovery policy
        assertCommandDiscoveryAllowed();
        const client = new Client({ name: "saf-mcp-discovery", version: VERSION });
        const stdParams: Record<string, unknown> = { command: entry.command, stderr: "pipe" };
        if (entry.args) stdParams.args = entry.args;
        if (entry.env) stdParams.env = entry.env;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const transport = new StdioClientTransport(stdParams as any);
        discovered = await discoverViaClient(client, transport);
        discovered.transport = "stdio";

        serverDefs.push(buildServerDef(discovered, { name: configName, transport: "stdio" }));
      } else {
        discoveredServers.push({
          configName,
          serverName: configName,
          serverVersion: undefined,
          toolCount: 0,
          tools: [],
          transport: "unknown",
          error: "No command or url specified in config entry",
        });
        continue;
      }

      discoveredServers.push({
        configName,
        serverName: discovered.name,
        serverVersion: discovered.serverInfo?.version,
        toolCount: discovered.tools.length,
        tools: discovered.tools,
        transport: discovered.transport,
        error: undefined,
      });
    } catch (err) {
      discoveredServers.push({
        configName,
        serverName: configName,
        serverVersion: undefined,
        toolCount: 0,
        tools: [],
        transport: entry.url ? "http" : "stdio",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  const architecture: AgentArchitecture = {
    name: "config-discovered",
    // One client config is one agent using several servers, not several agents.
    servers: serverDefs,
  };

  const analysis = analyzeArchitecture(architecture);

  return {
    discovered: {
      serversFound: Object.keys(serverEntries).length,
      servers: discoveredServers,
    },
    analysis,
  };
}
