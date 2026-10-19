import { analyzeConfig } from "./config.js";
import { describeTechnique, getCoverageSummary } from "./engine/coverage.js";
import type {
  ToolDefinition,
  ServerDefinition,
  AgentArchitecture,
  AnalysisResult,
} from "./engine/rules.js";
import {
  analyzeArchitecture,
  analyzeTool,
  analyzeServer,
} from "./engine/rules.js";
import {
  getTechnique,
  getMitigation,
  getThreatProfile,
  searchTechniques,
  searchMitigations,
  getMitigationsForTechnique,
  getTechniquesForMitigation,
  getUnmitigatedTechniques,
  rankMitigationsByImpact,
  getFrameworkStats,
} from "./engine/analyze.js";

// ── OpenAI Function-Calling Definitions ─────────────────────────────
// These conform to the OpenAI Chat Completions "tools" format and work
// with OpenAI SDK, Azure OpenAI, Semantic Kernel, and LangChain.

export const openAiFunctions = [
  {
    type: "function" as const,
    function: {
      name: "analyze_architecture",
      description: "Run a full SAF-MCP security analysis on an agent architecture definition. Returns risk summary, findings (matched techniques), and recommended mitigations.",
      parameters: {
        type: "object",
        properties: {
          architecture: {
            type: "object",
            description: "Agent architecture to analyze",
            properties: {
              name: { type: "string" },
              servers: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    name: { type: "string" },
                    transport: { type: "string", enum: ["stdio", "sse", "http", "websocket"] },
                    authentication: { type: "string" },
                    tools: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          name: { type: "string" },
                          description: { type: "string" },
                        },
                        required: ["name", "description"],
                      },
                    },
                    exposedEndpoints: { type: "array", items: { type: "string" } },
                    oauthConfig: {
                      type: "object",
                      properties: {
                        scopes: { type: "array", items: { type: "string" } },
                        callbackUrls: { type: "array", items: { type: "string" } },
                        authorizationServer: { type: "string" },
                      },
                    },
                  },
                  required: ["name"],
                },
              },
              tools: {
                type: "array",
                items: {
                  type: "object",
                  properties: { name: { type: "string" }, description: { type: "string" } },
                  required: ["name", "description"],
                },
              },
              multiAgent: { type: "boolean" },
              sharedMemory: { type: "boolean" },
              vectorStore: { type: "boolean" },
              ragPipeline: { type: "boolean" },
              multimodal: { type: "boolean" },
              cliAccess: { type: "boolean" },
              fileSystemAccess: { type: "boolean" },
              networkAccess: { type: "boolean" },
              oauthFlows: { type: "boolean" },
            },
          },
        },
        required: ["architecture"],
      },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "analyze_tool",
      description: "Analyze a single MCP tool definition for SAF-MCP security risks.",
      parameters: {
        type: "object",
        properties: {
          tool: {
            type: "object",
            properties: { name: { type: "string" }, description: { type: "string" } },
            required: ["name", "description"],
          },
        },
        required: ["tool"],
      },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "analyze_server",
      description: "Analyze an MCP server definition (with its tools) for security risks.",
      parameters: {
        type: "object",
        properties: {
          server: {
            type: "object",
            properties: {
              name: { type: "string" },
              transport: { type: "string" },
              authentication: { type: "string" },
              tools: {
                type: "array",
                items: {
                  type: "object",
                  properties: { name: { type: "string" }, description: { type: "string" } },
                  required: ["name", "description"],
                },
              },
              exposedEndpoints: { type: "array", items: { type: "string" } },
            },
            required: ["name"],
          },
        },
        required: ["server"],
      },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "get_technique",
      description: "Retrieve full details for a SAF-MCP technique by ID (e.g., SAFE-T1001).",
      parameters: {
        type: "object",
        properties: { id: { type: "string", description: "Technique ID such as SAFE-T1001" } },
        required: ["id"],
      },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "get_mitigation",
      description: "Retrieve full details for a SAF-MCP mitigation by ID (e.g., SAFE-M-1).",
      parameters: {
        type: "object",
        properties: { id: { type: "string", description: "Mitigation ID such as SAFE-M-1" } },
        required: ["id"],
      },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "search_techniques",
      description: "Search SAF-MCP techniques by keyword (matches ID, name, description).",
      parameters: {
        type: "object",
        properties: { query: { type: "string", description: "Search keyword" } },
        required: ["query"],
      },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "search_mitigations",
      description: "Search SAF-MCP mitigations by keyword (matches ID, name, description).",
      parameters: {
        type: "object",
        properties: { query: { type: "string", description: "Search keyword" } },
        required: ["query"],
      },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "get_mitigations_for_technique",
      description: "Given a technique ID, return all mitigations that address it.",
      parameters: {
        type: "object",
        properties: { techniqueId: { type: "string", description: "Technique ID" } },
        required: ["techniqueId"],
      },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "get_techniques_for_mitigation",
      description: "Given a mitigation ID, return all techniques it addresses.",
      parameters: {
        type: "object",
        properties: { mitigationId: { type: "string", description: "Mitigation ID" } },
        required: ["mitigationId"],
      },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "get_threat_profile",
      description: "Return a high-level SAF-MCP threat profile: severity distribution, unmitigated techniques, critical techniques, and overall mitigation coverage.",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "get_unmitigated_techniques",
      description: "List all SAF-MCP techniques that currently have no known mitigations.",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "rank_mitigations",
      description: "Rank all mitigations by the number and severity of techniques they address.",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "get_framework_stats",
      description: "Return SAF-MCP framework metadata: totals, tactic distribution, mitigation category distribution, and implementation guidance.",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "analyze_config",
      description:
        "Analyze an MCP client config (Claude Desktop or VS Code) without starting any server: unpinned packages and images, containers with host access, plaintext secrets, lookalike server names.",
      parameters: {
        type: "object",
        properties: { configJson: { type: "string", description: "The config file contents as a JSON string" } },
        required: ["configJson"],
      },
    },
  },
];

// ── Dispatcher ──────────────────────────────────────────────────────
// Call this from your OpenAI/SK tool_call handler to dispatch function
// calls to the engine. Returns the JSON string result.

export function dispatch(name: string, args: Record<string, unknown>): string {
  switch (name) {
    case "analyze_architecture":
      return JSON.stringify(analyzeArchitecture(args["architecture"] as AgentArchitecture));
    case "analyze_config":
      return JSON.stringify(analyzeConfig(args["configJson"] as string));
    case "analyze_tool":
      return JSON.stringify(analyzeTool(args["tool"] as ToolDefinition));
    case "analyze_server":
      return JSON.stringify(analyzeServer(args["server"] as ServerDefinition));
    case "get_technique": {
      const t = describeTechnique(args["id"] as string);
      return t ? JSON.stringify(t) : JSON.stringify({ error: "Technique not found" });
    }
    case "get_mitigation": {
      const m = getMitigation(args["id"] as string);
      return m ? JSON.stringify(m) : JSON.stringify({ error: "Mitigation not found" });
    }
    case "search_techniques":
      return JSON.stringify(searchTechniques(args["query"] as string));
    case "search_mitigations":
      return JSON.stringify(searchMitigations(args["query"] as string));
    case "get_mitigations_for_technique":
      return JSON.stringify(getMitigationsForTechnique(args["techniqueId"] as string));
    case "get_techniques_for_mitigation":
      return JSON.stringify(getTechniquesForMitigation(args["mitigationId"] as string));
    case "get_threat_profile":
      return JSON.stringify(getThreatProfile());
    case "get_unmitigated_techniques":
      return JSON.stringify(getUnmitigatedTechniques());
    case "rank_mitigations":
      return JSON.stringify(rankMitigationsByImpact().slice(0, 20));
    case "get_framework_stats":
      return JSON.stringify({ ...getFrameworkStats(), coverage: getCoverageSummary() });
    default:
      return JSON.stringify({ error: `Unknown function: ${name}` });
  }
}
