import type { Technique, Mitigation, Severity } from "../types.js";
import type { FrameworkMappings } from "../mappings/index.js";
import { getMappings, getCoverage } from "../mappings/index.js";
import type { FrameworkCoverage } from "../mappings/index.js";
import {
  getTechnique,
  getMitigation,
  getMitigationsForTechnique,
  listTechniques,
} from "./analyze.js";

// ── Input Types ─────────────────────────────────────────────────────

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema?: Record<string, unknown> | undefined;
  annotations?: Record<string, unknown> | undefined;
  parameters?: Record<string, unknown> | undefined;
}

export interface ServerDefinition {
  name: string;
  transport?: string | undefined;
  authentication?: string | undefined;
  tools?: ToolDefinition[] | undefined;
  permissions?: string[] | undefined;
  exposedEndpoints?: string[] | undefined;
  oauthConfig?: {
    scopes?: string[] | undefined;
    callbackUrls?: string[] | undefined;
    authorizationServer?: string | undefined;
  } | undefined;
}

export interface AgentArchitecture {
  name?: string | undefined;
  servers?: ServerDefinition[] | undefined;
  tools?: ToolDefinition[] | undefined;
  multiAgent?: boolean | undefined;
  sharedMemory?: boolean | undefined;
  vectorStore?: boolean | undefined;
  ragPipeline?: boolean | undefined;
  multimodal?: boolean | undefined;
  cliAccess?: boolean | undefined;
  fileSystemAccess?: boolean | undefined;
  networkAccess?: boolean | undefined;
  oauthFlows?: boolean | undefined;
}

// ── Output Types ────────────────────────────────────────────────────

export interface Finding {
  ruleId: string;
  severity: Severity;
  technique: { id: string; name: string };
  description: string;
  evidence: string;
  mitigations: { id: string; name: string; effectiveness: string }[];
  mappings: FrameworkMappings;
}

export interface RiskSummary {
  overallRisk: Severity;
  totalFindings: number;
  bySeverity: Record<string, number>;
  coverageScore: number;
}

export interface AnalysisResult {
  timestamp: string;
  target: string;
  summary: RiskSummary;
  findings: Finding[];
  frameworkCoverage: FrameworkCoverage[];
}

// ── Rule Definitions ────────────────────────────────────────────────

interface Rule {
  id: string;
  techniqueId: string;
  test: (input: AgentArchitecture) => string | null;
}

const EFFECTIVENESS_RANK: Record<string, number> = {
  "High (Provable Security)": 0,
  High: 1,
  "Medium-High": 2,
  Medium: 3,
};

/** Strongest controls first, then by mitigation number, so the top of the list is what to do first. */
function sortByEffectiveness(list: Mitigation[]): Mitigation[] {
  const num = (id: string): number => Number(id.split("-").pop());
  return [...list].sort(
    (a, b) =>
      (EFFECTIVENESS_RANK[a.effectiveness] ?? 9) - (EFFECTIVENESS_RANK[b.effectiveness] ?? 9) || num(a.id) - num(b.id),
  );
}

function buildFinding(rule: Rule, evidence: string): Finding | null {
  const technique = getTechnique(rule.techniqueId);
  if (!technique) return null;

  const mitigations = sortByEffectiveness(getMitigationsForTechnique(rule.techniqueId)).map((m) => ({
    id: m.id,
    name: m.name,
    effectiveness: m.effectiveness,
  }));

  return {
    ruleId: rule.id,
    severity: technique.severity,
    technique: { id: technique.id, name: technique.name },
    description: technique.description,
    evidence,
    mitigations,
    mappings: getMappings(rule.techniqueId),
  };
}

// ── Pattern Detectors ───────────────────────────────────────────────

const INJECTION_PATTERNS = [
  /ignore\s+(previous|above|all)\s+instructions/i,
  /system\s*:\s*/i,
  /\bdo\s+not\s+(reveal|show|display)/i,
  /\bexecute\s+(this|the\s+following)\b/i,
  /\boverride\b.*\binstructions?\b/i,
  /\bact\s+as\b/i,
  /\bpretend\s+(you are|to be)\b/i,
  /\byou\s+are\s+now\b/i,
  /\bnew\s+instructions?\b/i,
  /\bforget\s+(everything|all|your)\b/i,
  /\bdisregard\b.*\b(above|previous|prior)\b/i,
];

const UNICODE_PATTERNS = [
  /\u200B|\u200C|\u200D|\u2060|\uFEFF/,         // zero-width
  /[\u202A-\u202E]/,                              // bidi overrides
  /[\uE000-\uF8FF]/,                              // PUA
  /[\u2066-\u2069]/,                              // bidi isolates
  /[\u00AD]/,                                     // soft hyphen
  /[\u180E]/,                                     // Mongolian vowel separator
  /[\u2028\u2029]/,                               // line/paragraph separator
];

const CODE_EXEC_PATTERNS = [
  /\bsudo\b|\brm\s+-rf\b|\bchmod\s+777\b/i,
  /\beval\s*\(/i,
  /\bexec\s*\(/i,
  /\bchild_process\b/i,
  /\bFunction\s*\(/i,
  /\bimport\s*\(/i,
  /\brequire\s*\(/i,
  /\b__import__\b/i,
  /\bos\.system\b/i,
  /\bsubprocess\b/i,
];

const MARKUP_PATTERNS = [
  /<!--[\s\S]*?-->/,                              // HTML comments
  /<script[\s\S]*?>/i,                            // script tags
  /<img[^>]+onerror/i,                            // XSS via img
  /\]\([^)]*javascript:/i,                        // markdown JS
  /data:text\/html/i,                             // data URI
];

const TRAVERSAL_PATTERNS = [
  /\.\.\/|\.\.\\/, // path traversal
  /%2e%2e/i,       // encoded traversal
  /\.\.%2f/i,      // mixed encoding
];

const SUSPICIOUS_PATTERNS = [
  ...INJECTION_PATTERNS,
  ...UNICODE_PATTERNS,
  ...CODE_EXEC_PATTERNS,
  ...MARKUP_PATTERNS,
  ...TRAVERSAL_PATTERNS,
];

function scanText(text: string): string[] {
  const hits: string[] = [];
  for (const pattern of SUSPICIOUS_PATTERNS) {
    if (pattern.test(text)) {
      hits.push(pattern.source);
    }
  }
  return hits;
}

function scanToolDescriptions(tools: ToolDefinition[]): Map<string, string[]> {
  const results = new Map<string, string[]>();
  for (const tool of tools) {
    const hits = scanText(tool.description);
    if (hits.length > 0) {
      results.set(tool.name, hits);
    }
  }
  return results;
}

// ── Rules ───────────────────────────────────────────────────────────

const rules: Rule[] = [
  // Tool Poisoning — suspicious content in descriptions
  {
    id: "RULE-001",
    techniqueId: "SAFE-T1001",
    test(input) {
      const tools = allTools(input);
      if (tools.length === 0) return null;
      const hits = scanToolDescriptions(tools);
      if (hits.size === 0) return null;
      const details = [...hits.entries()]
        .map(([name, patterns]) => `${name}: ${patterns.join(", ")}`)
        .join("; ");
      return `Suspicious patterns in tool descriptions — ${details}`;
    },
  },

  // Supply Chain — tools from unverified servers
  {
    id: "RULE-002",
    techniqueId: "SAFE-T1002",
    test(input) {
      const servers = input.servers ?? [];
      const unverified = servers.filter(
        (s) => !s.authentication || s.authentication === "none",
      );
      if (unverified.length === 0) return null;
      return `${unverified.length} server(s) without authentication: ${unverified.map((s) => s.name).join(", ")}`;
    },
  },

  // Exposed Endpoints
  {
    id: "RULE-003",
    techniqueId: "SAFE-T1005",
    test(input) {
      const servers = input.servers ?? [];
      const exposed = servers.filter(
        (s) =>
          s.exposedEndpoints && s.exposedEndpoints.length > 0 &&
          (!s.authentication || s.authentication === "none"),
      );
      if (exposed.length === 0) return null;
      return `Unauthenticated exposed endpoints on: ${exposed.map((s) => s.name).join(", ")}`;
    },
  },

  // OAuth Phishing
  {
    id: "RULE-004",
    techniqueId: "SAFE-T1007",
    test(input) {
      if (!input.oauthFlows) return null;
      const servers = input.servers ?? [];
      const oauthServers = servers.filter((s) => s.oauthConfig);
      if (oauthServers.length === 0 && input.oauthFlows) {
        return "OAuth flows enabled but no server-level OAuth configuration found — verify authorization server trust";
      }
      const broadScope = oauthServers.filter(
        (s) => s.oauthConfig?.scopes && s.oauthConfig.scopes.length > 5,
      );
      if (broadScope.length > 0) {
        return `Broad OAuth scopes on: ${broadScope.map((s) => s.name).join(", ")}`;
      }
      return null;
    },
  },

  // Tool Shadowing — duplicate tool names across servers
  {
    id: "RULE-005",
    techniqueId: "SAFE-T1008",
    test(input) {
      const servers = input.servers ?? [];
      if (servers.length < 2) return null;
      const seen = new Map<string, string>();
      const duplicates: string[] = [];
      for (const server of servers) {
        for (const tool of server.tools ?? []) {
          const prev = seen.get(tool.name);
          if (prev && prev !== server.name) {
            duplicates.push(`"${tool.name}" on ${prev} and ${server.name}`);
          }
          seen.set(tool.name, server.name);
        }
      }
      if (duplicates.length === 0) return null;
      return `Duplicate tool names across servers: ${duplicates.join("; ")}`;
    },
  },

  // Command Injection — tools with shell/exec patterns
  {
    id: "RULE-006",
    techniqueId: "SAFE-T1101",
    test(input) {
      const tools = allTools(input);
      const risky = tools.filter((t) => {
        const desc = t.description.toLowerCase();
        return (
          desc.includes("shell") ||
          desc.includes("exec") ||
          desc.includes("command") ||
          desc.includes("run_command") ||
          desc.includes("subprocess") ||
          desc.includes("terminal")
        );
      });
      if (risky.length === 0) return null;
      return `Tools with shell/exec capabilities: ${risky.map((t) => t.name).join(", ")}`;
    },
  },

  // Prompt Injection surface
  {
    id: "RULE-007",
    techniqueId: "SAFE-T1102",
    test(input) {
      const tools = allTools(input);
      const injectable = tools.filter((t) => {
        const desc = t.description.toLowerCase();
        return (
          desc.includes("user input") ||
          desc.includes("user-provided") ||
          desc.includes("free text") ||
          desc.includes("natural language")
        );
      });
      if (injectable.length === 0) return null;
      return `Tools accepting free-form user input: ${injectable.map((t) => t.name).join(", ")}`;
    },
  },

  // Path Traversal
  {
    id: "RULE-008",
    techniqueId: "SAFE-T1105",
    test(input) {
      if (!input.fileSystemAccess) return null;
      const tools = allTools(input);
      const fileTools = tools.filter((t) => {
        const desc = t.description.toLowerCase();
        return (
          desc.includes("file") ||
          desc.includes("path") ||
          desc.includes("directory") ||
          desc.includes("read") ||
          desc.includes("write")
        );
      });
      if (fileTools.length === 0) return null;
      return `File-system tools present with filesystem access enabled: ${fileTools.map((t) => t.name).join(", ")}`;
    },
  },

  // Rug Pull risk — mutable tool definitions
  {
    id: "RULE-009",
    techniqueId: "SAFE-T1201",
    test(input) {
      const servers = input.servers ?? [];
      const dynamic = servers.filter(
        (s) =>
          s.transport === "sse" ||
          s.transport === "websocket" ||
          s.transport === "http",
      );
      if (dynamic.length === 0) return null;
      return `Servers with dynamic transport (tool definitions may change at runtime): ${dynamic.map((s) => s.name).join(", ")}`;
    },
  },

  // Vector Store Poisoning
  {
    id: "RULE-010",
    techniqueId: "SAFE-T2106",
    test(input) {
      if (!input.vectorStore && !input.sharedMemory) return null;
      return "Vector store or shared memory enabled — susceptible to context memory poisoning across sessions";
    },
  },

  // Cross-Tool Contamination
  {
    id: "RULE-011",
    techniqueId: "SAFE-T1701",
    test(input) {
      const servers = input.servers ?? [];
      if (servers.length < 2) return null;
      const totalTools = servers.reduce(
        (sum, s) => sum + (s.tools?.length ?? 0),
        0,
      );
      if (totalTools < 2) return null;
      return `Multi-server architecture (${servers.length} servers, ${totalTools} tools) — cross-tool contamination surface`;
    },
  },

  // Multi-agent instruction injection
  {
    id: "RULE-012",
    techniqueId: "SAFE-T1705",
    test(input) {
      if (!input.multiAgent) return null;
      return "Multi-agent architecture — susceptible to cross-agent instruction injection via shared message bus";
    },
  },

  // Data exfiltration via network tools
  {
    id: "RULE-013",
    techniqueId: "SAFE-T1910",
    test(input) {
      if (!input.networkAccess) return null;
      const tools = allTools(input);
      const netTools = tools.filter((t) => {
        const desc = t.description.toLowerCase();
        return (
          desc.includes("http") ||
          desc.includes("fetch") ||
          desc.includes("request") ||
          desc.includes("webhook") ||
          desc.includes("api")
        );
      });
      if (netTools.length === 0) return null;
      return `Network-capable tools with outbound access: ${netTools.map((t) => t.name).join(", ")}`;
    },
  },

  // RAG Backdoor
  {
    id: "RULE-014",
    techniqueId: "SAFE-T3001",
    test(input) {
      if (!input.ragPipeline) return null;
      return "RAG pipeline enabled — susceptible to backdoor attacks via retrieval manipulation";
    },
  },

  // Multimodal injection
  {
    id: "RULE-015",
    techniqueId: "SAFE-T1110",
    test(input) {
      if (!input.multimodal) return null;
      return "Multimodal input processing enabled — susceptible to prompt injection via images/audio";
    },
  },

  // CLI Weaponization
  {
    id: "RULE-016",
    techniqueId: "SAFE-T1111",
    test(input) {
      if (!input.cliAccess) return null;
      return "CLI access enabled — AI agent CLI tools can be weaponized for reconnaissance and data exfiltration";
    },
  },

  // Credential Harvest via file tools
  {
    id: "RULE-017",
    techniqueId: "SAFE-T1502",
    test(input) {
      if (!input.fileSystemAccess) return null;
      return "File system access enabled — credentials (.env, SSH keys, cloud configs) may be harvestable";
    },
  },

  // Over-Privileged Tool Abuse
  {
    id: "RULE-018",
    // Was SAFE-T1104 (Over-Privileged Tool Abuse), deprecated upstream and replaced by SAFE-T1302.
    techniqueId: "SAFE-T1302",
    test(input) {
      const tools = allTools(input);
      const overprivileged = tools.filter((t) => {
        const desc = t.description.toLowerCase();
        return (
          desc.includes("admin") ||
          desc.includes("root") ||
          desc.includes("sudo") ||
          desc.includes("all permissions") ||
          desc.includes("full access")
        );
      });
      if (overprivileged.length === 0) return null;
      return `Potentially over-privileged tools: ${overprivileged.map((t) => t.name).join(", ")}`;
    },
  },

  // ── Additional Rules (RULE-019 through RULE-032) ────────────────

  // Fake Tool Invocation / Function Spoofing
  {
    id: "RULE-019",
    techniqueId: "SAFE-T1103",
    test(input) {
      const servers = input.servers ?? [];
      const noSchema = servers.flatMap((s) => s.tools ?? []).filter(
        (t) => !t.inputSchema && !t.parameters,
      );
      if (noSchema.length === 0) return null;
      return `Tools without input schemas (function spoofing surface): ${noSchema.map((t) => t.name).join(", ")}`;
    },
  },

  // Autonomous Loop Exploit
  {
    id: "RULE-020",
    techniqueId: "SAFE-T1106",
    test(input) {
      const tools = allTools(input);
      const selfRef = tools.filter((t) => {
        const desc = t.description.toLowerCase();
        return desc.includes("recursive") || desc.includes("loop") || desc.includes("self-invoke") || desc.includes("retry");
      });
      if (selfRef.length === 0) return null;
      return `Tools with self-referencing/loop patterns: ${selfRef.map((t) => t.name).join(", ")}`;
    },
  },

  // Backdoored Server Binary
  {
    id: "RULE-021",
    techniqueId: "SAFE-T1203",
    test(input) {
      const servers = input.servers ?? [];
      const unverified = servers.filter(
        (s) => !s.authentication || s.authentication === "none",
      );
      if (unverified.length === 0) return null;
      const hasExec = unverified.some((s) =>
        (s.tools ?? []).some((t) => {
          const d = t.description.toLowerCase();
          return d.includes("install") || d.includes("cron") || d.includes("startup") || d.includes("service");
        }),
      );
      if (!hasExec) return null;
      return "Unauthenticated server with install/persistence capabilities — potential backdoor vector";
    },
  },

  // Context Memory Implant
  {
    id: "RULE-022",
    techniqueId: "SAFE-T1204",
    test(input) {
      if (!input.vectorStore) return null;
      const tools = allTools(input);
      const writeTools = tools.filter((t) => {
        const d = t.description.toLowerCase();
        return d.includes("write") || d.includes("store") || d.includes("save") || d.includes("insert") || d.includes("upsert");
      });
      if (writeTools.length === 0) return null;
      return `Write-capable tools with vector store — context memory implant risk: ${writeTools.map((t) => t.name).join(", ")}`;
    },
  },

  // Credential Relay Chain
  {
    id: "RULE-023",
    techniqueId: "SAFE-T1304",
    test(input) {
      if (!input.oauthFlows) return null;
      const servers = input.servers ?? [];
      if (servers.length < 2) return null;
      const oauthServers = servers.filter((s) => s.oauthConfig);
      if (oauthServers.length === 0) return null;
      return `Multiple servers with OAuth flows — credential relay chain possible across: ${oauthServers.map((s) => s.name).join(", ")}`;
    },
  },

  // Consent-Fatigue Exploit
  {
    id: "RULE-024",
    techniqueId: "SAFE-T1403",
    test(input) {
      const tools = allTools(input);
      if (tools.length < 15) return null;
      return `${tools.length} tools registered — high tool count increases consent-fatigue exploitation risk`;
    },
  },

  // Full-Schema Poisoning
  {
    id: "RULE-025",
    techniqueId: "SAFE-T1501",
    test(input) {
      const tools = allTools(input);
      const poisoned = tools.filter((t) => {
        const schema = JSON.stringify(t.inputSchema ?? t.parameters ?? {}).toLowerCase();
        return INJECTION_PATTERNS.some((p) => p.test(schema)) ||
               UNICODE_PATTERNS.some((p) => p.test(schema));
      });
      if (poisoned.length === 0) return null;
      return `Suspicious patterns in tool schemas (full-schema poisoning): ${poisoned.map((t) => t.name).join(", ")}`;
    },
  },

  // Env-Var Scraping
  {
    id: "RULE-026",
    techniqueId: "SAFE-T1503",
    test(input) {
      if (!input.fileSystemAccess) return null;
      const tools = allTools(input);
      const envTools = tools.filter((t) => {
        const d = t.description.toLowerCase();
        return d.includes(".env") || d.includes("environment") || d.includes("config") || d.includes("secret");
      });
      if (envTools.length === 0) return null;
      return `Tools with env/config access and filesystem enabled: ${envTools.map((t) => t.name).join(", ")}`;
    },
  },

  // System Prompt Disclosure
  {
    id: "RULE-027",
    techniqueId: "SAFE-T1603",
    test(input) {
      const tools = allTools(input);
      const disclosureRisk = tools.filter((t) => {
        const d = t.description.toLowerCase();
        return d.includes("system prompt") || d.includes("instructions") || d.includes("policy") || d.includes("rules");
      });
      if (disclosureRisk.length === 0) return null;
      return `Tools referencing system prompts/instructions — prompt disclosure risk: ${disclosureRisk.map((t) => t.name).join(", ")}`;
    },
  },

  // Database Dump
  {
    id: "RULE-028",
    techniqueId: "SAFE-T1803",
    test(input) {
      const tools = allTools(input);
      const dbTools = tools.filter((t) => {
        const d = t.description.toLowerCase();
        return d.includes("sql") || d.includes("database") || d.includes("query") || d.includes("table");
      });
      if (dbTools.length === 0) return null;
      return `Tools with database access: ${dbTools.map((t) => t.name).join(", ")}`;
    },
  },

  // Data Destruction
  {
    id: "RULE-029",
    techniqueId: "SAFE-T2101",
    test(input) {
      const tools = allTools(input);
      const destructive = tools.filter((t) => {
        const d = t.description.toLowerCase();
        return d.includes("delete") || d.includes("drop") || d.includes("remove") || d.includes("destroy") || d.includes("truncate");
      });
      if (destructive.length === 0) return null;
      return `Destructive tools present: ${destructive.map((t) => t.name).join(", ")}`;
    },
  },

  // Code Sabotage
  {
    id: "RULE-030",
    techniqueId: "SAFE-T2103",
    test(input) {
      const tools = allTools(input);
      const codeTools = tools.filter((t) => {
        const d = t.description.toLowerCase();
        return d.includes("commit") || d.includes("push") || d.includes("pull request") || d.includes("merge") || d.includes("deploy");
      });
      if (codeTools.length === 0) return null;
      return `Tools with code deploy/commit capabilities: ${codeTools.map((t) => t.name).join(", ")}`;
    },
  },

  // Fraudulent Transactions
  {
    id: "RULE-031",
    techniqueId: "SAFE-T2104",
    test(input) {
      const tools = allTools(input);
      const financial = tools.filter((t) => {
        const d = t.description.toLowerCase();
        return d.includes("payment") || d.includes("transfer") || d.includes("transaction") || d.includes("invoice") || d.includes("wallet");
      });
      if (financial.length === 0) return null;
      return `Financial/payment tools present: ${financial.map((t) => t.name).join(", ")}`;
    },
  },

  // OAuth Protocol Downgrade
  {
    id: "RULE-032",
    techniqueId: "SAFE-T1408",
    test(input) {
      if (!input.oauthFlows) return null;
      const servers = input.servers ?? [];
      const noPkce = servers.filter((s) => {
        const config = s.oauthConfig;
        if (!config) return false;
        const scopes = config.scopes ?? [];
        return scopes.length > 0 && !s.authentication?.toLowerCase().includes("pkce");
      });
      if (noPkce.length === 0) return null;
      return `OAuth servers without PKCE enforcement: ${noPkce.map((s) => s.name).join(", ")}`;
    },
  },
];

// ── Helpers ─────────────────────────────────────────────────────────

function allTools(input: AgentArchitecture): ToolDefinition[] {
  const serverTools = (input.servers ?? []).flatMap((s) => s.tools ?? []);
  return [...(input.tools ?? []), ...serverTools];
}

function computeOverallRisk(bySeverity: Record<string, number>): Severity {
  if (bySeverity["Critical"] && bySeverity["Critical"] > 0) return "Critical";
  if (bySeverity["High"] && bySeverity["High"] > 0) return "High";
  if (bySeverity["Medium"] && bySeverity["Medium"] > 0) return "Medium";
  return "Low";
}

function computeCoverageScore(findings: Finding[]): number {
  if (findings.length === 0) return 1.0;
  const mitigated = findings.filter((f) => f.mitigations.length > 0).length;
  return mitigated / findings.length;
}

// ── Public API ──────────────────────────────────────────────────────

/** Rule id to technique id, for tests and documentation. */
export function listRules(): Array<{ id: string; techniqueId: string }> {
  return rules.map((r) => ({ id: r.id, techniqueId: r.techniqueId }));
}

export function analyzeArchitecture(input: AgentArchitecture): AnalysisResult {
  const findings: Finding[] = [];

  for (const rule of rules) {
    const evidence = rule.test(input);
    if (evidence !== null) {
      const finding = buildFinding(rule, evidence);
      if (finding) {
        findings.push(finding);
      }
    }
  }

  const bySeverity: Record<string, number> = {};
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  }

  const techniqueIds = findings.map((f) => f.technique.id);

  return {
    timestamp: new Date().toISOString(),
    target: input.name ?? "unnamed-architecture",
    summary: {
      overallRisk: computeOverallRisk(bySeverity),
      totalFindings: findings.length,
      bySeverity,
      coverageScore: computeCoverageScore(findings),
    },
    findings,
    frameworkCoverage: getCoverage(techniqueIds),
  };
}

export function analyzeTool(tool: ToolDefinition): AnalysisResult {
  return analyzeArchitecture({
    name: tool.name,
    tools: [tool],
  });
}

export function analyzeServer(server: ServerDefinition): AnalysisResult {
  return analyzeArchitecture({
    name: server.name,
    servers: [server],
  });
}
