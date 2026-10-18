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
import { scanString, scanSchema, verdict, describeSignals, identifierToWords, schemaStrings, type Signal } from "./detect.js";

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
  /**
   * For content rules (RULE-001, RULE-025): "high" when the text shows a clear
   * attack signal, "medium" when only weaker signals combine. Absent for rules
   * that report a capability or configuration rather than suspicious content.
   */
  confidence?: "high" | "medium";
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
  test: (input: AgentArchitecture) => string | RuleHit | null;
}

interface RuleHit {
  evidence: string;
  confidence?: "high" | "medium";
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

function buildFinding(rule: Rule, hit: string | RuleHit): Finding | null {
  const { evidence, confidence } = typeof hit === "string" ? { evidence: hit, confidence: undefined } : hit;
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
    ...(confidence ? { confidence } : {}),
    mitigations,
    mappings: getMappings(rule.techniqueId),
  };
}

// ── Pattern Detectors ───────────────────────────────────────────────

/** Whole word (or phrase) match on lowercased text; avoids "capital" matching "api". */
function mentions(text: string, ...patterns: RegExp[]): boolean {
  const t = text.toLowerCase();
  return patterns.some((p) => p.test(t));
}

/** Content scan of one tool for RULE-001: name, description, annotations. */
function poisoningSignals(tool: ToolDefinition): Signal[] {
  return [
    ...scanString(identifierToWords(tool.name), "name"),
    ...scanString(tool.description, "description"),
    ...schemaStrings(tool.annotations ?? {}, "annotations").flatMap(([at, text]) => scanString(text, at)),
  ];
}

/** Run a content scan over tools and turn it into a rule result. */
function contentRule(tools: ToolDefinition[], scan: (t: ToolDefinition) => Signal[], prefix: string): RuleHit | null {
  const flagged: string[] = [];
  let high = false;
  for (const t of tools) {
    const v = verdict(scan(t));
    if (!v.report) continue;
    if (v.confidence === "high") high = true;
    flagged.push(`${t.name}: ${describeSignals(v.signals)}`);
  }
  if (flagged.length === 0) return null;
  return { evidence: `${prefix} ${flagged.join(" | ")}`, confidence: high ? "high" : "medium" };
}

// ── Rules ───────────────────────────────────────────────────────────

const rules: Rule[] = [
  // Tool Poisoning — suspicious content in descriptions
  {
    id: "RULE-001",
    techniqueId: "SAFE-T1001",
    test(input) {
      return contentRule(allTools(input), poisoningSignals, "Suspicious content in tool metadata:");
    },
  },

  // Unauthenticated server reachable over a network transport.
  // Stdio servers are local child processes with no listener, so they are skipped.
  // Servers with exposed endpoints are reported by RULE-003 instead.
  {
    id: "RULE-002",
    techniqueId: "SAFE-T1005",
    test(input) {
      const servers = input.servers ?? [];
      const open = servers.filter(
        (s) =>
          (!s.authentication || s.authentication === "none") &&
          s.transport?.toLowerCase() !== "stdio" &&
          !(s.exposedEndpoints && s.exposedEndpoints.length > 0),
      );
      if (open.length === 0) return null;
      const describe = (s: ServerDefinition): string => (s.transport ? `${s.name} (${s.transport})` : `${s.name} (transport not stated)`);
      return `Server(s) without authentication that may be reachable over the network, including from a browser on the same machine: ${open.map(describe).join(", ")}`;
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
      // Servers are told apart by position, not name: a server that copies
      // another server's name as well as its tools is the shadowing case.
      const nameCount = new Map<string, number>();
      for (const s of servers) nameCount.set(s.name, (nameCount.get(s.name) ?? 0) + 1);
      const seenLabel = new Map<string, number>();
      const labels = servers.map((s) => {
        if ((nameCount.get(s.name) ?? 0) < 2) return s.name;
        const n = (seenLabel.get(s.name) ?? 0) + 1;
        seenLabel.set(s.name, n);
        return `${s.name} (#${n})`;
      });
      const owners = new Map<string, Set<number>>();
      servers.forEach((server, i) => {
        for (const tool of server.tools ?? []) {
          if (!owners.has(tool.name)) owners.set(tool.name, new Set());
          owners.get(tool.name)!.add(i);
        }
      });
      const shared = [...owners.entries()].filter(([, idx]) => idx.size > 1);
      if (shared.length === 0) return null;
      const SHOW = 8;
      const listed = shared
        .slice(0, SHOW)
        .map(([tool, idx]) => `"${tool}" on ${[...idx].map((i) => labels[i]).join(" and ")}`)
        .join("; ");
      const more = shared.length > SHOW ? `; and ${shared.length - SHOW} more` : "";
      const sameName = [...nameCount.entries()].filter(([, n]) => n > 1).map(([n]) => n);
      const note = sameName.length ? ` Servers reporting the same name: ${sameName.join(", ")}.` : "";
      return `${shared.length} tool name(s) offered by more than one server: ${listed}${more}.${note}`;
    },
  },

  // Command Injection — tools with shell/exec patterns
  {
    id: "RULE-006",
    techniqueId: "SAFE-T1101",
    test(input) {
      const tools = allTools(input);
      const risky = tools.filter((t) => {
        return mentions(
          `${identifierToWords(t.name)} ${t.description}`,
          /\b(shell|bash|zsh|powershell|cmd\.exe|terminal|subprocess|exec)\b/,
          /\b(run|runs|execute|executes|exec)\b[^.]{0,30}\b(commands?|scripts?|programs?|binaries|processes)\b/,
          /\bcommand[- ]line\b|\brun command\b|\bchild process(es)?\b/,
          /\b(start|starts|spawn|spawns|launch|launches)\b[^.]{0,30}\b(commands?|process(es)?|programs?|executables?)\b/,
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
        return mentions(t.description, /\buser[- ](input|provided|supplied)\b|\bfree[- ](text|form)\b|\bnatural language\b|\barbitrary text\b/);
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
        return mentions(t.description, /\b(files?|filenames?|paths?|director(y|ies)|folders?|read|reads|reading|write|writes|writing)\b/);
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
        return mentions(
          t.description,
          /\bhttps?\b|\b(fetch|fetches|webhooks?|apis?|urls?|endpoints?|upload|uploads|download|downloads)\b/,
          /\b(http|web|network|outbound|post|get)\s+requests?\b/,
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
        return mentions(
          t.description,
          /\bsudo\b|\bsuperuser\b|\ball permissions\b|\bfull (admin |administrator |system )?access\b|\belevated privileges?\b/,
          /\b(admin|administrator|administrative)\s+(access|rights|privileges?|panel|console|role|permissions?)\b/,
          /\broot\s+(access|privileges?|user|shell|permissions?)\b|\bas (root|superuser|an? admin|admin|an? administrator|administrator)\b/,
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
        return mentions(desc, /\b(recursive\w*|recursion|loops?|looping|self[- ]invok\w*|retry|retries|retrying)\b/);
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
          return mentions(d, /\b(install\w*|cron\w*|startup|systemd|launch ?agents?|autostart|auto[- ]start|scheduled tasks?)\b|\b(system|background) services?\b/);
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
        return mentions(d, /\b(write|writes|writing|wrote|store|stores|stored|storing|save|saves|saved|saving|insert\w*|upsert\w*|ingest\w*|index(es|ing)?)\b/);
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
      return contentRule(tools, (t) => scanSchema(t.inputSchema ?? t.parameters ?? {}), "Suspicious content in tool input schemas:");
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
        return mentions(d, /\.env\b|\benvironment variables?\b|\benv vars?\b|\b(config|configuration|credentials?|secrets?)\s+files?\b|\b(secrets?|api keys?|access tokens?|credentials)\b/);
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
        return mentions(d, /\bsystem (prompts?|instructions|messages?)\b|\b(initial|hidden|original) (prompt|instructions)\b|\bdeveloper messages?\b|\byour (instructions|prompt)\b|\bprompt (template|configuration)\b/);
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
        return mentions(d, /\b(sql|databases?|tables?|db|postgres\w*|mysql|sqlite|mongo\w*|warehouse|bigquery|snowflake)\b/);
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
        return mentions(d, /\b(delet\w+|drop|drops|dropped|dropping|remov\w+|destroy\w*|truncat\w+|wipe\w*|eras\w+|purg\w+)\b/);
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
        return mentions(d, /\b(commit\w*|pull requests?|merg\w+|deploy\w*|releases? to production)\b|\bgit push\b|\bpush(es|ed|ing)?\s+(code|changes|commits?|to (a |the )?(branch|repo\w*|remote|main|master|production))\b/);
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
        return mentions(d, /\b(payments?|pay|pays|wire|transactions?|invoic\w+|wallets?|refund\w*|payouts?|funds)\b|\b(transfer|send|move)s?\s+(money|funds|payments?|crypto\w*|tokens)\b|\bcharge\w*\s+(a |the )?(card|customer)\b/);
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
