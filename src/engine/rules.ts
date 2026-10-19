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
import { scanString, scanSchema, verdict, describeSignals, identifierToWords, schemaStrings, nameKey, type Signal } from "./detect.js";

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
  /**
   * How a client starts this server (from an MCP client config): the command,
   * its arguments, and environment. Values are inspected, never echoed in full.
   */
  launch?: {
    command: string;
    args?: string[] | undefined;
    env?: Record<string, string> | undefined;
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
  /** "evidence", "configuration", or "exposure": what the finding rests on. */
  basis: Basis;
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
  /**
   * What a finding from this rule rests on:
   * - "evidence": the content itself shows an attack (hidden instructions, concealment)
   * - "configuration": a specific risky setting (no auth, unpinned launch, privileged container)
   * - "exposure": the architecture has what an attack needs, with no sign it is being used
   */
  basis: Basis;
  test: (input: AgentArchitecture) => string | RuleHit | null;
}

export type Basis = "evidence" | "configuration" | "exposure";

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
    basis: rule.basis,
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

/** All content signals for one tool: metadata plus input schema. */
function allSignals(tool: ToolDefinition): Signal[] {
  return [...poisoningSignals(tool), ...scanSchema(tool.inputSchema ?? tool.parameters ?? {})];
}

/** A rule that reports tools carrying strong signals of the given kinds. */
function signalKindRule(
  tools: ToolDefinition[],
  matches: (s: Signal) => boolean,
  prefix: string,
): RuleHit | null {
  const flagged: string[] = [];
  for (const t of tools) {
    const hits = allSignals(t).filter((s) => s.strength === "strong" && matches(s));
    if (hits.length) flagged.push(`${t.name}: ${describeSignals(hits)}`);
  }
  return flagged.length ? { evidence: `${prefix} ${flagged.join(" | ")}`, confidence: "high" } : null;
}

// ── Launch command analysis (MCP client configs) ────────────────────

const baseCommand = (command: string): string =>
  (command.split(/[\\/]/).pop() ?? command).toLowerCase().replace(/\.(exe|cmd|bat|ps1)$/, "");

/** Docker run flags that take a separate value. */
const DOCKER_VALUE_FLAGS = new Set([
  "-e", "--env", "-v", "--volume", "--name", "-p", "--publish", "--network", "--net", "-u", "--user", "--mount",
  "--env-file", "-w", "--workdir", "--entrypoint", "--platform", "--cap-add", "--cap-drop", "--pid", "--ipc",
  "-l", "--label", "--add-host", "--dns", "--security-opt", "-m", "--memory", "--cpus", "--gpus", "--device",
  "--tmpfs", "--ulimit", "--restart", "--hostname", "-h", "--userns", "--runtime", "--log-driver", "--pull",
]);

interface DockerRun {
  flags: Array<[string, string | undefined]>;
  image: string | undefined;
}

function parseDockerRun(args: string[]): DockerRun | undefined {
  const i = args.findIndex((a) => a === "run" || a === "create");
  if (i === -1) return undefined;
  const flags: Array<[string, string | undefined]> = [];
  let image: string | undefined;
  for (let j = i + 1; j < args.length; j++) {
    const a = args[j]!;
    if (a.startsWith("-")) {
      const eq = a.indexOf("=");
      if (eq !== -1) flags.push([a.slice(0, eq), a.slice(eq + 1)]);
      else if (DOCKER_VALUE_FLAGS.has(a)) flags.push([a, args[++j]]);
      else flags.push([a, undefined]);
      continue;
    }
    image = a;
    break;
  }
  return { flags, image };
}

/** Package launchers that fetch and run a package on every start. */
const LAUNCHERS: Record<string, { skip: Set<string>; pinned: (spec: string) => boolean }> = (() => {
  const npmPinned = (spec: string): boolean => {
    const at = spec.lastIndexOf("@");
    return at > 0 && /^\d+\.\d+\.\d+(-[0-9a-z.]+)?$/i.test(spec.slice(at + 1));
  };
  const pyPinned = (spec: string): boolean => /==\d+(\.\d+)*$|@\d+\.\d+(\.\d+)?$/.test(spec);
  const npmSkip = new Set(["-y", "--yes", "-p", "--package", "--quiet", "-q", "exec", "dlx", "x"]);
  return {
    npx: { skip: npmSkip, pinned: npmPinned },
    bunx: { skip: npmSkip, pinned: npmPinned },
    pnpx: { skip: npmSkip, pinned: npmPinned },
    pnpm: { skip: npmSkip, pinned: npmPinned },
    yarn: { skip: npmSkip, pinned: npmPinned },
    npm: { skip: npmSkip, pinned: npmPinned },
    uvx: { skip: new Set(["--from", "--with", "-q", "--quiet"]), pinned: pyPinned },
    pipx: { skip: new Set(["run", "--spec", "-q", "--quiet"]), pinned: pyPinned },
  };
})();

const isLauncher = (a: string): boolean => Object.prototype.hasOwnProperty.call(LAUNCHERS, baseCommand(a));
const isShellWrapper = (base: string): boolean => base === "cmd" || base === "powershell" || base === "pwsh";

/** The launcher and its arguments, unwrapping "cmd /c npx ..." style wrappers. */
function unwrapLauncher(command: string, args: string[]): { launcher: string; argv: string[] } | undefined {
  const base = baseCommand(command);
  if (isShellWrapper(base)) {
    const k = args.findIndex(isLauncher);
    return k === -1 ? undefined : { launcher: baseCommand(args[k]!), argv: args.slice(k + 1) };
  }
  return isLauncher(base) ? { launcher: base, argv: args } : undefined;
}

/** The package a launcher will fetch, or undefined if this is not a launcher invocation. */
function launchedPackage(command: string, args: string[]): { pkg: string; pinned: boolean } | undefined {
  const u = unwrapLauncher(command, args);
  if (!u) return undefined;
  const spec = LAUNCHERS[u.launcher]!;
  if ((u.launcher === "npm" && u.argv[0] !== "exec") || ((u.launcher === "pnpm" || u.launcher === "yarn") && u.argv[0] !== "dlx")) {
    return undefined;
  }
  const pkg = u.argv.find((a) => !spec.skip.has(a) && !a.startsWith("-"));
  return pkg ? { pkg, pinned: spec.pinned(pkg) } : undefined;
}

/** Token shapes with a well known prefix. Matching values are masked in evidence. */
const SECRET_SHAPES: RegExp[] = [
  /^gh[pousr]_[A-Za-z0-9]{20,}$/, /^github_pat_[A-Za-z0-9_]{20,}$/, /^sk-ant-[A-Za-z0-9_-]{20,}$/,
  /^sk-(proj-)?[A-Za-z0-9_-]{20,}$/, /^xox[abprs]-[A-Za-z0-9-]{10,}$/, /^AKIA[0-9A-Z]{16}$/,
  /^AIza[0-9A-Za-z_-]{30,}$/, /^(sk|rk)_live_[A-Za-z0-9]{16,}$/, /^glpat-[A-Za-z0-9_-]{20,}$/,
  /^npm_[A-Za-z0-9]{30,}$/, /^hf_[A-Za-z0-9]{30,}$/,
];
const SECRET_NAME = /(token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)/i;
const PLACEHOLDER = /^\$\{|^\$[A-Z_]+$|^<.*>$|^%[A-Z_]+%$|your[_-]|xxx|changeme|example|placeholder|\*\*\*/i;

function looksLikeSecret(name: string, value: string): boolean {
  const v = value.trim();
  if (!v || PLACEHOLDER.test(v)) return false;
  if (SECRET_SHAPES.some((re) => re.test(v))) return true;
  return SECRET_NAME.test(name) && v.length >= 20 && /[A-Za-z]/.test(v) && /\d/.test(v) && !/\s/.test(v);
}

/** Never echo a secret: first four characters only. */
const mask = (v: string): string => `${v.trim().slice(0, 4)}…`;

// ── Capability classification (for combination rules) ───────────────

const PRIVATE_READ = [
  /\b(read|reads|reading|get|gets|list|lists|search|searches|query|queries|retrieve\w*|access\w*|view|views|open|opens|export\w*)\b[^.]{0,40}\b(files?|documents?|emails?|inbox|mailbox|messages?|database|records?|contacts|calendar|notes|repositor(y|ies)|source code|secrets?|credentials?|customers?|tickets?|drive|spreadsheets?)\b/,
];
const OUTBOUND_SEND = [
  /\b(send|sends|post|posts|upload\w*|publish\w*|forward\w*|share|shares)\b[^.]{0,40}\b(emails?|messages?|slack|teams|webhooks?|urls?|https?|endpoints?|servers?|channels?|issues?|comments?|gists?|requests?|recipients?|anyone|external)\b/,
  /\b(send|sends)\s+(an?\s+)?emails?\b|\bhttp\s+(post|requests?)\b|\bwebhooks?\b/,
];
const UNTRUSTED_READ = [
  /\b(fetch|fetches|read|reads|get|gets|browse|browses|scrape\w*|load|loads|open|opens|download\w*|search|searches)\b[^.]{0,40}\b(web ?pages?|websites?|urls?|internet|the web|inbox|incoming|emails?|issues?|pull requests?|comments?|rss|feeds?|public)\b/,
];
const PRIVILEGED_ACT = [
  /\b(shell|bash|powershell|terminal|subprocess)\b|\b(run|runs|execute|executes)\b[^.]{0,30}\b(commands?|scripts?|code|programs?)\b/,
  /\b(delet\w+|drop|drops|destroy\w*|truncat\w+|wipe\w*|overwrit\w+|deploy\w*|merg\w+|commit\w*|transfer\w*|pay|pays|payments?|refund\w*|install\w*)\b/,
  /\b(write|writes|writing)\s+(to\s+)?(files?|disk|the file ?system)\b/,
];

const capability = (t: ToolDefinition, patterns: RegExp[]): boolean => mentions(`${identifierToWords(t.name)} ${t.description}`, ...patterns);
const names = (tools: ToolDefinition[]): string => tools.map((t) => t.name).join(", ");

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
    basis: "evidence",
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
    basis: "configuration",
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
    basis: "configuration",
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
    basis: "configuration",
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
    basis: "configuration",
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
    basis: "exposure",
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
    basis: "exposure",
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
    basis: "exposure",
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
    basis: "configuration",
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
    basis: "exposure",
    test(input) {
      if (!input.vectorStore && !input.sharedMemory) return null;
      return "Vector store or shared memory enabled — susceptible to context memory poisoning across sessions";
    },
  },

  // Cross-Tool Contamination
  {
    id: "RULE-011",
    techniqueId: "SAFE-T1701",
    basis: "exposure",
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
    basis: "exposure",
    test(input) {
      if (!input.multiAgent) return null;
      return "Multi-agent architecture — susceptible to cross-agent instruction injection via shared message bus";
    },
  },

  // Data exfiltration via network tools
  {
    id: "RULE-013",
    techniqueId: "SAFE-T1910",
    basis: "exposure",
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
    basis: "exposure",
    test(input) {
      if (!input.ragPipeline) return null;
      return "RAG pipeline enabled — susceptible to backdoor attacks via retrieval manipulation";
    },
  },

  // Multimodal injection
  {
    id: "RULE-015",
    techniqueId: "SAFE-T1110",
    basis: "exposure",
    test(input) {
      if (!input.multimodal) return null;
      return "Multimodal input processing enabled — susceptible to prompt injection via images/audio";
    },
  },

  // CLI Weaponization
  {
    id: "RULE-016",
    techniqueId: "SAFE-T1111",
    basis: "exposure",
    test(input) {
      if (!input.cliAccess) return null;
      return "CLI access enabled — AI agent CLI tools can be weaponized for reconnaissance and data exfiltration";
    },
  },

  // Credential Harvest via file tools
  {
    id: "RULE-017",
    techniqueId: "SAFE-T1502",
    basis: "exposure",
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
    basis: "exposure",
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
    basis: "configuration",
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
    basis: "exposure",
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
    basis: "exposure",
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
    basis: "exposure",
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
    basis: "exposure",
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
    basis: "configuration",
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
    basis: "evidence",
    test(input) {
      const tools = allTools(input);
      return contentRule(tools, (t) => scanSchema(t.inputSchema ?? t.parameters ?? {}), "Suspicious content in tool input schemas:");
    },
  },

  // Env-Var Scraping
  {
    id: "RULE-026",
    techniqueId: "SAFE-T1503",
    basis: "exposure",
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
    basis: "exposure",
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
    basis: "exposure",
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
    basis: "exposure",
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
    basis: "exposure",
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
    basis: "exposure",
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
    basis: "configuration",
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

  // ── 2.3.0: specific techniques for existing content signals ─────

  // Instruction Steganography: hidden or invisible text in tool metadata or schemas
  {
    id: "RULE-033",
    techniqueId: "SAFE-T1402",
    basis: "evidence",
    test(input) {
      return signalKindRule(
        allTools(input),
        (s) => s.kind === "invisible" || s.kind === "encoded" || s.label === "instruction in an HTML comment",
        "Hidden content in tool metadata:",
      );
    },
  },

  // Response Tampering: the model is told to keep actions from the user
  {
    id: "RULE-034",
    techniqueId: "SAFE-T1404",
    basis: "evidence",
    test(input) {
      return signalKindRule(allTools(input), (s) => s.kind === "concealment", "Tool metadata tells the model to hide behavior from the user:");
    },
  },

  // Server Impersonation: distinct servers presenting the same or a lookalike name
  {
    id: "RULE-035",
    techniqueId: "SAFE-T1004",
    basis: "configuration",
    test(input) {
      const servers = input.servers ?? [];
      if (servers.length < 2) return null;
      const groups = new Map<string, string[]>();
      for (const s of servers) {
        const key = nameKey(s.name);
        if (!key) continue;
        groups.set(key, [...(groups.get(key) ?? []), s.name]);
      }
      const clashes = [...groups.values()].filter((g) => g.length > 1);
      if (clashes.length === 0) return null;
      // Lookalikes can render identically, so say which names hide non-ASCII letters.
      const show = (n: string): string => {
        const odd = [...n].filter((c) => c.charCodeAt(0) > 127);
        return odd.length
          ? `"${n}" (contains ${odd.map((c) => `U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}`).join(", ")})`
          : `"${n}"`;
      };
      return `Servers with the same or lookalike names: ${clashes.map((g) => g.map(show).join(" and ")).join("; ")}`;
    },
  },

  // Parameter Exfiltration: metadata directs secrets or user data into a parameter
  {
    id: "RULE-036",
    techniqueId: "SAFE-T1911",
    basis: "evidence",
    test(input) {
      return signalKindRule(allTools(input), (s) => s.kind === "paramexfil", "Tool metadata directs data into a parameter:");
    },
  },

  // Metadata Manipulation: annotations understate what the tool does
  {
    id: "RULE-037",
    techniqueId: "SAFE-T1406",
    basis: "evidence",
    test(input) {
      const ACTS = /\b(delet\w+|remov\w+|drop|drops|destroy\w*|truncat\w+|wip(e|es|ing)|overwrit\w+|writ(e|es|ing)|modif(y|ies)|updat(e|es)|send|sends|post|posts|upload\w*|transfer\w*|pay|deploy\w*|install\w*|kill\w*|shutdown)\b|\b(run|runs|execut\w+)\s+(an?\s+|the\s+|any\s+|arbitrary\s+)?(shell\s+|system\s+)?(commands?|scripts?|code|programs?|binar(y|ies))\b/;
      const flagged = allTools(input).filter((t) => {
        const a = t.annotations ?? {};
        const claimsSafe = a["readOnlyHint"] === true || a["destructiveHint"] === false;
        return claimsSafe && mentions(`${identifierToWords(t.name)} ${t.description}`, ACTS);
      });
      if (flagged.length === 0) return null;
      return `Annotations claim read only or non destructive, but the tool describes changing or sending data: ${flagged.map((t) => t.name).join(", ")}`;
    },
  },

  // ── 2.3.0: launch configuration (MCP client configs) ────────────

  // Supply Chain Compromise: servers fetched unpinned at every launch, or piped from the web
  {
    id: "RULE-038",
    techniqueId: "SAFE-T1002",
    basis: "configuration",
    test(input) {
      const problems: string[] = [];
      for (const s of input.servers ?? []) {
        if (!s.launch) continue;
        const { command } = s.launch;
        const args = s.launch.args ?? [];
        const launched = launchedPackage(command, args);
        if (launched && !launched.pinned) {
          problems.push(`${s.name} runs "${launched.pkg}" without an exact version, so each launch can fetch different code`);
        }
        if (baseCommand(command) === "docker") {
          const run = parseDockerRun(args);
          if (run?.image && !run.image.includes("@sha256:")) {
            const lastPart = run.image.split("/").pop() ?? run.image;
            const tagged = lastPart.includes(":") && !lastPart.endsWith(":latest");
            problems.push(
              `${s.name} runs image "${run.image}" ${tagged ? "by tag, which can be moved" : "with no fixed version"}; pin it by digest (@sha256:...)`,
            );
          }
        }
        const joined = `${command} ${args.join(" ")}`;
        if (/\b(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b|\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|]*\|\s*iex\b/i.test(joined)) {
          problems.push(`${s.name} downloads a script and runs it at launch`);
        }
      }
      return problems.length ? `Launch commands that can run unreviewed code: ${problems.join("; ")}` : null;
    },
  },

  // Sandbox Escape: containers launched with host level access
  {
    id: "RULE-039",
    techniqueId: "SAFE-T1303",
    basis: "configuration",
    test(input) {
      const problems: string[] = [];
      for (const s of input.servers ?? []) {
        if (!s.launch || baseCommand(s.launch.command) !== "docker") continue;
        const run = parseDockerRun(s.launch.args ?? []);
        if (!run) continue;
        const found = new Set<string>();
        for (const [flag, value] of run.flags) {
          const v = (value ?? "").toLowerCase();
          if (flag === "--privileged") found.add("--privileged");
          if (flag === "--cap-add" && /^(all|sys_admin|sys_ptrace|sys_module|net_admin|dac_read_search)$/.test(v)) found.add(`--cap-add ${value}`);
          if ((flag === "-v" || flag === "--volume" || flag === "--mount") && (/^\/:|source=\/(,|$)/.test(v) || v.includes("docker.sock") || v.includes("docker_engine"))) {
            found.add(`${flag} ${value}`);
          }
          if ((flag === "--pid" || flag === "--ipc" || flag === "--userns") && v === "host") found.add(`${flag}=host`);
          if ((flag === "-u" || flag === "--user") && (v === "0" || v === "root" || v.startsWith("0:") || v.startsWith("root:"))) found.add(`${flag} ${value}`);
          if (flag === "--security-opt" && /unconfined|no-new-privileges[:=]false/.test(v)) found.add(`--security-opt ${value}`);
        }
        if (found.size) problems.push(`${s.name}: ${[...found].join(", ")}`);
      }
      return problems.length ? `Containers launched with access to the host: ${problems.join("; ")}` : null;
    },
  },

  // File-Based Credential Harvest: plaintext secrets stored in a client config
  {
    id: "RULE-040",
    techniqueId: "SAFE-T1502",
    basis: "configuration",
    test(input) {
      const problems: string[] = [];
      for (const s of input.servers ?? []) {
        if (!s.launch) continue;
        const found: string[] = [];
        for (const [name, value] of Object.entries(s.launch.env ?? {})) {
          if (typeof value === "string" && looksLikeSecret(name, value)) found.push(`${name} (${mask(value)})`);
        }
        const args = s.launch.args ?? [];
        args.forEach((a, i) => {
          const eq = a.indexOf("=");
          const [flag, value] = eq > 0 ? [a.slice(0, eq), a.slice(eq + 1)] : [args[i - 1] ?? "", a];
          const shaped = SECRET_SHAPES.some((re) => re.test(value.trim()));
          if (shaped || (flag.startsWith("-") && looksLikeSecret(flag, value))) found.push(`argument ${i + 1} (${mask(value)})`);
        });
        if (found.length) problems.push(`${s.name}: ${[...new Set(found)].join(", ")}`);
      }
      return problems.length
        ? `Plaintext secrets in the client config, readable by anything that can read the file: ${problems.join("; ")}`
        : null;
    },
  },

  // ── 2.4.0: capability combinations ──────────────────────────────

  // Tool-to-Tool Exfil: one tool can read private data and another can send it out
  {
    id: "RULE-041",
    techniqueId: "SAFE-T1914",
    basis: "exposure",
    test(input) {
      const tools = allTools(input);
      const readers = tools.filter((t) => capability(t, PRIVATE_READ));
      const senders = tools.filter((t) => capability(t, OUTBOUND_SEND));
      if (readers.length === 0 || senders.length === 0) return null;
      if (readers.length === 1 && senders.length === 1 && readers[0] === senders[0]) return null;
      const untrusted = tools.filter((t) => capability(t, UNTRUSTED_READ));
      const trifecta = untrusted.length
        ? ` Untrusted content also reaches this agent (${names(untrusted)}), so an injected instruction could drive the whole path: private data, untrusted input, and a way out.`
        : "";
      return `Private data can be read by ${names(readers)} and sent out by ${names(senders)}.${trifecta}`;
    },
  },

  // Tool-Chaining Pivot: untrusted content can steer a tool that changes things
  {
    id: "RULE-042",
    techniqueId: "SAFE-T1703",
    basis: "exposure",
    test(input) {
      const tools = allTools(input);
      const untrusted = tools.filter((t) => capability(t, UNTRUSTED_READ));
      const actors = tools.filter((t) => capability(t, PRIVILEGED_ACT) && !untrusted.includes(t));
      if (untrusted.length === 0 || actors.length === 0) return null;
      return `Content from untrusted sources (${names(untrusted)}) reaches an agent that can also act through ${names(actors)}; an instruction hidden in that content could trigger those actions.`;
    },
  },

  // HTTP POST Exfil: a tool that sends requests to any URL the model chooses
  {
    id: "RULE-043",
    techniqueId: "SAFE-T1913",
    basis: "exposure",
    test(input) {
      const flagged = allTools(input).filter((t) => {
        const text = `${identifierToWords(t.name)} ${t.description}`;
        const anyUrl = mentions(text, /\b(any|arbitrary|given|specified|provided|custom|user supplied)\s+(urls?|endpoints?|address(es)?|hosts?|domains?)\b/);
        const sends = mentions(text, /\b(send|sends|post|posts|put|request|requests|call|calls|upload\w*|webhook\w*)\b/);
        const schema = (t.inputSchema ?? t.parameters ?? {}) as { properties?: Record<string, unknown> };
        const props = Object.keys(schema.properties ?? {}).map((k) => k.toLowerCase());
        const schemaShape = props.some((p) => p === "url" || p === "endpoint") && props.some((p) => ["method", "body", "data", "payload"].includes(p));
        return (anyUrl && sends) || schemaShape;
      });
      if (flagged.length === 0) return null;
      return `Tools that can send requests to any URL the model chooses: ${names(flagged)}`;
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
export function listRules(): Array<{ id: string; techniqueId: string; basis: Basis }> {
  return rules.map((r) => ({ id: r.id, techniqueId: r.techniqueId, basis: r.basis }));
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
