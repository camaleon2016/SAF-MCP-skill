/**
 * Sync src/data with a pinned commit of the upstream SAF-MCP catalog.
 *
 * What it syncs:
 *   - Techniques: the technique set, upstream names (old names kept as aliases),
 *     lifecycle status, replacements for deprecated techniques, profiles, and
 *     severity: upstream's, unless scripts/severity-overrides.json records a
 *     deliberate departure with a rationale.
 *   - Mitigations: entries upstream links to, and lifecycle status
 *     (mitigations upstream never published are marked "withdrawn").
 *   - Technique <-> mitigation links, written symmetrically.
 *
 * Usage:
 *   npx tsx scripts/sync-catalog.ts --upstream <path to safe-mcp checkout>
 *   npx tsx scripts/sync-catalog.ts --upstream <path> --check   (CI: fail on drift)
 *
 * Link sources (union):
 *   A. research/framework-model.yml   techniques[].mitigations   (canonical registry)
 *   B. mitigations/SAF-M-<n>/README.md  "## Mitigates" section     (mitigation pages)
 * The two disagree upstream (for example SAF-M-1 lists SAF-T1001 but the
 * registry entry for SAF-T1001 omits it), so both are used.
 *
 * Local IDs keep the SAFE- prefix for now; upstream SAF- IDs are mapped 1:1.
 */
import { readFileSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { resolve, join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DATA = join(ROOT, "src", "data");
const REPORT = join(ROOT, "docs", "catalog-sync-report.md");
const CHANGES = join(ROOT, "docs", "catalog-sync-changes.md");

// ── Args ────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const check = args.includes("--check");
const upIdx = args.indexOf("--upstream");
const upstreamDir = resolve(upIdx >= 0 && args[upIdx + 1] ? args[upIdx + 1]! : process.env["SAF_UPSTREAM"] ?? "../safe-mcp");
if (!existsSync(join(upstreamDir, "research", "framework-model.yml"))) {
  console.error(`Upstream checkout not found at ${upstreamDir}. Pass --upstream <path to safe-mcp>.`);
  process.exit(2);
}

const pinned = JSON.parse(readFileSync(join(ROOT, "scripts", "upstream.json"), "utf-8")) as { commit: string };
let upstreamCommit = "unknown";
try {
  upstreamCommit = execFileSync("git", ["-C", upstreamDir, "rev-parse", "HEAD"], { encoding: "utf-8" }).trim();
} catch {
  /* not a git checkout; reported below */
}
if (upstreamCommit !== pinned.commit) {
  console.error(
    `Upstream checkout is at ${upstreamCommit}, but scripts/upstream.json pins ${pinned.commit}.\n` +
      `Check out the pinned commit, or update scripts/upstream.json if you are deliberately moving to a new upstream.`,
  );
  process.exit(2);
}

// ── Helpers ─────────────────────────────────────────────────────────

/** Git on Windows often checks files out with CRLF; compare and parse as LF. */
const readText = (path: string): string => readFileSync(path, "utf-8").replace(/\r\n/g, "\n");

const toLocal = (id: string): string => id.replace(/^SAF-/, "SAFE-");
const mitNum = (id: string): number => Number(id.split("-").pop());
const byMitNum = (a: string, b: string): number => mitNum(a) - mitNum(b);
const stripMd = (s: string): string =>
  s.replace(/\*\*(.+?)\*\*/g, "$1").replace(/`(.+?)`/g, "$1").replace(/\[(.+?)\]\(.+?\)/g, "$1").trim();

function section(md: string, heading: string): string | undefined {
  const re = new RegExp(`^## ${heading}\\s*\\n([\\s\\S]*?)(?=^## |(?![\\s\\S]))`, "m");
  return re.exec(md)?.[1];
}

function field(md: string, name: string): string | undefined {
  return new RegExp(`^\\*\\*${name}\\*\\*:\\s*(.+?)\\s*$`, "m").exec(md)?.[1]?.trim();
}

/** "Medium-High (depends on ...)" -> "Medium-High"; keeps the one value the schema allows with a qualifier. */
function normalizeLevel(raw: string | undefined, allowed: string[]): string | undefined {
  if (!raw) return undefined;
  if (allowed.includes(raw)) return raw;
  const head = raw.replace(/\s*\(.*$/, "").trim();
  return allowed.includes(head) ? head : undefined;
}

function firstSentence(paragraph: string): string {
  const text = stripMd(paragraph.replace(/\s+/g, " "));
  const m = /^(.+?[.!?])(\s|$)/.exec(text);
  return (m?.[1] ?? text).trim();
}

// ── Load ────────────────────────────────────────────────────────────

interface Technique {
  id: string; name: string; tactic: string; tacticName: string; severity: string; description: string;
  mitigations: string[]; aliases?: string[]; lifecycleStatus?: string; replacedBy?: string[];
  severitySource?: string; upstreamSeverity?: string; severityRationale?: string;
  deprecationReason?: string; profiles?: string[]; [k: string]: unknown;
}
interface Mitigation {
  id: string; name: string; category: string; effectiveness: string; description: string;
  mitigates: string[]; relatedMitigations: string[]; [k: string]: unknown;
}

const techniquesPath = join(DATA, "techniques.json");
const mitigationsPath = join(DATA, "mitigations.json");
const techniquesBefore = readText(techniquesPath);
const mitigationsBefore = readText(mitigationsPath);
const techData = JSON.parse(techniquesBefore) as Record<string, unknown> & {
  techniques: Technique[]; framework: Record<string, unknown>; tactics: Array<{ id: string; name: string }>;
  tacticDistribution: Record<string, number>;
};
const mitData = JSON.parse(mitigationsBefore) as Record<string, unknown> & {
  mitigations: Mitigation[]; framework: Record<string, unknown>; categories: string[]; categoryDistribution: Record<string, number>;
};

const localMitById = new Map(mitData.mitigations.map((m) => [m.id, m]));

interface UpTechnique {
  technique_id: string; name: string; lifecycle_status: string; tactics?: string[]; profiles?: string[];
  aliases?: string[]; replaced_by?: string[]; deprecation?: { reason?: string };
  attack_mappings?: Array<{ id: string }>; mitigations?: string[];
}
const registry = parseYaml(readText(join(upstreamDir, "research", "framework-model.yml"))) as {
  techniques: UpTechnique[];
};

// ── Sync techniques ─────────────────────────────────────────────────

const stripComments = (s: string): string => s.replace(/<!--[\s\S]*?-->/g, "");
const SEVERITIES = ["Critical", "High", "Medium", "Low"];
const pageSeverity = (md: string | undefined): string | undefined => {
  const raw = md ? /^\s*-?\s*\*\*Severity\*\*:\s*([A-Za-z]+)/m.exec(md)?.[1] : undefined;
  if (!raw) return undefined;
  const v = raw[0]!.toUpperCase() + raw.slice(1).toLowerCase();
  return SEVERITIES.includes(v) ? v : undefined;
};
const techPage = (localId: string): string | undefined => {
  const p = join(upstreamDir, "techniques", localId.replace(/^SAFE-/, "SAF-"), "README.md");
  return existsSync(p) ? readText(p) : undefined;
};

// Severity overrides: deliberate, documented departures from upstream.
interface SeverityOverride { severity: string; rationale: string }
const overridesFile = JSON.parse(readText(join(ROOT, "scripts", "severity-overrides.json"))) as {
  overrides?: Record<string, SeverityOverride>;
};
const overrides = overridesFile.overrides ?? {};
const knownIds = new Set(registry.techniques.map((t) => toLocal(t.technique_id)));
for (const [id, o] of Object.entries(overrides)) {
  if (!knownIds.has(id)) throw new Error(`severity-overrides.json: ${id} is not an upstream technique`);
  if (!SEVERITIES.includes(o.severity)) throw new Error(`severity-overrides.json: ${id} has invalid severity "${o.severity}" (use ${SEVERITIES.join(", ")})`);
  if (!o.rationale || o.rationale.trim().length < 20) throw new Error(`severity-overrides.json: ${id} needs a rationale (at least a sentence)`);
}

const techById = new Map(techData.techniques.map((t) => [t.id, t]));
const tacticName = (id: string): string => techData.tactics.find((t) => t.id === id)?.name ?? id;
const addedTechniques: string[] = [];
const renamed: Array<[string, string, string]> = [];
const severityChanges: Array<[string, string, string]> = [];
const noUpstreamSeverity: string[] = [];

for (const up of registry.techniques) {
  const id = toLocal(up.technique_id);
  const md = techPage(id);
  let t = techById.get(id);
  if (!t) {
    const tactic = up.tactics?.[0];
    const severity = pageSeverity(md);
    const overview = stripComments(section(md ?? "", "Overview") ?? "").split(/\n\s*\n/).find((p) => p.trim()) ?? "";
    if (!tactic || !severity || !overview) {
      throw new Error(`${id}: cannot add, upstream is missing a tactic, severity, or overview`);
    }
    t = {
      id,
      name: up.name,
      tactic,
      tacticName: tacticName(tactic),
      severity,
      description: firstSentence(overview),
      mitigations: [],
      mitreAttackMapping: (up.attack_mappings ?? []).map((a) => a.id),
    };
    // Place it after the last technique of the same tactic, keeping the file's order.
    let at = -1;
    techData.techniques.forEach((x, i) => { if (x.tactic === tactic) at = i; });
    techData.techniques.splice(at === -1 ? techData.techniques.length : at + 1, 0, t);
    techById.set(id, t);
    addedTechniques.push(id);
  } else {
    if (t.name !== up.name) {
      renamed.push([id, t.name, up.name]);
      t.aliases = [...new Set([...(t.aliases ?? []), t.name])];
      t.name = up.name;
    }
  }

  // Severity: override, else upstream, else keep the local value.
  const upSev = pageSeverity(md);
  const ov = overrides[id];
  const previous = t.severity;
  if (ov) {
    if (upSev && ov.severity === upSev) {
      throw new Error(`severity-overrides.json: ${id} override equals upstream (${upSev}); remove it`);
    }
    t.severity = ov.severity;
    t.severitySource = "override";
    t.severityRationale = ov.rationale.trim();
    if (upSev) t.upstreamSeverity = upSev; else delete t.upstreamSeverity;
  } else if (upSev) {
    t.severity = upSev;
    t.severitySource = "upstream";
    delete t.upstreamSeverity;
    delete t.severityRationale;
  } else {
    t.severitySource = "local";
    delete t.upstreamSeverity;
    delete t.severityRationale;
    noUpstreamSeverity.push(id);
  }
  if (previous !== t.severity && !addedTechniques.includes(id)) severityChanges.push([id, previous, t.severity]);
  const aliases = [...new Set([...(t.aliases ?? []), ...(up.aliases ?? [])])].filter((a) => a !== t!.name);
  if (aliases.length) t.aliases = aliases; else delete t.aliases;
  t.lifecycleStatus = up.lifecycle_status;
  if (up.lifecycle_status === "deprecated") {
    t.replacedBy = (up.replaced_by ?? []).map(toLocal);
    if (up.deprecation?.reason) t.deprecationReason = up.deprecation.reason; else delete t.deprecationReason;
  } else {
    delete t.replacedBy;
    delete t.deprecationReason;
  }
  t.profiles = [...(up.profiles ?? [])];
}
const upstreamTechIds = new Set(registry.techniques.map((t) => toLocal(t.technique_id)));
const notUpstream = techData.techniques.filter((t) => !upstreamTechIds.has(t.id)).map((t) => t.id);
if (notUpstream.length) throw new Error(`Local techniques missing upstream (IDs are permanent upstream, so this needs a look): ${notUpstream.join(", ")}`);
const localTechIds = new Set(techData.techniques.map((t) => t.id));

const upMitDirs = readdirSync(join(upstreamDir, "mitigations")).filter((d) => /^SAF-M-\d+$/.test(d));
const upstreamMitIds = new Set(upMitDirs.map(toLocal));

// ── Collect upstream links ──────────────────────────────────────────

const key = (t: string, m: string): string => `${t}|${m}`;
const links = new Map<string, Set<"registry" | "mitigation page">>();
const addLink = (t: string, m: string, src: "registry" | "mitigation page"): void => {
  const k = key(t, m);
  if (!links.has(k)) links.set(k, new Set());
  links.get(k)!.add(src);
};

for (const t of registry.techniques) {
  for (const m of t.mitigations ?? []) addLink(toLocal(t.technique_id), toLocal(m), "registry");
}
const mitPages = new Map<string, string>();
for (const dir of upMitDirs) {
  const p = join(upstreamDir, "mitigations", dir, "README.md");
  if (!existsSync(p)) continue;
  const md = readText(p);
  mitPages.set(toLocal(dir), md);
  for (const tid of (section(md, "Mitigates") ?? "").match(/SAF-T\d+/g) ?? []) {
    addLink(toLocal(tid), toLocal(dir), "mitigation page");
  }
}

// Only links between techniques we ship and mitigations that exist upstream.
const kept = [...links.keys()]
  .map((k) => k.split("|") as [string, string])
  .filter(([t, m]) => localTechIds.has(t) && upstreamMitIds.has(m));
const skippedTechniques = [...new Set([...links.keys()].map((k) => k.split("|")[0]!).filter((t) => !localTechIds.has(t)))].sort();

// ── Add mitigations that upstream links to but we do not ship ───────

const EFFECTIVENESS = ["High (Provable Security)", "High", "Medium-High", "Medium"];
const COMPLEXITY = ["High", "Medium-High", "Medium", "Low-Medium", "Low"];
const added: string[] = [];
for (const m of [...new Set(kept.map(([, m]) => m))].sort(byMitNum)) {
  if (localMitById.has(m)) continue;
  const md = mitPages.get(m);
  if (!md) throw new Error(`Upstream links to ${m} but its README is missing`);
  const title = /^# SAF-M-\d+:\s*(.+)$/m.exec(md)?.[1] ?? m;
  const category = (field(md, "Category") ?? "Uncategorized").replace(/\s*\(.*$/, "");
  const name = title.replace(new RegExp(`^${category.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*-\\s*`), "").trim();
  const effectiveness = normalizeLevel(field(md, "Effectiveness"), EFFECTIVENESS);
  if (!effectiveness) throw new Error(`${m}: unrecognized effectiveness "${field(md, "Effectiveness")}"`);
  const entry: Mitigation = {
    id: m,
    name,
    category,
    effectiveness,
    implementationComplexity: normalizeLevel(field(md, "Implementation Complexity"), COMPLEXITY),
    firstPublished: field(md, "First Published"),
    description: firstSentence((section(md, "Description") ?? "").split(/\n\s*\n/)[0] ?? ""),
    mitigates: [],
    relatedMitigations: [...new Set(((section(md, "Related Mitigations") ?? "").match(/SAF-M-\d+/g) ?? []).map(toLocal))]
      .filter((r) => r !== m)
      .sort(byMitNum),
    references: [`https://github.com/safe-agentic-framework/safe-mcp/tree/${pinned.commit}/mitigations/${m.replace(/^SAFE-/, "SAF-")}`],
  };
  for (const k of Object.keys(entry)) if (entry[k] === undefined) delete entry[k];
  mitData.mitigations.push(entry);
  localMitById.set(m, entry);
  added.push(m);
}
mitData.mitigations.sort((a, b) => byMitNum(a.id, b.id));

// ── Rewrite links symmetrically ─────────────────────────────────────

const before = new Set<string>();
for (const t of techData.techniques) for (const m of t.mitigations) before.add(key(t.id, m));
for (const m of mitData.mitigations) for (const t of m.mitigates) before.add(key(t, m.id));
const after = new Set(kept.map(([t, m]) => key(t, m)));

for (const t of techData.techniques) {
  t.mitigations = kept.filter(([tid]) => tid === t.id).map(([, m]) => m).sort(byMitNum);
}
const techOrder = new Map(techData.techniques.map((t, i) => [t.id, i]));
for (const m of mitData.mitigations) {
  m.mitigates = kept.filter(([, mid]) => mid === m.id).map(([t]) => t).sort((a, b) => techOrder.get(a)! - techOrder.get(b)!);
}

// ── Recompute metadata the engine actually serves ───────────────────

const WITHDRAWN_NOTE =
  "Listed in the upstream SAF-MCP mitigation index but never published as a mitigation page, and later removed from the index. " +
  "Kept so older reports still resolve; never recommended in findings.";
for (const m of mitData.mitigations) {
  if (upstreamMitIds.has(m.id)) {
    m["lifecycleStatus"] = "active";
    delete m["withdrawnNote"];
  } else {
    m["lifecycleStatus"] = "withdrawn";
    m["withdrawnNote"] = WITHDRAWN_NOTE;
  }
}
const activeMits = mitData.mitigations.filter((m) => m["lifecycleStatus"] === "active");
const effCount = (e: string): number => activeMits.filter((m) => m.effectiveness === e).length;
const stats = {
  totalMitigations: activeMits.length,
  withdrawnMitigations: mitData.mitigations.length - activeMits.length,
  highEffectiveness: effCount("High") + effCount("High (Provable Security)"),
  mediumHighEffectiveness: effCount("Medium-High"),
  mediumEffectiveness: effCount("Medium"),
  lowEffectiveness: 0,
};
Object.assign(mitData.framework, stats);
techData.framework["totalMitigations"] = stats.totalMitigations;
const activeTechs = techData.techniques.filter((t) => t.lifecycleStatus === "active");
techData.framework["name"] = "SAF-MCP";
mitData.framework["name"] = "SAF-MCP";
techData.framework["fullName"] = "Secure Agentic Framework for Model Context Protocol (SAF-MCP, formerly SAFE-MCP)";
techData.framework["totalTechniques"] = techData.techniques.length;
techData.framework["activeTechniques"] = activeTechs.length;
techData.framework["deprecatedTechniques"] = techData.techniques.length - activeTechs.length;
const tacticDist: Record<string, number> = {};
for (const tac of techData.tactics) tacticDist[tac.name] = activeTechs.filter((t) => t.tactic === tac.id).length;
techData.tacticDistribution = tacticDist;
const catDist: Record<string, number> = {};
for (const m of activeMits) catDist[m.category] = (catDist[m.category] ?? 0) + 1;
mitData.categoryDistribution = catDist;
mitData.categories = [...new Set([...mitData.categories, ...Object.keys(catDist)])];

// The engine never reads these copies inside techniques.json; they only drift.
delete techData["mitigations"];
delete techData["mitigationStats"];
delete techData["mitigationCategoryDistribution"];

// ── Report ──────────────────────────────────────────────────────────

const dropped = [...before].filter((k) => !after.has(k)).map((k) => k.split("|") as [string, string]).sort();
const gained = [...after].filter((k) => !before.has(k)).length;
const orphaned = mitData.mitigations.filter((m) => m.mitigates.length === 0).map((m) => m.id);
const removedUpstream = mitData.mitigations.filter((m) => !upstreamMitIds.has(m.id)).map((m) => m.id);
const fromBoth = kept.filter(([t, m]) => links.get(key(t, m))!.size === 2).length;
const fromPageOnly = kept.filter(([t, m]) => { const s = links.get(key(t, m))!; return s.size === 1 && s.has("mitigation page"); }).length;
const nameOf = (id: string): string => localMitById.get(id)?.name ?? "";

const header = `Generated by \`scripts/sync-catalog.ts\` from SAF-MCP commit [\`${pinned.commit.slice(0, 7)}\`](https://github.com/safe-agentic-framework/safe-mcp/tree/${pinned.commit}). Do not edit by hand; rerun the script.`;
const list = (ids: string[]): string => (ids.length ? ids.map((m) => `- ${m}${nameOf(m) ? `: ${nameOf(m)}` : ""}`).join("\n") : "None.");

// Stable: describes the data against upstream. Checked in CI.
const deprecated = techData.techniques.filter((t) => t.lifecycleStatus === "deprecated");
const overrideRows = techData.techniques
  .filter((t) => t.severitySource === "override")
  .map((t) => `| ${t.id} | ${t.name} | ${t.upstreamSeverity ?? "none"} | ${t.severity} | ${t.severityRationale ?? ""} |`);
const techName = (id: string): string => techById.get(id)?.name ?? "";
const report = `# Catalog Sync Report

${header}

## Summary

| | Count |
|---|---|
| Techniques | ${techData.techniques.length} (${activeTechs.length} active, ${deprecated.length} deprecated) |
| Mitigations | ${mitData.mitigations.length} (${activeMits.length} active, ${mitData.mitigations.length - activeMits.length} withdrawn) |
| Technique to mitigation links | ${after.size} |
| Techniques with at least one mitigation | ${techData.techniques.filter((t) => t.mitigations.length > 0).length} of ${techData.techniques.length} |
| Links in both the registry and a mitigation page | ${fromBoth} |
| Links only on a mitigation page (missing from the upstream registry) | ${fromPageOnly} |

## Deprecated techniques

Kept so lookups and older reports resolve. Rules must target the replacement instead (enforced by \`src/tests/catalog.ts\`).

| Technique | Name | Replaced by |
|---|---|---|
${deprecated.map((t) => `| ${t.id} | ${t.name} | ${(t.replacedBy ?? []).map((r) => `${r} ${techName(r)}`).join("; ")} |`).join("\n")}

## Severity

Severities come from upstream technique pages, except for the overrides below (from \`scripts/severity-overrides.json\`).

### Overrides

| Technique | Name | Upstream | Used here | Rationale |
|---|---|---|---|---|
${overrideRows.length ? overrideRows.join("\n") : "| none | | | | |"}

### No upstream severity

These pages state no severity, so the existing local value is kept.

${list(noUpstreamSeverity)}

## Withdrawn mitigations

${WITHDRAWN_NOTE}

${list(removedUpstream)}

## Upstream techniques not shipped locally

${list(skippedTechniques)}

## Mitigations with no links

${list(orphaned.filter((m) => !removedUpstream.includes(m)))}
`;

// One time: what this particular run changed. For PR review, not checked.
const changes = `# Catalog Sync Changes

${header}

This file records what the most recent sync changed. It is rewritten only when a sync changes something.

## Techniques added

${list(addedTechniques)}

## Severity changes

${severityChanges.length ? severityChanges.sort((a, b) => a[0].localeCompare(b[0])).map(([id, a, b]) => `- ${id} ${techName(id)}: ${a} → ${b}`).join("\n") : "None."}

## Techniques renamed upstream

Old names are kept in \`aliases\`, so searches for them still match.

${renamed.length ? renamed.map(([id, a, b]) => `- ${id}: ${a} → ${b}`).join("\n") : "None."}

## Links

- Links before: ${before.size}
- Links after: ${after.size}
- Links added: ${gained}
- Links dropped: ${dropped.length}

## Mitigations added from upstream

${list(added)}

## Local links dropped

Each pair existed in this repo but appears in neither upstream source. If one is correct, propose it upstream (registry entry and mitigation page) rather than restoring it here.

| Technique | Mitigation | Mitigation exists upstream |
|---|---|---|
${dropped.map(([t, m]) => `| ${t} | ${m} ${nameOf(m)} | ${upstreamMitIds.has(m) ? "yes" : "no (removed)"} |`).join("\n")}
`;

// ── Write or check ──────────────────────────────────────────────────

const techniquesAfter = JSON.stringify(techData, null, 2) + "\n";
const mitigationsAfter = JSON.stringify(mitData, null, 2) + "\n";
const reportBefore = existsSync(REPORT) ? readText(REPORT) : "";

if (check) {
  const drift = [
    techniquesAfter !== techniquesBefore && "src/data/techniques.json",
    mitigationsAfter !== mitigationsBefore && "src/data/mitigations.json",
    report !== reportBefore && "docs/catalog-sync-report.md",
  ].filter(Boolean);
  if (drift.length) {
    console.error(`Out of sync with upstream ${pinned.commit.slice(0, 7)}: ${drift.join(", ")}.\nRun: npx tsx scripts/sync-catalog.ts --upstream <path>`);
    process.exit(1);
  }
  console.log(`Catalog matches upstream ${pinned.commit.slice(0, 7)}.`);
} else {
  writeFileSync(techniquesPath, techniquesAfter);
  writeFileSync(mitigationsPath, mitigationsAfter);
  writeFileSync(REPORT, report);
  if (gained > 0 || dropped.length > 0 || added.length > 0 || addedTechniques.length > 0 || renamed.length > 0 || severityChanges.length > 0) {
    writeFileSync(CHANGES, changes);
  }
  console.log(
    `Synced from ${pinned.commit.slice(0, 7)}: ${techData.techniques.length} techniques (${addedTechniques.length} added, ` +
      `${renamed.length} renamed), ${after.size} links (was ${before.size}), ${added.length} mitigations added. ` +
      `See docs/catalog-sync-report.md.`,
  );
}
