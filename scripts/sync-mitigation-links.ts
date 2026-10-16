/**
 * Regenerate technique <-> mitigation links in src/data from the upstream
 * SAF-MCP catalog, so every link traces to an upstream source.
 *
 * Usage:
 *   npx tsx scripts/sync-mitigation-links.ts --upstream <path to safe-mcp checkout>
 *   npx tsx scripts/sync-mitigation-links.ts --upstream <path> --check   (CI: fail on drift)
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
const REPORT = join(ROOT, "docs", "mitigation-link-report.md");
const CHANGES = join(ROOT, "docs", "mitigation-link-changes.md");

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

interface Technique { id: string; mitigations: string[]; [k: string]: unknown }
interface Mitigation {
  id: string; name: string; category: string; effectiveness: string; description: string;
  mitigates: string[]; relatedMitigations: string[]; [k: string]: unknown;
}

const techniquesPath = join(DATA, "techniques.json");
const mitigationsPath = join(DATA, "mitigations.json");
const techniquesBefore = readText(techniquesPath);
const mitigationsBefore = readText(mitigationsPath);
const techData = JSON.parse(techniquesBefore) as Record<string, unknown> & { techniques: Technique[]; framework: Record<string, unknown> };
const mitData = JSON.parse(mitigationsBefore) as Record<string, unknown> & {
  mitigations: Mitigation[]; framework: Record<string, unknown>; categories: string[]; categoryDistribution: Record<string, number>;
};

const localTechIds = new Set(techData.techniques.map((t) => t.id));
const localMitById = new Map(mitData.mitigations.map((m) => [m.id, m]));

const registry = parseYaml(readText(join(upstreamDir, "research", "framework-model.yml"))) as {
  techniques: Array<{ technique_id: string; mitigations?: string[] }>;
};

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

const effCount = (e: string): number => mitData.mitigations.filter((m) => m.effectiveness === e).length;
const stats = {
  totalMitigations: mitData.mitigations.length,
  highEffectiveness: effCount("High") + effCount("High (Provable Security)"),
  mediumHighEffectiveness: effCount("Medium-High"),
  mediumEffectiveness: effCount("Medium"),
  lowEffectiveness: 0,
};
Object.assign(mitData.framework, stats);
techData.framework["totalMitigations"] = stats.totalMitigations;
const catDist: Record<string, number> = {};
for (const m of mitData.mitigations) catDist[m.category] = (catDist[m.category] ?? 0) + 1;
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

const header = `Generated by \`scripts/sync-mitigation-links.ts\` from SAF-MCP commit [\`${pinned.commit.slice(0, 7)}\`](https://github.com/safe-agentic-framework/safe-mcp/tree/${pinned.commit}). Do not edit by hand; rerun the script.`;
const list = (ids: string[]): string => (ids.length ? ids.map((m) => `- ${m}${nameOf(m) ? `: ${nameOf(m)}` : ""}`).join("\n") : "None.");

// Stable: describes the data against upstream. Checked in CI.
const report = `# Mitigation Link Report

${header}

## Summary

| | Count |
|---|---|
| Technique to mitigation links | ${after.size} |
| Techniques with at least one mitigation | ${techData.techniques.filter((t) => t.mitigations.length > 0).length} of ${techData.techniques.length} |
| Links in both the registry and a mitigation page | ${fromBoth} |
| Links only on a mitigation page (missing from the upstream registry) | ${fromPageOnly} |
| Mitigations shipped | ${mitData.mitigations.length} |

## Mitigations shipped locally but removed upstream

These have no links until the catalog sync removes or replaces them.

${list(removedUpstream)}

## Upstream techniques not shipped locally

Links to these are skipped until the catalog sync adds them.

${list(skippedTechniques)}

## Orphaned mitigations

${list(orphaned)}
`;

// One time: what this particular run changed. For PR review, not checked.
const changes = `# Mitigation Link Changes

${header}

This file records what the most recent sync changed. It is rewritten only when a sync changes links.

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
    report !== reportBefore && "docs/mitigation-link-report.md",
  ].filter(Boolean);
  if (drift.length) {
    console.error(`Out of sync with upstream ${pinned.commit.slice(0, 7)}: ${drift.join(", ")}.\nRun: npx tsx scripts/sync-mitigation-links.ts --upstream <path>`);
    process.exit(1);
  }
  console.log(`Mitigation links match upstream ${pinned.commit.slice(0, 7)}.`);
} else {
  writeFileSync(techniquesPath, techniquesAfter);
  writeFileSync(mitigationsPath, mitigationsAfter);
  writeFileSync(REPORT, report);
  if (gained > 0 || dropped.length > 0 || added.length > 0) writeFileSync(CHANGES, changes);
  console.log(
    `Synced from ${pinned.commit.slice(0, 7)}: ${after.size} links (was ${before.size}), ` +
      `${added.length} mitigations added, ${dropped.length} local links dropped. See docs/mitigation-link-report.md.`,
  );
}
