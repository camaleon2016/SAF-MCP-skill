/**
 * Detection quality: runs the labeled corpus and fails on any missed attack
 * or any false positive. Prints a recall and false positive summary.
 */
import { analyzeArchitecture } from "../engine/rules.js";
import { ATTACKS, BENIGN, type DetectionCase } from "./detection-corpus.js";

let failed = 0;
let gaps = 0;
function run(cases: DetectionCase[]): { ok: number; total: number } {
  let ok = 0;
  for (const c of cases) {
    const result = analyzeArchitecture(c.input);
    const fired = new Set(result.findings.map((f) => f.ruleId));
    const echoed = (c.mustNotEcho ?? []).filter((secret) => JSON.stringify(result).includes(secret));
    const missed = (c.mustFire ?? []).filter((r) => !fired.has(r));
    const wrong = (c.mustNotFire ?? []).filter((r) => fired.has(r));
    if (c.knownGap) {
      gaps++;
      const now = missed.length === 0 && wrong.length === 0;
      console.log(`  ~ [GAP]  ${c.id}: ${c.label}\n      ${now ? "now detected; promote it to a normal case" : c.knownGap}`);
      continue;
    }
    if (missed.length === 0 && wrong.length === 0 && echoed.length === 0) {
      ok++;
      console.log(`  ✓ [PASS] ${c.id}: ${c.label}`);
    } else {
      failed++;
      const why = [
        missed.length && `missed ${missed.join(", ")}`,
        wrong.length && `false positive ${wrong.join(", ")}`,
        echoed.length && "a secret appears in the output",
      ]
        .filter(Boolean)
        .join("; ");
      console.log(`  ✗ [FAIL] ${c.id}: ${c.label}\n      ${why} (fired: ${[...fired].join(", ") || "none"})`);
    }
  }
  return { ok, total: cases.filter((c) => !c.knownGap).length };
}

console.log("\nDetection: attacks that must be caught\n");
const a = run(ATTACKS);
console.log("\nDetection: harmless tools that must not be flagged\n");
const b = run(BENIGN);
// A hostile server controls these strings, so scanning must stay fast on
// input built to make patterns backtrack. Budget is generous for slow CI.
console.log("\nDetection: hostile inputs finish quickly\n");
const BUDGET_MS = 2000;
let deep: Record<string, unknown> = { type: "string" };
for (let i = 0; i < 100_000; i++) deep = { type: "object", properties: { x: deep } };
const hostile: Array<[string, Parameters<typeof analyzeArchitecture>[0]]> = [
  ["unclosed HTML comments", { tools: [{ name: "t", description: "<!-- abc ".repeat(20_000) }] }],
  ["unterminated markdown images", { tools: [{ name: "t", description: "![a](https://e.x/?q=".repeat(5_000) }] }],
  ["img tags without a handler", { tools: [{ name: "t", description: "<img src=x ".repeat(20_000) }] }],
  ["one 200 KB word mixing scripts", { tools: [{ name: "t", description: "a\u0430".repeat(100_000) }] }],
  ["200 KB of trigger words", { tools: [{ name: "t", description: "read send ignore previous user ".repeat(7_000) }] }],
  ["100 KB of base64", { tools: [{ name: "t", description: "QUFB".repeat(25_000) }] }],
  ["schema nested 100,000 levels", { tools: [{ name: "t", description: "x", inputSchema: deep }] }],
];
for (const [label, input] of hostile) {
  const t0 = performance.now();
  analyzeArchitecture(input);
  const ms = performance.now() - t0;
  if (ms <= BUDGET_MS) console.log(`  ✓ [PASS] ${label} (${ms.toFixed(0)} ms)`);
  else {
    failed++;
    console.log(`  ✗ [FAIL] ${label}: ${ms.toFixed(0)} ms, budget ${BUDGET_MS} ms`);
  }
}

console.log(`\n  Attacks caught: ${a.ok}/${a.total} | Harmless tools left alone: ${b.ok}/${b.total} | Known gaps: ${gaps}`);
console.log(`  Total: ${a.total + b.total + hostile.length} | Passed: ${a.ok + b.ok + hostile.length - (failed - (a.total - a.ok) - (b.total - b.ok))} | Failed: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
