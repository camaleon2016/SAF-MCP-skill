/**
 * Package checks: the library entry point is side effect free, the command
 * entry point is runnable, and every version string agrees.
 */
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import * as lib from "../lib.js";

let passed = 0;
let failed = 0;
async function test(name: string, fn: () => void | Promise<void>): Promise<void> {
  try {
    await fn();
    passed++;
    console.log(`  ✓ [PASS] ${name}`);
  } catch (err) {
    failed++;
    console.log(`  ✗ [FAIL] ${name}\n      ${err instanceof Error ? err.message : String(err)}`);
  }
}

const pkg = JSON.parse(readFileSync("package.json", "utf-8")) as {
  version: string; main: string; types: string; bin: Record<string, string>;
  exports: Record<string, unknown>; files: string[];
};

console.log("\nPackage\n");

await test("PKG-001: importing the library exits on its own with stdin open (no stdio server)", async () => {
  const child = spawn(process.execPath, ["--import", "tsx", "src/tests/fixtures/import-lib.ts"], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  let out = "";
  let err = "";
  child.stdout.on("data", (d) => (out += String(d)));
  child.stderr.on("data", (d) => (err += String(d)));
  // Deliberately never end stdin: an idle pipe is what kept the old entry point alive.
  const code = await new Promise<number | null>((resolve) => {
    const timer = setTimeout(() => {
      child.kill();
      resolve(null);
    }, 15_000);
    child.on("exit", (c) => {
      clearTimeout(timer);
      resolve(c);
    });
  });
  if (code === null) throw new Error("still running after 15s: importing the library started something long lived");
  if (code !== 0) throw new Error(`exited with ${code}: ${err.trim().slice(0, 300)}`);
  const lines = out.trim().split("\n");
  if (lines.length !== 1) throw new Error(`expected exactly one line of output, got: ${out.slice(0, 300)}`);
  const parsed = JSON.parse(lines[0]!) as { version: string; risk: string };
  if (parsed.version !== pkg.version || parsed.risk !== "Critical") throw new Error(`unexpected output ${lines[0]}`);
});

await test("PKG-002: the library exports the documented API", () => {
  const expected = [
    "VERSION", "analyzeTool", "analyzeServer", "analyzeArchitecture", "openAiFunctions", "dispatch",
    "getMappings", "getCoverage", "STRIDE_LABELS", "discoverAndAnalyzeStdio", "discoverAndAnalyzeHttp",
    "discoverAndAnalyzeConfig", "normalizeId", "getTechnique", "getMitigation", "searchTechniques",
    "searchMitigations", "getMitigationsForTechnique", "getTechniquesForMitigation", "getThreatProfile",
    "getFrameworkStats", "rankMitigationsByImpact", "getUnmitigatedTechniques",
  ];
  const missing = expected.filter((k) => !(k in lib));
  if (missing.length) throw new Error(`missing exports: ${missing.join(", ")}`);
});

await test("PKG-003: every version string matches package.json", () => {
  const spec = JSON.parse(readFileSync("src/openapi/openapi.json", "utf-8")) as { info: { version: string } };
  const mismatches = [
    lib.VERSION !== pkg.version && `src/version.ts says ${lib.VERSION}`,
    spec.info.version !== pkg.version && `openapi.json says ${spec.info.version}`,
  ].filter(Boolean);
  if (mismatches.length) throw new Error(`package.json is ${pkg.version}; ${mismatches.join("; ")}`);
});

await test("PKG-004: entry points are wired correctly", () => {
  const problems: string[] = [];
  if (pkg.main !== "dist/lib.js") problems.push(`main is ${pkg.main}`);
  if (pkg.types !== "dist/lib.d.ts") problems.push(`types is ${pkg.types}`);
  if (pkg.bin["safe-mcp-skill"] !== "dist/index.js") problems.push("bin does not point at dist/index.js");
  if (!readFileSync("src/index.ts", "utf-8").startsWith("#!/usr/bin/env node")) problems.push("src/index.ts lacks a shebang");
  if (/^export /m.test(readFileSync("src/index.ts", "utf-8"))) problems.push("src/index.ts exports API; it must stay command only");
  if (problems.length) throw new Error(problems.join("; "));
});

console.log(`\n  Total: ${passed + failed} | Passed: ${passed} | Failed: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
