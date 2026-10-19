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
  if (pkg.bin["saf-mcp-skill"] !== "dist/index.js") problems.push("bin does not point at dist/index.js");
  if (!readFileSync("src/index.ts", "utf-8").startsWith("#!/usr/bin/env node")) problems.push("src/index.ts lacks a shebang");
  if (/^export /m.test(readFileSync("src/index.ts", "utf-8"))) problems.push("src/index.ts exports API; it must stay command only");
  if (problems.length) throw new Error(problems.join("; "));
});

await test("PKG-005: the OpenAPI spec documents every REST route the server handles", () => {
  const server = readFileSync("src/openapi/serve.ts", "utf-8");
  const spec = JSON.parse(readFileSync("src/openapi/openapi.json", "utf-8")) as { paths: Record<string, Record<string, unknown>> };
  const routes = new Set<string>();
  for (const m of server.matchAll(/req\.method === "([A-Z]+)" && path === "([^"]+)"/g)) routes.add(`${m[1]!.toLowerCase()} ${m[2]}`);
  for (const m of server.matchAll(/path\.match\(\/\^\\\/v1\\\/([a-z-]+)\\\/\(\.\+\)\$\/\)/g)) routes.add(`get /v1/${m[1]}/{id}`);
  const missing = [...routes].filter((r) => {
    const [method, route] = r.split(" ") as [string, string];
    return !spec.paths[route]?.[method];
  });
  if (routes.size < 15) throw new Error(`found only ${routes.size} routes in serve.ts; the route pattern may have changed`);
  if (missing.length) throw new Error(`routes missing from openapi.json: ${missing.join(", ")}`);
});

await test("PKG-006: versions quoted in the README match package.json", () => {
  const readme = readFileSync("README.md", "utf-8");
  const quoted = [
    ...[...readme.matchAll(/saf-mcp-skill@(\d+\.\d+\.\d+)/g)].map((m) => m[1]!),
    ...[...readme.matchAll(/"serverVersion": "(\d+\.\d+\.\d+)"/g)].map((m) => m[1]!),
  ];
  const stale = [...new Set(quoted.filter((v) => v !== pkg.version))];
  if (stale.length) throw new Error(`README quotes ${stale.join(", ")}; package.json is ${pkg.version}`);
});

await test("PKG-007: the lockfile and publish target use only the public npm registry", () => {
  const lock = JSON.parse(readFileSync("package-lock.json", "utf-8")) as { packages?: Record<string, { resolved?: string }> };
  const other = new Set<string>();
  for (const entry of Object.values(lock.packages ?? {})) {
    if (entry.resolved && !entry.resolved.startsWith("https://registry.npmjs.org/")) other.add(new URL(entry.resolved).host);
  }
  if (other.size) {
    throw new Error(
      `package-lock.json resolves packages from ${[...other].join(", ")}. ` +
        "This usually means npm install ran against a private or corporate registry; reinstall with --registry=https://registry.npmjs.org/.",
    );
  }
  const publishTo = (JSON.parse(readFileSync("package.json", "utf-8")) as { publishConfig?: { registry?: string } }).publishConfig?.registry;
  if (publishTo !== "https://registry.npmjs.org/") throw new Error(`publishConfig.registry is ${publishTo ?? "unset"}`);
});

await test("PKG-008: the README tool table lists exactly the registered MCP tools", () => {
  const server = readFileSync("src/server.ts", "utf-8");
  const readme = readFileSync("README.md", "utf-8");
  const registered = new Set([...server.matchAll(/registerTool\(\s*"([a-z_]+)"/g)].map((m) => m[1]!));
  const section = readme.slice(readme.indexOf("## MCP Tools"), readme.indexOf("## Rules Engine"));
  const listed = new Set([...section.matchAll(/^\| `([a-z_]+)` \|/gm)].map((m) => m[1]!));
  const claimed = Number(/exposes (\d+) tools/.exec(section)?.[1]);
  const problems = [
    ...[...registered].filter((t) => !listed.has(t)).map((t) => `${t} missing from README`),
    ...[...listed].filter((t) => !registered.has(t)).map((t) => `${t} in README but not registered`),
    ...(claimed !== registered.size ? [`README says ${claimed} tools; ${registered.size} are registered`] : []),
  ];
  if (problems.length) throw new Error(problems.join("; "));
});

console.log(`\n  Total: ${passed + failed} | Passed: ${passed} | Failed: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
