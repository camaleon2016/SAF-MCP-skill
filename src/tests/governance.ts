/**
 * Governance tests: the skill's own attack surface.
 * Unit checks on the policy module, then end to end attacks against a
 * live REST server started as a child process.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { IncomingMessage } from "node:http";
import {
  PolicyError,
  setNetworkMode,
  resetPolicyMode,
  enforceStartupPolicy,
  checkBrowserSafety,
  assertCommandDiscoveryAllowed,
  assertUrlAllowed,
} from "../governance/policy.js";
import { checkAccess, getClientIp } from "../governance/access.js";

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

function assert(cond: unknown, msg: string): void {
  if (!cond) throw new Error(msg);
}

async function throwsPolicy(fn: () => unknown | Promise<unknown>, label: string): Promise<void> {
  try {
    await fn();
  } catch (err) {
    if (err instanceof PolicyError) return;
    throw new Error(`${label}: expected PolicyError, got ${String(err)}`);
  }
  throw new Error(`${label}: expected PolicyError, nothing was thrown`);
}

const GOV_VARS = [
  "HOST", "SAFE_MCP_REQUIRE_API_KEY", "SAFE_MCP_API_KEYS", "SAFE_MCP_REQUIRE_IP_ALLOWLIST",
  "SAFE_MCP_IP_ALLOWLIST", "SAFE_MCP_TRUST_PROXY", "SAFE_MCP_ALLOW_INSECURE_BIND",
  "SAFE_MCP_ALLOW_COMMAND_DISCOVERY", "SAFE_MCP_ALLOW_PRIVATE_URLS", "SAFE_MCP_CORS_ORIGINS",
  "SAFE_MCP_ALLOWED_HOSTS",
];

function withEnv(vars: Record<string, string>): void {
  for (const k of GOV_VARS) delete process.env[k];
  Object.assign(process.env, vars);
  resetPolicyMode();
}

function fakeReq(opts: {
  ip?: string;
  headers?: Record<string, string>;
  method?: string;
}): IncomingMessage {
  return {
    method: opts.method ?? "GET",
    headers: { host: "127.0.0.1:3002", ...(opts.headers ?? {}) },
    socket: { remoteAddress: opts.ip ?? "127.0.0.1" },
  } as unknown as IncomingMessage;
}

const KEY = "test-key-0123456789abcdef";

console.log("\nGovernance: unit checks\n");

await test("GOV-001: X-Forwarded-For is ignored unless SAFE_MCP_TRUST_PROXY=true", () => {
  withEnv({});
  const req = fakeReq({ ip: "203.0.113.9", headers: { "x-forwarded-for": "10.0.0.1" } });
  assert(getClientIp(req) === "203.0.113.9", `got ${getClientIp(req)}`);
});

await test("GOV-002: with a trusted proxy, the rightmost X-Forwarded-For entry is used", () => {
  withEnv({ SAFE_MCP_TRUST_PROXY: "true" });
  const req = fakeReq({ headers: { "x-forwarded-for": "10.0.0.1, 198.51.100.7" } });
  assert(getClientIp(req) === "198.51.100.7", `got ${getClientIp(req)}`);
});

await test("GOV-003: CIDR allowlist entries match addresses inside the range", () => {
  withEnv({ SAFE_MCP_REQUIRE_IP_ALLOWLIST: "true", SAFE_MCP_IP_ALLOWLIST: "10.0.0.0/8" });
  assert(checkAccess(fakeReq({ ip: "10.20.30.40" })).allowed, "10.20.30.40 should be allowed");
  assert(checkAccess(fakeReq({ ip: "::ffff:10.1.2.3" })).allowed, "IPv4 mapped address should be allowed");
  assert(!checkAccess(fakeReq({ ip: "11.0.0.1" })).allowed, "11.0.0.1 should be denied");
});

await test("GOV-004: a spoofed X-Forwarded-For cannot satisfy the allowlist", () => {
  withEnv({ SAFE_MCP_REQUIRE_IP_ALLOWLIST: "true", SAFE_MCP_IP_ALLOWLIST: "10.0.0.0/8" });
  const req = fakeReq({ ip: "203.0.113.9", headers: { "x-forwarded-for": "10.0.0.1" } });
  assert(!checkAccess(req).allowed, "spoofed header should not grant access");
});

await test("GOV-005: API key required, missing or wrong key is denied, right key allowed", () => {
  withEnv({ SAFE_MCP_REQUIRE_API_KEY: "true", SAFE_MCP_API_KEYS: KEY });
  assert(!checkAccess(fakeReq({})).allowed, "missing key should be denied");
  assert(!checkAccess(fakeReq({ headers: { "x-api-key": "nope" } })).allowed, "wrong key should be denied");
  assert(checkAccess(fakeReq({ headers: { "x-api-key": KEY } })).allowed, "right key should be allowed");
  assert(checkAccess(fakeReq({ headers: { authorization: `Bearer ${KEY}` } })).allowed, "bearer form should be allowed");
});

await test("GOV-006: startup refuses REQUIRE_API_KEY with no keys (no fail open)", async () => {
  withEnv({ SAFE_MCP_REQUIRE_API_KEY: "true" });
  await throwsPolicy(() => enforceStartupPolicy("127.0.0.1"), "empty keys");
});

await test("GOV-007: startup refuses REQUIRE_IP_ALLOWLIST with an empty or invalid list", async () => {
  withEnv({ SAFE_MCP_REQUIRE_IP_ALLOWLIST: "true" });
  await throwsPolicy(() => enforceStartupPolicy("127.0.0.1"), "empty allowlist");
  withEnv({ SAFE_MCP_REQUIRE_IP_ALLOWLIST: "true", SAFE_MCP_IP_ALLOWLIST: "10.0.0.0/99" });
  await throwsPolicy(() => enforceStartupPolicy("127.0.0.1"), "bad prefix");
});

await test("GOV-008: startup refuses a non loopback bind without API keys", async () => {
  withEnv({});
  setNetworkMode("0.0.0.0");
  await throwsPolicy(() => enforceStartupPolicy("0.0.0.0"), "open bind");
  withEnv({ SAFE_MCP_REQUIRE_API_KEY: "true", SAFE_MCP_API_KEYS: KEY });
  setNetworkMode("0.0.0.0");
  enforceStartupPolicy("0.0.0.0");
  withEnv({ SAFE_MCP_ALLOW_INSECURE_BIND: "true" });
  setNetworkMode("0.0.0.0");
  enforceStartupPolicy("0.0.0.0");
});

await test("GOV-009: command discovery is allowed over stdio and off on network transports", async () => {
  withEnv({});
  assertCommandDiscoveryAllowed();
  setNetworkMode("127.0.0.1");
  await throwsPolicy(() => assertCommandDiscoveryAllowed(), "network default");
});

await test("GOV-010: enabling command discovery on a network transport requires API keys", async () => {
  withEnv({ SAFE_MCP_ALLOW_COMMAND_DISCOVERY: "true" });
  setNetworkMode("127.0.0.1");
  await throwsPolicy(() => enforceStartupPolicy("127.0.0.1"), "no keys");
  withEnv({ SAFE_MCP_ALLOW_COMMAND_DISCOVERY: "true", SAFE_MCP_REQUIRE_API_KEY: "true", SAFE_MCP_API_KEYS: KEY });
  setNetworkMode("127.0.0.1");
  enforceStartupPolicy("127.0.0.1");
  assertCommandDiscoveryAllowed();
});

await test("GOV-011: URL discovery blocks metadata, link local, and non http schemes", async () => {
  withEnv({});
  await throwsPolicy(() => assertUrlAllowed("http://169.254.169.254/latest/meta-data/"), "AWS metadata");
  await throwsPolicy(() => assertUrlAllowed("http://[fe80::1]/"), "link local v6");
  await throwsPolicy(() => assertUrlAllowed("http://[::ffff:169.254.169.254]/"), "mapped metadata");
  await throwsPolicy(() => assertUrlAllowed("file:///etc/passwd"), "file scheme");
});

await test("GOV-012: private targets allowed on a loopback bind, blocked when exposed", async () => {
  withEnv({});
  setNetworkMode("127.0.0.1");
  await assertUrlAllowed("http://127.0.0.1:3001/v1/mcp");
  withEnv({ SAFE_MCP_REQUIRE_API_KEY: "true", SAFE_MCP_API_KEYS: KEY });
  setNetworkMode("0.0.0.0");
  await throwsPolicy(() => assertUrlAllowed("http://10.0.0.5:3001/mcp"), "private when exposed");
  process.env["SAFE_MCP_ALLOW_PRIVATE_URLS"] = "true";
  await assertUrlAllowed("http://10.0.0.5:3001/mcp");
});

await test("GOV-013: cross origin browser requests are refused", () => {
  withEnv({});
  setNetworkMode("127.0.0.1");
  const evil = fakeReq({ method: "POST", headers: { origin: "https://evil.example", "content-type": "application/json" } });
  assert(!checkBrowserSafety(evil).allowed, "foreign origin should be refused");
  const nullOrigin = fakeReq({ method: "POST", headers: { origin: "null", "content-type": "application/json" } });
  assert(!checkBrowserSafety(nullOrigin).allowed, "null origin should be refused");
  process.env["SAFE_MCP_CORS_ORIGINS"] = "https://tools.example";
  const ok = fakeReq({ method: "POST", headers: { origin: "https://tools.example", "content-type": "application/json" } });
  assert(checkBrowserSafety(ok).allowed, "listed origin should be allowed");
});

await test("GOV-014: DNS rebinding (foreign Host header on a loopback bind) is refused", () => {
  withEnv({});
  setNetworkMode("127.0.0.1");
  assert(!checkBrowserSafety(fakeReq({ headers: { host: "attacker.example:3002" } })).allowed, "foreign host");
  assert(checkBrowserSafety(fakeReq({ headers: { host: "localhost:3002" } })).allowed, "localhost");
  assert(checkBrowserSafety(fakeReq({ headers: { host: "[::1]:3002" } })).allowed, "ipv6 loopback");
});

await test("GOV-015: POST bodies that skip the CORS preflight (text/plain) are refused", () => {
  withEnv({});
  setNetworkMode("127.0.0.1");
  const req = fakeReq({ method: "POST", headers: { "content-type": "text/plain" } });
  assert(!checkBrowserSafety(req).allowed, "text/plain POST should be refused");
});

// ── End to end against a live REST server ─────────────────────────

console.log("\nGovernance: end to end against the REST server\n");

const PORT = 3902;
const BASE = `http://127.0.0.1:${PORT}`;
const MARKER = join(tmpdir(), `safe-mcp-gov-${process.pid}`);

function startServer(env: Record<string, string>): Promise<{ proc: ChildProcess; output: () => string }> {
  const childEnv: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined && !GOV_VARS.includes(k)) childEnv[k] = v;
  Object.assign(childEnv, { PORT: String(PORT), LOG_TO_FILE: "false", LOG_TO_STDERR: "false" }, env);
  const proc = spawn(process.execPath, ["--import", "tsx", "src/openapi/serve.ts"], { env: childEnv });
  let out = "";
  proc.stderr?.on("data", (d) => (out += String(d)));
  proc.stdout?.on("data", (d) => (out += String(d)));
  return new Promise((resolve) => {
    const deadline = Date.now() + 15_000;
    const poll = async (): Promise<void> => {
      if (proc.exitCode !== null) return resolve({ proc, output: () => out });
      try {
        await fetch(`${BASE}/health`);
        return resolve({ proc, output: () => out });
      } catch {
        if (Date.now() > deadline) return resolve({ proc, output: () => out });
        setTimeout(poll, 200);
      }
    };
    void poll();
  });
}

async function stop(proc: ChildProcess): Promise<void> {
  if (proc.exitCode !== null) return;
  proc.kill();
  await new Promise((r) => proc.once("exit", r));
}

const spawnPayload = JSON.stringify({ command: "sh", args: ["-c", `touch ${MARKER}`] });

{
  rmSync(MARKER, { force: true });
  const { proc } = await startServer({});

  await test("E2E-001: default REST server refuses stdio discovery and nothing runs", async () => {
    const r = await fetch(`${BASE}/v1/discover/stdio`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: spawnPayload,
    });
    assert(r.status === 403, `expected 403, got ${r.status}`);
    await new Promise((res) => setTimeout(res, 500));
    assert(!existsSync(MARKER), "marker file was created: command ran");
  });

  await test("E2E-002: config discovery with a command entry does not run it", async () => {
    const configJson = JSON.stringify({ mcpServers: { x: { command: "sh", args: ["-c", `touch ${MARKER}`] } } });
    const r = await fetch(`${BASE}/v1/discover/config`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ configJson }),
    });
    const body = (await r.json()) as { discovered?: { servers?: Array<{ error?: string }> } };
    await new Promise((res) => setTimeout(res, 500));
    assert(!existsSync(MARKER), "marker file was created: command ran");
    assert(/disabled/.test(body.discovered?.servers?.[0]?.error ?? ""), "entry should report the policy error");
  });

  await test("E2E-003: browser preflight from a foreign origin is refused", async () => {
    const r = await fetch(`${BASE}/v1/discover/http`, {
      method: "OPTIONS",
      headers: { Origin: "https://evil.example", "Access-Control-Request-Method": "POST" },
    });
    assert(r.status === 403, `expected 403, got ${r.status}`);
    assert(!r.headers.get("access-control-allow-origin"), "no CORS allow header expected");
  });

  await test("E2E-004: DNS rebinding Host header is refused", async () => {
    const r = await new Promise<number>((resolve, reject) => {
      // fetch() will not let us set Host, so use the http module directly.
      import("node:http").then(({ request }) => {
        const q = request({ host: "127.0.0.1", port: PORT, path: "/v1/framework/stats", headers: { Host: "attacker.example" } },
          (res) => { res.resume(); resolve(res.statusCode ?? 0); });
        q.on("error", reject);
        q.end();
      }, reject);
    });
    assert(r === 403, `expected 403, got ${r}`);
  });

  await test("E2E-005: metadata URL discovery is blocked", async () => {
    const r = await fetch(`${BASE}/v1/discover/http`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "http://169.254.169.254/latest/meta-data/" }),
    });
    assert(r.status === 403, `expected 403, got ${r.status}`);
  });

  await test("E2E-006: normal analysis still works", async () => {
    const r = await fetch(`${BASE}/v1/analyze/tool`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "exec", description: "Execute arbitrary shell commands" }),
    });
    assert(r.status === 200, `expected 200, got ${r.status}`);
  });

  await stop(proc);
}

await test("E2E-007: server refuses to start on 0.0.0.0 without API keys", async () => {
  const { proc, output } = await startServer({ HOST: "0.0.0.0" });
  await new Promise((r) => (proc.exitCode !== null ? r(null) : proc.once("exit", r)));
  assert(proc.exitCode === 1, `expected exit code 1, got ${proc.exitCode}`);
  assert(/Refusing to start/.test(output()), "expected a refusal message");
});

rmSync(MARKER, { force: true });
console.log(`\n  Total: ${passed + failed} | Passed: ${passed} | Failed: ${failed}\n`);
process.exit(failed > 0 ? 1 : 0);
