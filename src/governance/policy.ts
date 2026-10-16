/**
 * Security policy for the skill's own attack surface.
 *
 * Everything here reads process.env at call time (not import time) so the
 * policy is testable and so a misconfiguration is reported where it is used.
 *
 * Threat model in one paragraph: the stdio entry point is launched by a local
 * user who is already the operator, so command discovery is allowed there.
 * The HTTP and REST entry points accept requests from other parties
 * (other hosts, or a browser tab via cross origin requests and DNS rebinding),
 * so on those transports anything that spawns a process is off unless the
 * operator turns it on AND requires API keys.
 */
import { BlockList, isIP } from "node:net";
import { lookup } from "node:dns/promises";
import type { IncomingMessage } from "node:http";

export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
}

// ── Env helpers ─────────────────────────────────────────────────────

function envFlag(name: string): boolean | undefined {
  const v = process.env[name];
  if (v === undefined || v === "") return undefined;
  return v.toLowerCase() === "true";
}

export function envList(name: string): string[] {
  return (process.env[name] ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

// ── Transport mode ──────────────────────────────────────────────────

let networkMode = false;
let bindHost = "127.0.0.1";

/** Called once by the HTTP and REST entry points before listening. */
export function setNetworkMode(host: string): void {
  networkMode = true;
  bindHost = host;
}

/** Test helper: return to the default (stdio) mode. */
export function resetPolicyMode(): void {
  networkMode = false;
  bindHost = "127.0.0.1";
}

export function isNetworkMode(): boolean {
  return networkMode;
}

// ── Address helpers ─────────────────────────────────────────────────

/** Strip IPv6 brackets, zone ids, and IPv4 mapped prefixes. */
export function normalizeIp(raw: string): string {
  let ip = raw.trim();
  if (ip.startsWith("[") && ip.endsWith("]")) ip = ip.slice(1, -1);
  const zone = ip.indexOf("%");
  if (zone !== -1) ip = ip.slice(0, zone);
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) ip = mapped[1]!;
  return ip;
}

export function isLoopbackHost(host: string): boolean {
  const h = normalizeIp(host.toLowerCase());
  return h === "localhost" || h === "::1" || /^127\.\d+\.\d+\.\d+$/.test(h);
}

function addToBlockList(list: BlockList, entry: string, source: string): void {
  const [addrRaw, prefixRaw] = entry.split("/");
  const addr = normalizeIp(addrRaw ?? "");
  const family = isIP(addr);
  if (family === 0) {
    throw new PolicyError(`${source}: "${entry}" is not an IP address or CIDR range`);
  }
  const type = family === 4 ? "ipv4" : "ipv6";
  if (prefixRaw === undefined) {
    list.addAddress(addr, type);
    return;
  }
  const prefix = Number(prefixRaw);
  const max = family === 4 ? 32 : 128;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > max) {
    throw new PolicyError(`${source}: "${entry}" has an invalid prefix length`);
  }
  list.addSubnet(addr, prefix, type);
}

export function buildBlockList(entries: string[], source: string): BlockList {
  const list = new BlockList();
  for (const e of entries) addToBlockList(list, e, source);
  return list;
}

export function blockListHas(list: BlockList, ip: string): boolean {
  const addr = normalizeIp(ip);
  const family = isIP(addr);
  if (family === 0) return false;
  return list.check(addr, family === 4 ? "ipv4" : "ipv6");
}

// ── Startup validation (fail closed) ────────────────────────────────

/**
 * Throws if the configuration would leave the server open in a way the
 * operator probably did not intend. Called before listen().
 */
export function enforceStartupPolicy(host: string): void {
  const requireKey = envFlag("SAFE_MCP_REQUIRE_API_KEY") === true;
  const keys = envList("SAFE_MCP_API_KEYS");
  const requireIp = envFlag("SAFE_MCP_REQUIRE_IP_ALLOWLIST") === true;
  const ips = envList("SAFE_MCP_IP_ALLOWLIST");

  if (requireKey && keys.length === 0) {
    throw new PolicyError(
      "SAFE_MCP_REQUIRE_API_KEY=true but SAFE_MCP_API_KEYS is empty. Refusing to start with authentication silently disabled.",
    );
  }
  if (requireKey && keys.some((k) => k.length < 16)) {
    throw new PolicyError("Every entry in SAFE_MCP_API_KEYS must be at least 16 characters.");
  }
  if (requireIp && ips.length === 0) {
    throw new PolicyError(
      "SAFE_MCP_REQUIRE_IP_ALLOWLIST=true but SAFE_MCP_IP_ALLOWLIST is empty. Refusing to start with the allowlist silently disabled.",
    );
  }
  if (ips.length > 0) buildBlockList(ips, "SAFE_MCP_IP_ALLOWLIST"); // validates entries

  if (!isLoopbackHost(host) && !requireKey && envFlag("SAFE_MCP_ALLOW_INSECURE_BIND") !== true) {
    throw new PolicyError(
      `HOST=${host} is reachable from other machines but API keys are not required. ` +
        "Set SAFE_MCP_REQUIRE_API_KEY=true and SAFE_MCP_API_KEYS, or set SAFE_MCP_ALLOW_INSECURE_BIND=true if you accept the risk.",
    );
  }
  if (commandDiscoveryAllowed() && networkMode && !requireKey) {
    throw new PolicyError(
      "SAFE_MCP_ALLOW_COMMAND_DISCOVERY=true on a network transport lets any caller run commands on this host. " +
        "It also requires SAFE_MCP_REQUIRE_API_KEY=true.",
    );
  }
}

// ── Request checks: browsers and DNS rebinding ──────────────────────

function hostWithoutPort(hostHeader: string): string {
  if (hostHeader.startsWith("[")) {
    const end = hostHeader.indexOf("]");
    return hostHeader.slice(0, end + 1);
  }
  return hostHeader.split(":")[0] ?? hostHeader;
}

/**
 * Blocks two browser driven attacks:
 *  1. Cross origin requests from a web page the user happens to visit.
 *  2. DNS rebinding, where attacker.example resolves to 127.0.0.1.
 */
export function checkBrowserSafety(req: IncomingMessage): { allowed: boolean; reason?: string } {
  // Host header
  const allowedHosts = envList("SAFE_MCP_ALLOWED_HOSTS").map((h) => h.toLowerCase());
  const hostHeader = (req.headers.host ?? "").toLowerCase();
  const host = hostWithoutPort(hostHeader);
  if (allowedHosts.length > 0) {
    if (!allowedHosts.includes(host) && !allowedHosts.includes(hostHeader)) {
      return { allowed: false, reason: "Host header not allowed" };
    }
  } else if (isLoopbackHost(bindHost) && !isLoopbackHost(host)) {
    return { allowed: false, reason: "Host header not allowed" };
  }

  // Origin header (browsers always send it on cross origin requests)
  const origin = req.headers.origin;
  if (typeof origin === "string" && origin !== "null") {
    const allowedOrigins = envList("SAFE_MCP_CORS_ORIGINS");
    if (!allowedOrigins.includes(origin)) {
      return { allowed: false, reason: "Origin not allowed" };
    }
  } else if (origin === "null") {
    return { allowed: false, reason: "Origin not allowed" };
  }

  // Bodies must be declared JSON. A text/plain POST is a "simple" request
  // that skips the CORS preflight, so it must never be accepted.
  if (req.method === "POST") {
    const ct = (req.headers["content-type"] ?? "").toLowerCase();
    if (!ct.startsWith("application/json")) {
      return { allowed: false, reason: "Content-Type must be application/json" };
    }
  }
  return { allowed: true };
}

/** CORS response headers: only for origins the operator listed. */
export function corsHeaders(req: IncomingMessage): Record<string, string> {
  const origin = req.headers.origin;
  if (typeof origin !== "string") return {};
  if (!envList("SAFE_MCP_CORS_ORIGINS").includes(origin)) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Headers": "Content-Type, X-Api-Key, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    Vary: "Origin",
  };
}

// ── Command discovery ───────────────────────────────────────────────

export function commandDiscoveryAllowed(): boolean {
  const explicit = envFlag("SAFE_MCP_ALLOW_COMMAND_DISCOVERY");
  if (explicit !== undefined) return explicit;
  return !networkMode;
}

/**
 * Stdio and config discovery start the target as a child process.
 * Whoever can call them can run code on this host.
 */
export function assertCommandDiscoveryAllowed(): void {
  if (!commandDiscoveryAllowed()) {
    throw new PolicyError(
      "Command based discovery (stdio, or config entries with a command) is disabled on network transports " +
        "because it runs a process on this host. Use HTTP discovery, run the skill over stdio, " +
        "or set SAFE_MCP_ALLOW_COMMAND_DISCOVERY=true together with API keys.",
    );
  }
}

// ── URL discovery (SSRF) ────────────────────────────────────────────

/** Never reachable: cloud metadata services, link local, and "this network". */
const ALWAYS_BLOCKED = buildBlockList(
  [
    "0.0.0.0/8",
    "169.254.0.0/16",
    "100.100.100.200",
    "fe80::/10",
    "fd00:ec2::254",
  ],
  "built in",
);

/** Internal ranges: blocked only when the skill itself is exposed beyond loopback. */
const PRIVATE_RANGES = buildBlockList(
  ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "100.64.0.0/10", "::1", "fc00::/7"],
  "built in",
);

export async function assertUrlAllowed(rawUrl: string): Promise<URL> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new PolicyError(`Not a valid URL: ${rawUrl}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new PolicyError(`Only http and https URLs can be discovered (got ${url.protocol})`);
  }
  const hostname = normalizeIp(url.hostname);
  const addrs = isIP(hostname)
    ? [hostname]
    : (await lookup(hostname, { all: true })).map((a) => a.address);

  const blockPrivate =
    networkMode && !isLoopbackHost(bindHost) && envFlag("SAFE_MCP_ALLOW_PRIVATE_URLS") !== true;

  for (const a of addrs) {
    if (blockListHas(ALWAYS_BLOCKED, a)) {
      throw new PolicyError(`${url.hostname} resolves to ${a}, a link local or metadata address`);
    }
    if (blockPrivate && blockListHas(PRIVATE_RANGES, a)) {
      throw new PolicyError(
        `${url.hostname} resolves to private address ${a}. Set SAFE_MCP_ALLOW_PRIVATE_URLS=true to allow internal targets.`,
      );
    }
  }
  return url;
}
