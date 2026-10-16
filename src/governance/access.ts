import type { IncomingMessage } from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import { logAccessDenied, logAccessGranted } from "./logger.js";
import { buildBlockList, blockListHas, envList, normalizeIp } from "./policy.js";

// ── Helpers ─────────────────────────────────────────────────────────

/**
 * The client address used for access decisions.
 *
 * X-Forwarded-For is attacker controlled unless a proxy you run sets it,
 * so it is ignored unless SAFE_MCP_TRUST_PROXY=true. When trusted, the
 * rightmost entry is used: that is the one your proxy appended.
 */
export function getClientIp(req: IncomingMessage): string {
  if (process.env["SAFE_MCP_TRUST_PROXY"] === "true") {
    const forwarded = req.headers["x-forwarded-for"];
    if (typeof forwarded === "string" && forwarded.trim()) {
      const parts = forwarded.split(",").map((s) => s.trim()).filter(Boolean);
      const last = parts[parts.length - 1];
      if (last) return normalizeIp(last);
    }
  }
  return normalizeIp(req.socket.remoteAddress ?? "unknown");
}

function safeCompare(a: string, b: string): boolean {
  const bufA = createHash("sha256").update(a).digest();
  const bufB = createHash("sha256").update(b).digest();
  return timingSafeEqual(bufA, bufB);
}

// ── Access Check ────────────────────────────────────────────────────

export interface AccessResult {
  allowed: boolean;
  reason?: string | undefined;
}

/**
 * Configuration is read on every call and validated at startup by
 * enforceStartupPolicy(), so "required but empty" can never fail open.
 */
export function checkAccess(req: IncomingMessage): AccessResult {
  const clientIp = getClientIp(req);

  if (process.env["SAFE_MCP_REQUIRE_IP_ALLOWLIST"] === "true") {
    const entries = envList("SAFE_MCP_IP_ALLOWLIST");
    const allow = buildBlockList(entries, "SAFE_MCP_IP_ALLOWLIST");
    if (entries.length === 0 || !blockListHas(allow, clientIp)) {
      logAccessDenied("ip_not_allowlisted", clientIp, { allowlistSize: entries.length });
      return { allowed: false, reason: "IP address not in allowlist" };
    }
  }

  if (process.env["SAFE_MCP_REQUIRE_API_KEY"] === "true") {
    const keys = envList("SAFE_MCP_API_KEYS");
    const provided =
      req.headers["x-api-key"] ?? req.headers["authorization"]?.replace(/^Bearer\s+/i, "");
    if (typeof provided !== "string" || !provided) {
      logAccessDenied("missing_api_key", clientIp);
      return { allowed: false, reason: "API key required" };
    }
    // Compare against every key (no early exit) to keep timing flat.
    let valid = false;
    for (const key of keys) {
      if (safeCompare(provided, key)) valid = true;
    }
    if (!valid) {
      logAccessDenied("invalid_api_key", clientIp);
      return { allowed: false, reason: "Invalid API key" };
    }
  }

  logAccessGranted(clientIp);
  return { allowed: true };
}
