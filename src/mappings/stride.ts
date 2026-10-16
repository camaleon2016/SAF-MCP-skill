// ── STRIDE Mapping ──────────────────────────────────────────────────
// Maps each SAFE-MCP technique to one or more STRIDE categories.
//
// S = Spoofing          T = Tampering         R = Repudiation
// I = Information Disc. D = Denial of Service E = Elevation of Privilege

import type { StrideCategory } from "./types.js";

/** SAFE-T technique ID → STRIDE categories */
export const STRIDE_MAP: Record<string, StrideCategory[]> = {
  // Tool Poisoning — attacker tampers with tool description to spoof behavior
  "SAFE-T1001": ["T", "S"],
  // Supply Chain / Unverified Server — spoofed identity, tampering
  "SAFE-T1002": ["S", "T"],
  // Exposed Endpoints — information disclosure, elevation of privilege
  "SAFE-T1005": ["I", "E"],
  // OAuth Phishing — spoofing, elevation of privilege
  "SAFE-T1007": ["S", "E"],
  // Tool Shadowing — spoofing (impersonating another tool), tampering
  "SAFE-T1008": ["S", "T"],
  // Command Injection — elevation of privilege, tampering
  "SAFE-T1101": ["E", "T"],
  // Prompt Injection — tampering, spoofing
  "SAFE-T1102": ["T", "S"],
  // Function Spoofing — spoofing
  "SAFE-T1103": ["S"],
  // Over-Privileged Tools — elevation of privilege
  "SAFE-T1104": ["E"],
  // Agentic Confused Deputy — upstream replacement for SAFE-T1104; same mapping
  "SAFE-T1302": ["E"],
  // Path Traversal — information disclosure, elevation of privilege
  "SAFE-T1105": ["I", "E"],
  // Autonomous Loop Exploit — denial of service, tampering
  "SAFE-T1106": ["D", "T"],
  // Multimodal Injection — tampering, spoofing
  "SAFE-T1110": ["T", "S"],
  // CLI Weaponization — elevation of privilege, information disclosure
  "SAFE-T1111": ["E", "I"],
  // Rug Pull / Dynamic Transport — tampering, repudiation
  "SAFE-T1201": ["T", "R"],
  // Backdoored Binary — tampering, elevation of privilege
  "SAFE-T1203": ["T", "E"],
  // Context Memory Implant — tampering
  "SAFE-T1204": ["T"],
  // Credential Relay Chain — spoofing, elevation of privilege
  "SAFE-T1304": ["S", "E"],
  // Consent Fatigue — spoofing (social engineering), elevation of privilege
  "SAFE-T1403": ["S", "E"],
  // OAuth Protocol Downgrade — spoofing, elevation of privilege
  "SAFE-T1408": ["S", "E"],
  // Credential Harvest — information disclosure
  "SAFE-T1502": ["I"],
  // Full-Schema Poisoning — tampering, spoofing
  "SAFE-T1501": ["T", "S"],
  // Env-Var Scraping — information disclosure
  "SAFE-T1503": ["I"],
  // System Prompt Disclosure — information disclosure
  "SAFE-T1603": ["I"],
  // Cross-Tool Contamination — tampering
  "SAFE-T1701": ["T"],
  // Cross-Agent Injection — tampering, spoofing
  "SAFE-T1705": ["T", "S"],
  // Database Dump — information disclosure
  "SAFE-T1803": ["I"],
  // Data Exfiltration via Network — information disclosure
  "SAFE-T1910": ["I"],
  // Data Destruction — tampering, denial of service
  "SAFE-T2101": ["T", "D"],
  // Code Sabotage — tampering, repudiation
  "SAFE-T2103": ["T", "R"],
  // Fraudulent Transactions — spoofing, tampering
  "SAFE-T2104": ["S", "T"],
  // Vector Store Poisoning — tampering
  "SAFE-T2106": ["T"],
  // RAG Backdoor — tampering, information disclosure
  "SAFE-T3001": ["T", "I"],
};

export function getStride(techniqueId: string): StrideCategory[] {
  return STRIDE_MAP[techniqueId] ?? [];
}
