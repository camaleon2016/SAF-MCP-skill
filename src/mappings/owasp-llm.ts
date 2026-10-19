// ── OWASP LLM Top 10 (2025) Mapping ────────────────────────────────
// Maps each SAF-MCP technique to relevant OWASP LLM Top 10 categories.
//
// LLM01 Prompt Injection              LLM06 Excessive Agency
// LLM02 Sensitive Information Disc.   LLM07 System Prompt Leakage
// LLM03 Supply Chain                  LLM08 Vector & Embedding Weaknesses
// LLM04 Data and Model Poisoning      LLM09 Misinformation
// LLM05 Improper Output Handling      LLM10 Unbounded Consumption

import type { OwaspLlmRef } from "./types.js";

const OWASP_NAMES: Record<string, string> = {
  LLM01: "Prompt Injection",
  LLM02: "Sensitive Information Disclosure",
  LLM03: "Supply Chain",
  LLM04: "Data and Model Poisoning",
  LLM05: "Improper Output Handling",
  LLM06: "Excessive Agency",
  LLM07: "System Prompt Leakage",
  LLM08: "Vector and Embedding Weaknesses",
  LLM09: "Misinformation",
  LLM10: "Unbounded Consumption",
};

function refs(...ids: string[]): OwaspLlmRef[] {
  return ids.map((id) => ({ id, name: OWASP_NAMES[id] ?? id }));
}

/** SAFE-T technique ID → OWASP LLM Top 10 references */
const OWASP_LLM_MAP: Record<string, OwaspLlmRef[]> = {
  // Tool Poisoning — prompt injection via tool description
  "SAFE-T1001": refs("LLM01", "LLM04"),
  // Supply Chain / Unverified Server
  "SAFE-T1002": refs("LLM03"),
  // Exposed Endpoints — sensitive info disclosure
  "SAFE-T1005": refs("LLM02"),
  // OAuth Phishing — excessive agency via scope escalation
  "SAFE-T1007": refs("LLM06"),
  // Tool Shadowing — supply chain, prompt injection
  "SAFE-T1008": refs("LLM03", "LLM01"),
  // Command Injection — improper output handling, excessive agency
  "SAFE-T1101": refs("LLM05", "LLM06"),
  // Prompt Injection
  "SAFE-T1102": refs("LLM01"),
  // Function Spoofing — supply chain
  "SAFE-T1103": refs("LLM03"),
  // Over-Privileged Tools — excessive agency
  "SAFE-T1104": refs("LLM06"),
  // Agentic Confused Deputy — upstream replacement for SAFE-T1104; same mapping
  "SAFE-T1302": refs("LLM06"),
  // Path Traversal — sensitive info disclosure
  "SAFE-T1105": refs("LLM02"),
  // Autonomous Loop Exploit — unbounded consumption
  "SAFE-T1106": refs("LLM10"),
  // Multimodal Injection — prompt injection
  "SAFE-T1110": refs("LLM01"),
  // CLI Weaponization — excessive agency, improper output handling
  "SAFE-T1111": refs("LLM06", "LLM05"),
  // Rug Pull — supply chain
  "SAFE-T1201": refs("LLM03"),
  // Backdoored Binary — supply chain
  "SAFE-T1203": refs("LLM03"),
  // Context Memory Implant — data poisoning
  "SAFE-T1204": refs("LLM04"),
  // Credential Relay — excessive agency
  "SAFE-T1304": refs("LLM06"),
  // Consent Fatigue — excessive agency
  "SAFE-T1403": refs("LLM06"),
  // OAuth Protocol Downgrade — excessive agency
  "SAFE-T1408": refs("LLM06"),
  // Credential Harvest — sensitive info disclosure
  "SAFE-T1502": refs("LLM02"),
  // Full-Schema Poisoning — prompt injection, data poisoning
  "SAFE-T1501": refs("LLM01", "LLM04"),
  // Env-Var Scraping — sensitive info disclosure
  "SAFE-T1503": refs("LLM02"),
  // System Prompt Disclosure — system prompt leakage
  "SAFE-T1603": refs("LLM07"),
  // Cross-Tool Contamination — improper output handling
  "SAFE-T1701": refs("LLM05"),
  // Cross-Agent Injection — prompt injection
  "SAFE-T1705": refs("LLM01"),
  // Database Dump — sensitive info disclosure
  "SAFE-T1803": refs("LLM02"),
  // Data Exfiltration — sensitive info disclosure
  "SAFE-T1910": refs("LLM02"),
  // Added in 2.4.0, mirroring the closest existing technique noted on each line; review before relying on them.
  "SAFE-T1914": refs("LLM02"), // as SAFE-T1910
  "SAFE-T1913": refs("LLM02"), // as SAFE-T1910
  "SAFE-T1703": refs("LLM05"), // as SAFE-T1701
  // Added in 2.3.0, mirroring the closest existing technique noted on each line; review before relying on them.
  "SAFE-T1402": refs("LLM01"),
  "SAFE-T1404": refs("LLM01"),
  "SAFE-T1004": refs("LLM03"),
  "SAFE-T1911": refs("LLM02"), // as SAFE-T1910
  "SAFE-T1406": refs("LLM06"),
  "SAFE-T1303": refs("LLM06"),
  // Data Destruction — excessive agency
  "SAFE-T2101": refs("LLM06"),
  // Code Sabotage — excessive agency, improper output handling
  "SAFE-T2103": refs("LLM06", "LLM05"),
  // Fraudulent Transactions — excessive agency
  "SAFE-T2104": refs("LLM06"),
  // Vector Store Poisoning — vector & embedding weaknesses, data poisoning
  "SAFE-T2106": refs("LLM08", "LLM04"),
  // RAG Backdoor — vector & embedding weaknesses, misinformation
  "SAFE-T3001": refs("LLM08", "LLM09"),
};

export function getOwaspLlm(techniqueId: string): OwaspLlmRef[] {
  return OWASP_LLM_MAP[techniqueId] ?? [];
}
