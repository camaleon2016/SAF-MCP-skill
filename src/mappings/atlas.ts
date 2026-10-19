// ── MITRE ATLAS Mapping ─────────────────────────────────────────────
// Maps each SAF-MCP technique to relevant MITRE ATLAS v5.5 techniques.
// Only the ~30 ATLAS techniques relevant to MCP/agent security are included.

import type { AtlasRef } from "./types.js";

function ref(id: string, name: string): AtlasRef {
  return { id, name };
}

/** SAFE-T technique ID → MITRE ATLAS technique references */
const ATLAS_MAP: Record<string, AtlasRef[]> = {
  // Tool Poisoning
  "SAFE-T1001": [
    ref("AML.T0110", "AI Agent Tool Poisoning"),
    ref("AML.T0104", "Publish Poisoned AI Agent Tool"),
  ],
  // Supply Chain / Unverified Server
  "SAFE-T1002": [
    ref("AML.T0010", "ML Supply Chain Compromise"),
  ],
  // Exposed Endpoints
  "SAFE-T1005": [
    ref("AML.T0053", "AI Agent Tool Invocation"),
  ],
  // OAuth Phishing
  "SAFE-T1007": [
    ref("AML.T0053", "AI Agent Tool Invocation"),
  ],
  // Tool Shadowing
  "SAFE-T1008": [
    ref("AML.T0110", "AI Agent Tool Poisoning"),
    ref("AML.T0053", "AI Agent Tool Invocation"),
  ],
  // Command Injection
  "SAFE-T1101": [
    ref("AML.T0053", "AI Agent Tool Invocation"),
    ref("AML.T0040", "ML Model Inference API Access"),
  ],
  // Prompt Injection
  "SAFE-T1102": [
    ref("AML.T0051", "LLM Prompt Injection"),
    ref("AML.T0054", "LLM Jailbreak"),
  ],
  // Function Spoofing
  "SAFE-T1103": [
    ref("AML.T0110", "AI Agent Tool Poisoning"),
  ],
  // Over-Privileged Tools
  "SAFE-T1104": [
    ref("AML.T0053", "AI Agent Tool Invocation"),
  ],
  // Agentic Confused Deputy — upstream replacement for SAFE-T1104; same mapping
  "SAFE-T1302": [
    ref("AML.T0053", "AI Agent Tool Invocation"),
  ],
  // Path Traversal
  "SAFE-T1105": [
    ref("AML.T0086", "Exfiltration via AI Agent Tool"),
  ],
  // Autonomous Loop
  "SAFE-T1106": [
    ref("AML.T0053", "AI Agent Tool Invocation"),
  ],
  // Multimodal Injection
  "SAFE-T1110": [
    ref("AML.T0051", "LLM Prompt Injection"),
  ],
  // CLI Weaponization
  "SAFE-T1111": [
    ref("AML.T0053", "AI Agent Tool Invocation"),
    ref("AML.T0086", "Exfiltration via AI Agent Tool"),
  ],
  // Rug Pull
  "SAFE-T1201": [
    ref("AML.T0081", "Modify AI Agent Configuration"),
  ],
  // Backdoored Binary
  "SAFE-T1203": [
    ref("AML.T0010", "ML Supply Chain Compromise"),
  ],
  // Context Memory Implant
  "SAFE-T1204": [
    ref("AML.T0080", "AI Agent Context Poisoning"),
  ],
  // Credential Relay
  "SAFE-T1304": [
    ref("AML.T0086", "Exfiltration via AI Agent Tool"),
  ],
  // Consent Fatigue
  "SAFE-T1403": [
    ref("AML.T0053", "AI Agent Tool Invocation"),
  ],
  // OAuth Protocol Downgrade
  "SAFE-T1408": [
    ref("AML.T0053", "AI Agent Tool Invocation"),
  ],
  // Credential Harvest
  "SAFE-T1502": [
    ref("AML.T0086", "Exfiltration via AI Agent Tool"),
  ],
  // Full-Schema Poisoning
  "SAFE-T1501": [
    ref("AML.T0110", "AI Agent Tool Poisoning"),
    ref("AML.T0051", "LLM Prompt Injection"),
  ],
  // Env-Var Scraping
  "SAFE-T1503": [
    ref("AML.T0086", "Exfiltration via AI Agent Tool"),
  ],
  // System Prompt Disclosure
  "SAFE-T1603": [
    ref("AML.T0054", "LLM Jailbreak"),
  ],
  // Cross-Tool Contamination
  "SAFE-T1701": [
    ref("AML.T0080", "AI Agent Context Poisoning"),
  ],
  // Cross-Agent Injection
  "SAFE-T1705": [
    ref("AML.T0051", "LLM Prompt Injection"),
    ref("AML.T0080", "AI Agent Context Poisoning"),
  ],
  // Database Dump
  "SAFE-T1803": [
    ref("AML.T0086", "Exfiltration via AI Agent Tool"),
  ],
  // Data Exfiltration
  "SAFE-T1910": [
    ref("AML.T0086", "Exfiltration via AI Agent Tool"),
  ],
  // Added in 2.3.0, mirroring the closest existing technique noted on each line; review before relying on them.
  "SAFE-T1402": [ref("AML.T0110", "AI Agent Tool Poisoning"), ref("AML.T0051", "LLM Prompt Injection")], // as SAFE-T1001
  "SAFE-T1404": [ref("AML.T0051", "LLM Prompt Injection")],
  "SAFE-T1004": [ref("AML.T0104", "Publish Poisoned AI Agent Tool"), ref("AML.T0010", "ML Supply Chain Compromise")],
  "SAFE-T1911": [ref("AML.T0086", "Exfiltration via AI Agent Tool")], // as SAFE-T1910
  "SAFE-T1406": [ref("AML.T0110", "AI Agent Tool Poisoning"), ref("AML.T0081", "Modify AI Agent Configuration")],
  "SAFE-T1303": [ref("AML.T0053", "AI Agent Tool Invocation")], // as SAFE-T1101
  // Data Destruction
  "SAFE-T2101": [
    ref("AML.T0053", "AI Agent Tool Invocation"),
  ],
  // Code Sabotage
  "SAFE-T2103": [
    ref("AML.T0053", "AI Agent Tool Invocation"),
  ],
  // Fraudulent Transactions
  "SAFE-T2104": [
    ref("AML.T0053", "AI Agent Tool Invocation"),
  ],
  // Vector Store Poisoning
  "SAFE-T2106": [
    ref("AML.T0080", "AI Agent Context Poisoning"),
  ],
  // RAG Backdoor
  "SAFE-T3001": [
    ref("AML.T0080", "AI Agent Context Poisoning"),
    ref("AML.T0051", "LLM Prompt Injection"),
  ],
};

export function getAtlas(techniqueId: string): AtlasRef[] {
  return ATLAS_MAP[techniqueId] ?? [];
}
