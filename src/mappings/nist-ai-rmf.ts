// ── NIST AI RMF Mapping ─────────────────────────────────────────────
// Maps each SAF-MCP technique to relevant NIST AI RMF subcategories.
//
// GOVERN — governance, policies, accountability
// MAP    — context, risk framing, stakeholder analysis
// MEASURE — assessment, testing, monitoring
// MANAGE — response, mitigation, continuous improvement

import type { NistAiRmfRef } from "./types.js";

function gov(id: string): NistAiRmfRef {
  return { id, function: "GOVERN" };
}
function map(id: string): NistAiRmfRef {
  return { id, function: "MAP" };
}
function mea(id: string): NistAiRmfRef {
  return { id, function: "MEASURE" };
}
function man(id: string): NistAiRmfRef {
  return { id, function: "MANAGE" };
}

/** SAFE-T technique ID → NIST AI RMF subcategory references */
const NIST_AI_RMF_MAP: Record<string, NistAiRmfRef[]> = {
  // Tool Poisoning — needs input validation governance + testing
  "SAFE-T1001": [gov("GOVERN-1.2"), mea("MEASURE-2.6"), man("MANAGE-2.4")],
  // Supply Chain — third-party risk governance
  "SAFE-T1002": [gov("GOVERN-1.5"), map("MAP-3.4"), man("MANAGE-3.2")],
  // Exposed Endpoints — security controls
  "SAFE-T1005": [gov("GOVERN-1.4"), mea("MEASURE-2.5"), man("MANAGE-2.2")],
  // OAuth Phishing — access control governance
  "SAFE-T1007": [gov("GOVERN-1.4"), man("MANAGE-2.4")],
  // Tool Shadowing — supply chain + testing
  "SAFE-T1008": [gov("GOVERN-1.5"), mea("MEASURE-2.6")],
  // Command Injection — security testing, response
  "SAFE-T1101": [mea("MEASURE-2.6"), man("MANAGE-2.4"), gov("GOVERN-1.2")],
  // Prompt Injection — testing + monitoring
  "SAFE-T1102": [mea("MEASURE-2.6"), mea("MEASURE-2.7"), man("MANAGE-2.4")],
  // Function Spoofing — supply chain governance
  "SAFE-T1103": [gov("GOVERN-1.5"), mea("MEASURE-2.6")],
  // Over-Privileged Tools — least privilege governance
  "SAFE-T1104": [gov("GOVERN-1.4"), man("MANAGE-2.2")],
  // Agentic Confused Deputy — upstream replacement for SAFE-T1104; same mapping
  "SAFE-T1302": [gov("GOVERN-1.4"), man("MANAGE-2.2")],
  // Path Traversal — security testing
  "SAFE-T1105": [mea("MEASURE-2.6"), man("MANAGE-2.4")],
  // Autonomous Loop — monitoring + resource management
  "SAFE-T1106": [mea("MEASURE-2.7"), man("MANAGE-2.2")],
  // Multimodal Injection — testing for multimodal inputs
  "SAFE-T1110": [mea("MEASURE-2.6"), map("MAP-2.3")],
  // CLI Weaponization — access control
  "SAFE-T1111": [gov("GOVERN-1.4"), mea("MEASURE-2.6"), man("MANAGE-2.4")],
  // Rug Pull — third-party trust
  "SAFE-T1201": [gov("GOVERN-1.5"), mea("MEASURE-2.7")],
  // Backdoored Binary — supply chain
  "SAFE-T1203": [gov("GOVERN-1.5"), map("MAP-3.4"), mea("MEASURE-2.6")],
  // Context Memory Implant — data integrity monitoring
  "SAFE-T1204": [mea("MEASURE-2.7"), man("MANAGE-2.4")],
  // Credential Relay — access control governance
  "SAFE-T1304": [gov("GOVERN-1.4"), man("MANAGE-2.2")],
  // Consent Fatigue — human-AI interaction governance
  "SAFE-T1403": [gov("GOVERN-1.2"), map("MAP-2.3")],
  // OAuth Protocol Downgrade — security governance
  "SAFE-T1408": [gov("GOVERN-1.4"), mea("MEASURE-2.5")],
  // Credential Harvest — data protection
  "SAFE-T1502": [gov("GOVERN-1.4"), man("MANAGE-2.4")],
  // Full-Schema Poisoning — input validation
  "SAFE-T1501": [mea("MEASURE-2.6"), man("MANAGE-2.4")],
  // Env-Var Scraping — data protection governance
  "SAFE-T1503": [gov("GOVERN-1.4"), man("MANAGE-2.4")],
  // System Prompt Disclosure — confidentiality
  "SAFE-T1603": [gov("GOVERN-1.2"), man("MANAGE-2.4")],
  // Cross-Tool Contamination — isolation + monitoring
  "SAFE-T1701": [mea("MEASURE-2.7"), man("MANAGE-2.2")],
  // Cross-Agent Injection — multi-agent governance
  "SAFE-T1705": [gov("GOVERN-1.2"), mea("MEASURE-2.6"), man("MANAGE-2.4")],
  // Database Dump — data protection
  "SAFE-T1803": [gov("GOVERN-1.4"), man("MANAGE-2.4")],
  // Data Exfiltration — monitoring + response
  "SAFE-T1910": [mea("MEASURE-2.7"), man("MANAGE-2.4")],
  // Data Destruction — incident response
  "SAFE-T2101": [man("MANAGE-2.4"), man("MANAGE-4.1")],
  // Code Sabotage — integrity monitoring
  "SAFE-T2103": [mea("MEASURE-2.7"), man("MANAGE-2.4")],
  // Fraudulent Transactions — accountability
  "SAFE-T2104": [gov("GOVERN-1.2"), man("MANAGE-2.4")],
  // Vector Store Poisoning — data integrity
  "SAFE-T2106": [mea("MEASURE-2.7"), man("MANAGE-2.4")],
  // RAG Backdoor — data integrity + testing
  "SAFE-T3001": [mea("MEASURE-2.6"), mea("MEASURE-2.7"), man("MANAGE-2.4")],
};

export function getNistAiRmf(techniqueId: string): NistAiRmfRef[] {
  return NIST_AI_RMF_MAP[techniqueId] ?? [];
}
