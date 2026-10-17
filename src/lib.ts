/**
 * Library entry point: `import { analyzeTool } from "saf-mcp-skill"`.
 *
 * Importing this module has no side effects. The MCP stdio server lives in
 * index.ts (the `saf-mcp-skill` command) and only starts when run directly.
 */
export { VERSION } from "./version.js";

// OpenAI / LangChain / Azure OpenAI function calling:
//   import { openAiFunctions, dispatch } from "saf-mcp-skill"
export { openAiFunctions, dispatch } from "./openai.js";

// Analysis engine
export {
  analyzeArchitecture,
  analyzeTool,
  analyzeServer,
} from "./engine/rules.js";
export type {
  ToolDefinition,
  ServerDefinition,
  AgentArchitecture,
  AnalysisResult,
  Finding,
  RiskSummary,
} from "./engine/rules.js";

// Framework mappings
export { getMappings, getCoverage, STRIDE_LABELS } from "./mappings/index.js";
export type {
  FrameworkMappings,
  FrameworkCoverage,
  StrideCategory,
  AtlasRef,
  OwaspLlmRef,
  NistAiRmfRef,
} from "./mappings/index.js";

// Discovery (stdio discovery starts the target as a child process)
export {
  discoverAndAnalyzeStdio,
  discoverAndAnalyzeHttp,
  discoverAndAnalyzeConfig,
} from "./discovery.js";
export type {
  StdioDiscoveryInput,
  HttpDiscoveryInput,
  ConfigDiscoveryInput,
  DiscoveryResult,
  ConfigDiscoveryResult,
} from "./discovery.js";

// Catalog lookups
export {
  normalizeId,
  getTechnique,
  getMitigation,
  searchTechniques,
  searchMitigations,
  getMitigationsForTechnique,
  getTechniquesForMitigation,
  getThreatProfile,
  getFrameworkStats,
  rankMitigationsByImpact,
  getUnmitigatedTechniques,
} from "./engine/analyze.js";
export type { Technique, Mitigation, Severity } from "./types.js";
