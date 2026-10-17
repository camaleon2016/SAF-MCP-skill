// ── Unified Mapping Index ───────────────────────────────────────────
// Single entry point: given a technique ID, return all framework mappings.

import type { FrameworkMappings, FrameworkCoverage, StrideCategory } from "./types.js";
import { STRIDE_LABELS } from "./types.js";
import { getStride } from "./stride.js";
import { getOwaspLlm } from "./owasp-llm.js";
import { getAtlas } from "./atlas.js";
import { getNistAiRmf } from "./nist-ai-rmf.js";

export type { FrameworkMappings, FrameworkCoverage } from "./types.js";
export type {
  StrideCategory,
  AtlasRef,
  OwaspLlmRef,
  NistAiRmfRef,
} from "./types.js";
export { STRIDE_LABELS } from "./types.js";

/** Accept SAF-T and SAFE-T (any case); mappings are keyed by SAFE-T. */
function normalizeTechniqueId(id: string): string {
  return id.trim().toUpperCase().replace(/^SAF-(?=T)/, "SAFE-");
}

/** Get all framework mappings for a single SAFE-MCP technique. */
export function getMappings(rawTechniqueId: string): FrameworkMappings {
  const techniqueId = normalizeTechniqueId(rawTechniqueId);
  return {
    stride: getStride(techniqueId),
    atlas: getAtlas(techniqueId),
    owaspLlm: getOwaspLlm(techniqueId),
    nistAiRmf: getNistAiRmf(techniqueId),
  };
}

/** Compute coverage summaries from a set of findings (technique IDs). */
export function getCoverage(rawTechniqueIds: string[]): FrameworkCoverage[] {
  const techniqueIds = rawTechniqueIds.map(normalizeTechniqueId);
  const strideCounts: Record<string, number> = {};
  const owaspCounts: Record<string, number> = {};
  const atlasCounts: Record<string, number> = {};
  const nistCounts: Record<string, number> = {};

  let strideTotal = 0;
  let owaspTotal = 0;
  let atlasTotal = 0;
  let nistTotal = 0;

  for (const id of techniqueIds) {
    const m = getMappings(id);

    if (m.stride.length > 0) {
      strideTotal++;
      for (const s of m.stride) {
        strideCounts[STRIDE_LABELS[s]] = (strideCounts[STRIDE_LABELS[s]] ?? 0) + 1;
      }
    }

    if (m.owaspLlm.length > 0) {
      owaspTotal++;
      for (const o of m.owaspLlm) {
        owaspCounts[`${o.id} ${o.name}`] = (owaspCounts[`${o.id} ${o.name}`] ?? 0) + 1;
      }
    }

    if (m.atlas.length > 0) {
      atlasTotal++;
      for (const a of m.atlas) {
        atlasCounts[`${a.id} ${a.name}`] = (atlasCounts[`${a.id} ${a.name}`] ?? 0) + 1;
      }
    }

    if (m.nistAiRmf.length > 0) {
      nistTotal++;
      for (const n of m.nistAiRmf) {
        nistCounts[n.id] = (nistCounts[n.id] ?? 0) + 1;
      }
    }
  }

  return [
    { framework: "STRIDE", totalMapped: strideTotal, categories: strideCounts },
    { framework: "OWASP LLM Top 10 (2025)", totalMapped: owaspTotal, categories: owaspCounts },
    { framework: "MITRE ATLAS", totalMapped: atlasTotal, categories: atlasCounts },
    { framework: "NIST AI RMF", totalMapped: nistTotal, categories: nistCounts },
  ];
}
