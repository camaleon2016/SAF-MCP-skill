import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type {
  Technique,
  Mitigation,
  Tactic,
  Severity,
  TechniquesData,
  MitigationsData,
} from "../types.js";

// ── Data Loading ────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));
const dataDir = resolve(__dirname, "..", "data");

function loadJSON<T>(filename: string): T {
  const raw = readFileSync(resolve(dataDir, filename), "utf-8");
  return JSON.parse(raw) as T;
}

const techniquesData = loadJSON<TechniquesData>("techniques.json");
const mitigationsData = loadJSON<MitigationsData>("mitigations.json");

// ── Indexes ─────────────────────────────────────────────────────────

const techniqueById = new Map<string, Technique>(
  techniquesData.techniques.map((t) => [t.id, t]),
);

const mitigationById = new Map<string, Mitigation>(
  mitigationsData.mitigations.map((m) => [m.id, m]),
);

const tacticById = new Map<string, Tactic>(
  techniquesData.tactics.map((t) => [t.id, t]),
);

const techniquesByTactic = new Map<string, Technique[]>();
for (const t of techniquesData.techniques) {
  const list = techniquesByTactic.get(t.tactic) ?? [];
  list.push(t);
  techniquesByTactic.set(t.tactic, list);
}

const techniquesBySeverity = new Map<Severity, Technique[]>();
for (const t of techniquesData.techniques) {
  const list = techniquesBySeverity.get(t.severity) ?? [];
  list.push(t);
  techniquesBySeverity.set(t.severity, list);
}

// ── IDs ─────────────────────────────────────────────────────────────

/**
 * Upstream renamed SAF-MCP to SAF-MCP, so IDs now appear as SAF-T1001 and
 * SAF-M-1 as well as the original SAFE-T1001 and SAFE-M-1. Accept either
 * (any case) and return the form this catalog stores.
 */
export function normalizeId(id: string): string {
  const s = id.trim().toUpperCase();
  return s.replace(/^SAF-(?=[TM])/, "SAFE-");
}

const isActiveMitigation = (m: Mitigation): boolean => m.lifecycleStatus !== "withdrawn";
const isActiveTechnique = (t: Technique): boolean => t.lifecycleStatus !== "deprecated";

// ── Lookup Functions ────────────────────────────────────────────────

export function getTechnique(id: string): Technique | undefined {
  return techniqueById.get(normalizeId(id));
}

export function getMitigation(id: string): Mitigation | undefined {
  return mitigationById.get(normalizeId(id));
}

export function getTactic(id: string): Tactic | undefined {
  return tacticById.get(id);
}

// ── Query Functions ─────────────────────────────────────────────────

export function listTechniques(): Technique[] {
  return techniquesData.techniques;
}

export function listMitigations(): Mitigation[] {
  return mitigationsData.mitigations;
}

export function listTactics(): Tactic[] {
  return techniquesData.tactics;
}

export function getTechniquesBySeverity(severity: Severity): Technique[] {
  return techniquesBySeverity.get(severity) ?? [];
}

export function getTechniquesByTactic(tacticId: string): Technique[] {
  return techniquesByTactic.get(tacticId) ?? [];
}

export function searchTechniques(query: string): Technique[] {
  const q = query.toLowerCase();
  return techniquesData.techniques.filter(
    (t) =>
      t.id.toLowerCase().includes(q) ||
      normalizeId(q).toLowerCase() === t.id.toLowerCase() ||
      t.name.toLowerCase().includes(q) ||
      (t.aliases ?? []).some((a) => a.toLowerCase().includes(q)) ||
      t.description.toLowerCase().includes(q),
  );
}

export function searchMitigations(query: string): Mitigation[] {
  const q = query.toLowerCase();
  return mitigationsData.mitigations.filter(
    (m) =>
      isActiveMitigation(m) &&
      (normalizeId(q).toLowerCase() === m.id.toLowerCase() ||
      m.id.toLowerCase().includes(q) ||
      m.name.toLowerCase().includes(q) ||
      m.description.toLowerCase().includes(q)),
  );
}

// ── Relationship Queries ────────────────────────────────────────────

export function getMitigationsForTechnique(techniqueId: string): Mitigation[] {
  const technique = techniqueById.get(normalizeId(techniqueId));
  if (!technique) return [];
  return technique.mitigations
    .map((id) => mitigationById.get(id))
    .filter((m): m is Mitigation => m !== undefined && isActiveMitigation(m));
}

export function getTechniquesForMitigation(mitigationId: string): Technique[] {
  const mitigation = mitigationById.get(normalizeId(mitigationId));
  if (!mitigation) return [];
  return mitigation.mitigates
    .map((id) => techniqueById.get(id))
    .filter((t): t is Technique => t !== undefined);
}

export function getRelatedMitigations(mitigationId: string): Mitigation[] {
  const mitigation = mitigationById.get(normalizeId(mitigationId));
  if (!mitigation) return [];
  return mitigation.relatedMitigations
    .map((id) => mitigationById.get(id))
    .filter((m): m is Mitigation => m !== undefined);
}

export function getRelatedTechniques(techniqueId: string): Technique[] {
  const technique = techniqueById.get(normalizeId(techniqueId));
  if (!technique || !technique.relatedTechniques) return [];
  return technique.relatedTechniques
    .map((id) => techniqueById.get(id))
    .filter((t): t is Technique => t !== undefined);
}

// ── Analysis Functions ──────────────────────────────────────────────

export interface CoverageGap {
  technique: Technique;
  mitigationCount: number;
}

export function getUnmitigatedTechniques(): Technique[] {
  return techniquesData.techniques.filter((t) => isActiveTechnique(t) && t.mitigations.length === 0);
}

export function getCoverageGaps(maxMitigations: number = 1): CoverageGap[] {
  return techniquesData.techniques
    .filter((t) => isActiveTechnique(t) && t.mitigations.length <= maxMitigations)
    .map((t) => ({ technique: t, mitigationCount: t.mitigations.length }))
    .sort((a, b) => a.mitigationCount - b.mitigationCount);
}

export interface ThreatProfile {
  totalTechniques: number;
  bySeverity: Record<string, number>;
  topUnmitigated: CoverageGap[];
  criticalTechniques: Technique[];
  mitigationCoverage: number;
}

export function getThreatProfile(): ThreatProfile {
  // Deprecated techniques are folded into their replacements upstream.
  const all = techniquesData.techniques.filter(isActiveTechnique);
  const bySeverity: Record<string, number> = {};
  for (const t of all) {
    bySeverity[t.severity] = (bySeverity[t.severity] ?? 0) + 1;
  }

  const mitigated = all.filter((t) => t.mitigations.length > 0).length;

  return {
    totalTechniques: all.length,
    bySeverity,
    topUnmitigated: getCoverageGaps(0).slice(0, 10),
    criticalTechniques: getTechniquesBySeverity("Critical").filter(isActiveTechnique),
    mitigationCoverage: all.length > 0 ? mitigated / all.length : 0,
  };
}

export interface MitigationEffectivenessReport {
  mitigation: Mitigation;
  techniquesAddressed: number;
  coversSeverities: Severity[];
}

export function rankMitigationsByImpact(): MitigationEffectivenessReport[] {
  return mitigationsData.mitigations
    .filter(isActiveMitigation)
    .map((m) => {
      const techniques = getTechniquesForMitigation(m.id);
      const severities = [...new Set(techniques.map((t) => t.severity))];
      return {
        mitigation: m,
        techniquesAddressed: techniques.length,
        coversSeverities: severities,
      };
    })
    .sort((a, b) => b.techniquesAddressed - a.techniquesAddressed);
}

export interface AttackPathStep {
  technique: Technique;
  tactic: Tactic | undefined;
}

export function getAttackPath(tacticIds: string[]): AttackPathStep[] {
  return tacticIds.flatMap((tacticId) => {
    const tactic = tacticById.get(tacticId);
    const techniques = techniquesByTactic.get(tacticId) ?? [];
    return techniques.map((technique) => ({ technique, tactic }));
  });
}

// ── Framework Metadata ──────────────────────────────────────────────

export function getFrameworkStats() {
  return {
    techniques: techniquesData.framework,
    mitigations: mitigationsData.framework,
    tacticDistribution: techniquesData.tacticDistribution,
    mitigationCategoryDistribution: mitigationsData.categoryDistribution,
    implementationGuidance: mitigationsData.implementationGuidance,
  };
}
