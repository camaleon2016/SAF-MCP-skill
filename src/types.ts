// SAFE-MCP Framework TypeScript Types

// ── Severity & Effectiveness ────────────────────────────────────────

export type Severity = "Critical" | "High" | "Medium" | "Low";

export type Effectiveness =
  | "High (Provable Security)"
  | "High"
  | "Medium-High"
  | "Medium"
  | "Low";

export type ImplementationComplexity =
  | "High"
  | "Medium-High"
  | "Medium"
  | "Low-Medium"
  | "Low";

// ── Tactics ─────────────────────────────────────────────────────────

export interface Tactic {
  id: string;
  name: string;
  description: string;
}

// ── Techniques ──────────────────────────────────────────────────────

export interface SubTechnique {
  id: string;
  name: string;
  description: string;
}

export interface AttackVectors {
  primary: string;
  secondary: string[];
}

export interface Impact {
  confidentiality: Severity;
  integrity: Severity;
  availability: Severity;
  scope: string;
}

export interface Technique {
  id: string;
  name: string;
  tactic: string;
  tacticName: string;
  severity: Severity;
  description: string;
  mitigations: string[];
  mitreAttackMapping: string[];
  attackVectors?: AttackVectors;
  subTechniques?: SubTechnique[];
  impact?: Impact;
  relatedTechniques?: string[];
  realWorldIncidents?: string[];
  cves?: string[];
  /** Other names this technique has had or goes by (upstream renames, aliases). */
  aliases?: string[];
  /** Upstream lifecycle: deprecated techniques stay resolvable but rules must not target them. */
  lifecycleStatus?: "active" | "deprecated";
  replacedBy?: string[];
  deprecationReason?: string;
  /** Upstream SAF profiles this technique belongs to (core, mcp, code-agent, ...). */
  profiles?: string[];
}

// ── Mitigations ─────────────────────────────────────────────────────

export interface BestPractices {
  do: string[];
  dont: string[];
}

export interface CharactersFiltered {
  invisibleCharacters: string[];
  bidirectionalControlCharacters: string[];
  privateUseAreas: string[];
  unicodeTags: string[];
}

export interface Mitigation {
  id: string;
  name: string;
  category: string;
  effectiveness: Effectiveness;
  description: string;
  mitigates: string[];
  relatedMitigations: string[];
  implementationComplexity?: ImplementationComplexity;
  firstPublished?: string;
  references?: string[];
  corePrinciples?: string[];
  benefits?: string[];
  limitations?: string[];
  implementationPhases?: string[];
  implementationApproaches?: string[];
  detectionPatterns?: string[];
  bestPractices?: BestPractices;
  charactersFiltered?: CharactersFiltered;
  sanitizationModes?: string[];
  /** "withdrawn": listed upstream once but never published; resolvable, never recommended. */
  lifecycleStatus?: "active" | "withdrawn";
  withdrawnNote?: string;
}

// ── Top-level Data Structures ───────────────────────────────────────

export interface TechniquesFramework {
  name: string;
  fullName: string;
  repository: string;
  website: string;
  totalTactics: number;
  totalTechniques: number;
  totalMitigations: number;
  activeTechniques?: number;
  deprecatedTechniques?: number;
}

export interface MitigationsFramework {
  name: string;
  repository: string;
  totalMitigations: number;
  withdrawnMitigations?: number;
  highEffectiveness: number;
  mediumHighEffectiveness: number;
  mediumEffectiveness: number;
  lowEffectiveness: number;
}

export interface ImplementationPriority {
  label: string;
  mitigations?: string[];
  description?: string;
}

export interface ImplementationGuidance {
  defenseInDepth: string[];
  priorityImplementation: {
    critical: ImplementationPriority;
    important: ImplementationPriority;
    additional: ImplementationPriority;
  };
}

export interface TechniquesData {
  framework: TechniquesFramework;
  tactics: Tactic[];
  techniques: Technique[];
  tacticDistribution: Record<string, number>;
}

export interface MitigationsData {
  framework: MitigationsFramework;
  categories: string[];
  categoryDistribution: Record<string, number>;
  mitigations: Mitigation[];
  implementationGuidance: ImplementationGuidance;
}
