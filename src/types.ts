export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface LegalReference {
  jurisdiction: 'RU' | 'UZ' | 'US' | 'EU'
  title: string
  article: string
  summary: string
  maxPenalty: string
  caseReference: string
}

export interface CodeExample {
  language: 'php' | 'javascript' | 'python' | 'html'
  vulnerable: string
  secure: string
}

export interface AttackStep {
  title: string
  description: string
}

export interface VulnerabilityResource {
  label: string
  url: string
}

export interface Vulnerability {
  id: string
  name: string
  slug: string
  owaspId: string
  owaspRank: number
  cwe: string
  cveExamples: Array<{ id: string; description: string; year: number }>
  category: string
  severity: Severity
  cvss: number
  cvssVector: string
  exploitComplexity: 'Low' | 'Medium' | 'High'
  prevalence: number
  detectionDifficulty: number
  shortDescription: string
  overview: string
  affectedPlatforms: string[]
  attackMechanism: string
  attackerMindset: string
  defenderMindset: string
  attackSteps: AttackStep[]
  codeExample: CodeExample
  mitigationChecklist: string[]
  timeToFix: string
  legal: LegalReference[]
  resources: VulnerabilityResource[]
}

export interface LabFinding {
  title: string
  severity: Severity
  description: string
  recommendation: string
  legalContext: string
  cwe?: string
  evidence?: string
}

export interface RiskBreakdown {
  base: number
  exploitability: number
  impact: number
  scope: 'changed' | 'unchanged'
  confidentiality: 'none' | 'low' | 'high'
  integrity: 'none' | 'low' | 'high'
  availability: 'none' | 'low' | 'high'
  attackComplexity: 'low' | 'high'
  privilegesRequired: 'none' | 'low' | 'high'
  userInteraction: 'none' | 'required'
}

export interface SimulatedResult {
  technique: string
  techniques?: string[]
  summary: string
  statusCode: number
  headers: Record<string, string>
  body: string
  severity: Severity
  legalBadge: string
  latencyMs?: number
  findings?: LabFinding[]
  riskScore?: number
  cvssVector?: string
  riskBreakdown?: RiskBreakdown
}

export interface LabSession {
  id: string
  timestamp: string
  vulnType: string
  payloadsUsed: string[]
  results: SimulatedResult[]
  riskScore: number
}

export interface ThreatModelEntry {
  id: string
  category: string
  asset: string
  threatDescription: string
  currentControls: string
  proposedMitigation: string
}

export interface AttackTreeNode {
  id: string
  type: 'root' | 'sub-attack' | 'precondition' | 'defense'
  label: string
  x: number
  y: number
  probability: number
  cost: number
  parentId?: string
}

export interface DreadValues {
  damage: number
  reproducibility: number
  exploitability: number
  affectedUsers: number
  discoverability: number
}
