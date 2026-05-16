import type { LabFinding, RiskBreakdown, Severity } from '../../types'

const AC = { low: 0.77, high: 0.44 } as const
const PR_UNCHANGED = { none: 0.85, low: 0.62, high: 0.27 } as const
const PR_CHANGED = { none: 0.85, low: 0.68, high: 0.5 } as const
const UI = { none: 0.85, required: 0.62 } as const
const CIA = { none: 0, low: 0.22, high: 0.56 } as const

export interface ScoringInput {
  attackComplexity?: 'low' | 'high'
  privilegesRequired?: 'none' | 'low' | 'high'
  userInteraction?: 'none' | 'required'
  scope?: 'changed' | 'unchanged'
  confidentiality?: 'none' | 'low' | 'high'
  integrity?: 'none' | 'low' | 'high'
  availability?: 'none' | 'low' | 'high'
}

export function computeRisk(input: ScoringInput = {}): { score: number; vector: string; breakdown: RiskBreakdown } {
  const ac = input.attackComplexity ?? 'low'
  const pr = input.privilegesRequired ?? 'none'
  const ui = input.userInteraction ?? 'none'
  const scope = input.scope ?? 'unchanged'
  const c = input.confidentiality ?? 'none'
  const i = input.integrity ?? 'none'
  const a = input.availability ?? 'none'

  const prTable = scope === 'changed' ? PR_CHANGED : PR_UNCHANGED
  const exploitability = 8.22 * 0.85 * AC[ac] * prTable[pr] * UI[ui]
  const iss = 1 - (1 - CIA[c]) * (1 - CIA[i]) * (1 - CIA[a])
  const impact = scope === 'changed' ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss

  let base = 0
  if (impact > 0) {
    const raw = scope === 'changed' ? 1.08 * (impact + exploitability) : impact + exploitability
    base = Math.min(10, Math.ceil(raw * 10) / 10)
  }

  const vector = `CVSS:3.1/AV:N/AC:${ac === 'low' ? 'L' : 'H'}/PR:${pr === 'none' ? 'N' : pr === 'low' ? 'L' : 'H'}/UI:${ui === 'none' ? 'N' : 'R'}/S:${scope === 'changed' ? 'C' : 'U'}/C:${cia(c)}/I:${cia(i)}/A:${cia(a)}`

  return {
    score: Math.round(base * 10) / 10,
    vector,
    breakdown: {
      base,
      exploitability: Math.round(exploitability * 10) / 10,
      impact: Math.round(impact * 10) / 10,
      scope,
      confidentiality: c,
      integrity: i,
      availability: a,
      attackComplexity: ac,
      privilegesRequired: pr,
      userInteraction: ui
    }
  }
}

function cia(v: 'none' | 'low' | 'high') {
  return v === 'none' ? 'N' : v === 'low' ? 'L' : 'H'
}

export function severityFromScore(score: number): Severity {
  if (score === 0) return 'info'
  if (score < 4) return 'low'
  if (score < 7) return 'medium'
  if (score < 9) return 'high'
  return 'critical'
}

export function aggregateFindings(findings: LabFinding[]): Severity {
  const order: Severity[] = ['info', 'low', 'medium', 'high', 'critical']
  let max: Severity = 'info'
  for (const f of findings) {
    if (order.indexOf(f.severity) > order.indexOf(max)) max = f.severity
  }
  return max
}

export function severityToRisk(severity: Severity): number {
  switch (severity) {
    case 'critical':
      return 95
    case 'high':
      return 78
    case 'medium':
      return 55
    case 'low':
      return 25
    default:
      return 5
  }
}

export function entropyBits(value: string): number {
  if (!value) return 0
  const freq = new Map<string, number>()
  for (const ch of value) freq.set(ch, (freq.get(ch) ?? 0) + 1)
  const len = value.length
  let h = 0
  for (const count of freq.values()) {
    const p = count / len
    h -= p * Math.log2(p)
  }
  return Math.round(h * len * 10) / 10
}
