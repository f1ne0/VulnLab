import type { LabFinding, SimulatedResult } from '../../types'
import type { Locale } from '../../i18n'
import { aggregateFindings, computeRisk, severityToRisk } from './riskScoring'

interface ResourceRecord {
  id: string | number
  ownerId: string
  data: object
}

const RESOURCES: ResourceRecord[] = [
  { id: 1001, ownerId: 'u_self', data: { invoice: 'INV-2026-1001', amount: '$420.00', card: '**** 4242', name: 'You (researcher)' } },
  { id: 1002, ownerId: 'u_other', data: { invoice: 'INV-2026-1002', amount: '$12 500.00', card: '**** 8801', name: 'Sarah Lin, CFO' } },
  { id: 1003, ownerId: 'u_other', data: { invoice: 'INV-2026-1003', amount: '$98 200.00', card: '**** 0042', name: 'Confidential Inc.' } },
  { id: 1004, ownerId: 'u_other', data: { invoice: 'INV-2026-1004', amount: '$3 145.27', card: '**** 6611', name: 'admin@vulnlab.local' } },
  { id: 'admin', ownerId: 'u_admin', data: { panel: '/admin', features: ['user-impersonation', 'data-export', 'feature-flags'] } }
]

export function simulateIdor(payload: string, scenario: Record<string, string | boolean>, locale: Locale = 'ru'): SimulatedResult & { riskScore: number } {
  const isRu = locale === 'ru'
  const objLevel = Boolean(scenario.objectLevel)
  const findings: LabFinding[] = []

  const idMatch = payload.match(/[?&]?(?:id|invoice|user|order)=(\w+)/i) ?? payload.match(/\/(\d+|admin)\b/)
  const requestedId = idMatch?.[1] ?? payload.trim()
  const target = RESOURCES.find((r) => String(r.id) === requestedId)

  const isOwnObject = target && target.ownerId === 'u_self'
  const isAdminObject = requestedId === 'admin'
  const escalation = target && !isOwnObject

  if (!objLevel && escalation) {
    findings.push({
      title: isAdminObject ? (isRu ? 'Доступ к admin-объекту' : 'Access to admin object') : isRu ? 'Доступ к чужому объекту' : 'Access to another user object',
      severity: isAdminObject ? 'critical' : 'high',
      cwe: 'CWE-639',
      evidence: `id=${requestedId}`,
      description: isRu
        ? 'Object-level авторизация не проверяет владельца ресурса — классический IDOR.'
        : 'Object-level authorization missing — classic IDOR.',
      recommendation: isRu
        ? 'Проверяйте owner_id ресурса против session.user_id перед ответом.'
        : 'Check resource.owner_id against session.user_id before responding.',
      legalContext: isRu ? 'УК ст. 272 РФ / 278¹ РУз.' : 'Unauthorized access statutes.'
    })
  }

  if (/^\d{4}$/.test(String(requestedId))) {
    findings.push({
      title: isRu ? 'Sequential ID — массовое перечисление' : 'Sequential ID — enumeration friendly',
      severity: 'medium',
      cwe: 'CWE-340',
      description: isRu ? 'Числовые предсказуемые ID позволяют скриптовое перечисление всех записей.' : 'Predictable numeric IDs enable scripted enumeration of all records.',
      recommendation: isRu ? 'Используйте UUIDv7 или непредсказуемые идентификаторы.' : 'Use UUIDv7 or non-guessable identifiers.',
      legalContext: '—'
    })
  }

  if (objLevel) {
    findings.push({
      title: isRu ? 'Object-level авторизация активна' : 'Object-level authorization active',
      severity: 'info',
      description: isRu ? 'Запрос отклонён по проверке владельца.' : 'Request rejected by ownership check.',
      recommendation: '—',
      legalContext: '—'
    })
  }

  if (!target) {
    findings.push({
      title: isRu ? 'Ресурс не найден' : 'Resource not found',
      severity: 'info',
      description: '—',
      recommendation: '—',
      legalContext: '—'
    })
  }

  let body: object
  let status = 200
  if (!target) {
    body = { error: 'not found' }
    status = 404
  } else if (objLevel && !isOwnObject) {
    body = { error: 'forbidden', reason: 'ownership check failed' }
    status = 403
  } else {
    body = { id: target.id, owner: target.ownerId, ...target.data }
  }

  const overall = aggregateFindings(findings)
  const cvss = computeRisk({
    confidentiality: !objLevel && escalation ? 'high' : 'low',
    integrity: isAdminObject && !objLevel ? 'high' : 'none',
    privilegesRequired: 'low'
  })

  return {
    technique: isAdminObject && !objLevel ? (isRu ? 'IDOR → privilege escalation' : 'IDOR → privilege escalation') : isRu ? 'Insecure Direct Object Reference' : 'Insecure Direct Object Reference',
    techniques: findings.map((f) => f.title),
    summary: isRu
      ? `requestedId=${requestedId}, owner=${target?.ownerId ?? '—'}, objectLevel=${objLevel}`
      : `requestedId=${requestedId}, owner=${target?.ownerId ?? '—'}, objectLevel=${objLevel}`,
    statusCode: status,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body, null, 2),
    severity: overall,
    legalBadge: isRu ? 'УК ст. 272 / 278¹ — неправомерный доступ к чужим данным' : 'Unauthorized access to other users data',
    findings,
    riskScore: Math.max(severityToRisk(overall), Math.round(cvss.score * 10)),
    cvssVector: cvss.vector,
    riskBreakdown: cvss.breakdown
  }
}
