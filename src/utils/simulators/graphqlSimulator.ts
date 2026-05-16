import type { LabFinding, SimulatedResult } from '../../types'
import type { Locale } from '../../i18n'
import { aggregateFindings, computeRisk, severityToRisk } from './riskScoring'

export function simulateGraphql(payload: string, scenario: Record<string, string | boolean>, locale: Locale = 'ru'): SimulatedResult & { riskScore: number } {
  const isRu = locale === 'ru'
  const introspectionDisabled = Boolean(scenario.disableIntrospection)
  const depthLimit = Number(scenario.depthLimit) || 0
  const findings: LabFinding[] = []

  const isIntrospection = /__schema|__type/i.test(payload)
  const isBatch = /^\s*\[/.test(payload) || /mutation\s+\w+[^{}]*\{[\s\S]+mutation/i.test(payload)
  const depth = (payload.match(/\{/g) ?? []).length
  const aliasFlood = (payload.match(/\w+\s*:/g) ?? []).length > 20
  const fieldSuggestions = /Did you mean/i.test(payload)
  const directiveTrick = /@skip|@include|@stream|@defer/i.test(payload)

  if (isIntrospection && !introspectionDisabled) {
    findings.push({
      title: isRu ? 'Включён GraphQL introspection' : 'GraphQL introspection enabled',
      severity: 'medium',
      cwe: 'CWE-200',
      evidence: '__schema',
      description: isRu ? 'Атакующий получает полную карту схемы — все типы, поля, директивы.' : 'Attacker obtains full schema map — types, fields, directives.',
      recommendation: isRu ? 'Отключите introspection в production.' : 'Disable introspection in production.',
      legalContext: '—'
    })
  }

  if (isBatch) {
    findings.push({
      title: isRu ? 'Batch / array query' : 'Batch / array query',
      severity: 'high',
      cwe: 'CWE-770',
      description: isRu
        ? 'Множественные mutation в одном запросе используются для bypass rate-limit и brute-force.'
        : 'Multiple mutations per request used to bypass rate-limit and brute-force.',
      recommendation: isRu ? 'Запретите batched queries либо ограничьте число операций в запросе.' : 'Disable batched queries or cap operation count.',
      legalContext: '—'
    })
  }

  if (depth > 10 && (!depthLimit || depth > depthLimit)) {
    findings.push({
      title: isRu ? `Глубокая вложенность запроса (${depth} уровней)` : `Deeply nested query (${depth} levels)`,
      severity: 'high',
      cwe: 'CWE-674',
      evidence: `depth=${depth}`,
      description: isRu ? 'DoS через рекурсивную раскрутку связей user→friends→friends→...' : 'DoS via recursive expansion user→friends→friends→...',
      recommendation: isRu ? 'Установите depth-limit (5–7) и query-cost analysis.' : 'Set depth-limit (5–7) and query-cost analysis.',
      legalContext: isRu ? 'DoS = ст. 274/278⁴.' : 'DoS = computer sabotage.'
    })
  }

  if (aliasFlood) {
    findings.push({
      title: isRu ? 'Alias-flood / brute force' : 'Alias flood / brute force',
      severity: 'high',
      cwe: 'CWE-770',
      description: isRu ? '100+ alias на одну mutation login — обход rate-limit на верификацию пароля.' : '100+ aliases on a single login mutation — bypasses per-request rate limit.',
      recommendation: isRu ? 'Лимит по числу alias на операцию.' : 'Cap aliases per operation.',
      legalContext: '—'
    })
  }

  if (fieldSuggestions) {
    findings.push({
      title: isRu ? 'Утечка через "Did you mean"' : 'Leakage via "Did you mean"',
      severity: 'low',
      cwe: 'CWE-200',
      description: isRu ? 'Подсказки полей раскрывают скрытые операции даже с выключенным introspection.' : 'Field suggestions leak hidden operations even with introspection off.',
      recommendation: isRu ? 'Отключите field suggestions в production.' : 'Disable field suggestions in production.',
      legalContext: '—'
    })
  }

  if (directiveTrick) {
    findings.push({
      title: isRu ? 'Подозрительные директивы' : 'Suspicious directives',
      severity: 'medium',
      cwe: 'CWE-770',
      evidence: payload.match(/@\w+/g)?.join(', '),
      description: isRu ? '@stream/@defer могут переиспользоваться для DoS.' : '@stream/@defer can be abused for DoS.',
      recommendation: isRu ? 'Включайте директивы выборочно и с лимитами.' : 'Enable directives selectively with limits.',
      legalContext: '—'
    })
  }

  if (findings.length === 0) {
    findings.push({
      title: isRu ? 'GraphQL: подозрительных паттернов нет' : 'GraphQL: no suspicious patterns',
      severity: 'info',
      description: '—',
      recommendation: '—',
      legalContext: '—'
    })
  }

  let body: object
  if (isIntrospection && !introspectionDisabled) {
    body = {
      data: {
        __schema: {
          types: [
            { name: 'User', fields: ['id', 'email', 'role', 'mfaSecret', 'passwordHash', 'apiKey'] },
            { name: 'AdminMutation', fields: ['impersonate(userId: ID!)', 'exportAll', 'rotateSecret'] },
            { name: 'InternalQuery', fields: ['secrets', 'envVars', 'metrics'] }
          ],
          mutations: ['login', 'register', 'resetPassword', 'adminImpersonate', 'adminExportAll']
        }
      }
    }
  } else if (isBatch) {
    body = {
      data: Array.from({ length: 100 }, (_, i) => ({
        op: `login_${i}`,
        success: i === 47,
        token: i === 47 ? 'eyJhbGciOi…' : null
      }))
    }
  } else {
    body = { data: { ok: true, depth, fields: aliasFlood ? '20+' : 'normal' } }
  }

  const overall = aggregateFindings(findings)
  const cvss = computeRisk({
    confidentiality: isIntrospection && !introspectionDisabled ? 'high' : 'low',
    integrity: isBatch ? 'low' : 'none',
    availability: depth > 10 || aliasFlood ? 'high' : 'none'
  })

  return {
    technique: isRu ? 'GraphQL злоупотребления' : 'GraphQL abuse',
    techniques: findings.map((f) => f.title),
    summary: isRu
      ? `introspection=${isIntrospection}, batch=${isBatch}, depth=${depth}, aliases=${aliasFlood}`
      : `introspection=${isIntrospection}, batch=${isBatch}, depth=${depth}, aliases=${aliasFlood}`,
    statusCode: 200,
    headers: { 'Content-Type': 'application/json', Server: 'apollo-server/4.10' },
    body: JSON.stringify(body, null, 2),
    severity: overall,
    legalBadge: isRu ? 'Раскрытие схемы + DoS = ст. 272/274 РФ / 278¹/278⁴ РУз' : 'Schema disclosure + DoS',
    findings,
    riskScore: Math.max(severityToRisk(overall), Math.round(cvss.score * 10)),
    cvssVector: cvss.vector,
    riskBreakdown: cvss.breakdown
  }
}
