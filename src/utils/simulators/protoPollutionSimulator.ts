import type { LabFinding, SimulatedResult } from '../../types'
import type { Locale } from '../../i18n'
import { aggregateFindings, computeRisk, severityToRisk } from './riskScoring'

export function simulateProtoPollution(payload: string, scenario: Record<string, string | boolean>, locale: Locale = 'ru'): SimulatedResult & { riskScore: number } {
  const isRu = locale === 'ru'
  const safeMerge = Boolean(scenario.safeMerge)
  const findings: LabFinding[] = []

  let parsed: unknown = null
  let parseError = ''
  try {
    parsed = JSON.parse(payload)
  } catch (e) {
    parseError = (e as Error).message
  }

  const json = JSON.stringify(parsed ?? {})
  const hasProto = /__proto__|"constructor"|"prototype"/i.test(json)
  const polluteIsAdmin = /__proto__"\s*:\s*\{\s*"isAdmin"\s*:\s*true/i.test(payload) || /"isAdmin"\s*:\s*true/i.test(payload)
  const polluteShell = /__proto__"\s*:\s*\{\s*"shell"|env\.HOME|toString/i.test(payload)

  if (parseError) {
    findings.push({
      title: isRu ? 'Невалидный JSON' : 'Invalid JSON',
      severity: 'info',
      evidence: parseError,
      description: '—',
      recommendation: isRu ? 'Передайте валидный JSON-объект.' : 'Provide a valid JSON object.',
      legalContext: '—'
    })
  }

  if (hasProto && !safeMerge) {
    findings.push({
      title: isRu ? 'Загрязнение Object.prototype' : 'Object.prototype pollution',
      severity: 'critical',
      cwe: 'CWE-1321',
      evidence: payload.slice(0, 120),
      description: isRu
        ? 'Глубокий merge без allow-list ключей применяет __proto__, влияя на ВСЕ объекты в процессе.'
        : 'Deep merge without key allow-list applies __proto__, affecting ALL objects in the process.',
      recommendation: isRu
        ? 'Используйте Object.create(null) для входных map; библиотеки lodash >= 4.17.21.'
        : 'Use Object.create(null) for input maps; lodash >= 4.17.21.',
      legalContext: isRu ? 'Зачастую → RCE через template engines / env.' : 'Often → RCE via template engines / env.'
    })
  }

  if (polluteIsAdmin && !safeMerge) {
    findings.push({
      title: isRu ? 'Эскалация привилегий через isAdmin' : 'Privilege escalation via isAdmin',
      severity: 'critical',
      cwe: 'CWE-1321',
      description: isRu ? 'После загрязнения каждый объект сервера получает isAdmin=true по умолчанию.' : 'After pollution every server object inherits isAdmin=true by default.',
      recommendation: isRu ? 'Не доверяйте свойствам из prototype chain в auth-логике.' : 'Do not trust prototype-chain properties in auth logic.',
      legalContext: '—'
    })
  }

  if (polluteShell && !safeMerge) {
    findings.push({
      title: isRu ? 'Путь к RCE через child_process spawn' : 'Path to RCE via child_process spawn',
      severity: 'critical',
      cwe: 'CWE-1321',
      description: isRu ? 'Загрязнение env/shell параметров spawn() → выполнение команды атакующего.' : 'Polluting env/shell parameters of spawn() → attacker command execution.',
      recommendation: isRu ? 'Spawn с явным options-объектом без merge.' : 'Spawn with explicit options object, no merge.',
      legalContext: '—'
    })
  }

  if (safeMerge) {
    findings.push({
      title: isRu ? 'Безопасный merge активен' : 'Safe merge active',
      severity: 'info',
      description: isRu ? 'Ключи __proto__/constructor/prototype отфильтрованы.' : '__proto__/constructor/prototype keys filtered.',
      recommendation: '—',
      legalContext: '—'
    })
  }

  if (findings.length === 0) {
    findings.push({
      title: isRu ? 'Pollution не обнаружен' : 'No pollution detected',
      severity: 'info',
      description: '—',
      recommendation: '—',
      legalContext: '—'
    })
  }

  let body: object
  if (parseError) {
    body = { error: 'invalid JSON', reason: parseError }
  } else if (hasProto && !safeMerge) {
    body = {
      merged: parsed,
      sideEffects: {
        '({}).isAdmin': polluteIsAdmin ? true : '(unchanged)',
        '({}).polluted': true,
        templateRendered: '<%= toString %> → /usr/bin/id; id; uid=0(root)',
        warning: 'Process-wide Object.prototype contaminated'
      }
    }
  } else if (safeMerge) {
    body = { merged: stripDangerous(parsed), filteredKeys: ['__proto__', 'constructor', 'prototype'] }
  } else {
    body = { merged: parsed }
  }

  const overall = aggregateFindings(findings)
  const cvss = computeRisk({
    confidentiality: hasProto && !safeMerge ? 'low' : 'none',
    integrity: hasProto && !safeMerge ? 'high' : 'none',
    availability: 'low',
    scope: 'changed'
  })

  return {
    technique: isRu ? 'Prototype Pollution' : 'Prototype Pollution',
    techniques: findings.map((f) => f.title),
    summary: isRu
      ? `hasProto=${hasProto}, isAdmin=${polluteIsAdmin}, safeMerge=${safeMerge}`
      : `hasProto=${hasProto}, isAdmin=${polluteIsAdmin}, safeMerge=${safeMerge}`,
    statusCode: parseError ? 400 : 200,
    headers: { 'Content-Type': 'application/json', Server: 'Node.js/Express' },
    body: JSON.stringify(body, null, 2),
    severity: overall,
    legalBadge: isRu ? 'Эскалация и RCE — ст. 272/273 РФ / 278¹/278⁵ РУз' : 'Escalation/RCE statutes',
    findings,
    riskScore: Math.max(severityToRisk(overall), Math.round(cvss.score * 10)),
    cvssVector: cvss.vector,
    riskBreakdown: cvss.breakdown
  }
}

function stripDangerous(value: unknown): unknown {
  if (!value || typeof value !== 'object') return value
  const result: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (['__proto__', 'constructor', 'prototype'].includes(k)) continue
    result[k] = stripDangerous(v)
  }
  return result
}
