import type { LabFinding, SimulatedResult } from '../../types'
import type { Locale } from '../../i18n'
import { aggregateFindings, computeRisk, severityToRisk } from './riskScoring'

const ALLOWED_HOSTS = ['vulnlab.local', 'app.vulnlab.local', 'auth.vulnlab.local']

export function simulateOpenRedirect(payload: string, scenario: Record<string, string | boolean>, locale: Locale = 'ru'): SimulatedResult & { riskScore: number } {
  const isRu = locale === 'ru'
  const useAllowList = scenario.validation !== 'none'
  const validation = String(scenario.validation ?? 'startsWith')
  const findings: LabFinding[] = []

  let parsed: URL | null = null
  let host = ''
  try {
    parsed = new URL(payload, 'https://vulnlab.local')
    host = parsed.hostname.toLowerCase()
  } catch {
    // ignore
  }

  const isProtocolRelative = /^\/\//.test(payload)
  const isJsScheme = /^javascript:/i.test(payload)
  const isDataScheme = /^data:/i.test(payload)
  const isExternal = parsed && !ALLOWED_HOSTS.includes(host)
  const startsWithTrick = validation === 'startsWith' && /vulnlab\.local\.[a-z]/.test(payload)
  const userInfoTrick = parsed?.username && parsed.username.length > 0
  const blocked = useAllowList && validation === 'allowlist' && isExternal

  if (isJsScheme || isDataScheme) {
    findings.push({
      title: isRu ? 'Опасная схема URL' : 'Dangerous URL scheme',
      severity: 'high',
      cwe: 'CWE-601',
      evidence: payload.slice(0, 80),
      description: isRu ? 'javascript:/data: схемы выполняют код в контексте страницы.' : 'javascript:/data: schemes execute code in page context.',
      recommendation: isRu ? 'Allow-list только http/https.' : 'Allow-list http/https only.',
      legalContext: '—'
    })
  }

  if (isExternal && !blocked) {
    findings.push({
      title: isRu ? `Перенаправление на внешний хост: ${host}` : `Redirect to external host: ${host}`,
      severity: 'high',
      cwe: 'CWE-601',
      evidence: host,
      description: isRu ? 'Используется для фишинга — жертва верит origin приложения.' : 'Used in phishing — victim trusts the application origin.',
      recommendation: isRu ? 'Allow-list доменов, относительные URL.' : 'Domain allow-list, relative URLs.',
      legalContext: isRu ? 'Фишинг с использованием бренда — мошенничество (ст. 159 / 168).' : 'Brand-based phishing maps to fraud statutes.'
    })
  }

  if (startsWithTrick) {
    findings.push({
      title: isRu ? 'Bypass startsWith: vulnlab.local.attacker.tld' : 'startsWith bypass: vulnlab.local.attacker.tld',
      severity: 'high',
      cwe: 'CWE-601',
      evidence: host,
      description: isRu ? 'Префикс-проверка обходится подменой суффикса.' : 'Prefix check bypassed by suffix substitution.',
      recommendation: isRu ? 'Парсите URL и сравнивайте hostname строго.' : 'Parse URL and compare hostname strictly.',
      legalContext: '—'
    })
  }

  if (userInfoTrick) {
    findings.push({
      title: isRu ? 'userinfo-трюк: https://vulnlab.local@attacker.tld' : 'userinfo trick: https://vulnlab.local@attacker.tld',
      severity: 'high',
      cwe: 'CWE-601',
      description: isRu ? 'Часть до @ — userinfo, реальный хост идёт после.' : 'Part before @ is userinfo, real host follows after.',
      recommendation: isRu ? 'Отвергайте URL с userinfo.' : 'Reject URLs containing userinfo.',
      legalContext: '—'
    })
  }

  if (isProtocolRelative) {
    findings.push({
      title: isRu ? 'Protocol-relative URL' : 'Protocol-relative URL',
      severity: 'medium',
      cwe: 'CWE-601',
      description: isRu ? '//attacker.tld наследует протокол страницы и уводит пользователя.' : '//attacker.tld inherits page protocol and redirects user.',
      recommendation: isRu ? 'Принимайте только относительные URL, начинающиеся с одиночного /.' : 'Accept only relative URLs starting with a single /.',
      legalContext: '—'
    })
  }

  if (blocked) {
    findings.push({
      title: isRu ? 'Allow-list заблокировал редирект' : 'Allow-list blocked the redirect',
      severity: 'info',
      description: '—',
      recommendation: '—',
      legalContext: '—'
    })
  }

  if (findings.length === 0) {
    findings.push({
      title: isRu ? 'URL безопасен' : 'URL safe',
      severity: 'info',
      description: '—',
      recommendation: '—',
      legalContext: '—'
    })
  }

  const status = blocked ? 400 : 302
  const headers: Record<string, string> = blocked
    ? { 'Content-Type': 'application/json' }
    : { Location: payload, 'Content-Type': 'text/html' }

  const overall = aggregateFindings(findings)
  const cvss = computeRisk({
    confidentiality: 'low',
    integrity: isExternal ? 'low' : 'none',
    userInteraction: 'required'
  })

  return {
    technique: isRu ? 'Open Redirect' : 'Open Redirect',
    techniques: findings.map((f) => f.title),
    summary: isRu
      ? `host=${host || '—'}, external=${isExternal}, blocked=${blocked}`
      : `host=${host || '—'}, external=${isExternal}, blocked=${blocked}`,
    statusCode: status,
    headers,
    body: JSON.stringify(blocked ? { error: 'redirect blocked' } : { redirect: payload, hint: 'Location header set' }, null, 2),
    severity: overall,
    legalBadge: isRu ? 'Фишинговая связка — ст. 159 РФ / 168 РУз' : 'Fraud statutes when used for phishing',
    findings,
    riskScore: Math.max(severityToRisk(overall), Math.round(cvss.score * 10)),
    cvssVector: cvss.vector,
    riskBreakdown: cvss.breakdown
  }
}
