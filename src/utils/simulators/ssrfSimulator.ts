import type { LabFinding, SimulatedResult } from '../../types'
import type { Locale } from '../../i18n'
import { aggregateFindings, computeRisk, severityToRisk } from './riskScoring'

const SENSITIVE_HOSTS = [
  { host: '169.254.169.254', label: 'AWS/Azure IMDS' },
  { host: 'metadata.google.internal', label: 'GCP metadata' },
  { host: '100.100.100.200', label: 'Alibaba metadata' },
  { host: '127.0.0.1', label: 'loopback' },
  { host: 'localhost', label: 'loopback' },
  { host: '0.0.0.0', label: 'all-interfaces' },
  { host: '[::1]', label: 'IPv6 loopback' }
]

const PRIVATE_CIDRS = [/^10\./, /^192\.168\./, /^172\.(1[6-9]|2[0-9]|3[01])\./, /^169\.254\./]

interface Scenario {
  filter?: 'none' | 'blacklist' | 'allowlist'
  followRedirects?: boolean
}

export function simulateSsrf(payload: string, scenario: Record<string, string | boolean>, locale: Locale = 'ru'): SimulatedResult & { riskScore: number } {
  const isRu = locale === 'ru'
  const cfg: Scenario = {
    filter: (scenario.filter as Scenario['filter']) ?? 'blacklist',
    followRedirects: scenario.followRedirects !== false
  }

  const findings: LabFinding[] = []
  let parsed: URL | null = null
  try {
    parsed = new URL(payload)
  } catch {
    findings.push({
      title: isRu ? 'Невалидный URL' : 'Invalid URL',
      severity: 'info',
      description: isRu ? 'Не удалось распарсить ввод как URL.' : 'Could not parse input as URL.',
      recommendation: isRu ? 'Используйте схему http(s)://host.' : 'Use http(s)://host scheme.',
      legalContext: '—'
    })
    const cvss = computeRisk({})
    return {
      technique: isRu ? 'SSRF: невалидный URL' : 'SSRF: invalid URL',
      summary: isRu ? 'Запрос не сделан.' : 'No request made.',
      statusCode: 400,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'invalid url' }, null, 2),
      severity: 'info',
      legalBadge: '—',
      findings,
      riskScore: 5,
      cvssVector: cvss.vector,
      riskBreakdown: cvss.breakdown
    }
  }

  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  const scheme = parsed.protocol.replace(':', '').toLowerCase()
  const isMetadata = SENSITIVE_HOSTS.some((h) => host === h.host.toLowerCase().replace(/^\[|\]$/g, ''))
  const isPrivate = PRIVATE_CIDRS.some((re) => re.test(host)) || isMetadata
  const dangerousScheme = !['http', 'https'].includes(scheme)

  if (dangerousScheme) {
    findings.push({
      title: isRu ? `Опасная схема: ${scheme}://` : `Dangerous scheme: ${scheme}://`,
      severity: 'high',
      cwe: 'CWE-918',
      evidence: scheme,
      description: isRu ? 'file://, gopher://, dict:// позволяют читать FS или эксплуатировать внутренние протоколы.' : 'file://, gopher://, dict:// can read FS or pivot to internal protocols.',
      recommendation: isRu ? 'Allow-list схем: только http/https.' : 'Allow-list schemes: http/https only.',
      legalContext: isRu ? 'См. ст. 272 УК РФ / 278¹ УК РУз.' : 'Unauthorized-access statutes apply.'
    })
  }

  if (isPrivate && cfg.filter !== 'allowlist') {
    findings.push({
      title: isRu ? 'Доступ к внутреннему адресу' : 'Internal address access',
      severity: isMetadata ? 'critical' : 'high',
      cwe: 'CWE-918',
      evidence: host,
      description: isMetadata
        ? isRu ? 'Запрос к cloud metadata service — классический путь к temp credentials и IAM-токенам.' : 'Request to cloud metadata service — classic path to temp credentials and IAM tokens.'
        : isRu ? 'Доступ к приватной сети из application-level запроса.' : 'Reaching private network from application-level request.',
      recommendation: isRu ? 'Резолвите DNS перед запросом и блокируйте RFC1918/169.254.0.0/16; форсируйте IMDSv2.' : 'Resolve DNS before request and block RFC1918/169.254.0.0/16; enforce IMDSv2.',
      legalContext: isRu ? 'Доступ к закрытым сервисам без разрешения.' : 'Access to non-public services without authorization.'
    })
  }

  if (cfg.filter === 'blacklist' && /\.example\.com$|@/.test(parsed.href)) {
    findings.push({
      title: isRu ? 'Обход blacklist через DNS rebinding / userinfo' : 'Blacklist bypass via DNS rebinding / userinfo',
      severity: 'high',
      cwe: 'CWE-918',
      evidence: parsed.href,
      description: isRu ? 'Blacklist на хостнейм обходится через подставной DNS или userinfo (user@host).' : 'Hostname blacklists are bypassed via rebinding DNS or userinfo (user@host).',
      recommendation: isRu ? 'Используйте allow-list ip, а не строки хостов; запретите userinfo в URL.' : 'Use IP allow-list, not host strings; reject userinfo in URL.',
      legalContext: '—'
    })
  }

  if (cfg.followRedirects) {
    findings.push({
      title: isRu ? 'Следование редиректам без проверки' : 'Following redirects without re-validation',
      severity: 'medium',
      cwe: 'CWE-918',
      description: isRu ? 'Внешний 302 → 169.254.169.254 обходит первичную проверку.' : 'External 302 → 169.254.169.254 bypasses initial validation.',
      recommendation: isRu ? 'Отключите следование редиректам либо ревалидируйте каждый hop.' : 'Disable redirect following or re-validate each hop.',
      legalContext: '—'
    })
  }

  let body: object
  let status = 200
  if (isMetadata && cfg.filter !== 'allowlist') {
    body = {
      meta: 'EC2 IMDSv1 response (vulnerable)',
      'ami-id': 'ami-0abcdef1234567890',
      'instance-id': 'i-0d8f2c7b1e3a4c6f0',
      'instance-type': 't3.medium',
      'iam/security-credentials/web-prod-role': {
        Code: 'Success',
        Type: 'AWS-HMAC',
        AccessKeyId: 'ASIAIOSFODNN7EXAMPLE',
        SecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        Token: 'IQoJb3JpZ2luX2VjEN3//////////wEaCXVzLWVhc3QtMSJHMEUCIQDH7yU…<truncated>…',
        Expiration: '2026-05-13T15:30:00Z'
      },
      'public-ipv4': '54.93.117.42',
      'placement/region': 'eu-central-1'
    }
  } else if (isPrivate && cfg.filter !== 'allowlist') {
    body = { error: 'pivoted', target: host, response: 'connection refused (mocked)' }
    status = 502
  } else if (scheme === 'file') {
    body = { content: '/etc/passwd via file://\nroot:x:0:0:root:/root:/bin/bash\n…' }
  } else {
    body = { ok: true, target: parsed.href, note: 'external fetch (mock)' }
  }

  if (findings.length === 0) {
    findings.push({
      title: isRu ? 'SSRF не обнаружен' : 'No SSRF detected',
      severity: 'info',
      description: isRu ? 'URL прошёл проверки.' : 'URL passed validation.',
      recommendation: '—',
      legalContext: '—'
    })
  }

  const overall = aggregateFindings(findings)
  const cvss = computeRisk({
    confidentiality: isMetadata ? 'high' : overall === 'high' ? 'low' : 'none',
    integrity: 'low',
    scope: isMetadata ? 'changed' : 'unchanged',
    privilegesRequired: 'low'
  })

  return {
    technique: isMetadata ? (isRu ? 'SSRF → cloud metadata' : 'SSRF → cloud metadata') : isRu ? 'SSRF' : 'SSRF',
    techniques: findings.map((f) => f.title),
    summary: isRu
      ? `host=${host}, scheme=${scheme}, private=${isPrivate}, metadata=${isMetadata}, filter=${cfg.filter}.`
      : `host=${host}, scheme=${scheme}, private=${isPrivate}, metadata=${isMetadata}, filter=${cfg.filter}.`,
    statusCode: status,
    headers: { 'Content-Type': 'application/json', 'X-Fetched-By': 'app-proxy/1.4' },
    body: JSON.stringify(body, null, 2),
    severity: overall,
    legalBadge: isRu ? 'УК ст. 272 РФ / 278¹ РУз — неправомерный доступ' : 'Unauthorized-access statutes',
    findings,
    riskScore: Math.max(severityToRisk(overall), Math.round(cvss.score * 10)),
    cvssVector: cvss.vector,
    riskBreakdown: cvss.breakdown
  }
}
