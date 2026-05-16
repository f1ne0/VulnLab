import type { LabFinding, SimulatedResult } from '../../types'
import type { Locale } from '../../i18n'
import { aggregateFindings, computeRisk, severityFromScore } from './riskScoring'
import { parseCsp } from './xssSimulator'

interface ParsedSetCookie {
  raw: string
  name: string
  attrs: Record<string, string | true>
}

function parseSetCookie(raw: string): ParsedSetCookie {
  const parts = raw.split(';').map((p) => p.trim())
  const [namePart = ''] = parts
  const name = namePart.split('=')[0] ?? ''
  const attrs: Record<string, string | true> = {}
  for (const part of parts.slice(1)) {
    const [k, ...rest] = part.split('=')
    attrs[k.toLowerCase()] = rest.length ? rest.join('=') : true
  }
  return { raw, name, attrs }
}

function parseHsts(raw: string) {
  const parts = raw.split(';').map((p) => p.trim().toLowerCase())
  const maxAgeRaw = parts.find((p) => p.startsWith('max-age='))
  const maxAge = maxAgeRaw ? Number(maxAgeRaw.split('=')[1]) : 0
  return {
    maxAge,
    includeSubDomains: parts.includes('includesubdomains'),
    preload: parts.includes('preload')
  }
}

export function analyzeHeaders(rawHeaders: string, locale: Locale = 'ru'): SimulatedResult & { score: number } {
  const isRu = locale === 'ru'
  const lines = rawHeaders
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)

  const parsed = new Map<string, string>()
  const cookies: ParsedSetCookie[] = []
  lines.forEach((line) => {
    const [name, ...rest] = line.split(':')
    if (!name || rest.length === 0) return
    const key = name.trim().toLowerCase()
    const value = rest.join(':').trim()
    if (key === 'set-cookie') {
      cookies.push(parseSetCookie(value))
    } else {
      parsed.set(key, value)
    }
  })

  const findings: LabFinding[] = []
  let score = 100

  const hstsRaw = parsed.get('strict-transport-security')
  if (!hstsRaw) {
    score -= 12
    findings.push({
      title: isRu ? 'Нет HSTS' : 'Missing HSTS',
      severity: 'high',
      cwe: 'CWE-319',
      description: isRu ? 'Без HSTS возможен downgrade на HTTP.' : 'Without HSTS HTTPS downgrade is possible.',
      recommendation: isRu ? 'Добавьте HSTS с max-age >= 180 дней + includeSubDomains.' : 'Add HSTS with max-age >= 180 days + includeSubDomains.',
      legalContext: isRu ? 'См. требования ФЗ-152 / GDPR к защите канала.' : 'Regulatory expectations of channel protection.'
    })
  } else {
    const hsts = parseHsts(hstsRaw)
    if (hsts.maxAge < 15552000) {
      score -= 8
      findings.push({
        title: isRu ? `Слабый HSTS max-age=${hsts.maxAge}` : `Weak HSTS max-age=${hsts.maxAge}`,
        severity: 'medium',
        cwe: 'CWE-319',
        evidence: hstsRaw,
        description: isRu ? 'max-age < 180 дней.' : 'max-age < 180 days.',
        recommendation: isRu ? 'Установите max-age >= 15552000.' : 'Set max-age >= 15552000.',
        legalContext: '—'
      })
    }
    if (!hsts.includeSubDomains) {
      score -= 4
      findings.push({
        title: isRu ? 'HSTS без includeSubDomains' : 'HSTS lacks includeSubDomains',
        severity: 'low',
        description: isRu ? 'Поддомены остаются уязвимы.' : 'Subdomains remain exposed.',
        recommendation: 'add includeSubDomains',
        legalContext: '—'
      })
    }
  }

  const cspRaw = parsed.get('content-security-policy')
  if (!cspRaw) {
    score -= 15
    findings.push({
      title: isRu ? 'Нет CSP' : 'Missing CSP',
      severity: 'high',
      cwe: 'CWE-693',
      description: isRu ? 'Без CSP XSS не сдерживается браузером.' : 'Without CSP XSS is not browser-mitigated.',
      recommendation: isRu ? 'Внедрите nonce-based CSP.' : 'Deploy a nonce-based CSP.',
      legalContext: '—'
    })
  } else {
    const csp = parseCsp(cspRaw)
    if (csp.unsafeInline) {
      score -= 10
      findings.push({
        title: "CSP: 'unsafe-inline'",
        severity: 'high',
        cwe: 'CWE-693',
        evidence: "'unsafe-inline'",
        description: isRu ? "'unsafe-inline' практически отключает CSP." : "'unsafe-inline' largely defeats CSP.",
        recommendation: isRu ? 'Перейдите на nonce/hash-based.' : 'Move to nonce/hash-based.',
        legalContext: '—'
      })
    }
    if (csp.unsafeEval) {
      score -= 6
      findings.push({
        title: "CSP: 'unsafe-eval'",
        severity: 'medium',
        cwe: 'CWE-693',
        description: isRu ? 'eval-семантика доступна.' : 'eval-class APIs remain available.',
        recommendation: isRu ? 'Удалите unsafe-eval.' : 'Remove unsafe-eval.',
        legalContext: '—'
      })
    }
    if (csp.wildcardSources.length) {
      score -= 4
      findings.push({
        title: isRu ? 'CSP: wildcard источники' : 'CSP: wildcard sources',
        severity: 'medium',
        evidence: csp.wildcardSources.join(', '),
        description: isRu ? 'Расширяет поверхность атаки.' : 'Broadens attack surface.',
        recommendation: isRu ? 'Сузьте до конкретных origin.' : 'Narrow to specific origins.',
        legalContext: '—'
      })
    }
    if (csp.missingDefault) {
      score -= 4
      findings.push({
        title: isRu ? 'CSP: нет default-src' : 'CSP: missing default-src',
        severity: 'low',
        description: isRu ? 'Дыры в покрытии директив.' : 'Coverage gaps in directives.',
        recommendation: "default-src 'self'",
        legalContext: '—'
      })
    }
    if (csp.missingFrameAncestors) {
      score -= 4
      findings.push({
        title: isRu ? 'CSP: нет frame-ancestors' : 'CSP: missing frame-ancestors',
        severity: 'low',
        description: isRu ? 'Возможен clickjacking.' : 'Clickjacking remains possible.',
        recommendation: "frame-ancestors 'none'",
        legalContext: '—'
      })
    }
    if (csp.missingBaseUri) {
      score -= 4
      findings.push({
        title: isRu ? 'CSP: нет base-uri' : 'CSP: missing base-uri',
        severity: 'low',
        description: isRu ? 'Возможна подмена <base>.' : '<base> hijacking possible.',
        recommendation: "base-uri 'self'",
        legalContext: '—'
      })
    }
  }

  const xfo = parsed.get('x-frame-options')
  const cspRawForXfo = parsed.get('content-security-policy') ?? ''
  if (!xfo && !/frame-ancestors/.test(cspRawForXfo)) {
    score -= 5
    findings.push({
      title: isRu ? 'Нет X-Frame-Options и frame-ancestors' : 'No X-Frame-Options or frame-ancestors',
      severity: 'medium',
      cwe: 'CWE-1021',
      description: isRu ? 'Возможен clickjacking.' : 'Clickjacking remains possible.',
      recommendation: isRu ? 'Добавьте X-Frame-Options: DENY или CSP frame-ancestors.' : 'Add X-Frame-Options: DENY or CSP frame-ancestors.',
      legalContext: '—'
    })
  } else if (xfo && /allow-from/i.test(xfo)) {
    score -= 3
    findings.push({
      title: isRu ? 'X-Frame-Options: ALLOW-FROM устарел' : 'X-Frame-Options: ALLOW-FROM is obsolete',
      severity: 'low',
      description: isRu ? 'Многие браузеры игнорируют ALLOW-FROM.' : 'Many browsers ignore ALLOW-FROM.',
      recommendation: isRu ? 'Используйте CSP frame-ancestors.' : 'Use CSP frame-ancestors.',
      legalContext: '—'
    })
  }

  if (parsed.get('x-content-type-options') !== 'nosniff') {
    score -= 5
    findings.push({
      title: isRu ? 'Нет X-Content-Type-Options: nosniff' : 'Missing X-Content-Type-Options: nosniff',
      severity: 'medium',
      cwe: 'CWE-430',
      description: isRu ? 'Возможен MIME-sniffing.' : 'MIME-sniffing remains possible.',
      recommendation: 'X-Content-Type-Options: nosniff',
      legalContext: '—'
    })
  }

  const refPolicy = parsed.get('referrer-policy')
  if (!refPolicy) {
    score -= 4
    findings.push({
      title: isRu ? 'Нет Referrer-Policy' : 'Missing Referrer-Policy',
      severity: 'low',
      description: isRu ? 'Утечка пути/параметров в Referer.' : 'Leakage of path/params via Referer.',
      recommendation: 'Referrer-Policy: strict-origin-when-cross-origin',
      legalContext: '—'
    })
  } else if (/unsafe-url|no-referrer-when-downgrade/i.test(refPolicy)) {
    score -= 3
    findings.push({
      title: isRu ? 'Слабая Referrer-Policy' : 'Weak Referrer-Policy',
      severity: 'low',
      evidence: refPolicy,
      description: isRu ? 'Слишком много данных отправляется в Referer.' : 'Sends too much data in Referer.',
      recommendation: 'strict-origin-when-cross-origin',
      legalContext: '—'
    })
  }

  const acao = parsed.get('access-control-allow-origin')
  if (acao === '*') {
    score -= 10
    findings.push({
      title: isRu ? 'CORS: Access-Control-Allow-Origin: *' : 'CORS: Access-Control-Allow-Origin: *',
      severity: 'high',
      cwe: 'CWE-942',
      evidence: acao,
      description: isRu ? 'Wildcard CORS опасен при наличии креденшалов.' : 'Wildcard CORS is dangerous with credentials.',
      recommendation: isRu ? 'Ограничьте список origin.' : 'Restrict to specific origins.',
      legalContext: '—'
    })
  }

  if (parsed.get('access-control-allow-credentials') === 'true' && acao && acao !== 'null') {
    if (acao === '*') {
      score -= 5
      findings.push({
        title: isRu ? 'CORS: креденшалы + wildcard' : 'CORS: credentials + wildcard',
        severity: 'critical',
        cwe: 'CWE-942',
        description: isRu ? 'Эта комбинация запрещена спецификацией и крайне опасна.' : 'This combination is spec-forbidden and very dangerous.',
        recommendation: isRu ? 'Указывайте конкретный Origin.' : 'Echo a specific Origin instead.',
        legalContext: '—'
      })
    }
  }

  if (parsed.get('cross-origin-opener-policy') !== 'same-origin') {
    score -= 3
    findings.push({
      title: isRu ? 'COOP не same-origin' : 'COOP not same-origin',
      severity: 'low',
      description: isRu ? 'Снижена изоляция окон.' : 'Reduced cross-window isolation.',
      recommendation: 'Cross-Origin-Opener-Policy: same-origin',
      legalContext: '—'
    })
  }

  if (!parsed.get('cross-origin-resource-policy')) {
    score -= 3
    findings.push({
      title: isRu ? 'Нет CORP' : 'Missing CORP',
      severity: 'low',
      description: isRu ? 'Ресурсы могут быть встроены кросс-сайтно.' : 'Resources may be embedded cross-site.',
      recommendation: 'Cross-Origin-Resource-Policy: same-origin',
      legalContext: '—'
    })
  }

  if (!parsed.get('permissions-policy')) {
    score -= 3
    findings.push({
      title: isRu ? 'Нет Permissions-Policy' : 'Missing Permissions-Policy',
      severity: 'low',
      description: isRu ? 'Используются дефолтные разрешения браузера.' : 'Default browser permissions apply.',
      recommendation: isRu ? 'Отключите неиспользуемые фичи (camera, geolocation, etc.).' : 'Disable unused features (camera, geolocation, etc.).',
      legalContext: '—'
    })
  }

  if (!parsed.get('cache-control')) {
    score -= 3
    findings.push({
      title: isRu ? 'Нет Cache-Control' : 'Missing Cache-Control',
      severity: 'low',
      description: isRu ? 'Чувствительные данные могут попасть в кэш.' : 'Sensitive data may be cached.',
      recommendation: 'Cache-Control: no-store',
      legalContext: '—'
    })
  }

  const server = parsed.get('server')
  const poweredBy = parsed.get('x-powered-by')
  if (server || poweredBy) {
    score -= 6
    findings.push({
      title: isRu ? 'Утечка fingerprint сервера' : 'Server fingerprint leakage',
      severity: 'low',
      cwe: 'CWE-200',
      evidence: [server, poweredBy].filter(Boolean).join(' | '),
      description: isRu ? `Раскрыто: ${[server, poweredBy].filter(Boolean).join(' | ')}` : `Disclosed: ${[server, poweredBy].filter(Boolean).join(' | ')}`,
      recommendation: isRu ? 'Удалите/обобщите banner-заголовки.' : 'Remove/generalize banner headers.',
      legalContext: '—'
    })
  }

  cookies.forEach((cookie) => {
    if (!('secure' in cookie.attrs)) {
      score -= 4
      findings.push({
        title: isRu ? `Cookie ${cookie.name}: нет Secure` : `Cookie ${cookie.name}: missing Secure`,
        severity: 'medium',
        cwe: 'CWE-614',
        description: isRu ? 'Cookie передаётся по HTTP.' : 'Cookie may travel over HTTP.',
        recommendation: 'Set-Cookie: ...; Secure',
        legalContext: '—'
      })
    }
    if (!('httponly' in cookie.attrs)) {
      score -= 4
      findings.push({
        title: isRu ? `Cookie ${cookie.name}: нет HttpOnly` : `Cookie ${cookie.name}: missing HttpOnly`,
        severity: 'medium',
        cwe: 'CWE-1004',
        description: isRu ? 'Cookie доступна для JS — риск XSS-кражи.' : 'Cookie accessible to JS — XSS theft risk.',
        recommendation: 'Set-Cookie: ...; HttpOnly',
        legalContext: '—'
      })
    }
    const sameSite = cookie.attrs['samesite']
    if (!sameSite || (typeof sameSite === 'string' && sameSite.toLowerCase() === 'none')) {
      score -= 4
      findings.push({
        title: isRu ? `Cookie ${cookie.name}: SameSite слабый` : `Cookie ${cookie.name}: weak SameSite`,
        severity: 'medium',
        cwe: 'CWE-352',
        evidence: typeof sameSite === 'string' ? sameSite : 'absent',
        description: isRu ? 'Возможна CSRF-атака.' : 'CSRF remains possible.',
        recommendation: 'SameSite=Lax|Strict',
        legalContext: '—'
      })
    }
  })

  if (findings.length === 0) {
    findings.push({
      title: isRu ? 'Замечаний нет' : 'No findings',
      severity: 'info',
      description: isRu ? 'Все базовые заголовки настроены.' : 'All baseline headers in place.',
      recommendation: '—',
      legalContext: '—'
    })
  }

  score = Math.max(0, Math.min(100, score))
  const overall = aggregateFindings(findings)
  const cvss = computeRisk({
    confidentiality: overall === 'critical' ? 'high' : 'low',
    integrity: 'low'
  })

  return {
    technique: isRu ? 'HTTP response hardening' : 'HTTP response hardening',
    summary: isRu
      ? `Оценка ${score}/100, findings=${findings.length}.`
      : `Score ${score}/100, findings=${findings.length}.`,
    statusCode: 200,
    headers: Object.fromEntries(parsed.entries()),
    body: JSON.stringify({ findings: findings.length, score }, null, 2),
    severity: score < 45 ? 'critical' : severityFromScore(10 - score / 10),
    legalBadge: isRu ? 'Регуляторный и договорный риск' : 'Regulatory/contractual exposure',
    findings,
    score,
    riskScore: 100 - score,
    cvssVector: cvss.vector,
    riskBreakdown: cvss.breakdown
  }
}
