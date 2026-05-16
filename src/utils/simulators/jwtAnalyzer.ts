import type { LabFinding, SimulatedResult } from '../../types'
import type { Locale } from '../../i18n'
import { aggregateFindings, computeRisk, entropyBits, severityToRisk } from './riskScoring'

export interface JwtAnalysis {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  signature: string
  algorithm: string
  expired: boolean
  malformed: boolean
  issues: string[]
  bruteForceMatch?: string
  bruteForceEntropy?: number
  bruteForceStats?: { match?: string; attempts: number; durationMs: number; rate: number }
  tamperedToken?: string
}

const WORDLIST = [
  'secret',
  'password',
  '123456',
  'admin',
  'jwt_secret',
  'changeme',
  'qwerty',
  'letmein',
  'welcome',
  'token',
  'p@ssw0rd',
  'root',
  'master',
  'iloveyou',
  'dragon',
  'monkey',
  'shadow',
  'football',
  'jesus',
  'hunter2',
  'azerty',
  'baseball',
  'starwars',
  'whatever',
  'jordan',
  'access',
  'flower',
  'mustang',
  'trustno1',
  'superman',
  'batman',
  'passw0rd',
  'pass',
  'test',
  'demo',
  'devsecret',
  'mysecret',
  'topsecret',
  'supersecret',
  'jwtsecret',
  'apisecret',
  'application',
  'qwerty123',
  'admin123',
  'default',
  'guest',
  'public',
  'private',
  'sample',
  'example',
  'your-256-bit-secret',
  'jwt-secret',
  'mysupersecretkey',
  'CHANGE_ME',
  'KEY',
  '0000',
  '1111',
  'aaaa',
  'devsecret123',
  'staging',
  'production',
  'secret123',
  'P@ssw0rd!',
  'admin@123',
  'Welcome1',
  'Letmein1',
  'a-string-secret-at-least-256-bits-long'
]

function decodeBase64Url(input: string): string {
  if (!input) return ''
  const pad = input.length % 4 === 0 ? '' : '='.repeat(4 - (input.length % 4))
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/') + pad
  const binary = window.atob(normalized)
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0))
  return new TextDecoder().decode(bytes)
}

function base64UrlEncode(value: object): string {
  return btoa(JSON.stringify(value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function base64UrlToBytes(input: string): Uint8Array {
  if (!input) return new Uint8Array()
  const pad = input.length % 4 === 0 ? '' : '='.repeat(4 - (input.length % 4))
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/') + pad
  const binary = window.atob(normalized)
  return Uint8Array.from(binary, (c) => c.charCodeAt(0))
}

async function hmacSign(secret: string, data: string, alg: 'SHA-256' | 'SHA-384' | 'SHA-512'): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: alg }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data))
  return new Uint8Array(sig)
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

interface BruteForceResult {
  match?: string
  attempts: number
  durationMs: number
  rate: number
}

async function bruteForceHmac(token: string, alg: string): Promise<BruteForceResult> {
  const parts = token.split('.')
  const empty: BruteForceResult = { attempts: 0, durationMs: 0, rate: 0 }
  if (parts.length !== 3) return empty
  const hash = alg === 'HS256' ? 'SHA-256' : alg === 'HS384' ? 'SHA-384' : alg === 'HS512' ? 'SHA-512' : null
  if (!hash) return empty
  const data = `${parts[0]}.${parts[1]}`
  const expected = base64UrlToBytes(parts[2])
  const t0 = performance.now()
  let attempts = 0
  let match: string | undefined
  for (const candidate of WORDLIST) {
    attempts++
    try {
      const sig = await hmacSign(candidate, data, hash)
      if (bytesEqual(sig, expected)) {
        match = candidate
        break
      }
    } catch {
      continue
    }
  }
  const durationMs = performance.now() - t0
  return { match, attempts, durationMs, rate: durationMs > 0 ? Math.round((attempts / durationMs) * 1000) : 0 }
}

export async function analyzeJwt(token: string, locale: Locale = 'ru'): Promise<SimulatedResult & JwtAnalysis & { riskScore: number }> {
  const isRu = locale === 'ru'
  const [headerPart = '', payloadPart = '', signature = ''] = token.split('.')
  let header: Record<string, unknown> = {}
  let payload: Record<string, unknown> = {}
  let malformed = false
  const findings: LabFinding[] = []

  try {
    header = JSON.parse(decodeBase64Url(headerPart)) as Record<string, unknown>
  } catch {
    malformed = true
  }
  try {
    payload = JSON.parse(decodeBase64Url(payloadPart)) as Record<string, unknown>
  } catch {
    malformed = true
  }

  if (malformed) {
    findings.push({
      title: isRu ? 'Неверная структура токена' : 'Malformed token',
      severity: 'medium',
      cwe: 'CWE-345',
      description: isRu ? 'Токен или base64url-кодировка повреждены.' : 'Token or base64url encoding is corrupted.',
      recommendation: isRu ? 'Проверьте формат токена.' : 'Verify token format.',
      legalContext: isRu ? 'Сам по себе невалидный токен не нарушение.' : 'A malformed token alone is not a violation.'
    })
  }

  const algorithm = typeof header.alg === 'string' ? header.alg : 'unknown'

  if (algorithm.toLowerCase() === 'none') {
    findings.push({
      title: isRu ? 'alg = none' : 'alg = none',
      severity: 'critical',
      cwe: 'CWE-347',
      evidence: 'alg=none',
      description: isRu
        ? 'Подпись отключена; уязвимый backend примет любой токен с alg=none.'
        : 'Signature disabled; vulnerable backends accept any alg=none token.',
      recommendation: isRu ? 'Жёстко фиксируйте список допустимых алгоритмов.' : 'Pin allowed algorithms in the verifier.',
      legalContext: isRu ? 'Подделка токена = неправомерный доступ.' : 'Forged tokens constitute unauthorized access.'
    })
  }

  if (/^HS/.test(algorithm) && header.jwk) {
    findings.push({
      title: isRu ? 'Встроенный jwk в заголовке' : 'Embedded jwk in header',
      severity: 'high',
      cwe: 'CWE-345',
      description: isRu
        ? 'Заголовок с jwk позволяет атакующему навязать собственный ключ.'
        : 'jwk header lets an attacker supply their own verification key.',
      recommendation: isRu ? 'Игнорируйте jwk/jku/x5u в заголовке.' : 'Ignore jwk/jku/x5u headers on verification.',
      legalContext: isRu ? 'См. подделка токена.' : 'See token forgery.'
    })
  }

  if (typeof header.jku === 'string' || typeof header.x5u === 'string') {
    findings.push({
      title: isRu ? 'Внешний источник ключа (jku/x5u)' : 'External key source (jku/x5u)',
      severity: 'high',
      cwe: 'CWE-345',
      evidence: (header.jku as string) ?? (header.x5u as string),
      description: isRu
        ? 'Verifier рискует подгрузить ключ с произвольного URL.'
        : 'Verifier risks fetching a key from an arbitrary URL.',
      recommendation: isRu ? 'Разрешите только фиксированный allow-list URL ключей.' : 'Allow-list trusted key URLs only.',
      legalContext: isRu ? 'Подделка токена через подмену ключа.' : 'Token forgery via key substitution.'
    })
  }

  if (typeof header.kid === 'string' && /['"\\;<>]|\.\.\//.test(header.kid)) {
    findings.push({
      title: isRu ? 'Подозрительный kid' : 'Suspicious kid',
      severity: 'high',
      cwe: 'CWE-89',
      evidence: header.kid,
      description: isRu
        ? 'Значение kid содержит спецсимволы — потенциальная SQLi/path traversal при подстановке.'
        : 'kid contains special characters — potential SQLi/path traversal when concatenated.',
      recommendation: isRu ? 'Валидируйте kid как идентификатор по allow-list.' : 'Validate kid as an allow-listed identifier.',
      legalContext: isRu ? 'Эксплуатация kid → неправомерный доступ.' : 'kid exploitation leads to unauthorized access.'
    })
  }

  const exp = typeof payload.exp === 'number' ? payload.exp : undefined
  const expired = exp ? exp * 1000 < Date.now() : false
  if (expired) {
    findings.push({
      title: isRu ? 'Токен истёк' : 'Token expired',
      severity: 'low',
      cwe: 'CWE-613',
      description: isRu ? 'exp в прошлом.' : 'exp is in the past.',
      recommendation: isRu ? 'Проверяйте exp на verifier.' : 'Verify exp server-side.',
      legalContext: isRu ? 'Принятие истёкших токенов усугубляет инцидент.' : 'Accepting expired tokens worsens incidents.'
    })
  }

  if (!exp) {
    findings.push({
      title: isRu ? 'Отсутствует claim exp' : 'Missing exp claim',
      severity: 'medium',
      cwe: 'CWE-613',
      description: isRu ? 'Без exp токен фактически вечен.' : 'Without exp the token is effectively eternal.',
      recommendation: isRu ? 'Требуйте exp с разумным TTL.' : 'Require exp with a reasonable TTL.',
      legalContext: isRu ? 'Вечные токены — фактор негативной оценки практики.' : 'Eternal tokens are a negative-practice factor.'
    })
  }

  if (exp && exp * 1000 - Date.now() > 365 * 24 * 3600 * 1000) {
    findings.push({
      title: isRu ? 'Очень длинный exp (> 1 года)' : 'Very long exp (> 1 year)',
      severity: 'medium',
      cwe: 'CWE-613',
      description: isRu ? 'TTL > 1 года значительно расширяет окно злоупотребления.' : 'TTL > 1 year drastically widens abuse window.',
      recommendation: isRu ? 'Снизьте TTL и используйте refresh-токены.' : 'Shorten TTL and use refresh tokens.',
      legalContext: isRu ? 'Усугубляет масштаб инцидента.' : 'Aggravates incident scope.'
    })
  }

  if (!payload.iss) {
    findings.push({
      title: isRu ? 'Отсутствует claim iss' : 'Missing iss claim',
      severity: 'low',
      description: isRu ? 'Без iss verifier не может различать эмитентов.' : 'Without iss the verifier cannot distinguish issuers.',
      recommendation: isRu ? 'Добавьте и проверяйте iss.' : 'Add and validate iss.',
      legalContext: isRu ? 'Неточная атрибуция затрудняет расследование.' : 'Poor attribution complicates investigation.'
    })
  }

  if (!payload.aud) {
    findings.push({
      title: isRu ? 'Отсутствует claim aud' : 'Missing aud claim',
      severity: 'low',
      description: isRu ? 'Токен принимают любые сервисы.' : 'Token is accepted by any service.',
      recommendation: isRu ? 'Используйте aud для разграничения сервисов.' : 'Use aud to scope tokens to services.',
      legalContext: isRu ? 'Расширяет blast-radius при утечке.' : 'Expands blast radius on leak.'
    })
  }

  let bruteForceMatch: string | undefined
  let bruteForceEntropy: number | undefined
  let bruteForceStats: BruteForceResult | undefined
  if (!malformed && /^HS(256|384|512)$/.test(algorithm)) {
    bruteForceStats = await bruteForceHmac(token, algorithm)
    bruteForceMatch = bruteForceStats.match
    if (bruteForceMatch) {
      bruteForceEntropy = entropyBits(bruteForceMatch)
      findings.push({
        title: isRu ? `Слабый HMAC-секрет: «${bruteForceMatch}»` : `Weak HMAC secret: "${bruteForceMatch}"`,
        severity: 'critical',
        cwe: 'CWE-326',
        evidence: `secret="${bruteForceMatch}" · ${bruteForceStats?.attempts}/${WORDLIST.length} attempts · ${bruteForceStats?.durationMs.toFixed(0)}ms · ${bruteForceStats?.rate} H/s`,
        description: isRu
          ? `Подпись подтверждена кандидатом из wordlist (${bruteForceStats?.attempts} попыток за ${bruteForceStats?.durationMs.toFixed(0)} мс, ≈${bruteForceStats?.rate} hash/s). Энтропия секрета ≈ ${bruteForceEntropy} бит.`
          : `Signature verified with a wordlist candidate (${bruteForceStats?.attempts} attempts in ${bruteForceStats?.durationMs.toFixed(0)}ms, ≈${bruteForceStats?.rate} hash/s). Secret entropy ≈ ${bruteForceEntropy} bits.`,
        recommendation: isRu
          ? 'Замените секрет на 32+ случайных байта; рассмотрите переход на RS256/EdDSA.'
          : 'Replace with 32+ random bytes; consider RS256/EdDSA.',
        legalContext: isRu ? 'Подделка валидного токена ⇒ неправомерный доступ.' : 'Forging a valid token ⇒ unauthorized access.'
      })
    } else {
      findings.push({
        title: isRu ? 'HMAC: wordlist не сработал' : 'HMAC: wordlist did not match',
        severity: 'info',
        description: isRu
          ? 'Распространённые секреты не подошли. Это не доказывает сильный ключ — расширьте wordlist.'
          : 'Common secrets did not match. Does not prove strong key — expand wordlist.',
        recommendation: isRu ? 'Регулярно ротируйте секреты.' : 'Rotate secrets regularly.',
        legalContext: isRu ? '—' : '—'
      })
    }
  }

  const tamperedHeader = { ...header, alg: 'none' }
  const tamperedToken = `${base64UrlEncode(tamperedHeader)}.${payloadPart}.`

  const overall = aggregateFindings(findings.length ? findings : [
    {
      title: isRu ? 'Замечаний нет' : 'No issues found',
      severity: 'info',
      description: '',
      recommendation: '',
      legalContext: ''
    }
  ])

  const cvss = computeRisk({
    confidentiality: overall === 'critical' ? 'high' : 'low',
    integrity: overall === 'critical' || overall === 'high' ? 'high' : 'low',
    privilegesRequired: 'none'
  })

  return {
    technique: isRu ? 'Глубокий анализ JWT' : 'Deep JWT analysis',
    techniques: findings.map((f) => f.title),
    summary: isRu
      ? `alg=${algorithm}, ${malformed ? 'malformed, ' : ''}findings=${findings.length}${bruteForceMatch ? `, brute=${bruteForceMatch}` : ''}.`
      : `alg=${algorithm}, ${malformed ? 'malformed, ' : ''}findings=${findings.length}${bruteForceMatch ? `, brute=${bruteForceMatch}` : ''}.`,
    statusCode: findings.length ? 200 : 204,
    headers: { 'Content-Type': 'application/jwt-analysis+json' },
    body: JSON.stringify({ algorithm, expired, malformed, bruteForceMatch, findings: findings.length }, null, 2),
    severity: overall,
    legalBadge: isRu ? 'Подделка токена = неправомерный доступ' : 'Forged token = unauthorized access',
    findings,
    header,
    payload,
    signature,
    algorithm,
    expired,
    malformed,
    issues: findings.map((f) => f.title),
    bruteForceMatch,
    bruteForceEntropy,
    bruteForceStats,
    tamperedToken,
    riskScore: Math.max(severityToRisk(overall), Math.round(cvss.score * 10)),
    cvssVector: cvss.vector,
    riskBreakdown: cvss.breakdown
  }
}
