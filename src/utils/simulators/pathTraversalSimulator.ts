import type { LabFinding, SimulatedResult } from '../../types'
import type { Locale } from '../../i18n'
import { aggregateFindings, computeRisk, severityToRisk } from './riskScoring'

const SANDBOX_BASE = '/var/www/html/uploads'

const MOCK_FS: Record<string, string> = {
  '/etc/passwd': [
    'root:x:0:0:root:/root:/bin/bash',
    'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
    'bin:x:2:2:bin:/bin:/usr/sbin/nologin',
    'sys:x:3:3:sys:/dev:/usr/sbin/nologin',
    'sync:x:4:65534:sync:/bin:/bin/sync',
    'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
    'systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin',
    'mysql:x:108:115:MySQL Server,,,:/nonexistent:/bin/false',
    'postgres:x:109:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash',
    'redis:x:110:118::/var/lib/redis:/usr/sbin/nologin',
    'admin:x:1000:1000:Admin,,,:/home/admin:/bin/bash',
    'deploy:x:1001:1001:Deploy CI,,,:/home/deploy:/bin/bash',
    'sshd:x:111:65534::/run/sshd:/usr/sbin/nologin'
  ].join('\n'),
  '/etc/shadow': [
    'root:$6$rounds=656000$VW1zJ8Lq$qP3sN4XlOjB.iHk2c.7yT.PpQfXm9R4lQg5b3xKxNqV1iLp/yT8O6gRn3kYf9xPzL9rVbXqQwYjGq2pTiE3xV/:19500:0:99999:7:::',
    'daemon:*:19500:0:99999:7:::',
    'www-data:*:19500:0:99999:7:::',
    'postgres:$6$rounds=656000$Kj8aN.qP$8mB2.PqL5sX4nVf3yT7oUg.6kRzB1aH9mD5cQ.qNxL2jPwS3uYt0yT8O6gRn3kYf9xPzL9rVbXqQwYjGq2pTiE3xV/:19500:0:99999:7:::',
    'admin:$6$rounds=656000$lab.UZ.diploma$rT8nM2.pQ9kJ4sX1vF7oUg.6yT8O6gRn3kYf9xPzL9rVbXqQwYjGq2pTiE3xV/.PqL5sX4nVf3yT7oUg.6kRzB1aH9mD5cQ:19500:0:99999:7:::'
  ].join('\n'),
  '/var/www/.env': [
    '# Production environment for VulnLab — DO NOT COMMIT',
    'NODE_ENV=production',
    'APP_KEY=base64:8KQ3vF2sN9pL6mR4xJ7oUg5kRzB1aH9mD5cQ.qNxL=',
    'DB_HOST=10.0.0.21',
    'DB_PORT=5432',
    'DB_NAME=vulnlab_prod',
    'DB_USER=app_rw',
    'DB_PASSWORD=Qx9!mP2$kL7nV4@pB8',
    'REDIS_URL=redis://:9f85d9738c7b4ac8a580d4f845cb1f55@10.0.0.22:6379/0',
    'JWT_SECRET=hGd83bN!sP9q@LkX2vF7oUg5kR',
    'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
    'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    'AWS_REGION=eu-central-1',
    'AWS_S3_BUCKET=vulnlab-prod-backups',
    'STRIPE_SECRET_KEY=sk_live_FAKE_DEMO_KEY_FOR_LAB_PURPOSES_ONLY',
    'SENDGRID_API_KEY=SG.FAKE_DEMO_KEY.FOR_LAB_PURPOSES_ONLY',
    'SENTRY_DSN=https://fakekey@o42.ingest.sentry.io/1234567',
    'SLACK_BOT_TOKEN=xoxb-FAKE-DEMO-TOKEN-FOR-LAB-ONLY'
  ].join('\n'),
  '/proc/self/environ':
    'PATH=/usr/local/sbin:/usr/bin\x00HOME=/var/www\x00PWD=/var/www/html\x00DB_PASSWORD=Qx9!mP2$kL7nV4@pB8\x00JWT_SECRET=hGd83bN!sP9q@LkX2vF7oUg5kR\x00AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  '/proc/self/cmdline': '/usr/sbin/nginx\x00-g\x00daemon off;\x00-c\x00/etc/nginx/nginx.conf',
  '/proc/version': 'Linux version 6.1.0-13-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14)) #1 SMP PREEMPT_DYNAMIC Debian 6.1.55-1 (2023-09-29)',
  '/windows/win.ini': '; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1',
  '/windows/system32/drivers/etc/hosts': '127.0.0.1 localhost\n::1 localhost\n10.0.0.21 db-master.internal\n10.0.0.31 admin-panel.internal',
  '/home/admin/.ssh/id_rsa': [
    '-----BEGIN OPENSSH PRIVATE KEY-----',
    'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn',
    'NhAAAAAwEAAQAAAQEAr0Lab1234567890ResearchOnlyMockDataDoNotUseAnywhereE',
    'lseThisIsATotallyFakeKeyForVulnLabDiplomaProjectAtUniversityOfTashkent',
    'PleaseDoNotAttemptToReuseThisInRealEnvironmentsItIsNotAValidSshKeyJust',
    'PlaceholderDataForRendering12345abcdefABCDEFhijkLMNOPqrstuvwxyz==',
    '-----END OPENSSH PRIVATE KEY-----'
  ].join('\n'),
  '/home/admin/.aws/credentials': '[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nregion = eu-central-1\n\n[backup]\naws_access_key_id = AKIAI44QH8DHBEXAMPLE\naws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY',
  '/var/www/html/.git/config': '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote "origin"]\n\turl = https://oauth2:ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789@github.com/vulnlab/web-prod.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[user]\n\tname = Deploy CI\n\temail = deploy@vulnlab.local',
  '/var/log/nginx/access.log': [
    '194.110.84.21 - - [13/May/2026:07:14:22 +0500] "GET /api/users?id=1 HTTP/1.1" 200 1842 "-" "curl/8.4.0"',
    '194.110.84.21 - - [13/May/2026:07:14:23 +0500] "GET /api/users?id=1\' OR \'1\'=\'1 HTTP/1.1" 200 184201 "-" "sqlmap/1.7.11"',
    '5.182.211.99 - - [13/May/2026:07:15:01 +0500] "GET /admin HTTP/1.1" 302 0 "-" "Mozilla/5.0"'
  ].join('\n')
}

function decodeAllLayers(input: string): { decoded: string; passes: number } {
  let current = input
  let passes = 0
  for (let i = 0; i < 4; i++) {
    let next: string
    try {
      next = decodeURIComponent(current)
    } catch {
      break
    }
    if (next === current) break
    current = next
    passes++
  }
  return { decoded: current, passes }
}

function unicodeDecode(input: string): string {
  return input
    .replace(/%c0%ae/gi, '.')
    .replace(/%c0%2e/gi, '.')
    .replace(/%e0%80%ae/gi, '.')
    .replace(/%u002e/gi, '.')
    .replace(/%u2215/gi, '/')
}

function normalize(input: string): string {
  const segments = input.replace(/\\/g, '/').split('/')
  const stack: string[] = []
  for (const seg of segments) {
    if (seg === '' || seg === '.') continue
    if (seg === '..') {
      if (stack.length) stack.pop()
      continue
    }
    stack.push(seg)
  }
  return '/' + stack.join('/')
}

function resolveAgainstBase(base: string, input: string): { resolved: string; escaped: boolean } {
  const combined = input.startsWith('/') ? input : `${base}/${input}`
  const resolved = normalize(combined)
  const baseNormalized = normalize(base)
  const escaped = !resolved.startsWith(baseNormalized + '/') && resolved !== baseNormalized
  return { resolved, escaped }
}

function matchMock(path: string): string | null {
  const lower = path.toLowerCase()
  for (const key of Object.keys(MOCK_FS)) {
    if (lower === key.toLowerCase() || lower.endsWith(key.toLowerCase())) return key
  }
  return null
}

export function simulatePathTraversal(
  input: string,
  locale: Locale = 'ru'
): SimulatedResult & { normalized: string; encodedVariants: string[]; resolved: string; escaped: boolean; riskScore: number } {
  const isRu = locale === 'ru'
  const findings: LabFinding[] = []

  const { decoded, passes } = decodeAllLayers(input)
  const afterUnicode = unicodeDecode(decoded)
  const normalizedInput = afterUnicode.replace(/\\/g, '/')
  const { resolved, escaped } = resolveAgainstBase(SANDBOX_BASE, normalizedInput)
  const mockHit = escaped ? matchMock(resolved) : null

  if (passes >= 2) {
    findings.push({
      title: isRu ? `Двойное кодирование (${passes} проходов)` : `Multi-pass URL encoding (${passes})`,
      severity: 'high',
      cwe: 'CWE-22',
      evidence: input,
      description: isRu
        ? 'Один decode-проход недостаточно для нейтрализации payload.'
        : 'A single decode pass is insufficient to neutralize the payload.',
      recommendation: isRu ? 'Декодируйте до фиксированной точки и потом валидируйте.' : 'Decode to a fixed point before validation.',
      legalContext: isRu ? 'См. CWE-22.' : 'See CWE-22.'
    })
  }

  if (/%c0%ae|%e0%80%ae|%u00/.test(input.toLowerCase())) {
    findings.push({
      title: isRu ? 'Overlong UTF-8 / unicode escape' : 'Overlong UTF-8 / unicode escape',
      severity: 'high',
      cwe: 'CWE-176',
      evidence: input.match(/%c0%ae|%e0%80%ae|%u00\w+/i)?.[0],
      description: isRu ? 'Нестандартное кодирование точки/слэша обходит наивные фильтры.' : 'Non-standard dot/slash encoding bypasses naive filters.',
      recommendation: isRu ? 'Используйте строгий decode и канонизацию.' : 'Use strict decode + canonicalization.',
      legalContext: '—'
    })
  }

  if (/%00|\x00/.test(input)) {
    findings.push({
      title: isRu ? 'Null byte injection' : 'Null byte injection',
      severity: 'high',
      cwe: 'CWE-158',
      evidence: '%00',
      description: isRu ? 'Null-байт усекает строку в C-уровневых API.' : 'Null byte truncates strings in C-level APIs.',
      recommendation: isRu ? 'Отвергайте \\0 во входе.' : 'Reject \\0 in input.',
      legalContext: '—'
    })
  }

  if (/^\\\\|^\/\//.test(input)) {
    findings.push({
      title: isRu ? 'Windows UNC path' : 'Windows UNC path',
      severity: 'high',
      cwe: 'CWE-22',
      evidence: input,
      description: isRu ? 'UNC может перенаправить чтение на удалённый share.' : 'UNC may redirect reads to a remote share.',
      recommendation: isRu ? 'Отвергайте UNC-пути.' : 'Reject UNC paths.',
      legalContext: '—'
    })
  }

  if (/^[A-Za-z]:[/\\]/.test(input) || input.startsWith('/etc') || input.startsWith('/proc')) {
    findings.push({
      title: isRu ? 'Абсолютный путь' : 'Absolute path',
      severity: 'medium',
      cwe: 'CWE-36',
      evidence: input,
      description: isRu ? 'Абсолютный путь обходит относительные склейки.' : 'Absolute path bypasses relative joins.',
      recommendation: isRu ? 'Принимайте только относительные пути.' : 'Accept relative paths only.',
      legalContext: '—'
    })
  }

  if (escaped) {
    const severity = mockHit ? 'critical' : 'high'
    findings.push({
      title: isRu ? 'Выход за пределы sandbox' : 'Sandbox escape',
      severity,
      cwe: 'CWE-22',
      evidence: resolved,
      description: isRu
        ? `Нормализованный путь ${resolved} вне базовой директории ${SANDBOX_BASE}.`
        : `Normalized path ${resolved} is outside base directory ${SANDBOX_BASE}.`,
      recommendation: isRu
        ? 'Резолвите путь относительно базы и явно сравнивайте префикс.'
        : 'Resolve path against base and explicitly compare prefix.',
      legalContext: isRu ? 'Чтение защищённых файлов = ст. 272 УК РФ.' : 'Reading protected files = unauthorized access.'
    })
    if (mockHit) {
      const isSecret = /shadow|\.env|id_rsa|\.git|\.aws/i.test(mockHit)
      if (isSecret) {
        findings.push({
          title: isRu ? `Утечка секретного файла: ${mockHit}` : `Sensitive file leaked: ${mockHit}`,
          severity: 'critical',
          cwe: 'CWE-552',
          description: isRu ? 'Содержит креденшалы/ключи.' : 'Contains credentials/keys.',
          recommendation: isRu ? 'Сегрегируйте секреты и используйте принцип наименьших привилегий FS.' : 'Segregate secrets and apply FS least-privilege.',
          legalContext: isRu ? 'Доступ к таким файлам = неправомерный доступ к охраняемой информации.' : 'Access to such files = unauthorized access to protected info.'
        })
      }
    }
  }

  if (findings.length === 0) {
    findings.push({
      title: isRu ? 'Traversal не подтверждён' : 'Traversal not confirmed',
      severity: 'info',
      description: isRu ? 'Путь остался внутри sandbox.' : 'Path stayed inside sandbox.',
      recommendation: isRu ? 'Продолжайте канонизацию и проверки.' : 'Continue canonicalization + checks.',
      legalContext: '—'
    })
  }

  const overall = aggregateFindings(findings)
  const cvss = computeRisk({
    confidentiality: mockHit ? 'high' : escaped ? 'low' : 'none',
    integrity: 'none'
  })

  return {
    technique: escaped
      ? isRu
        ? 'Path traversal — выход из sandbox'
        : 'Path traversal — sandbox escape'
      : isRu
        ? 'Traversal не подтверждён'
        : 'Traversal not confirmed',
    techniques: findings.map((f) => f.title),
    summary: isRu
      ? `Decode passes: ${passes}, resolved=${resolved}, escaped=${escaped}, hit=${mockHit ?? '—'}.`
      : `Decode passes: ${passes}, resolved=${resolved}, escaped=${escaped}, hit=${mockHit ?? '—'}.`,
    statusCode: mockHit ? 200 : escaped ? 403 : 404,
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    body: mockHit ? MOCK_FS[mockHit] : isRu ? 'Файл не найден внутри симулированной FS.' : 'File not found inside simulated FS.',
    severity: overall,
    legalBadge: isRu ? 'УК РФ ст. 272 — незаконное чтение файлов' : 'Unauthorized file-read statutes',
    findings,
    normalized: resolved,
    encodedVariants: ['%2e%2e%2f', '..%2f', '%2e%2e/', '%252e%252e%252f', '%c0%ae%c0%ae/', '..%c0%af'],
    resolved,
    escaped,
    riskScore: Math.max(severityToRisk(overall), Math.round(cvss.score * 10)),
    cvssVector: cvss.vector,
    riskBreakdown: cvss.breakdown
  }
}
