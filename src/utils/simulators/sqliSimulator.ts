import type { LabFinding, SimulatedResult } from '../../types'
import type { Locale } from '../../i18n'
import { aggregateFindings, computeRisk, severityToRisk } from './riskScoring'

export interface SqlTarget {
  id: string
  label: string
  query: string
  dialect: 'mysql' | 'postgres' | 'mssql' | 'mongo'
}

export const sqlTargets: SqlTarget[] = [
  { id: 'auth', label: '/api/auth/login', query: 'SELECT * FROM users WHERE email = ? AND password = ?', dialect: 'mysql' },
  { id: 'report', label: '/api/reports/search', query: 'SELECT id,title FROM reports WHERE title LIKE ?', dialect: 'postgres' },
  { id: 'admin', label: '/api/admin/users', query: 'SELECT id,email,role FROM users WHERE role = ?', dialect: 'mssql' },
  { id: 'mongo', label: '/api/mongo/users', query: "db.users.find({ email: <input>, password: <input> })", dialect: 'mongo' }
]

interface SqlToken {
  type: 'string' | 'number' | 'ident' | 'comment' | 'op' | 'ws'
  value: string
}

function tokenize(input: string): SqlToken[] {
  const tokens: SqlToken[] = []
  let i = 0
  while (i < input.length) {
    const ch = input[i]
    if (ch === "'" || ch === '"') {
      const quote = ch
      let j = i + 1
      while (j < input.length && input[j] !== quote) {
        if (input[j] === '\\') j += 2
        else j++
      }
      tokens.push({ type: 'string', value: input.slice(i, Math.min(j + 1, input.length)) })
      i = j + 1
      continue
    }
    if (ch === '-' && input[i + 1] === '-') {
      const end = input.indexOf('\n', i)
      tokens.push({ type: 'comment', value: input.slice(i, end === -1 ? input.length : end) })
      i = end === -1 ? input.length : end
      continue
    }
    if (ch === '#') {
      const end = input.indexOf('\n', i)
      tokens.push({ type: 'comment', value: input.slice(i, end === -1 ? input.length : end) })
      i = end === -1 ? input.length : end
      continue
    }
    if (ch === '/' && input[i + 1] === '*') {
      const end = input.indexOf('*/', i + 2)
      tokens.push({ type: 'comment', value: input.slice(i, end === -1 ? input.length : end + 2) })
      i = end === -1 ? input.length : end + 2
      continue
    }
    if (/\s/.test(ch)) {
      let j = i
      while (j < input.length && /\s/.test(input[j])) j++
      tokens.push({ type: 'ws', value: input.slice(i, j) })
      i = j
      continue
    }
    if (/[0-9]/.test(ch)) {
      let j = i
      while (j < input.length && /[0-9.]/.test(input[j])) j++
      tokens.push({ type: 'number', value: input.slice(i, j) })
      i = j
      continue
    }
    if (/[a-zA-Z_@$]/.test(ch)) {
      let j = i
      while (j < input.length && /[a-zA-Z_0-9$.]/.test(input[j])) j++
      tokens.push({ type: 'ident', value: input.slice(i, j) })
      i = j
      continue
    }
    tokens.push({ type: 'op', value: ch })
    i++
  }
  return tokens
}

function hasIdent(tokens: SqlToken[], names: string[]): boolean {
  const lower = names.map((n) => n.toLowerCase())
  return tokens.some((t) => t.type === 'ident' && lower.includes(t.value.toLowerCase()))
}

function sequence(tokens: SqlToken[], idents: string[]): boolean {
  const filtered = tokens.filter((t) => t.type !== 'ws')
  const target = idents.map((n) => n.toLowerCase())
  for (let i = 0; i <= filtered.length - target.length; i++) {
    let ok = true
    for (let j = 0; j < target.length; j++) {
      const t = filtered[i + j]
      if (!(t.type === 'ident' && t.value.toLowerCase() === target[j])) {
        ok = false
        break
      }
    }
    if (ok) return true
  }
  return false
}

interface DetectionInput {
  payload: string
  tokens: SqlToken[]
  target: SqlTarget
  isRu: boolean
}

interface Detection {
  technique: string
  finding: LabFinding
  cvss: ReturnType<typeof computeRisk>
  body?: unknown
  statusCode?: number
  latencyMs?: number
}

function detectUnion({ tokens, isRu }: DetectionInput): Detection | null {
  if (!sequence(tokens, ['union', 'select']) && !sequence(tokens, ['union', 'all', 'select'])) return null
  const cvss = computeRisk({ attackComplexity: 'low', privilegesRequired: 'none', confidentiality: 'high', integrity: 'low' })
  return {
    technique: isRu ? 'UNION-based SQLi' : 'UNION-based SQLi',
    cvss,
    statusCode: 200,
    body: {
      schema: {
        database: 'vulnlab_prod',
        version: '8.0.32-MySQL Community Server (GPL)',
        currentUser: 'webapp@10.0.0.14',
        privileges: ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FILE']
      },
      tables: [
        { name: 'users', rows: 18472, columns: ['id', 'email', 'password_hash', 'role', 'mfa_secret', 'created_at'] },
        { name: 'sessions', rows: 4218, columns: ['id', 'user_id', 'token', 'ip', 'expires_at'] },
        { name: 'payment_methods', rows: 9117, columns: ['id', 'user_id', 'card_last4', 'card_token', 'billing_zip'] },
        { name: 'audit_log', rows: 1820341, columns: ['id', 'actor_id', 'action', 'target', 'ts'] },
        { name: 'api_keys', rows: 312, columns: ['id', 'name', 'secret_hash', 'scopes', 'revoked_at'] }
      ],
      dump: [
        { id: 1, email: 'admin@vulnlab.local', password_hash: '$2b$12$KIXq8bM5pV0qFp7lWUe.MeZ3Bd1k0lq4u.Y8R6Hkz1tFq7m4Zr6Vy', role: 'administrator', mfa_secret: 'JBSWY3DPEHPK3PXP' },
        { id: 2, email: 'cto@vulnlab.local', password_hash: '$2b$12$Q9c1f3K8L0bO5kU3wEr4u.cT2yH7nL0a/aXk1Eq.q1bDk8nQ2pR7m', role: 'administrator', mfa_secret: 'KRSXG5DSMV2W64TF' },
        { id: 47, email: 'finance@vulnlab.local', password_hash: '$2b$12$X4mZ8/bN3qFg9pV1yWeR5.uP8oJ2kL7nM5tR0/xB6Yh4Eq8nC3sQ.', role: 'finance', mfa_secret: 'GEZDGNBVGY3TQOJQ' },
        { id: 88, email: 'sre@vulnlab.local', password_hash: '$2b$12$wQ7c2lN5kJ8pT3rY9bM4u.eX1oH6fG2sV0/dC8aR4Bk6Lq9nP.5y', role: 'sre', mfa_secret: 'MFRGGZDFMZTWQ2LK' }
      ],
      note: isRu
        ? 'UNION SELECT дописал к легитимному запросу attacker-controlled выборку, обойдя оригинальный фильтр.'
        : 'UNION SELECT appended an attacker-controlled result set, bypassing the original filter.'
    },
    finding: {
      title: isRu ? 'Перечисление схемы через UNION SELECT' : 'Schema enumeration via UNION SELECT',
      severity: 'critical',
      cwe: 'CWE-89',
      evidence: 'UNION SELECT … FROM information_schema',
      description: isRu
        ? 'Payload содержит UNION SELECT, что позволяет дописать произвольный результирующий набор к исходному запросу.'
        : 'Payload contains UNION SELECT which appends an attacker-controlled result set to the original query.',
      recommendation: isRu
        ? 'Используйте параметризованные запросы и отключите конкатенацию пользовательского ввода в SQL.'
        : 'Use parameterized queries and forbid string concatenation of user input into SQL.',
      legalContext: isRu
        ? 'Раскрытие структуры БД через UNION квалифицируется как неправомерный доступ (ст. 272 УК РФ).'
        : 'UNION-based schema disclosure is treated as unauthorized access in major jurisdictions.'
    }
  }
}

function detectErrorBased({ tokens, payload, target, isRu }: DetectionInput): Detection | null {
  const errorFns = ['updatexml', 'extractvalue', 'exp', 'floor', 'cast', 'convert', 'xmltype']
  if (!hasIdent(tokens, errorFns) && !/sql syntax|mysql_fetch|pg_query/i.test(payload)) return null
  const cvss = computeRisk({ confidentiality: 'high', integrity: 'none' })
  const errorByDialect = {
    mysql: {
      error: "XPATH syntax error: '~admin@vulnlab.local:$2b$12$KIXq8bM5pV0qFp7lWUe.MeZ3Bd1k0lq4u.Y8R6Hkz1tFq7m4Zr6Vy:administrator~'",
      sqlstate: '42000',
      code: 1105,
      stack: [
        "at Connection.protocol._enqueue (/app/node_modules/mysql2/lib/connection.js:217:21)",
        "at Connection.query (/app/node_modules/mysql2/lib/connection.js:438:17)",
        "at UsersRepo.findByEmail (/app/src/repo/users.ts:42:18)",
        "at AuthService.login (/app/src/services/auth.ts:88:34)"
      ]
    },
    postgres: {
      error: "ERROR: invalid input syntax for type integer: \"id=1,email=admin@vulnlab.local,password_hash=$2b$12$KIXq8bM5pV0qFp7lWUe.MeZ3Bd1k0lq4u.Y8R6Hkz1tFq7m4Zr6Vy,role=administrator\"\n  LINE 1: SELECT * FROM users WHERE email = '...' AND password = '...'",
      sqlstate: '22P02',
      code: 22023,
      stack: [
        "psycopg2.errors.InvalidTextRepresentation",
        "  File \"/app/repo/users.py\", line 42, in find_by_email",
        "    cursor.execute(query, (email,))",
        "  File \"/app/services/auth.py\", line 88, in login"
      ]
    },
    mssql: {
      error: "Conversion failed when converting the nvarchar value 'admin@vulnlab.local|$2b$12$KIXq8bM5pV0qFp7lWUe.MeZ3Bd1k0lq4u|administrator' to data type int.",
      sqlstate: 'S0001',
      code: 245,
      stack: [
        "at System.Data.SqlClient.SqlCommand.ExecuteReader()",
        "at VulnLab.Data.UsersRepository.FindByEmail(String email) in /src/Data/UsersRepository.cs:line 42",
        "at VulnLab.Services.AuthService.Login(LoginDto dto) in /src/Services/AuthService.cs:line 88"
      ]
    },
    mongo: {
      error: 'MongoServerError: $where clause threw exception: ReferenceError: admin is not defined',
      sqlstate: '—',
      code: 139,
      stack: ['at handleErrorResponse (/app/node_modules/mongodb/lib/cmap/wire_protocol.js:411:14)']
    }
  } as const
  const err = errorByDialect[target.dialect]
  return {
    technique: isRu ? 'Error-based SQLi' : 'Error-based SQLi',
    cvss,
    statusCode: 500,
    body: { error: err.error, sqlstate: err.sqlstate, code: err.code, stack: err.stack, exfiltrated: err.error.match(/\$2b\$[^,'~ ]+/)?.[0] },
    finding: {
      title: isRu ? 'Извлечение данных через ошибки БД' : 'Error-based data extraction',
      severity: 'high',
      cwe: 'CWE-209',
      evidence: err.error.slice(0, 140),
      description: isRu
        ? 'Полезная нагрузка вызывает диагностическую ошибку, в которой утекают данные таблиц/колонок.'
        : 'Payload triggers a diagnostic DB error that leaks table/column data.',
      recommendation: isRu
        ? 'Скрывайте детали SQL-ошибок и логируйте их только серверно.'
        : 'Hide detailed SQL errors from clients and only log them server-side.',
      legalContext: isRu
        ? 'Использование утечки диагностики для перечисления объектов БД образует состав ст. 272 УК РФ.'
        : 'Exploiting diagnostic leakage to enumerate DB objects supports unauthorized-access charges.'
    }
  }
}

function detectTimeBased({ tokens, payload, target, isRu }: DetectionInput): Detection | null {
  const timeFns = ['sleep', 'benchmark', 'pg_sleep', 'waitfor', 'dbms_pipe']
  if (!hasIdent(tokens, timeFns) && !/waitfor\s+delay/i.test(payload)) return null
  const cvss = computeRisk({ attackComplexity: 'high', confidentiality: 'low' })
  return {
    technique: isRu ? 'Time-based blind SQLi' : 'Time-based blind SQLi',
    cvss,
    latencyMs: 5000,
    statusCode: 200,
    body: {
      result: true,
      timingObserved: '5034ms',
      baseline: '47ms',
      dialect: target.dialect,
      extractionProgress: {
        target: 'users.password_hash WHERE id=1',
        method: 'binary search via SUBSTRING + ASCII',
        extracted: '$2b$12$KIXq8b',
        position: 12,
        totalLength: 60,
        etaSeconds: 240
      },
      queriesSent: 96,
      bandwidthBitsPerQuery: 1,
      note: isRu
        ? 'За одну итерацию посимвольно подтверждается 1 бит. На полный hash потребуется ~60×7 = 420 запросов.'
        : 'Each iteration confirms 1 bit per character. Full hash takes ~60×7 = 420 requests.'
    },
    finding: {
      title: isRu ? 'Подтверждён тайминговый канал' : 'Timing side-channel confirmed',
      severity: 'high',
      cwe: 'CWE-89',
      evidence: payload.match(/(sleep|benchmark|pg_sleep|waitfor[^,]*)/i)?.[0],
      description: isRu
        ? 'Payload вызывает контролируемую задержку, что позволяет посимвольно извлекать данные по таймингам.'
        : 'Payload causes a controlled delay, enabling per-character data extraction via timing.',
      recommendation: isRu
        ? 'Прервите конкатенацию ввода, ограничьте время выполнения запросов, выровняйте задержки.'
        : 'Eliminate input concatenation, cap query execution time, and normalize response timing.',
      legalContext: isRu
        ? 'Слепое тайминг-зондирование чужой системы рассматривается как несанкционированный тест.'
        : 'Blind timing probing of third-party systems still qualifies as unauthorized testing.'
    }
  }
}

function detectBoolean({ payload, isRu }: DetectionInput): Detection | null {
  const tautology = /(['"`]?\s*or\s*['"`]?\s*\d+\s*=\s*\d+|['"`]?\s*or\s*['"`]?[a-z]+['"`]?\s*=\s*['"`]?[a-z]+)/i
  if (!tautology.test(payload) && !/\bor\s+1=1\b/i.test(payload)) return null
  const cvss = computeRisk({ confidentiality: 'high', integrity: 'high', privilegesRequired: 'none' })
  return {
    technique: isRu ? 'Boolean-based bypass' : 'Boolean-based bypass',
    cvss,
    statusCode: 200,
    body: {
      user: {
        id: 1,
        email: 'admin@vulnlab.local',
        role: 'administrator',
        mfaEnabled: false,
        lastLogin: '2026-05-13T07:14:22.481Z',
        lastLoginIp: '194.110.84.21',
        sessionId: '0f8a5d2b-1c7e-4d9f-8a3b-12cc7f0e8d44'
      },
      tokens: {
        access: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZW1haWwiOiJhZG1pbkB2dWxubGFiLmxvY2FsIiwicm9sZSI6ImFkbWluaXN0cmF0b3IiLCJpYXQiOjE3MTUxNTAwMDAsImV4cCI6MTcxNTE1MzYwMH0.3Y8K9Vh2L0p1q7nM4kJ8rT3wX2cZ6aD',
        refresh: 'rt_8b7e2a14c9f04d36',
        csrf: '9f85d9738c7b4ac8a580d4f845cb1f55'
      },
      cookieHeader: 'session=eyJhbGciOi…; HttpOnly; SameSite=Lax; Path=/'
    },
    finding: {
      title: isRu ? 'Тавтологический обход условия WHERE' : 'Tautological WHERE bypass',
      severity: 'critical',
      cwe: 'CWE-89',
      evidence: payload.match(/or\s+\d+=\d+|or\s+['"][^'"]+['"]\s*=\s*['"][^'"]+['"]/i)?.[0],
      description: isRu
        ? 'Внедрённое условие OR делает WHERE всегда истинным — классический обход аутентификации.'
        : 'Injected OR condition makes WHERE always true — classic authentication bypass.',
      recommendation: isRu
        ? 'Используйте prepared statements; не сравнивайте пароль конкатенацией строк.'
        : 'Use prepared statements; never compare passwords via string concatenation.',
      legalContext: isRu
        ? 'Обход аутентификации — один из наиболее явных признаков неправомерного доступа.'
        : 'Authentication bypass is among the clearest indicators of unauthorized access.'
    }
  }
}

function detectStacked({ payload, isRu }: DetectionInput): Detection | null {
  if (!/;\s*(drop|truncate|alter|insert|update|delete|create)\b/i.test(payload)) return null
  const destructive = /;\s*(drop|truncate|alter)\b/i.test(payload)
  const cvss = computeRisk({
    confidentiality: 'high',
    integrity: 'high',
    availability: destructive ? 'high' : 'low'
  })
  return {
    technique: isRu ? 'Stacked queries' : 'Stacked queries',
    cvss,
    statusCode: destructive ? 500 : 200,
    body: destructive
      ? {
          error: "Table 'vulnlab_prod.users' was dropped via stacked query.",
          objectsAffected: ['users', 'sessions', 'payment_methods'],
          referentialIntegrity: 'CASCADE — 32,597 dependent rows removed',
          binlogPosition: 'mysql-bin.000142:8819302',
          rollbackAvailable: false,
          recoveryTimeEstimate: '6h 20m from offsite backup (last snapshot 2026-05-13T06:00Z)'
        }
      : {
          rowsAffected: 1,
          insertedId: 99999,
          newRole: 'administrator',
          actor: 'webapp@10.0.0.14',
          appliedAt: '2026-05-13T07:14:22.481Z',
          note: isRu ? 'Второй запрос изменил роль текущего пользователя.' : 'Second statement elevated current user role.'
        },
    finding: {
      title: isRu ? 'Стекированный запрос' : 'Stacked query injection',
      severity: destructive ? 'critical' : 'high',
      cwe: 'CWE-89',
      evidence: payload.match(/;\s*\w+/)?.[0],
      description: isRu
        ? 'Через `;` исполняется дополнительный запрос — атакующий может менять/уничтожать данные.'
        : 'A second statement is executed via `;` — attacker can modify or destroy data.',
      recommendation: isRu
        ? 'Отключите multi-statement в драйвере БД и используйте только параметризованные вызовы.'
        : 'Disable multi-statement in the DB driver and use only parameterized calls.',
      legalContext: isRu
        ? 'Разрушительные DDL-инъекции повышают тяжесть последствий (ст. 273 УК РФ).'
        : 'Destructive DDL injection escalates penalty exposure (computer-damage statutes).'
    }
  }
}

function detectComments({ tokens, isRu }: DetectionInput): Detection | null {
  if (!tokens.some((t) => t.type === 'comment')) return null
  const cvss = computeRisk({ confidentiality: 'low' })
  return {
    technique: isRu ? 'Усечение запроса через комментарий' : 'Query truncation via comment',
    cvss,
    finding: {
      title: isRu ? 'Усечение запроса комментарием' : 'Comment-based truncation',
      severity: 'medium',
      cwe: 'CWE-89',
      evidence: tokens.find((t) => t.type === 'comment')?.value,
      description: isRu
        ? 'Inline-комментарий отсекает остаток запроса, что часто используется для обхода проверок.'
        : 'Inline comment truncates the rest of the statement — frequently used to bypass checks.',
      recommendation: isRu ? 'Не позволяйте пользовательскому вводу попадать в SQL дословно.' : 'Never embed raw user input in SQL.',
      legalContext: isRu
        ? 'Сам по себе комментарий незаконен только в сочетании с целевой атакой.'
        : 'Comments alone are not unlawful, only as part of a targeted exploitation.'
    }
  }
}

function detectOOB({ payload, target, isRu }: DetectionInput): Detection | null {
  if (target.dialect === 'mongo') return null
  const oob = /(load_file|into\s+outfile|into\s+dumpfile|xp_dirtree|xp_cmdshell|utl_http|dbms_ldap)/i.test(payload)
  if (!oob) return null
  const cvss = computeRisk({ confidentiality: 'high', integrity: 'low', scope: 'changed' })
  return {
    technique: isRu ? 'Out-of-band эксфильтрация' : 'Out-of-band exfiltration',
    cvss,
    finding: {
      title: isRu ? 'OOB-канал данных' : 'Out-of-band data channel',
      severity: 'critical',
      cwe: 'CWE-89',
      evidence: payload.match(/(load_file|xp_dirtree|utl_http)\b[^\s]*/i)?.[0],
      description: isRu
        ? 'Payload пытается передать данные наружу через файловую систему/HTTP/DNS — обход in-band ограничений.'
        : 'Payload exfiltrates data via FS/HTTP/DNS — bypasses in-band restrictions.',
      recommendation: isRu
        ? 'Запретите функции файлового и сетевого доступа у учётной записи БД; ограничьте egress.'
        : 'Revoke file/network privileges on the DB user and restrict egress.',
      legalContext: isRu
        ? 'OOB-каналы напрямую свидетельствуют о намеренной эксфильтрации.'
        : 'OOB channels directly evidence deliberate exfiltration.'
    }
  }
}

function detectOrderBy({ payload, isRu }: DetectionInput): Detection | null {
  if (!/order\s+by\s+\d+/i.test(payload)) return null
  const cvss = computeRisk({ attackComplexity: 'high', confidentiality: 'low' })
  return {
    technique: isRu ? 'ORDER BY enumeration' : 'ORDER BY enumeration',
    cvss,
    finding: {
      title: isRu ? 'Перебор колонок через ORDER BY' : 'Column enumeration via ORDER BY',
      severity: 'medium',
      cwe: 'CWE-89',
      evidence: payload.match(/order\s+by\s+\d+/i)?.[0],
      description: isRu
        ? 'Payload типичен для разведки числа колонок перед UNION-атакой.'
        : 'Pattern typical of column-count reconnaissance preceding a UNION attack.',
      recommendation: isRu ? 'Используйте allow-list для сортировки.' : 'Use an allow-list for sortable columns.',
      legalContext: isRu
        ? 'Зондирующая активность сама по себе обычно фиксируется в инциденте как этап разведки.'
        : 'Probing activity is usually recorded as the recon stage of an incident.'
    }
  }
}

function detectNoSqli({ payload, target, isRu }: DetectionInput): Detection | null {
  if (target.dialect !== 'mongo') return null
  if (!/\$ne|\$gt|\$lt|\$where|\$regex|\$exists/i.test(payload)) return null
  const cvss = computeRisk({ confidentiality: 'high', integrity: 'low' })
  return {
    technique: isRu ? 'NoSQL-инъекция (MongoDB)' : 'NoSQL injection (MongoDB)',
    cvss,
    statusCode: 200,
    body: {
      matched: true,
      query: { email: { $ne: null }, password: { $ne: null } },
      user: {
        _id: '64f3a1c8e8b9d4f1a2c70d11',
        email: 'admin@vulnlab.local',
        role: 'admin',
        apiKey: 'sk_live_51N2pQrLkjFq9wYx7tH3aB',
        createdAt: '2024-08-14T12:01:00.000Z'
      },
      collectionStats: { docs: 18472, indexes: 4, sizeBytes: 14_320_512 }
    },
    finding: {
      title: isRu ? 'Операторная NoSQL-инъекция' : 'Operator NoSQL injection',
      severity: 'high',
      cwe: 'CWE-943',
      evidence: payload.match(/\$\w+/)?.[0],
      description: isRu
        ? 'Передача operator-объектов (`$ne`, `$gt`, `$where`) в запрос Mongo обходит проверку.'
        : 'Passing operator objects (`$ne`, `$gt`, `$where`) into Mongo queries bypasses checks.',
      recommendation: isRu
        ? 'Приводите ввод к строкам и используйте безопасные query-билдеры.'
        : 'Coerce input to strings and use safe query builders.',
      legalContext: isRu
        ? 'Обход аутентификации в NoSQL обрабатывается так же, как в реляционных СУБД.'
        : 'NoSQL auth bypass is treated the same as in relational DBs.'
    }
  }
}

export function simulateSQLi(payload: string, targetId: string, locale: Locale = 'ru'): SimulatedResult & { riskScore: number } {
  const isRu = locale === 'ru'
  const target = sqlTargets.find((t) => t.id === targetId) ?? sqlTargets[0]
  const tokens = tokenize(payload)
  const input: DetectionInput = { payload, tokens, target, isRu }

  const detectors = [
    detectUnion,
    detectErrorBased,
    detectTimeBased,
    detectStacked,
    detectBoolean,
    detectOOB,
    detectOrderBy,
    detectNoSqli,
    detectComments
  ]

  const detections: Detection[] = []
  for (const d of detectors) {
    const r = d(input)
    if (r) detections.push(r)
  }

  const headers = {
    Server: `VulnLab-${target.dialect}/2.0`,
    'Content-Type': 'application/json; charset=utf-8',
    'X-Sandbox': 'browser-only'
  }

  if (detections.length === 0) {
    const cvss = computeRisk({})
    return {
      technique: isRu ? 'Известные SQLi-паттерны не обнаружены' : 'No known SQLi pattern detected',
      summary: isRu
        ? 'Сигнатуры SQL Injection не сработали. Попробуйте UNION SELECT, OR 1=1, SLEEP(), ; DROP, $ne и др.'
        : 'No SQLi signatures matched. Try UNION SELECT, OR 1=1, SLEEP(), ; DROP, $ne, etc.',
      statusCode: 200,
      headers,
      body: JSON.stringify({ ok: true, data: [] }, null, 2),
      severity: 'low',
      legalBadge: isRu ? 'Нарушение не подтверждено' : 'No violation confirmed',
      findings: [
        {
          title: isRu ? 'Совпадение с сигнатурами не найдено' : 'No simulator match',
          severity: 'info',
          description: isRu
            ? 'Payload не задействовал ни один моделируемый SQLi-сценарий.'
            : 'Payload did not trigger a modeled SQLi path.',
          recommendation: isRu
            ? 'Тестируйте структурированно: boolean, UNION, error-, time-based, stacked.'
            : 'Test in a structured way: boolean, UNION, error-, time-based, stacked.',
          legalContext: isRu
            ? 'Зондирование чужих систем без разрешения остаётся правовым риском.'
            : 'Probing third-party systems without permission still carries legal risk.'
        }
      ],
      riskScore: 5,
      cvssVector: cvss.vector,
      riskBreakdown: cvss.breakdown
    }
  }

  const findings = detections.map((d) => d.finding)
  const overall = aggregateFindings(findings)
  const topCvss = detections.reduce((acc, d) => (d.cvss.score > acc.cvss.score ? d : acc))
  const techniques = detections.map((d) => d.technique)
  const primary = detections[0]
  const bodyPayload = primary.body ?? { ok: true, technique: primary.technique }

  return {
    technique: techniques[0],
    techniques,
    summary: isRu
      ? `Обнаружено техник: ${techniques.length}. Доминирующая: ${techniques[0]}. CVSS базовый: ${topCvss.cvss.score}.`
      : `Detected techniques: ${techniques.length}. Leading: ${techniques[0]}. Base CVSS: ${topCvss.cvss.score}.`,
    statusCode: primary.statusCode ?? 200,
    headers,
    body: JSON.stringify(bodyPayload, null, 2),
    severity: overall,
    legalBadge: isRu ? 'УК РФ ст. 272 / 273 — неправомерный доступ или модификация' : 'Unauthorized access / data modification statutes',
    latencyMs: detections.find((d) => d.latencyMs)?.latencyMs,
    findings,
    riskScore: Math.max(severityToRisk(overall), Math.round(topCvss.cvss.score * 10)),
    cvssVector: topCvss.cvss.vector,
    riskBreakdown: topCvss.cvss.breakdown
  }
}
