import type { LabFinding, SimulatedResult } from '../../types'
import type { Locale } from '../../i18n'
import { aggregateFindings, computeRisk, severityToRisk } from './riskScoring'

export function simulateLdap(payload: string, scenario: Record<string, string | boolean>, locale: Locale = 'ru'): SimulatedResult & { riskScore: number } {
  const isRu = locale === 'ru'
  const escaped = Boolean(scenario.escaped)
  const findings: LabFinding[] = []

  const wildcard = /\*/.test(payload)
  const operatorInject = /\)\s*\(|\|\(|&\(/.test(payload)
  const nullInject = /\\00|%00/.test(payload)
  const trueCond = /\)\s*\(\s*\|\s*\(\s*[a-z]+\s*=\s*\*/i.test(payload) || /\)\s*\(\s*[a-z]+\s*=\s*\*/i.test(payload)
  const dnInject = /,\s*ou\s*=|cn\s*=\s*admin/i.test(payload)

  if ((wildcard || operatorInject) && !escaped) {
    findings.push({
      title: isRu ? 'LDAP-инъекция через метасимволы' : 'LDAP injection via metacharacters',
      severity: 'high',
      cwe: 'CWE-90',
      evidence: payload.slice(0, 80),
      description: isRu ? '* и круглые скобки изменяют структуру search filter.' : '* and parentheses alter the search filter structure.',
      recommendation: isRu ? 'Экранируйте *, (, ), \\, NUL по RFC 4515.' : 'Escape *, (, ), \\, NUL per RFC 4515.',
      legalContext: '—'
    })
  }

  if (trueCond && !escaped) {
    findings.push({
      title: isRu ? 'Обход аутентификации через всегда-истинный фильтр' : 'Auth bypass via always-true filter',
      severity: 'critical',
      cwe: 'CWE-90',
      evidence: payload.match(/\)\s*\(\s*\|\s*\([^)]+\)/)?.[0] ?? payload.slice(0, 80),
      description: isRu ? 'Фильтр вида )(|(uid=*) превращает запрос в всегда-истинный.' : 'Filter pattern )(|(uid=*) makes the query always true.',
      recommendation: isRu ? 'Не вставляйте ввод в filter; используйте параметризацию (например, ldapjs.escapeFilter).' : 'Never interpolate input into filter; use parameterization (e.g. ldapjs.escapeFilter).',
      legalContext: isRu ? 'УК ст. 272/278¹.' : 'Unauthorized access.'
    })
  }

  if (nullInject) {
    findings.push({
      title: isRu ? 'Null-byte инъекция' : 'Null-byte injection',
      severity: 'medium',
      cwe: 'CWE-158',
      description: isRu ? '\\00 завершает строку в нижележащем C-парсере.' : '\\00 terminates the string in the underlying C parser.',
      recommendation: isRu ? 'Отвергайте \\0 во входных данных.' : 'Reject \\0 in input.',
      legalContext: '—'
    })
  }

  if (dnInject) {
    findings.push({
      title: isRu ? 'DN injection' : 'DN injection',
      severity: 'high',
      cwe: 'CWE-90',
      description: isRu ? 'Подстановка DN-компонентов меняет область поиска.' : 'Injected DN components change the search scope.',
      recommendation: isRu ? 'Не используйте ввод как часть DN.' : 'Do not use input as part of DN.',
      legalContext: '—'
    })
  }

  if (escaped) {
    findings.push({
      title: isRu ? 'Фильтр экранирован' : 'Filter escaped',
      severity: 'info',
      description: '—',
      recommendation: '—',
      legalContext: '—'
    })
  }

  if (findings.length === 0) {
    findings.push({
      title: isRu ? 'LDAP injection не обнаружен' : 'No LDAP injection',
      severity: 'info',
      description: '—',
      recommendation: '—',
      legalContext: '—'
    })
  }

  let body: object
  if (escaped) {
    body = { matched: 0, dn: null }
  } else if (trueCond) {
    body = {
      matched: 4,
      results: [
        { dn: 'cn=root,ou=people,dc=vulnlab,dc=local', mail: 'root@vulnlab.local', memberOf: ['cn=admins,ou=groups,dc=vulnlab,dc=local'] },
        { dn: 'cn=Sarah Lin,ou=finance,dc=vulnlab,dc=local', mail: 'cfo@vulnlab.local', title: 'CFO' },
        { dn: 'cn=Service Account,ou=svc,dc=vulnlab,dc=local', mail: 'svc-ci@vulnlab.local', userPassword: 'CI-rotated-secret' },
        { dn: 'cn=admin,ou=people,dc=vulnlab,dc=local', mail: 'admin@vulnlab.local', memberOf: ['cn=domain-admins'] }
      ]
    }
  } else if (wildcard || operatorInject) {
    body = { matched: 1, results: [{ dn: 'cn=research,ou=people,dc=vulnlab,dc=local', mail: 'researcher@vulnlab.local' }] }
  } else {
    body = { matched: 0 }
  }

  const overall = aggregateFindings(findings)
  const cvss = computeRisk({
    confidentiality: trueCond && !escaped ? 'high' : 'low',
    integrity: trueCond && !escaped ? 'low' : 'none',
    privilegesRequired: 'none'
  })

  return {
    technique: trueCond ? (isRu ? 'LDAP injection → auth bypass' : 'LDAP injection → auth bypass') : isRu ? 'LDAP injection' : 'LDAP injection',
    techniques: findings.map((f) => f.title),
    summary: isRu
      ? `wildcard=${wildcard}, operatorInject=${operatorInject}, escaped=${escaped}`
      : `wildcard=${wildcard}, operatorInject=${operatorInject}, escaped=${escaped}`,
    statusCode: 200,
    headers: { 'Content-Type': 'application/json', 'X-LDAP-Server': 'openldap-2.6.4' },
    body: JSON.stringify(body, null, 2),
    severity: overall,
    legalBadge: isRu ? 'УК ст. 272 РФ / 278¹ РУз' : 'Unauthorized-access statutes',
    findings,
    riskScore: Math.max(severityToRisk(overall), Math.round(cvss.score * 10)),
    cvssVector: cvss.vector,
    riskBreakdown: cvss.breakdown
  }
}
