import type { LabFinding, SimulatedResult } from '../../types'
import type { Locale } from '../../i18n'
import { aggregateFindings, computeRisk, severityToRisk } from './riskScoring'

export function simulateXxe(payload: string, scenario: Record<string, string | boolean>, locale: Locale = 'ru'): SimulatedResult & { riskScore: number } {
  const isRu = locale === 'ru'
  const externalEntitiesDisabled = Boolean(scenario.disableExternalEntities)
  const findings: LabFinding[] = []

  const hasDoctype = /<!DOCTYPE\b/i.test(payload)
  const hasEntity = /<!ENTITY\b/i.test(payload)
  const externalSystem = payload.match(/SYSTEM\s+["']([^"']+)["']/i)?.[1]
  const externalPublic = payload.match(/PUBLIC\s+"[^"]*"\s+"([^"]+)"/i)?.[1]
  const parameterEntity = /<!ENTITY\s+%\s+\w+/i.test(payload)
  const target = externalSystem ?? externalPublic ?? ''
  const targetsFile = /^file:|^\/etc|^\/var|^\/proc/i.test(target)
  const targetsHttp = /^https?:|^ftp:/i.test(target)
  const targetsMetadata = /169\.254\.169\.254|metadata\.google\.internal/i.test(target)

  if (hasDoctype && hasEntity) {
    findings.push({
      title: isRu ? 'Внешняя сущность DOCTYPE' : 'External DOCTYPE entity',
      severity: 'high',
      cwe: 'CWE-611',
      evidence: payload.match(/<!ENTITY[^>]+>/i)?.[0],
      description: isRu ? 'Документ содержит DOCTYPE с ENTITY — потенциальный XXE.' : 'DOCTYPE with ENTITY — potential XXE.',
      recommendation: isRu ? 'Отключите DOCTYPE и внешние сущности в XML-парсере.' : 'Disable DOCTYPE and external entities in the XML parser.',
      legalContext: '—'
    })
  }

  if (targetsFile && !externalEntitiesDisabled) {
    findings.push({
      title: isRu ? 'Чтение локального файла через XXE' : 'Local file read via XXE',
      severity: 'critical',
      cwe: 'CWE-611',
      evidence: target,
      description: isRu ? `Сущность ссылается на ${target} — XML-парсер вернёт содержимое файла.` : `Entity references ${target} — XML parser will inline file contents.`,
      recommendation: isRu ? 'setFeature("http://apache.org/xml/features/disallow-doctype-decl", true).' : 'setFeature("http://apache.org/xml/features/disallow-doctype-decl", true).',
      legalContext: isRu ? 'Чтение защищённых файлов = ст. 272/278¹.' : 'Unauthorized file read.'
    })
  }

  if (targetsHttp && !externalEntitiesDisabled) {
    findings.push({
      title: isRu ? 'XXE → SSRF' : 'XXE → SSRF',
      severity: targetsMetadata ? 'critical' : 'high',
      cwe: 'CWE-611',
      evidence: target,
      description: isRu ? 'XXE используется как мост к внутренним HTTP-сервисам.' : 'XXE pivoted to internal HTTP services.',
      recommendation: isRu ? 'Отключите загрузку внешних DTD и блокируйте egress парсера.' : 'Disable external DTD loading; restrict parser egress.',
      legalContext: '—'
    })
  }

  if (parameterEntity && !externalEntitiesDisabled) {
    findings.push({
      title: isRu ? 'OOB-эксфильтрация через parameter entity' : 'OOB exfiltration via parameter entity',
      severity: 'critical',
      cwe: 'CWE-611',
      description: isRu ? 'Парамент-сущности позволяют посимвольный вынос данных через DNS/HTTP-канал.' : 'Parameter entities allow character-by-character exfiltration via DNS/HTTP.',
      recommendation: isRu ? 'Полностью отключите внешние DTD и parameter entities.' : 'Disable external DTD and parameter entities entirely.',
      legalContext: '—'
    })
  }

  if (externalEntitiesDisabled) {
    findings.push({
      title: isRu ? 'Внешние сущности отключены' : 'External entities disabled',
      severity: 'info',
      description: isRu ? 'Парсер сконфигурирован безопасно.' : 'Parser configured securely.',
      recommendation: '—',
      legalContext: '—'
    })
  }

  if (findings.length === 0) {
    findings.push({
      title: isRu ? 'XXE не обнаружен' : 'No XXE pattern',
      severity: 'info',
      description: '—',
      recommendation: '—',
      legalContext: '—'
    })
  }

  let respBody: string
  if (externalEntitiesDisabled) {
    respBody = '<?xml version="1.0"?><error>External entities disabled</error>'
  } else if (targetsFile) {
    respBody = `<?xml version="1.0"?>\n<root>\n  <user>root:x:0:0:root:/root:/bin/bash</user>\n  <user>www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin</user>\n  <user>admin:x:1000:1000:Admin:/home/admin:/bin/bash</user>\n</root>`
  } else if (targetsMetadata) {
    respBody = `<?xml version="1.0"?>\n<root>\n  <iam-role>web-prod-role</iam-role>\n  <access-key>ASIAIOSFODNN7EXAMPLE</access-key>\n  <secret>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</secret>\n</root>`
  } else if (targetsHttp) {
    respBody = `<?xml version="1.0"?>\n<root>\n  <internal>200 OK from ${target}</internal>\n</root>`
  } else {
    respBody = '<?xml version="1.0"?><root><ok>true</ok></root>'
  }

  const overall = aggregateFindings(findings)
  const cvss = computeRisk({
    confidentiality: targetsFile || targetsMetadata ? 'high' : overall === 'high' ? 'low' : 'none',
    integrity: 'none',
    scope: targetsMetadata ? 'changed' : 'unchanged'
  })

  return {
    technique: isRu ? 'XML External Entity (XXE)' : 'XML External Entity (XXE)',
    techniques: findings.map((f) => f.title),
    summary: isRu
      ? `target=${target || '—'}, disabled=${externalEntitiesDisabled}`
      : `target=${target || '—'}, disabled=${externalEntitiesDisabled}`,
    statusCode: externalEntitiesDisabled ? 400 : 200,
    headers: { 'Content-Type': 'application/xml' },
    body: respBody,
    severity: overall,
    legalBadge: isRu ? 'УК ст. 272/278¹ при чтении защищённых файлов' : 'Unauthorized access on protected file reads',
    findings,
    riskScore: Math.max(severityToRisk(overall), Math.round(cvss.score * 10)),
    cvssVector: cvss.vector,
    riskBreakdown: cvss.breakdown
  }
}
