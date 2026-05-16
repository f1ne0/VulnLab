import type { LabFinding, SimulatedResult } from '../../types'
import type { Locale } from '../../i18n'
import { aggregateFindings, computeRisk, severityToRisk } from './riskScoring'

type Engine = 'jinja2' | 'twig' | 'freemarker' | 'velocity' | 'erb' | 'handlebars'

const PATTERNS: Record<Engine, RegExp[]> = {
  jinja2: [/\{\{.*?\}\}/, /\{%.*?%\}/, /config\.from_pyfile|request\.application/],
  twig: [/\{\{.*?\}\}/, /_self|_context|_charset/],
  freemarker: [/<#assign|<#list|\$\{[^}]+\}/, /freemarker\.template\.utility\.Execute/],
  velocity: [/\#set\s*\(/, /\$Runtime|\$class/],
  erb: [/<%=.*?%>|<%.*?%>/, /system\(|`/],
  handlebars: [/\{\{.*?\}\}/, /lookup|constructor/]
}

const RCE_MARKERS = [
  /__class__|__mro__|__subclasses__|__globals__|__builtins__/i,
  /Runtime\.getRuntime|ProcessBuilder|getClass\(\)\.forName/,
  /freemarker\.template\.utility\.Execute|Runtime/,
  /Runtime|exec\(|system\(|popen\(/i,
  /constructor\.constructor/i
]

interface Scenario {
  engine?: Engine
  sandbox?: boolean
}

export function simulateSsti(payload: string, scenario: Record<string, string | boolean>, locale: Locale = 'ru'): SimulatedResult & { riskScore: number } {
  const isRu = locale === 'ru'
  const engine: Engine = (scenario.engine as Engine) ?? 'jinja2'
  const cfg: Required<Scenario> = {
    engine,
    sandbox: Boolean(scenario.sandbox)
  }

  const findings: LabFinding[] = []
  const engineHit = PATTERNS[cfg.engine].some((re: RegExp) => re.test(payload))
  const rceHit = RCE_MARKERS.some((re) => re.test(payload))

  const evalResult = tryEval(payload, cfg.engine)

  if (engineHit) {
    findings.push({
      title: isRu ? `Сигнатура шаблонизатора (${cfg.engine})` : `Template syntax (${cfg.engine})`,
      severity: 'medium',
      cwe: 'CWE-94',
      evidence: payload.match(PATTERNS[cfg.engine][0])?.[0],
      description: isRu ? 'Пользовательский ввод попадает в шаблонизатор.' : 'User input reaches the template engine.',
      recommendation: isRu ? 'Не вставляйте ввод в шаблонную строку; используйте placeholder-механизм.' : 'Never interpolate input into template strings; use placeholders.',
      legalContext: '—'
    })
  }

  if (rceHit && !cfg.sandbox) {
    findings.push({
      title: isRu ? 'Эскалация SSTI → RCE' : 'SSTI → RCE escalation',
      severity: 'critical',
      cwe: 'CWE-94',
      evidence: payload.slice(0, 120),
      description: isRu
        ? 'Payload содержит маркеры выхода в runtime (Python __mro__, Java Runtime, Node constructor).'
        : 'Payload contains runtime escape markers (Python __mro__, Java Runtime, Node constructor).',
      recommendation: isRu ? 'Включите sandbox шаблонизатора и блокируйте опасные filters/globals.' : 'Enable sandbox; block dangerous filters/globals.',
      legalContext: isRu ? 'RCE = ст. 272/273 УК РФ / 278¹/278⁵ УК РУз.' : 'RCE qualifies as unauthorized access + malware.'
    })
  }

  if (rceHit && cfg.sandbox) {
    findings.push({
      title: isRu ? 'Sandbox bypass попытка' : 'Sandbox bypass attempt',
      severity: 'high',
      cwe: 'CWE-94',
      description: isRu ? 'Sandbox замедляет, но не гарантирует защиту — известные bypass через bytecode/registry.' : 'Sandbox slows but does not guarantee — known bypasses via bytecode/registry.',
      recommendation: isRu ? 'Изолируйте рендеринг в отдельный процесс с минимальными правами.' : 'Render templates in a separated, least-privilege process.',
      legalContext: '—'
    })
  }

  if (findings.length === 0) {
    findings.push({
      title: isRu ? 'SSTI не обнаружен' : 'No SSTI detected',
      severity: 'info',
      description: '—',
      recommendation: '—',
      legalContext: '—'
    })
  }

  const overall = aggregateFindings(findings)
  const cvss = computeRisk({
    confidentiality: rceHit && !cfg.sandbox ? 'high' : 'low',
    integrity: rceHit && !cfg.sandbox ? 'high' : 'low',
    availability: rceHit && !cfg.sandbox ? 'high' : 'none',
    scope: rceHit ? 'changed' : 'unchanged',
    privilegesRequired: 'none'
  })

  return {
    technique: rceHit && !cfg.sandbox ? (isRu ? 'SSTI → RCE' : 'SSTI → RCE') : isRu ? 'Server-Side Template Injection' : 'Server-Side Template Injection',
    techniques: findings.map((f) => f.title),
    summary: isRu
      ? `engine=${cfg.engine}, sandbox=${cfg.sandbox}, evalResult=${evalResult}`
      : `engine=${cfg.engine}, sandbox=${cfg.sandbox}, evalResult=${evalResult}`,
    statusCode: rceHit ? 200 : 200,
    headers: { 'Content-Type': 'text/html', Server: `Web/${cfg.engine}` },
    body: JSON.stringify({ rendered: evalResult, engine: cfg.engine, sandbox: cfg.sandbox }, null, 2),
    severity: overall,
    legalBadge: isRu ? 'УК ст. 272/273 РФ / 278¹/278⁵ РУз' : 'Unauthorized access + malware statutes',
    findings,
    riskScore: Math.max(severityToRisk(overall), Math.round(cvss.score * 10)),
    cvssVector: cvss.vector,
    riskBreakdown: cvss.breakdown
  }
}

function tryEval(payload: string, engine: Engine): string {
  const mathMatch = payload.match(/\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}/)
  if (mathMatch) return String(Number(mathMatch[1]) * Number(mathMatch[2]))
  if (/__subclasses__|__mro__/.test(payload)) {
    return "<class 'subprocess.Popen'>(['cat', '/etc/passwd']) -> root:x:0:0:root:/root:/bin/bash"
  }
  if (/Runtime\.getRuntime\(\)\.exec/.test(payload)) {
    return 'java.lang.UNIXProcess@7d4793a8 ; stdout=uid=33(www-data) gid=33(www-data)'
  }
  if (/freemarker\.template\.utility\.Execute/.test(payload)) {
    return 'uid=0(root) gid=0(root) groups=0(root)'
  }
  if (/constructor\.constructor/.test(payload)) {
    return 'Function: alert -> 1'
  }
  return engine === 'jinja2' ? '(no template output)' : '(rendered template fragment)'
}
