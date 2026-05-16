import type { LabFinding, SimulatedResult } from '../../types'
import type { Locale } from '../../i18n'
import { aggregateFindings, computeRisk, severityToRisk } from './riskScoring'

interface Scenario {
  xfo?: 'none' | 'DENY' | 'SAMEORIGIN' | 'ALLOW-FROM'
  frameAncestors?: string
  csrfToken?: boolean
}

export function simulateClickjacking(payload: string, scenario: Record<string, string | boolean>, locale: Locale = 'ru'): SimulatedResult & { riskScore: number } {
  const isRu = locale === 'ru'
  const cfg: Scenario = {
    xfo: (scenario.xfo as Scenario['xfo']) ?? 'none',
    frameAncestors: (scenario.frameAncestors as string) ?? '',
    csrfToken: Boolean(scenario.csrfToken)
  }
  const target = payload.trim() || '/bank/transfer'
  const findings: LabFinding[] = []

  const noXfo = cfg.xfo === 'none'
  const allowFromObsolete = cfg.xfo === 'ALLOW-FROM'
  const noFrameAncestors = !cfg.frameAncestors
  const exposed = (noXfo || allowFromObsolete) && noFrameAncestors

  if (exposed) {
    findings.push({
      title: isRu ? 'Страница может быть встроена в чужой iframe' : 'Page can be embedded in attacker iframe',
      severity: 'high',
      cwe: 'CWE-1021',
      evidence: `XFO=${cfg.xfo}, frame-ancestors=${cfg.frameAncestors || '—'}`,
      description: isRu
        ? 'Атакующий накладывает прозрачный фрейм с целевой кнопкой/формой — пользователь кликает «вслепую».'
        : 'Attacker overlays a transparent frame with target button/form — user clicks blindly.',
      recommendation: isRu
        ? "Установите Content-Security-Policy: frame-ancestors 'none' (или нужный origin)."
        : "Set Content-Security-Policy: frame-ancestors 'none' (or required origin).",
      legalContext: isRu ? 'Связка clickjacking + CSRF → мошенничество.' : 'Clickjacking + CSRF → fraud.'
    })
  }

  if (allowFromObsolete) {
    findings.push({
      title: isRu ? 'X-Frame-Options: ALLOW-FROM устарел' : 'X-Frame-Options: ALLOW-FROM is obsolete',
      severity: 'medium',
      description: isRu ? 'Chrome/Firefox игнорируют ALLOW-FROM.' : 'Chrome/Firefox ignore ALLOW-FROM.',
      recommendation: isRu ? 'Используйте CSP frame-ancestors.' : 'Use CSP frame-ancestors.',
      legalContext: '—'
    })
  }

  if (!cfg.csrfToken && exposed) {
    findings.push({
      title: isRu ? 'Усиление: нет CSRF-токена' : 'Amplification: no CSRF token',
      severity: 'high',
      cwe: 'CWE-352',
      description: isRu ? 'Click через iframe выполнит state-changing запрос без подтверждения.' : 'Frame click executes a state-changing request without confirmation.',
      recommendation: isRu ? 'Добавьте anti-CSRF токен на чувствительные формы.' : 'Add anti-CSRF token to sensitive forms.',
      legalContext: '—'
    })
  }

  if (!exposed) {
    findings.push({
      title: isRu ? 'Защита от clickjacking активна' : 'Clickjacking protection active',
      severity: 'info',
      description: isRu ? 'Заголовки запрещают встраивание в фрейм.' : 'Headers forbid embedding in a frame.',
      recommendation: '—',
      legalContext: '—'
    })
  }

  const html = exposed
    ? `<!doctype html>\n<html><head><style>iframe{opacity:0.01;position:absolute;top:120px;left:80px;width:480px;height:240px;}\n.bait{position:relative;z-index:-1;font:18px sans-serif;padding:200px 100px;}</style></head>\n<body>\n<div class="bait">🎁 Поздравляем! Нажмите «Получить приз» ниже:</div>\n<button>Получить приз</button>\n<iframe src="https://vulnlab.local${target}" sandbox="allow-forms allow-same-origin"></iframe>\n</body></html>`
    : `<!-- iframe не загружается: X-Frame-Options=${cfg.xfo}, CSP frame-ancestors=${cfg.frameAncestors || '—'} -->`

  const overall = aggregateFindings(findings)
  const cvss = computeRisk({
    confidentiality: 'low',
    integrity: exposed ? 'low' : 'none',
    userInteraction: 'required'
  })

  return {
    technique: exposed ? (isRu ? 'Clickjacking возможен' : 'Clickjacking possible') : isRu ? 'Clickjacking заблокирован' : 'Clickjacking blocked',
    techniques: findings.map((f) => f.title),
    summary: isRu
      ? `target=${target}, XFO=${cfg.xfo}, frame-ancestors=${cfg.frameAncestors || '—'}, csrf=${cfg.csrfToken}`
      : `target=${target}, XFO=${cfg.xfo}, frame-ancestors=${cfg.frameAncestors || '—'}, csrf=${cfg.csrfToken}`,
    statusCode: 200,
    headers: {
      'Content-Type': 'text/html',
      ...(cfg.xfo !== 'none' && cfg.xfo !== 'ALLOW-FROM' ? { 'X-Frame-Options': cfg.xfo ?? '' } : {}),
      ...(cfg.frameAncestors ? { 'Content-Security-Policy': `frame-ancestors ${cfg.frameAncestors}` } : {})
    },
    body: html,
    severity: overall,
    legalBadge: isRu ? 'Связка с CSRF → мошенничество (ст. 159 РФ / 168 РУз)' : 'Chained with CSRF → fraud',
    findings,
    riskScore: Math.max(severityToRisk(overall), Math.round(cvss.score * 10)),
    cvssVector: cvss.vector,
    riskBreakdown: cvss.breakdown
  }
}
