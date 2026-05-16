import type { LabFinding, SimulatedResult } from '../../types'
import type { Locale } from '../../i18n'
import { aggregateFindings, computeRisk, severityToRisk } from './riskScoring'

export type XssContext = 'html' | 'attribute' | 'js-string' | 'url' | 'css' | 'comment'

const DANGEROUS_TAGS = [
  'script',
  'iframe',
  'object',
  'embed',
  'svg',
  'math',
  'meta',
  'link',
  'video',
  'audio',
  'source',
  'details',
  'marquee',
  'body',
  'image',
  'input',
  'form',
  'base'
]

const EVENT_HANDLERS = [
  'onerror',
  'onload',
  'onfocus',
  'onclick',
  'ontoggle',
  'onstart',
  'onanimationend',
  'onbeforetoggle',
  'onmouseover',
  'onpointerdown',
  'onauxclick',
  'oninput',
  'onchange',
  'onscroll',
  'oncopy'
]

const DOM_SINKS = [
  'innerHTML',
  'outerHTML',
  'document.write',
  'document.writeln',
  'eval',
  'setTimeout(',
  'setInterval(',
  'Function(',
  'location.hash',
  'location.search',
  'srcdoc',
  'insertAdjacentHTML'
]

function detectTags(payload: string): string[] {
  const re = /<\s*([a-zA-Z][a-zA-Z0-9]*)\b/g
  const tags = new Set<string>()
  let m: RegExpExecArray | null
  while ((m = re.exec(payload))) tags.add(m[1].toLowerCase())
  return Array.from(tags)
}

function detectEvents(payload: string): string[] {
  const lower = payload.toLowerCase()
  return EVENT_HANDLERS.filter((h) => new RegExp(`\\b${h}\\s*=`).test(lower))
}

function detectDomSinks(payload: string): string[] {
  return DOM_SINKS.filter((s) => payload.includes(s))
}

function detectContexts(payload: string): XssContext[] {
  const ctx = new Set<XssContext>()
  if (/<\s*[a-z]/i.test(payload)) ctx.add('html')
  if (/(["'])[^"']*\1\s*[a-z]+\s*=/i.test(payload) || /=\s*["'][^"']*$/.test(payload)) ctx.add('attribute')
  if (/javascript:|data:[^,]*script/i.test(payload)) ctx.add('url')
  if (/<!--|-->/.test(payload)) ctx.add('comment')
  if (/expression\s*\(|@import\s+/i.test(payload)) ctx.add('css')
  if (/['"`].*?\$\{|['"`].*?\+/.test(payload) && /alert|eval|fetch/.test(payload)) ctx.add('js-string')
  return Array.from(ctx)
}

export interface CspDirectives {
  raw: string
  directives: Record<string, string[]>
  unsafeInline: boolean
  unsafeEval: boolean
  wildcardSources: string[]
  missingDefault: boolean
  missingFrameAncestors: boolean
  missingBaseUri: boolean
}

export function parseCsp(raw: string): CspDirectives {
  const directives: Record<string, string[]> = {}
  raw
    .split(';')
    .map((p) => p.trim())
    .filter(Boolean)
    .forEach((part) => {
      const [name, ...rest] = part.split(/\s+/)
      directives[name.toLowerCase()] = rest
    })
  const allSources = Object.values(directives).flat()
  return {
    raw,
    directives,
    unsafeInline: allSources.includes("'unsafe-inline'"),
    unsafeEval: allSources.includes("'unsafe-eval'"),
    wildcardSources: allSources.filter((s) => s === '*' || s === 'data:' || s === 'https:'),
    missingDefault: !directives['default-src'],
    missingFrameAncestors: !directives['frame-ancestors'],
    missingBaseUri: !directives['base-uri']
  }
}

export function simulateXss(
  payload: string,
  cspOrEnabled: string | boolean,
  locale: Locale = 'ru'
): SimulatedResult & {
  classification: string
  previewHtml: string
  cookieLeak: string
  contexts: XssContext[]
  cspAnalysis?: CspDirectives
  riskScore: number
} {
  const isRu = locale === 'ru'
  const cspRaw =
    typeof cspOrEnabled === 'string'
      ? cspOrEnabled
      : cspOrEnabled
        ? "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'"
        : ''
  const cspAnalysis = cspRaw ? parseCsp(cspRaw) : undefined

  const tags = detectTags(payload)
  const events = detectEvents(payload)
  const sinks = detectDomSinks(payload)
  const contexts = detectContexts(payload)
  const hasScript = tags.includes('script')
  const hasJsUrl = /javascript:/i.test(payload)
  const isPolyglot = (tags.length >= 2 && events.length >= 1) || /jaVasCript|--><svg|`-->'/i.test(payload)
  const isMutation = /<noscript>|<svg[^>]*><style|<template/i.test(payload)
  const dangerousTags = tags.filter((t) => DANGEROUS_TAGS.includes(t))

  const findings: LabFinding[] = []

  const cspBlocks = cspAnalysis && !cspAnalysis.unsafeInline && !cspAnalysis.wildcardSources.length
  const effective = !(cspBlocks && (hasScript || events.length > 0 || hasJsUrl))

  if (dangerousTags.length > 0) {
    findings.push({
      title: isRu ? `Опасные теги: ${dangerousTags.join(', ')}` : `Dangerous tags: ${dangerousTags.join(', ')}`,
      severity: effective ? 'high' : 'medium',
      cwe: 'CWE-79',
      evidence: dangerousTags.join(', '),
      description: isRu
        ? 'Payload содержит теги с активной исполнительной семантикой.'
        : 'Payload contains tags with active execution semantics.',
      recommendation: isRu
        ? 'Используйте allow-list тегов и атрибутов при санитизации (DOMPurify-style).'
        : 'Use an allow-list sanitizer (DOMPurify-style) for tags and attributes.',
      legalContext: isRu
        ? 'Захват сессии через XSS квалифицируется как неправомерный доступ.'
        : 'Session hijacking via XSS qualifies as unauthorized access.'
    })
  }

  if (events.length > 0) {
    findings.push({
      title: isRu ? `Обработчики событий: ${events.join(', ')}` : `Event handlers: ${events.join(', ')}`,
      severity: effective ? 'high' : 'medium',
      cwe: 'CWE-79',
      evidence: events.join(', '),
      description: isRu
        ? 'Атрибуты-обработчики событий исполняют произвольный JS при триггере.'
        : 'Event handler attributes execute arbitrary JS when triggered.',
      recommendation: isRu
        ? 'Запретите вставку on*-атрибутов через санитизатор.'
        : 'Block on*-attributes via sanitizer policy.',
      legalContext: isRu ? 'См. ст. 272 УК РФ.' : 'See unauthorized-access statutes.'
    })
  }

  if (sinks.length > 0) {
    findings.push({
      title: isRu ? `DOM sinks: ${sinks.join(', ')}` : `DOM sinks: ${sinks.join(', ')}`,
      severity: 'high',
      cwe: 'CWE-79',
      evidence: sinks.join(', '),
      description: isRu
        ? 'Используются опасные браузерные API, выполняющие строку как HTML/JS.'
        : 'Payload targets browser APIs that execute strings as HTML/JS.',
      recommendation: isRu
        ? 'Замените innerHTML/eval на textContent и явные DOM-операции; включите Trusted Types.'
        : 'Replace innerHTML/eval with textContent and explicit DOM ops; enable Trusted Types.',
      legalContext: isRu
        ? 'DOM-based XSS — частая основа атак на пользователей.'
        : 'DOM-based XSS is a common basis for user-targeting attacks.'
    })
  }

  if (hasJsUrl) {
    findings.push({
      title: isRu ? 'javascript: URL' : 'javascript: URL',
      severity: 'high',
      cwe: 'CWE-79',
      evidence: payload.match(/javascript:[^\s"'<>]*/i)?.[0],
      description: isRu
        ? 'javascript:-URL исполняет код при навигации/клике.'
        : 'javascript: URLs execute code on navigation/click.',
      recommendation: isRu ? 'Проверяйте схему URL по allow-list.' : 'Validate URL scheme via allow-list.',
      legalContext: isRu ? 'См. ст. 272 УК РФ при захвате сессии.' : 'Unauthorized access statutes apply on session takeover.'
    })
  }

  if (isPolyglot) {
    findings.push({
      title: isRu ? 'Polyglot-вектор' : 'Polyglot vector',
      severity: 'high',
      cwe: 'CWE-79',
      description: isRu
        ? 'Payload одновременно валиден в нескольких контекстах (HTML/attr/JS).'
        : 'Payload is simultaneously valid in multiple contexts (HTML/attr/JS).',
      recommendation: isRu
        ? 'Кодируйте вывод по фактическому контексту, а не общим filter-функциям.'
        : 'Output-encode per actual context, not via generic filters.',
      legalContext: isRu
        ? 'Использование полиглотов — типичный признак целенаправленной атаки.'
        : 'Polyglot use is typical of targeted attacks.'
    })
  }

  if (isMutation) {
    findings.push({
      title: isRu ? 'Mutation XSS (mXSS)' : 'Mutation XSS (mXSS)',
      severity: 'high',
      cwe: 'CWE-79',
      description: isRu
        ? 'Браузер может перестроить DOM после санитизации, активируя ранее «безопасные» узлы.'
        : 'Browser may reshape DOM after sanitization, activating previously safe nodes.',
      recommendation: isRu
        ? 'Используйте Trusted Types и санитизаторы с защитой от mXSS (последние версии DOMPurify).'
        : 'Use Trusted Types and mXSS-aware sanitizers (recent DOMPurify).',
      legalContext: isRu ? 'См. ст. 272 УК РФ.' : 'Unauthorized-access statutes apply.'
    })
  }

  if (cspAnalysis) {
    if (cspAnalysis.unsafeInline) {
      findings.push({
        title: isRu ? "CSP содержит 'unsafe-inline'" : "CSP allows 'unsafe-inline'",
        severity: 'high',
        cwe: 'CWE-693',
        evidence: "'unsafe-inline'",
        description: isRu
          ? "'unsafe-inline' практически отключает защиту CSP от XSS."
          : "'unsafe-inline' largely defeats CSP's XSS protection.",
        recommendation: isRu ? 'Перейдите на nonce/hash-based CSP.' : 'Move to nonce/hash-based CSP.',
        legalContext: isRu ? 'Слабая CSP усугубляет аргументы о небрежности после инцидента.' : 'Weak CSP aggravates post-incident negligence arguments.'
      })
    }
    if (cspAnalysis.unsafeEval) {
      findings.push({
        title: isRu ? "CSP содержит 'unsafe-eval'" : "CSP allows 'unsafe-eval'",
        severity: 'medium',
        cwe: 'CWE-693',
        description: isRu ? 'eval-семантика остаётся доступной для эксплойтов.' : 'eval-class APIs remain available for exploits.',
        recommendation: isRu ? 'Уберите unsafe-eval и перепишите динамические части.' : 'Remove unsafe-eval and rewrite dynamic eval call sites.',
        legalContext: isRu ? 'См. выше.' : 'See above.'
      })
    }
    if (cspAnalysis.wildcardSources.length > 0) {
      findings.push({
        title: isRu ? 'Wildcard-источники в CSP' : 'Wildcard sources in CSP',
        severity: 'medium',
        evidence: cspAnalysis.wildcardSources.join(', '),
        description: isRu
          ? `Допущены источники: ${cspAnalysis.wildcardSources.join(', ')} — расширяют поверхность атаки.`
          : `Allowed sources: ${cspAnalysis.wildcardSources.join(', ')} — broaden attack surface.`,
        recommendation: isRu ? 'Заменяйте wildcard на конкретные origin.' : 'Replace wildcards with specific origins.',
        legalContext: isRu ? 'Усиливает компрометацию при цепочках уязвимостей.' : 'Amplifies impact in vulnerability chains.'
      })
    }
    if (cspAnalysis.missingBaseUri) {
      findings.push({
        title: isRu ? 'Отсутствует base-uri' : 'Missing base-uri',
        severity: 'medium',
        description: isRu
          ? 'Без base-uri возможен dangling-markup и подмена <base>.'
          : 'Without base-uri, dangling-markup and <base> hijacking are possible.',
        recommendation: isRu ? "Добавьте base-uri 'self'." : "Add base-uri 'self'.",
        legalContext: isRu ? 'См. п. о CSP.' : 'See CSP notes.'
      })
    }
    if (cspAnalysis.missingFrameAncestors) {
      findings.push({
        title: isRu ? 'Отсутствует frame-ancestors' : 'Missing frame-ancestors',
        severity: 'low',
        description: isRu ? 'Возможна clickjacking-эксплуатация.' : 'Clickjacking remains possible.',
        recommendation: isRu ? "Добавьте frame-ancestors 'none' либо нужный origin." : "Add frame-ancestors 'none' or required origin.",
        legalContext: isRu ? 'Clickjacking может комбинироваться с CSRF.' : 'Clickjacking can be chained with CSRF.'
      })
    }
  } else if (hasScript || events.length > 0) {
    findings.push({
      title: isRu ? 'CSP не задана' : 'No CSP set',
      severity: 'medium',
      description: isRu ? 'Без CSP даже простой XSS не нейтрализуется браузером.' : 'Without CSP, even simple XSS is not browser-mitigated.',
      recommendation: isRu ? 'Внедрите CSP nonce-based.' : 'Deploy a nonce-based CSP.',
      legalContext: isRu ? 'Отсутствие базовых защит может усугубить ответственность.' : 'Missing baseline protections can aggravate liability.'
    })
  }

  if (findings.length === 0) {
    findings.push({
      title: isRu ? 'Сильная сигнатура XSS не обнаружена' : 'No strong XSS signature detected',
      severity: 'info',
      description: isRu
        ? 'Payload не задействовал моделируемые XSS-векторы.'
        : 'Payload did not trigger modeled XSS vectors.',
      recommendation: isRu ? 'Пробуйте теги script/svg, on*-атрибуты, javascript:-URL.' : 'Try script/svg tags, on*-attributes, javascript: URLs.',
      legalContext: isRu ? 'Зондирование чужих систем небезопасно правово.' : 'Probing third-party systems is legally risky.'
    })
  }

  const classification = sinks.length
    ? isRu
      ? 'DOM-based XSS'
      : 'DOM-based XSS'
    : hasScript || events.length || hasJsUrl
      ? isRu
        ? 'Reflected / Stored XSS'
        : 'Reflected / Stored XSS'
      : isRu
        ? 'Сильной сигнатуры нет'
        : 'No strong signature'

  const overall = aggregateFindings(findings)
  const cvss = computeRisk({
    confidentiality: overall === 'critical' || overall === 'high' ? 'high' : 'low',
    integrity: 'low',
    userInteraction: 'required',
    scope: 'changed'
  })

  const cookieLeak = !effective
    ? isRu
      ? 'CSP заблокировала исполнение; доступ к cookie предотвращён.'
      : 'CSP blocked execution; cookie access prevented.'
    : 'document.cookie => session=lab-demo; role=researcher; csrftoken=9b2f-demo'

  return {
    technique: classification,
    techniques: findings.map((f) => f.title),
    summary: isRu
      ? `Контексты: ${contexts.join(', ') || '—'}. Эффективная эксплуатация: ${effective ? 'возможна' : 'блокирована CSP'}.`
      : `Contexts: ${contexts.join(', ') || '—'}. Effective exploitation: ${effective ? 'possible' : 'blocked by CSP'}.`,
    statusCode: effective ? 200 : 403,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': cspRaw || 'not set'
    },
    body: JSON.stringify(
      {
        rendered: effective,
        contexts,
        tags,
        events,
        sinks,
        polyglot: isPolyglot,
        mutation: isMutation,
        csp: cspAnalysis
          ? {
              unsafeInline: cspAnalysis.unsafeInline,
              unsafeEval: cspAnalysis.unsafeEval,
              wildcards: cspAnalysis.wildcardSources
            }
          : null
      },
      null,
      2
    ),
    severity: overall,
    legalBadge: isRu ? 'УК РФ ст. 272 — захват сессии' : 'Unauthorized-access statutes on session hijack',
    findings,
    classification,
    previewHtml: effective
      ? payload
      : `<p>${isRu ? 'CSP заблокировала активный контент.' : 'CSP blocked active content.'}</p>`,
    cookieLeak,
    contexts,
    cspAnalysis,
    riskScore: Math.max(severityToRisk(overall), Math.round(cvss.score * 10)),
    cvssVector: cvss.vector,
    riskBreakdown: cvss.breakdown
  }
}
