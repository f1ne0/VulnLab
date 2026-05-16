import type { LabFinding, SimulatedResult } from '../../types'
import type { Locale } from '../../i18n'
import { aggregateFindings, computeRisk, entropyBits, severityToRisk } from './riskScoring'

export interface CsrfDefences {
  sameSite: 'None' | 'Lax' | 'Strict'
  tokenCheck: boolean
  originCheck: boolean
  doubleSubmit: boolean
  customHeader: boolean
  method: 'GET' | 'POST'
}

export function validateCsrfToken(token: string): boolean {
  return /^[a-f0-9]{32,64}$/i.test(token)
}

export function generateCsrfAttack(
  formAction: string,
  amount: string,
  defences: CsrfDefences | boolean,
  locale: Locale = 'ru',
  token = ''
): SimulatedResult & { html: string; defences: CsrfDefences; tokenEntropy: number; riskScore: number } {
  const isRu = locale === 'ru'
  const def: CsrfDefences = typeof defences === 'boolean'
    ? {
        sameSite: defences ? 'Strict' : 'None',
        tokenCheck: defences,
        originCheck: defences,
        doubleSubmit: false,
        customHeader: false,
        method: 'POST'
      }
    : defences

  const findings: LabFinding[] = []

  if (def.method === 'GET') {
    findings.push({
      title: isRu ? 'State-changing GET' : 'State-changing GET',
      severity: 'critical',
      cwe: 'CWE-352',
      evidence: 'method=GET',
      description: isRu
        ? 'Изменяющая состояние операция через GET тривиально эксплуатируется через <img> и ссылки.'
        : 'State-changing GET can be trivially exploited via <img>/links.',
      recommendation: isRu ? 'Используйте POST/PUT/DELETE для изменений.' : 'Use POST/PUT/DELETE for state changes.',
      legalContext: isRu ? 'Поддельная транзакция — мошенничество.' : 'Forged transactions can amount to fraud.'
    })
  }

  if (def.sameSite === 'None' && !def.tokenCheck && !def.originCheck && !def.doubleSubmit && !def.customHeader) {
    findings.push({
      title: isRu ? 'Нет защиты от CSRF' : 'No CSRF protection',
      severity: 'critical',
      cwe: 'CWE-352',
      description: isRu ? 'SameSite=None без token/Origin — атака тривиальна.' : 'SameSite=None with no token/Origin — trivial attack.',
      recommendation: isRu
        ? 'Включите SameSite=Lax|Strict + anti-CSRF token + Origin check.'
        : 'Enable SameSite=Lax|Strict + anti-CSRF token + Origin check.',
      legalContext: isRu ? 'Поддельные транзакции против реальных пользователей — состав преступления.' : 'Forging transactions against real users may be criminal.'
    })
  }

  if (def.sameSite === 'Lax' && def.method !== 'GET' && !def.tokenCheck && !def.originCheck) {
    findings.push({
      title: isRu ? 'SameSite=Lax недостаточно' : 'SameSite=Lax insufficient',
      severity: 'medium',
      cwe: 'CWE-352',
      description: isRu
        ? 'Lax пропускает top-level POST в некоторых браузерах — нужен ещё один уровень защиты.'
        : 'Lax may permit top-level POST in some browsers — need an additional control.',
      recommendation: isRu ? 'Добавьте anti-CSRF token или Origin check.' : 'Add anti-CSRF token or Origin check.',
      legalContext: isRu ? 'См. CWE-352.' : 'See CWE-352.'
    })
  }

  if (!def.originCheck && def.method !== 'GET') {
    findings.push({
      title: isRu ? 'Origin/Referer не проверяются' : 'Origin/Referer not validated',
      severity: 'medium',
      cwe: 'CWE-346',
      description: isRu
        ? 'Без проверки Origin/Referer атакующий легко выдаёт чужой сайт за свой.'
        : 'Without Origin/Referer validation, attacker forges requests across origins.',
      recommendation: isRu ? 'Сравнивайте Origin с allow-list для state-changing запросов.' : 'Compare Origin with allow-list on state-changing requests.',
      legalContext: isRu ? 'См. CWE-352.' : 'See CWE-352.'
    })
  }

  const tokenEntropy = entropyBits(token)
  if (def.tokenCheck) {
    if (!token || token.length < 32) {
      findings.push({
        title: isRu ? 'Короткий CSRF-токен' : 'Short CSRF token',
        severity: 'high',
        cwe: 'CWE-330',
        evidence: `length=${token.length}`,
        description: isRu ? 'Токены < 32 символов уязвимы к подбору.' : 'Tokens shorter than 32 chars are guessable.',
        recommendation: isRu ? 'Используйте >= 16 байт криптослучайных данных.' : 'Use >= 16 bytes of cryptorandom data.',
        legalContext: isRu ? 'См. CWE-330.' : 'See CWE-330.'
      })
    } else if (tokenEntropy < 80) {
      findings.push({
        title: isRu ? `Низкая энтропия токена (~${tokenEntropy} бит)` : `Low token entropy (~${tokenEntropy} bits)`,
        severity: 'medium',
        cwe: 'CWE-330',
        description: isRu
          ? 'Слабая энтропия указывает на предсказуемую генерацию.'
          : 'Low entropy indicates predictable generation.',
        recommendation: isRu ? 'Используйте CSPRNG (crypto.randomBytes/random).' : 'Use CSPRNG (crypto.randomBytes/random).',
        legalContext: isRu ? 'См. CWE-330.' : 'See CWE-330.'
      })
    }
  } else {
    findings.push({
      title: isRu ? 'Нет проверки CSRF-токена' : 'No CSRF token check',
      severity: 'high',
      cwe: 'CWE-352',
      description: isRu ? 'Сервер не верифицирует anti-CSRF токен.' : 'Server does not verify an anti-CSRF token.',
      recommendation: isRu ? 'Внедрите synchronizer token или double-submit cookie.' : 'Use synchronizer token or double-submit cookie.',
      legalContext: isRu ? 'См. CWE-352.' : 'See CWE-352.'
    })
  }

  if (!def.doubleSubmit && !def.customHeader && !def.tokenCheck) {
    findings.push({
      title: isRu ? 'Нет double-submit / custom header' : 'No double-submit / custom header',
      severity: 'medium',
      cwe: 'CWE-352',
      description: isRu
        ? 'JSON-API без custom header защиты эксплуатируется через CORS-преrequest эксплоиты.'
        : 'JSON APIs without a custom-header check can be hit via CORS preflight tricks.',
      recommendation: isRu ? 'Требуйте X-Requested-With / X-CSRF на API.' : 'Require X-Requested-With / X-CSRF on APIs.',
      legalContext: isRu ? 'См. CWE-352.' : 'See CWE-352.'
    })
  }

  const blocked = def.tokenCheck && def.originCheck && def.sameSite !== 'None' && def.method !== 'GET'

  if (findings.length === 0) {
    findings.push({
      title: isRu ? 'Защита выглядит достаточной' : 'Defences appear sufficient',
      severity: 'info',
      description: isRu ? 'Все основные контрмеры активны.' : 'All major countermeasures are active.',
      recommendation: isRu ? 'Продолжайте регулярный аудит.' : 'Continue regular audits.',
      legalContext: '—'
    })
  }

  const overall = aggregateFindings(findings)
  const cvss = computeRisk({
    integrity: blocked ? 'low' : 'high',
    confidentiality: 'low',
    userInteraction: 'required',
    scope: 'changed'
  })

  const html = `<html><body><form id="csrf" action="${formAction}" method="${def.method}"><input name="amount" value="${amount}" /><input name="recipient" value="research-demo" /></form><script>document.getElementById('csrf').submit()</script></body></html>`

  return {
    technique: blocked
      ? isRu
        ? 'CSRF нейтрализован комбинацией защит'
        : 'CSRF blocked by combined defences'
      : isRu
        ? 'Поддельный запрос принят'
        : 'Forged request accepted',
    techniques: findings.map((f) => f.title),
    summary: isRu
      ? `SameSite=${def.sameSite}, token=${def.tokenCheck}, origin=${def.originCheck}, dsub=${def.doubleSubmit}, header=${def.customHeader}, method=${def.method}.`
      : `SameSite=${def.sameSite}, token=${def.tokenCheck}, origin=${def.originCheck}, dsub=${def.doubleSubmit}, header=${def.customHeader}, method=${def.method}.`,
    statusCode: blocked ? 403 : 200,
    headers: {
      'Content-Type': 'text/html',
      'Set-Cookie': `session=lab; SameSite=${def.sameSite}${def.sameSite === 'None' ? '; Secure' : ''}`
    },
    body: JSON.stringify({ forged: !blocked, amount, defences: def, tokenEntropy }, null, 2),
    severity: overall,
    legalBadge: isRu ? 'УК РФ ст. 272 / мошеннические последствия' : 'Unauthorized access / fraud exposure',
    html,
    defences: def,
    tokenEntropy,
    findings,
    riskScore: Math.max(severityToRisk(overall), Math.round(cvss.score * 10)),
    cvssVector: cvss.vector,
    riskBreakdown: cvss.breakdown
  }
}
