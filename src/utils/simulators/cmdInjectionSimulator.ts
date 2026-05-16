import type { LabFinding, SimulatedResult } from '../../types'
import type { Locale } from '../../i18n'
import { aggregateFindings, computeRisk, severityToRisk } from './riskScoring'

const META_CHARS = /[;&|`$()<>\\]/
const COMMAND_SEPS = /;|&&|\|\|?|`|\$\(|\$\{/
const KNOWN_COMMANDS = ['ls', 'cat', 'whoami', 'id', 'uname', 'pwd', 'ps', 'netstat', 'curl', 'wget', 'nc', 'bash', 'sh', 'python', 'perl', 'rm', 'dd', 'mkfifo']
const REVERSE_SHELL = /bash\s+-i|nc\s+(-e|-l|-c)|mkfifo|\/dev\/tcp\//
const BLIND_OOB = /curl\s+http|wget\s+http|nslookup|dig\s+/

export function simulateCmdInjection(payload: string, scenario: Record<string, string | boolean>, locale: Locale = 'ru'): SimulatedResult & { riskScore: number } {
  const isRu = locale === 'ru'
  const sanitized = Boolean(scenario.sanitized)
  const findings: LabFinding[] = []

  const hasMeta = META_CHARS.test(payload)
  const hasSep = COMMAND_SEPS.test(payload)
  const cmd = KNOWN_COMMANDS.find((c) => new RegExp(`(^|[;&|\`$(\\s])${c}([\\s$])?`).test(payload))
  const isReverseShell = REVERSE_SHELL.test(payload)
  const isBlindOob = BLIND_OOB.test(payload)
  const effective = !sanitized

  if (hasMeta && effective) {
    findings.push({
      title: isRu ? 'Shell-метасимволы в input' : 'Shell metacharacters in input',
      severity: 'high',
      cwe: 'CWE-78',
      evidence: payload.match(META_CHARS)?.[0],
      description: isRu ? 'Метасимволы (;|`$) попадают в shell без экранирования.' : 'Metacharacters (;|`$) reach the shell unescaped.',
      recommendation: isRu ? 'Используйте execFile/exec с массивом аргументов; никогда не используйте shell=true.' : 'Use execFile/exec with arg array; never shell=true.',
      legalContext: '—'
    })
  }

  if (hasSep && cmd && effective) {
    findings.push({
      title: isRu ? `Внедрение команды: ${cmd}` : `Command injection: ${cmd}`,
      severity: 'critical',
      cwe: 'CWE-78',
      evidence: payload.slice(0, 120),
      description: isRu ? 'Атакующий запускает произвольную команду в контексте веб-приложения.' : 'Attacker runs arbitrary commands in the application context.',
      recommendation: isRu ? 'Полностью убрать shell; использовать allow-list аргументов.' : 'Eliminate shell; allow-list arguments.',
      legalContext: isRu ? 'RCE = ст. 272/273 РФ / 278¹/278⁵ РУз.' : 'RCE = unauthorized access + malware.'
    })
  }

  if (isReverseShell && effective) {
    findings.push({
      title: isRu ? 'Обратный shell payload' : 'Reverse shell payload',
      severity: 'critical',
      cwe: 'CWE-78',
      evidence: payload.match(REVERSE_SHELL)?.[0],
      description: isRu ? 'Полезная нагрузка инициирует исходящее TCP-соединение и предоставляет интерактивный shell.' : 'Payload initiates outbound TCP and gives an interactive shell.',
      recommendation: isRu ? 'Заблокируйте egress; используйте seccomp/AppArmor для процесса web-сервера.' : 'Block egress; use seccomp/AppArmor for the web process.',
      legalContext: isRu ? 'Установление backdoor — отягчающее обстоятельство.' : 'Establishing a backdoor is an aggravating factor.'
    })
  }

  if (isBlindOob && effective) {
    findings.push({
      title: isRu ? 'Blind OOB-канал' : 'Blind OOB channel',
      severity: 'high',
      cwe: 'CWE-78',
      description: isRu ? 'Эксфильтрация через DNS/HTTP запрос, не видимый в ответе приложения.' : 'Exfiltration via DNS/HTTP not visible in the application response.',
      recommendation: isRu ? 'Блокируйте исходящий DNS/HTTP с серверов приложений.' : 'Block outbound DNS/HTTP from app servers.',
      legalContext: '—'
    })
  }

  if (sanitized) {
    findings.push({
      title: isRu ? 'Sanitizer активен' : 'Sanitizer active',
      severity: 'info',
      description: isRu ? 'Метасимволы экранированы — payload не достигает shell.' : 'Metachars escaped — payload does not reach shell.',
      recommendation: '—',
      legalContext: '—'
    })
  }

  if (findings.length === 0) {
    findings.push({
      title: isRu ? 'Command injection не обнаружен' : 'No command injection',
      severity: 'info',
      description: '—',
      recommendation: '—',
      legalContext: '—'
    })
  }

  let body: object
  if (sanitized) {
    body = { stdout: '', stderr: 'invalid argument', exitCode: 1 }
  } else if (cmd === 'cat' && /\/etc\/passwd/.test(payload)) {
    body = {
      stdout: 'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nadmin:x:1000:1000::/home/admin:/bin/bash',
      stderr: '',
      exitCode: 0,
      duration: '12ms'
    }
  } else if (cmd === 'id' || /id\b/.test(payload)) {
    body = { stdout: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)', stderr: '', exitCode: 0 }
  } else if (cmd === 'whoami') {
    body = { stdout: 'www-data', stderr: '', exitCode: 0 }
  } else if (cmd === 'uname') {
    body = { stdout: 'Linux web-prod-3 6.1.0-13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.55-1 x86_64 GNU/Linux', stderr: '', exitCode: 0 }
  } else if (isReverseShell) {
    body = { stdout: '', stderr: 'connection to 5.182.211.99:4444 from web-prod-3.internal:51842 [tcp/*] succeeded', exitCode: 0, channel: 'tcp' }
  } else {
    body = { stdout: `output of: ${payload}`, stderr: '', exitCode: 0 }
  }

  const overall = aggregateFindings(findings)
  const cvss = computeRisk({
    confidentiality: !sanitized && cmd ? 'high' : 'low',
    integrity: !sanitized && cmd ? 'high' : 'none',
    availability: !sanitized && cmd ? 'high' : 'none',
    scope: 'changed'
  })

  return {
    technique: isReverseShell ? (isRu ? 'OS Command Injection → Reverse Shell' : 'OS Command Injection → Reverse Shell') : isRu ? 'OS Command Injection' : 'OS Command Injection',
    techniques: findings.map((f) => f.title),
    summary: isRu
      ? `cmd=${cmd ?? '—'}, sanitized=${sanitized}, reverseShell=${isReverseShell}`
      : `cmd=${cmd ?? '—'}, sanitized=${sanitized}, reverseShell=${isReverseShell}`,
    statusCode: sanitized ? 400 : 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body, null, 2),
    severity: overall,
    legalBadge: isRu ? 'УК ст. 272/273 РФ / 278¹/278⁵ РУз' : 'Unauthorized access + malware',
    findings,
    riskScore: Math.max(severityToRisk(overall), Math.round(cvss.score * 10)),
    cvssVector: cvss.vector,
    riskBreakdown: cvss.breakdown
  }
}
