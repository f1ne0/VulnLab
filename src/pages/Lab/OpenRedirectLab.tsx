import { GenericLab } from './GenericLab'
import { simulateOpenRedirect } from '../../utils/simulators/openRedirectSimulator'
import { useI18n } from '../../i18n'

export function OpenRedirectLab() {
  const { locale } = useI18n()
  const isRu = locale === 'ru'
  return (
    <GenericLab
      config={{
        vulnType: 'Open Redirect',
        defaultPayload: 'https://vulnlab.local.attacker.tld/login',
        payloadLabel: isRu ? 'next= параметр' : 'next= parameter',
        inputSize: 'short',
        defaultScenario: { validation: 'startsWith' },
        scenarioControls: [
          {
            type: 'select',
            key: 'validation',
            label: isRu ? 'Валидация' : 'Validation',
            options: [
              { value: 'none', label: isRu ? 'нет' : 'none' },
              { value: 'startsWith', label: 'startsWith(host)' },
              { value: 'allowlist', label: 'allow-list (parsed)' }
            ]
          }
        ],
        presets: [
          { id: 'phish', title: 'startsWith bypass', payload: 'https://vulnlab.local.attacker.tld/login' },
          { id: 'userinfo', title: 'userinfo trick', payload: 'https://vulnlab.local@attacker.tld/' },
          { id: 'proto', title: 'protocol-relative', payload: '//attacker.tld/login' },
          { id: 'js', title: 'javascript: scheme', payload: 'javascript:alert(document.cookie)' },
          { id: 'safe', title: 'безопасный относительный', payload: '/dashboard' }
        ],
        simulate: (payload, scenario, loc) => simulateOpenRedirect(payload, scenario, loc)
      }}
    />
  )
}
