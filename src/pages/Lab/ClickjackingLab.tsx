import { GenericLab } from './GenericLab'
import { simulateClickjacking } from '../../utils/simulators/clickjackingSimulator'
import { useI18n } from '../../i18n'

export function ClickjackingLab() {
  const { locale } = useI18n()
  const isRu = locale === 'ru'
  return (
    <GenericLab
      config={{
        vulnType: 'Clickjacking',
        defaultPayload: '/bank/transfer',
        payloadLabel: isRu ? 'Целевой URL' : 'Target URL',
        bodyLanguage: 'html',
        inputSize: 'short',
        defaultScenario: { xfo: 'none', frameAncestors: '', csrfToken: false },
        scenarioControls: [
          {
            type: 'select',
            key: 'xfo',
            label: 'X-Frame-Options',
            options: [
              { value: 'none', label: isRu ? 'не задано' : 'not set' },
              { value: 'DENY', label: 'DENY' },
              { value: 'SAMEORIGIN', label: 'SAMEORIGIN' },
              { value: 'ALLOW-FROM', label: 'ALLOW-FROM (obsolete)' }
            ]
          },
          { type: 'text', key: 'frameAncestors', label: 'CSP frame-ancestors', placeholder: "'none' | 'self'" },
          { type: 'toggle', key: 'csrfToken', label: 'anti-CSRF token' }
        ],
        presets: [
          { id: 'bank', title: 'банковский transfer', payload: '/bank/transfer' },
          { id: 'admin', title: 'admin promote', payload: '/admin/users/1/promote' },
          { id: 'oauth', title: 'OAuth consent', payload: '/oauth/authorize?client_id=x&scope=admin' }
        ],
        simulate: (payload, scenario, loc) => simulateClickjacking(payload, scenario, loc)
      }}
    />
  )
}
