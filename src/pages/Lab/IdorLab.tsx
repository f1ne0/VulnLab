import { GenericLab } from './GenericLab'
import { simulateIdor } from '../../utils/simulators/idorSimulator'
import { useI18n } from '../../i18n'

export function IdorLab() {
  const { locale } = useI18n()
  const isRu = locale === 'ru'
  return (
    <GenericLab
      config={{
        vulnType: 'IDOR',
        defaultPayload: '/api/invoices/1002',
        payloadLabel: isRu ? 'URL ресурса' : 'Resource URL',
        inputSize: 'short',
        defaultScenario: { objectLevel: false },
        scenarioControls: [
          { type: 'toggle', key: 'objectLevel', label: isRu ? 'object-level authorization' : 'object-level authorization' }
        ],
        presets: [
          { id: 'self', title: 'свой инвойс 1001', payload: '/api/invoices/1001' },
          { id: 'other', title: 'чужой инвойс 1002 (CFO)', payload: '/api/invoices/1002' },
          { id: 'big', title: 'крупный инвойс 1003', payload: '/api/invoices/1003' },
          { id: 'admin-invoice', title: 'admin invoice 1004', payload: '/api/invoices/1004' },
          { id: 'admin-panel', title: '→ admin object', payload: '/api/objects/admin' }
        ],
        simulate: (payload, scenario, loc) => simulateIdor(payload, scenario, loc)
      }}
    />
  )
}
