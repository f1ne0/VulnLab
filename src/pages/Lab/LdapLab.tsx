import { GenericLab } from './GenericLab'
import { simulateLdap } from '../../utils/simulators/ldapSimulator'
import { useI18n } from '../../i18n'

export function LdapLab() {
  const { locale } = useI18n()
  const isRu = locale === 'ru'
  return (
    <GenericLab
      config={{
        vulnType: 'LDAP Injection',
        defaultPayload: '*)(uid=*))(|(uid=*',
        payloadLabel: isRu ? 'LDAP filter input' : 'LDAP filter input',
        inputSize: 'short',
        defaultScenario: { escaped: false },
        scenarioControls: [
          { type: 'toggle', key: 'escaped', label: isRu ? 'экранирование RFC 4515' : 'RFC 4515 escaping' }
        ],
        presets: [
          { id: 'wild', title: 'wildcard *', payload: '*' },
          { id: 'bypass', title: 'auth bypass )(|(uid=*)', payload: '*)(uid=*))(|(uid=*' },
          { id: 'admin', title: 'admin user enumeration', payload: 'admin*' },
          { id: 'dn', title: 'DN injection', payload: ',ou=admins,dc=vulnlab,dc=local' },
          { id: 'null', title: 'null byte', payload: 'admin\\00*' }
        ],
        simulate: (payload, scenario, loc) => simulateLdap(payload, scenario, loc)
      }}
    />
  )
}
