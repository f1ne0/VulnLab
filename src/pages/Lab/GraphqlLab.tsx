import { GenericLab } from './GenericLab'
import { simulateGraphql } from '../../utils/simulators/graphqlSimulator'
import { useI18n } from '../../i18n'

const INTROSPECTION = `query IntrospectionQuery {\n  __schema {\n    types { name fields { name } }\n    mutationType { name }\n  }\n}`
const BATCH = Array.from({ length: 100 }, (_, i) => `loginAttempt${i}: login(email:"admin@vulnlab.local", password:"${'p'.repeat(i % 6 + 1)}")`).join('\n  ')
const DEEP_NEST = `query { user { friends { friends { friends { friends { friends { friends { friends { friends { friends { friends { friends { id } } } } } } } } } } } } }`

export function GraphqlLab() {
  const { locale } = useI18n()
  const isRu = locale === 'ru'
  return (
    <GenericLab
      config={{
        vulnType: 'GraphQL',
        defaultPayload: INTROSPECTION,
        payloadLabel: isRu ? 'GraphQL запрос' : 'GraphQL query',
        bodyLanguage: 'json',
        defaultScenario: { disableIntrospection: false, depthLimit: '0' },
        scenarioControls: [
          { type: 'toggle', key: 'disableIntrospection', label: isRu ? 'отключить introspection' : 'disable introspection' },
          { type: 'text', key: 'depthLimit', label: 'depth limit (0 = off)', placeholder: '5' }
        ],
        presets: [
          { id: 'intro', title: 'IntrospectionQuery', payload: INTROSPECTION },
          { id: 'batch', title: 'batch login brute-force (100×)', payload: `mutation { ${BATCH} }` },
          { id: 'deep', title: 'deep nested DoS', payload: DEEP_NEST },
          { id: 'didyou', title: 'Did you mean leak', payload: `query { user { adminPasword } }` }
        ],
        simulate: (payload, scenario, loc) => simulateGraphql(payload, scenario, loc)
      }}
    />
  )
}
