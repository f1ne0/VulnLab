import { GenericLab } from './GenericLab'
import { simulateSsrf } from '../../utils/simulators/ssrfSimulator'
import { useI18n } from '../../i18n'

export function SsrfLab() {
  const { locale } = useI18n()
  const isRu = locale === 'ru'
  return (
    <GenericLab
      config={{
        vulnType: 'SSRF',
        defaultPayload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/web-prod-role',
        payloadLabel: isRu ? 'URL цели' : 'Target URL',
        bodyLanguage: 'json',
        inputSize: 'short',
        defaultScenario: { filter: 'blacklist', followRedirects: true },
        scenarioControls: [
          {
            type: 'select',
            key: 'filter',
            label: isRu ? 'Фильтр URL' : 'URL filter',
            options: [
              { value: 'none', label: isRu ? 'нет' : 'none' },
              { value: 'blacklist', label: 'blacklist' },
              { value: 'allowlist', label: 'allow-list' }
            ]
          },
          { type: 'toggle', key: 'followRedirects', label: isRu ? 'следовать редиректам' : 'follow redirects' }
        ],
        presets: [
          { id: 'aws', title: 'AWS IMDS credentials', payload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/web-prod-role' },
          { id: 'gcp', title: 'GCP metadata token', payload: 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' },
          { id: 'localhost', title: 'localhost admin', payload: 'http://127.0.0.1:8080/admin' },
          { id: 'private', title: 'private network DB', payload: 'http://10.0.0.21:5432' },
          { id: 'file', title: 'file:// /etc/passwd', payload: 'file:///etc/passwd' },
          { id: 'rebind', title: 'DNS rebinding bypass', payload: 'http://attacker.tld@169.254.169.254/latest/meta-data/' }
        ],
        simulate: (payload, scenario, loc) => simulateSsrf(payload, scenario, loc)
      }}
    />
  )
}
