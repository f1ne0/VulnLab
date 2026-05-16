import { Button, HStack, Select, SimpleGrid, Text, Textarea, VStack } from '@chakra-ui/react'
import { useMemo, useState } from 'react'
import { TerminalWindow } from '../../components/ui/TerminalWindow'
import { SeverityBadge } from '../../components/ui/SeverityBadge'
import { FindingsList } from '../../components/ui/FindingsList'
import { payloadLibrary } from '../../data/payloadLibrary'
import { simulateXss } from '../../utils/simulators/xssSimulator'
import { useLabStore } from '../../store/labStore'
import { useI18n } from '../../i18n'
import { useToast } from '@chakra-ui/react'

const DEFAULT_CSP = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'"

export function XSSLab() {
  const { t, locale } = useI18n()
  const toast = useToast()
  const xssPayloads = useMemo(() => payloadLibrary.filter((item) => item.type === 'xss'), [])
  const [payload, setPayload] = useState(xssPayloads[0]?.payload ?? '<script>alert(1)</script>')
  const [csp, setCsp] = useState(DEFAULT_CSP)
  const [result, setResult] = useState(() => simulateXss(payload, csp, locale))
  const [lastRunAt, setLastRunAt] = useState<string | null>(null)
  const { logResult } = useLabStore()

  const run = () => {
    const next = simulateXss(payload, csp, locale)
    setResult(next)
    setLastRunAt(new Date().toLocaleTimeString(locale === 'ru' ? 'ru-RU' : 'en-US'))
    logResult('XSS', payload, next, next.riskScore)
    toast({ title: t('common.executed'), description: next.technique, status: 'info' })
  }

  return (
    <SimpleGrid columns={{ base: 1, xl: 3 }} spacing={4} sx={{ "&> *": { minW: 0 } }}>
      <TerminalWindow title={t('lab.section.payload')}>
        <VStack align="stretch" spacing={4}>
          <Text fontSize="sm" color="whiteAlpha.700">
            {t('common.localDisclaimer')}
          </Text>
          <Select onChange={(event) => setPayload(event.target.value)} value={payload}>
            {xssPayloads.map((item) => (
              <option key={item.id} value={item.payload}>
                {item.title}
              </option>
            ))}
          </Select>
          <Textarea value={payload} onChange={(event) => setPayload(event.target.value)} minH="180px" fontFamily="mono" />
          <Text fontSize="sm" color="whiteAlpha.700">{locale === 'ru' ? 'CSP-политика (пусто = выключена)' : 'CSP policy (empty = disabled)'}</Text>
          <Textarea value={csp} onChange={(event) => setCsp(event.target.value)} minH="80px" fontFamily="mono" placeholder="default-src 'self'; …" />
          <Button variant="terminal" onClick={run}>
            {t('lab.xss.render')}
          </Button>
          {lastRunAt && <Text color="brand.300">{t('common.runAt')}: {lastRunAt}</Text>}
        </VStack>
      </TerminalWindow>
      <TerminalWindow title={t('lab.section.preview')}>
        <VStack align="stretch" spacing={4}>
          <HStack justify="space-between">
            <Text fontFamily="heading">{result.classification}</Text>
            <SeverityBadge severity={result.severity} />
          </HStack>
          <iframe
            title="XSS preview"
            sandbox="allow-scripts"
            srcDoc={`<html><body style="background:#060910;color:#dffef4;font-family:Instrument Sans,sans-serif;padding:16px">${result.previewHtml}</body></html>`}
            style={{ width: '100%', minHeight: '260px', background: '#060910', border: '1px solid rgba(0,255,178,0.08)', borderRadius: '16px' }}
          />
          <Text color="warning.500" fontSize="sm">{result.cookieLeak}</Text>
          <Text fontSize="xs" color="whiteAlpha.600">contexts: {result.contexts.join(', ') || '—'}</Text>
        </VStack>
      </TerminalWindow>
      <TerminalWindow title={t('lab.section.analysis')}>
        <VStack align="stretch" spacing={4}>
          <Text color="whiteAlpha.800">{result.summary}</Text>
          <Text color="danger.500">{result.legalBadge}</Text>
          <FindingsList
            findings={result.findings ?? []}
            riskScore={result.riskScore}
            cvssVector={result.cvssVector}
            riskBreakdown={result.riskBreakdown}
            recommendationLabel={t('lab.recommendation')}
            legalLabel={t('lab.legalContext')}
          />
        </VStack>
      </TerminalWindow>
    </SimpleGrid>
  )
}
