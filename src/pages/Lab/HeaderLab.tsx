import { Button, SimpleGrid, Text, Textarea, VStack } from '@chakra-ui/react'
import { useState } from 'react'
import { TerminalWindow } from '../../components/ui/TerminalWindow'
import { analyzeHeaders } from '../../utils/simulators/headerAnalyzer'
import { SeverityBadge } from '../../components/ui/SeverityBadge'
import { FindingsList } from '../../components/ui/FindingsList'
import { useLabStore } from '../../store/labStore'
import { useI18n } from '../../i18n'
import { useToast } from '@chakra-ui/react'

const preset = `server: nginx/1.18.0\nx-powered-by: Express\ncontent-type: text/html; charset=utf-8\naccess-control-allow-origin: *\nstrict-transport-security: max-age=60\ncontent-security-policy: default-src 'self'; script-src 'unsafe-inline'\nset-cookie: session=abc; SameSite=None`

export function HeaderLab() {
  const { t, locale } = useI18n()
  const toast = useToast()
  const { logResult } = useLabStore()
  const [rawHeaders, setRawHeaders] = useState(preset)
  const [analysis, setAnalysis] = useState(() => analyzeHeaders(rawHeaders, locale))
  const [lastRunAt, setLastRunAt] = useState<string | null>(null)

  const run = () => {
    const next = analyzeHeaders(rawHeaders, locale)
    setAnalysis(next)
    setLastRunAt(new Date().toLocaleTimeString(locale === 'ru' ? 'ru-RU' : 'en-US'))
    logResult('HTTP Headers', rawHeaders.slice(0, 80), next, next.riskScore ?? 100 - next.score)
    toast({ title: t('common.executed'), description: next.technique, status: 'info' })
  }

  return (
    <SimpleGrid columns={{ base: 1, xl: 3 }} spacing={4} sx={{ "&> *": { minW: 0 } }}>
      <TerminalWindow title={t('lab.section.headersInput')}>
        <VStack align="stretch" spacing={4}>
          <Text fontSize="sm" color="whiteAlpha.700">
            {t('common.localDisclaimer')}
          </Text>
          <Textarea value={rawHeaders} onChange={(event) => setRawHeaders(event.target.value)} minH="280px" fontFamily="mono" />
          <Button variant="terminal" onClick={run}>{t('lab.headers.analyze')}</Button>
          {lastRunAt && <Text color="brand.300">{t('common.runAt')}: {lastRunAt}</Text>}
        </VStack>
      </TerminalWindow>
      <TerminalWindow title={t('lab.section.score')}>
        <VStack align="stretch" spacing={4}>
          <Text fontFamily="heading" color="brand.300" fontSize="4xl">
            {analysis.score}/100
          </Text>
          <SeverityBadge severity={analysis.severity} />
          <Text>{analysis.summary}</Text>
          <Text fontSize="xs" fontFamily="mono" color="whiteAlpha.600">{analysis.cvssVector}</Text>
        </VStack>
      </TerminalWindow>
      <TerminalWindow title={t('lab.section.analysis')}>
        <FindingsList
          findings={analysis.findings ?? []}
          riskScore={analysis.riskScore}
          cvssVector={undefined}
          riskBreakdown={analysis.riskBreakdown}
          recommendationLabel={t('lab.recommendation')}
          legalLabel={t('lab.legalContext')}
        />
      </TerminalWindow>
    </SimpleGrid>
  )
}
