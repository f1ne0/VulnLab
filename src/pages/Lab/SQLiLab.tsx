import { Button, HStack, Select, SimpleGrid, Text, Textarea, VStack, useToast } from '@chakra-ui/react'
import { useMemo, useState } from 'react'
import { TerminalWindow } from '../../components/ui/TerminalWindow'
import { SeverityBadge } from '../../components/ui/SeverityBadge'
import { FindingsList } from '../../components/ui/FindingsList'
import { payloadLibrary } from '../../data/payloadLibrary'
import { simulateSQLi, sqlTargets } from '../../utils/simulators/sqliSimulator'
import { useLabStore } from '../../store/labStore'
import { CodeBlock } from '../../components/ui/CodeBlock'
import { useI18n } from '../../i18n'

export function SQLiLab() {
  const { t, locale } = useI18n()
  const sqliPresets = useMemo(() => payloadLibrary.filter((p) => p.type === 'sqli'), [])
  const [payload, setPayload] = useState(`' OR '1'='1`)
  const [target, setTarget] = useState(sqlTargets[0].id)
  const [result, setResult] = useState(() => simulateSQLi(payload, target, locale))
  const [lastRunAt, setLastRunAt] = useState<string | null>(null)
  const { logResult } = useLabStore()
  const toast = useToast()

  const runSimulation = () => {
    const next = simulateSQLi(payload, target, locale)
    setResult(next)
    setLastRunAt(new Date().toLocaleTimeString(locale === 'ru' ? 'ru-RU' : 'en-US'))
    logResult(locale === 'ru' ? 'SQL-инъекция' : 'SQL Injection', payload, next, next.riskScore)
    toast({
      title: t('lab.sqli.done'),
      description: next.technique,
      status: next.severity === 'critical' ? 'error' : 'info'
    })
  }

  return (
    <SimpleGrid columns={{ base: 1, xl: 3 }} spacing={4} sx={{ "&> *": { minW: 0 } }}>
      <TerminalWindow title={t('lab.section.target')}>
        <VStack align="stretch" spacing={4}>
          <Text fontSize="sm" color="whiteAlpha.700">
            {t('common.localDisclaimer')}
          </Text>
          <Select value={target} onChange={(event) => setTarget(event.target.value)} borderColor="rgba(0,255,178,0.12)">
            {sqlTargets.map((item) => (
              <option key={item.id} value={item.id}>
                {item.label} ({item.dialect})
              </option>
            ))}
          </Select>
          <Select placeholder={locale === 'ru' ? 'выбрать payload-пресет…' : 'pick payload preset…'} onChange={(e) => e.target.value && setPayload(e.target.value)}>
            {sqliPresets.map((item) => (
              <option key={item.id} value={item.payload}>
                {item.title}
              </option>
            ))}
          </Select>
          <Textarea value={payload} onChange={(event) => setPayload(event.target.value)} minH="200px" fontFamily="mono" />
          <Button variant="terminal" onClick={runSimulation}>
            {t('lab.sqli.execute')}
          </Button>
          {lastRunAt && <Text color="brand.300">{t('common.runAt')}: {lastRunAt}</Text>}
        </VStack>
      </TerminalWindow>
      <TerminalWindow title={t('lab.section.query')}>
        <VStack align="stretch" spacing={4}>
          <CodeBlock language="sql" code={sqlTargets.find((item) => item.id === target)?.query ?? ''} />
          <HStack justify="space-between">
            <Text fontFamily="heading">HTTP {result.statusCode}</Text>
            <SeverityBadge severity={result.severity} />
          </HStack>
          {result.latencyMs && <Text fontSize="xs" color="warning.500">latency: {result.latencyMs}ms</Text>}
          <CodeBlock language="json" code={result.body} />
        </VStack>
      </TerminalWindow>
      <TerminalWindow title={t('lab.section.analysis')}>
        <VStack align="stretch" spacing={4}>
          <Text fontFamily="heading" color="brand.300">
            {t('common.detectedTechnique')}: {result.technique}
          </Text>
          <Text color="whiteAlpha.800">{result.summary}</Text>
          <Text color="danger.500" fontWeight="700">
            {result.legalBadge}
          </Text>
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
