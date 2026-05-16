import { Button, FormControl, FormLabel, HStack, Input, Select, SimpleGrid, Switch, Text, Textarea, VStack } from '@chakra-ui/react'
import { useState, type ReactNode } from 'react'
import { TerminalWindow } from '../../components/ui/TerminalWindow'
import { SeverityBadge } from '../../components/ui/SeverityBadge'
import { CodeBlock } from '../../components/ui/CodeBlock'
import { FindingsList } from '../../components/ui/FindingsList'
import { useLabStore } from '../../store/labStore'
import { useI18n } from '../../i18n'
import { useToast } from '@chakra-ui/react'
import type { SimulatedResult } from '../../types'

export type ScenarioControl =
  | { type: 'toggle'; key: string; label: string }
  | { type: 'select'; key: string; label: string; options: Array<{ value: string; label: string }> }
  | { type: 'text'; key: string; label: string; placeholder?: string }

export interface GenericLabConfig<TResult extends SimulatedResult> {
  vulnType: string
  defaultPayload: string
  payloadLabel: string
  presets?: Array<{ id: string; title: string; payload: string }>
  scenarioControls?: ScenarioControl[]
  defaultScenario?: Record<string, string | boolean>
  bodyLanguage?: string
  targetLabel?: string
  targetInfo?: ReactNode
  inputSize?: 'short' | 'long'
  simulate: (payload: string, scenario: Record<string, string | boolean>, locale: 'ru' | 'en') => TResult
  extraOutput?: (result: TResult) => ReactNode
}

export function GenericLab<TResult extends SimulatedResult>({ config }: { config: GenericLabConfig<TResult> }) {
  const { t, locale } = useI18n()
  const toast = useToast()
  const { logResult } = useLabStore()
  const [payload, setPayload] = useState(config.defaultPayload)
  const [scenario, setScenario] = useState<Record<string, string | boolean>>(config.defaultScenario ?? {})
  const [result, setResult] = useState<TResult>(() => config.simulate(config.defaultPayload, config.defaultScenario ?? {}, locale))
  const [lastRunAt, setLastRunAt] = useState<string | null>(null)

  const run = () => {
    const next = config.simulate(payload, scenario, locale)
    setResult(next)
    setLastRunAt(new Date().toLocaleTimeString(locale === 'ru' ? 'ru-RU' : 'en-US'))
    logResult(config.vulnType, payload.slice(0, 200), next, next.riskScore ?? 0)
    toast({ title: t('common.executed'), description: next.technique, status: 'info' })
  }

  const setScenarioValue = (key: string, value: string | boolean) => setScenario((prev) => ({ ...prev, [key]: value }))

  return (
    <SimpleGrid columns={{ base: 1, xl: 3 }} spacing={4} sx={{ '& > *': { minW: 0 } }}>
      <TerminalWindow title={config.payloadLabel}>
        <VStack align="stretch" spacing={3}>
          <Text fontSize="sm" color="whiteAlpha.700">
            {t('common.localDisclaimer')}
          </Text>
          {config.targetInfo && <CodeBlock language="text" code={String(config.targetInfo)} />}
          {config.presets && config.presets.length > 0 && (
            <Select placeholder={locale === 'ru' ? 'выбрать payload-пресет…' : 'pick payload preset…'} onChange={(e) => e.target.value && setPayload(e.target.value)}>
              {config.presets.map((item) => (
                <option key={item.id} value={item.payload}>
                  {item.title}
                </option>
              ))}
            </Select>
          )}
          {config.inputSize === 'short' ? (
            <Input value={payload} onChange={(e) => setPayload(e.target.value)} fontFamily="mono" />
          ) : (
            <Textarea value={payload} onChange={(e) => setPayload(e.target.value)} minH="180px" fontFamily="mono" />
          )}
          {config.scenarioControls?.map((ctrl) => {
            if (ctrl.type === 'toggle') {
              return (
                <FormControl key={ctrl.key} display="flex" alignItems="center" gap={3}>
                  <FormLabel m={0} fontSize="sm">{ctrl.label}</FormLabel>
                  <Switch isChecked={Boolean(scenario[ctrl.key])} onChange={(e) => setScenarioValue(ctrl.key, e.target.checked)} />
                </FormControl>
              )
            }
            if (ctrl.type === 'select') {
              return (
                <FormControl key={ctrl.key}>
                  <FormLabel fontSize="sm">{ctrl.label}</FormLabel>
                  <Select value={String(scenario[ctrl.key] ?? ctrl.options[0]?.value ?? '')} onChange={(e) => setScenarioValue(ctrl.key, e.target.value)}>
                    {ctrl.options.map((opt) => (
                      <option key={opt.value} value={opt.value}>{opt.label}</option>
                    ))}
                  </Select>
                </FormControl>
              )
            }
            return (
              <FormControl key={ctrl.key}>
                <FormLabel fontSize="sm">{ctrl.label}</FormLabel>
                <Input value={String(scenario[ctrl.key] ?? '')} placeholder={ctrl.placeholder} onChange={(e) => setScenarioValue(ctrl.key, e.target.value)} fontFamily="mono" />
              </FormControl>
            )
          })}
          <Button variant="terminal" onClick={run}>
            {t('common.executed')}
          </Button>
          {lastRunAt && <Text color="brand.300">{t('common.runAt')}: {lastRunAt}</Text>}
        </VStack>
      </TerminalWindow>
      <TerminalWindow title={config.targetLabel ?? t('lab.section.query')}>
        <VStack align="stretch" spacing={3}>
          <HStack justify="space-between">
            <Text fontFamily="heading">HTTP {result.statusCode}</Text>
            <SeverityBadge severity={result.severity} />
          </HStack>
          {result.latencyMs && <Text fontSize="xs" color="warning.500">latency: {result.latencyMs}ms</Text>}
          <CodeBlock language={config.bodyLanguage ?? 'json'} code={result.body} />
          {config.extraOutput?.(result)}
        </VStack>
      </TerminalWindow>
      <TerminalWindow title={t('lab.section.analysis')}>
        <VStack align="stretch" spacing={3}>
          <Text fontFamily="heading" color="brand.300">
            {t('common.detectedTechnique')}: {result.technique}
          </Text>
          <Text color="whiteAlpha.800">{result.summary}</Text>
          <Text color="danger.500" fontWeight="700">{result.legalBadge}</Text>
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
