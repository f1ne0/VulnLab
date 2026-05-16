import { Button, HStack, Input, Select, SimpleGrid, Text, VStack } from '@chakra-ui/react'
import { useMemo, useState } from 'react'
import { TerminalWindow } from '../../components/ui/TerminalWindow'
import { simulatePathTraversal } from '../../utils/simulators/pathTraversalSimulator'
import { CodeBlock } from '../../components/ui/CodeBlock'
import { FindingsList } from '../../components/ui/FindingsList'
import { payloadLibrary } from '../../data/payloadLibrary'
import { useLabStore } from '../../store/labStore'
import { useI18n } from '../../i18n'
import { useToast } from '@chakra-ui/react'

export function PathTraversalLab() {
  const { t, locale } = useI18n()
  const toast = useToast()
  const { logResult } = useLabStore()
  const pathPresets = useMemo(() => payloadLibrary.filter((p) => p.type === 'path'), [])
  const [input, setInput] = useState('../../etc/passwd')
  const [result, setResult] = useState(() => simulatePathTraversal(input, locale))
  const [lastRunAt, setLastRunAt] = useState<string | null>(null)

  const run = () => {
    const next = simulatePathTraversal(input, locale)
    setResult(next)
    setLastRunAt(new Date().toLocaleTimeString(locale === 'ru' ? 'ru-RU' : 'en-US'))
    logResult('Path Traversal', input, next, next.riskScore)
    toast({ title: t('common.executed'), description: next.technique, status: 'info' })
  }

  return (
    <SimpleGrid columns={{ base: 1, xl: 3 }} spacing={4} sx={{ "&> *": { minW: 0 } }}>
      <TerminalWindow title={t('lab.section.pathInput')}>
        <VStack align="stretch" spacing={4}>
          <Text fontSize="sm" color="whiteAlpha.700">
            {t('common.localDisclaimer')}
          </Text>
          <Select placeholder={locale === 'ru' ? 'выбрать payload-пресет…' : 'pick payload preset…'} onChange={(e) => e.target.value && setInput(e.target.value)}>
            {pathPresets.map((item) => (
              <option key={item.id} value={item.payload}>
                {item.title}
              </option>
            ))}
          </Select>
          <Input value={input} onChange={(event) => setInput(event.target.value)} fontFamily="mono" />
          <Button variant="terminal" onClick={run}>{t('lab.path.normalize')}</Button>
          {lastRunAt && <Text color="brand.300">{t('common.runAt')}: {lastRunAt}</Text>}
          <HStack flexWrap="wrap">
            {result.encodedVariants.map((variant) => (
              <Text key={variant} px={2} py={1} borderRadius="full" bg="rgba(255,255,255,0.04)" fontFamily="mono" fontSize="xs">
                {variant}
              </Text>
            ))}
          </HStack>
        </VStack>
      </TerminalWindow>
      <TerminalWindow title={t('lab.section.normalized')}>
        <VStack align="stretch" spacing={4}>
          <Text fontFamily="mono" color="brand.300">
            {result.normalized}
          </Text>
          <Text fontSize="sm" color={result.escaped ? 'danger.500' : 'brand.300'}>
            {result.escaped ? (locale === 'ru' ? 'выход за пределы sandbox' : 'sandbox escape') : (locale === 'ru' ? 'внутри sandbox' : 'inside sandbox')}
          </Text>
          <Text>{result.summary}</Text>
        </VStack>
      </TerminalWindow>
      <TerminalWindow title={t('lab.section.fileOutput')}>
        <VStack align="stretch" spacing={3}>
          <CodeBlock language="text" code={result.body} />
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
