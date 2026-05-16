import { Button, FormControl, FormLabel, HStack, Input, Select, SimpleGrid, Switch, Text, VStack } from '@chakra-ui/react'
import { useState } from 'react'
import { TerminalWindow } from '../../components/ui/TerminalWindow'
import { FindingsList } from '../../components/ui/FindingsList'
import { validateCsrfToken, generateCsrfAttack } from '../../utils/simulators/csrfSimulator'
import type { CsrfDefences } from '../../utils/simulators/csrfSimulator'
import { CodeBlock } from '../../components/ui/CodeBlock'
import { useLabStore } from '../../store/labStore'
import { useI18n } from '../../i18n'
import { useToast } from '@chakra-ui/react'

export function CSRFLab() {
  const { t, locale } = useI18n()
  const toast = useToast()
  const { logResult } = useLabStore()
  const [action, setAction] = useState('/bank/transfer')
  const [amount, setAmount] = useState('15000')
  const [token, setToken] = useState('9f85d9738c7b4ac8a580d4f845cb1f55')
  const [def, setDef] = useState<CsrfDefences>({
    sameSite: 'None',
    tokenCheck: false,
    originCheck: false,
    doubleSubmit: false,
    customHeader: false,
    method: 'POST'
  })
  const [result, setResult] = useState(() => generateCsrfAttack(action, amount, def, locale, token))
  const [lastRunAt, setLastRunAt] = useState<string | null>(null)

  const run = () => {
    const next = generateCsrfAttack(action, amount, def, locale, token)
    setResult(next)
    setLastRunAt(new Date().toLocaleTimeString(locale === 'ru' ? 'ru-RU' : 'en-US'))
    logResult('CSRF', `${action} ${amount}`, next, next.riskScore)
    toast({ title: t('common.executed'), description: next.technique, status: 'info' })
  }

  const updateDef = <K extends keyof CsrfDefences>(key: K, value: CsrfDefences[K]) => {
    setDef((prev) => ({ ...prev, [key]: value }))
  }

  return (
    <SimpleGrid columns={{ base: 1, xl: 3 }} spacing={4} sx={{ "&> *": { minW: 0 } }}>
      <TerminalWindow title={t('lab.section.form')}>
        <VStack align="stretch" spacing={3}>
          <Text fontSize="sm" color="whiteAlpha.700">
            {t('common.localDisclaimer')}
          </Text>
          <FormControl>
            <FormLabel>{t('lab.csrf.action')}</FormLabel>
            <Input value={action} onChange={(event) => setAction(event.target.value)} />
          </FormControl>
          <FormControl>
            <FormLabel>{t('lab.csrf.amount')}</FormLabel>
            <Input value={amount} onChange={(event) => setAmount(event.target.value)} />
          </FormControl>
          <HStack>
            <FormControl>
              <FormLabel>method</FormLabel>
              <Select value={def.method} onChange={(e) => updateDef('method', e.target.value as 'GET' | 'POST')}>
                <option value="POST">POST</option>
                <option value="GET">GET</option>
              </Select>
            </FormControl>
            <FormControl>
              <FormLabel>SameSite</FormLabel>
              <Select value={def.sameSite} onChange={(e) => updateDef('sameSite', e.target.value as CsrfDefences['sameSite'])}>
                <option value="None">None</option>
                <option value="Lax">Lax</option>
                <option value="Strict">Strict</option>
              </Select>
            </FormControl>
          </HStack>
          <FormControl display="flex" alignItems="center" gap={3}>
            <FormLabel m={0}>token check</FormLabel>
            <Switch isChecked={def.tokenCheck} onChange={(e) => updateDef('tokenCheck', e.target.checked)} />
          </FormControl>
          <FormControl display="flex" alignItems="center" gap={3}>
            <FormLabel m={0}>Origin check</FormLabel>
            <Switch isChecked={def.originCheck} onChange={(e) => updateDef('originCheck', e.target.checked)} />
          </FormControl>
          <FormControl display="flex" alignItems="center" gap={3}>
            <FormLabel m={0}>double-submit</FormLabel>
            <Switch isChecked={def.doubleSubmit} onChange={(e) => updateDef('doubleSubmit', e.target.checked)} />
          </FormControl>
          <FormControl display="flex" alignItems="center" gap={3}>
            <FormLabel m={0}>custom header</FormLabel>
            <Switch isChecked={def.customHeader} onChange={(e) => updateDef('customHeader', e.target.checked)} />
          </FormControl>
          <FormControl>
            <FormLabel>{t('lab.csrf.token')}</FormLabel>
            <Input value={token} onChange={(event) => setToken(event.target.value)} fontFamily="mono" />
          </FormControl>
          <Text color={validateCsrfToken(token) ? 'brand.300' : 'danger.500'} fontSize="sm">
            {t('lab.csrf.tokenValidity')}: {validateCsrfToken(token) ? t('lab.csrf.valid') : t('lab.csrf.invalid')} · entropy ≈ {result.tokenEntropy} bit
          </Text>
          <Button variant="terminal" onClick={run}>
            {t('lab.csrf.generate')}
          </Button>
          {lastRunAt && <Text color="brand.300">{t('common.runAt')}: {lastRunAt}</Text>}
        </VStack>
      </TerminalWindow>
      <TerminalWindow title={t('lab.section.html')}>
        <CodeBlock language="html" code={result.html} />
      </TerminalWindow>
      <TerminalWindow title={t('lab.section.analysis')}>
        <VStack align="stretch" spacing={4}>
          <Text fontFamily="heading" color="brand.300">
            {t('common.detectedTechnique')}: {result.technique}
          </Text>
          <Text>{result.summary}</Text>
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
