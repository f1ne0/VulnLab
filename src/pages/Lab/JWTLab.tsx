import { Button, HStack, Input, SimpleGrid, Spinner, Text, Textarea, VStack } from '@chakra-ui/react'
import { useEffect, useMemo, useState } from 'react'
import { TerminalWindow } from '../../components/ui/TerminalWindow'
import { FindingsList } from '../../components/ui/FindingsList'
import { analyzeJwt } from '../../utils/simulators/jwtAnalyzer'
import { CodeBlock } from '../../components/ui/CodeBlock'
import { useLabStore } from '../../store/labStore'
import { useI18n } from '../../i18n'
import { useToast } from '@chakra-ui/react'

const samplePrefix =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyZXNlYXJjaGVyIiwicm9sZSI6InVzZXIiLCJpc3MiOiJ2dWxubGFiIiwiYXVkIjoicmVzZWFyY2gtdWkiLCJleHAiOjQxMDAwMDAwMDB9'

async function signWithSecret(data: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data))
  const bytes = new Uint8Array(sig)
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

type Analysis = Awaited<ReturnType<typeof analyzeJwt>>

export function JWTLab() {
  const { t, locale } = useI18n()
  const toast = useToast()
  const { logResult } = useLabStore()
  const [token, setToken] = useState(`${samplePrefix}.signature`)
  const [analysis, setAnalysis] = useState<Analysis | null>(null)
  const [loading, setLoading] = useState(false)
  const [lastRunAt, setLastRunAt] = useState<string | null>(null)
  const [customClaims, setCustomClaims] = useState('{"sub":"analyst","role":"admin","exp":4100000000}')

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    ;(async () => {
      const sig = await signWithSecret(samplePrefix, 'secret')
      const realToken = `${samplePrefix}.${sig}`
      if (cancelled) return
      setToken(realToken)
      const res = await analyzeJwt(realToken, locale)
      if (cancelled) return
      setAnalysis(res)
      setLoading(false)
    })()
    return () => {
      cancelled = true
    }
  }, [])

  const generatedToken = useMemo(() => {
    try {
      const header = { alg: 'HS256', typ: 'JWT' }
      const payload = JSON.parse(customClaims) as Record<string, unknown>
      const encode = (value: object) => btoa(JSON.stringify(value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
      return `${encode(header)}.${encode(payload)}.simulated-signature`
    } catch {
      return locale === 'ru' ? 'Некорректный JSON claims' : 'Invalid JSON claims'
    }
  }, [customClaims, locale])

  const run = async () => {
    setLoading(true)
    const next = await analyzeJwt(token, locale)
    setAnalysis(next)
    setLoading(false)
    setLastRunAt(new Date().toLocaleTimeString(locale === 'ru' ? 'ru-RU' : 'en-US'))
    logResult('JWT', token, next, next.riskScore)
    toast({ title: t('common.executed'), description: next.technique, status: 'info' })
  }

  return (
    <SimpleGrid columns={{ base: 1, xl: 3 }} spacing={4} sx={{ "&> *": { minW: 0 } }}>
      <TerminalWindow title={t('lab.section.token')}>
        <VStack align="stretch" spacing={4}>
          <Text fontSize="sm" color="whiteAlpha.700">
            {t('common.localDisclaimer')}
          </Text>
          <Textarea value={token} onChange={(event) => setToken(event.target.value)} minH="220px" fontFamily="mono" />
          <Button variant="terminal" onClick={run} isDisabled={loading}>
            {loading ? <Spinner size="sm" /> : t('lab.jwt.analyze')}
          </Button>
          {lastRunAt && <Text color="brand.300">{t('common.runAt')}: {lastRunAt}</Text>}
        </VStack>
      </TerminalWindow>
      <TerminalWindow title={t('lab.section.decoded')}>
        <VStack align="stretch" spacing={4}>
          {analysis ? (
            <>
              <HStack justify="space-between">
                <Text fontFamily="heading">alg={analysis.algorithm}</Text>
                <Text color={analysis.expired ? 'danger.500' : 'brand.300'}>{analysis.expired ? t('lab.jwt.expired') : t('lab.jwt.active')}</Text>
              </HStack>
              <CodeBlock language="json" code={JSON.stringify(analysis.header, null, 2)} />
              <CodeBlock language="json" code={JSON.stringify(analysis.payload, null, 2)} />
              {analysis.bruteForceStats && (
                <VStack align="stretch" spacing={1} p={2} bg="rgba(255,0,80,0.08)" borderRadius="md">
                  <Text fontSize="xs" fontFamily="mono" color="whiteAlpha.700">
                    [hashcat-style] mode=HMAC · attempts={analysis.bruteForceStats.attempts} · time={analysis.bruteForceStats.durationMs.toFixed(0)}ms · {analysis.bruteForceStats.rate} H/s
                  </Text>
                  {analysis.bruteForceMatch ? (
                    <Text color="danger.500" fontSize="sm">
                      [CRACKED] secret = «{analysis.bruteForceMatch}» · entropy ≈ {analysis.bruteForceEntropy} bit
                    </Text>
                  ) : (
                    <Text color="brand.300" fontSize="sm">
                      [exhausted] wordlist не дал совпадений — ключ не из top-50
                    </Text>
                  )}
                </VStack>
              )}
              <Text color="warning.500" fontSize="xs">{t('lab.jwt.algDemo')}: {analysis.tamperedToken ?? t('lab.jwt.notAvailable')}</Text>
            </>
          ) : (
            <Spinner />
          )}
        </VStack>
      </TerminalWindow>
      <TerminalWindow title={t('lab.section.generator')}>
        <VStack align="stretch" spacing={4}>
          <Input value={customClaims} onChange={(event) => setCustomClaims(event.target.value)} fontFamily="mono" />
          <CodeBlock language="text" code={generatedToken} />
          {analysis && (
            <FindingsList
              findings={analysis.findings ?? []}
              riskScore={analysis.riskScore}
              cvssVector={analysis.cvssVector}
              riskBreakdown={analysis.riskBreakdown}
              recommendationLabel={t('lab.recommendation')}
              legalLabel={t('lab.legalContext')}
            />
          )}
        </VStack>
      </TerminalWindow>
    </SimpleGrid>
  )
}
