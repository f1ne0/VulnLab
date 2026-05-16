import { Box, Heading, Select, SimpleGrid, Text, VStack } from '@chakra-ui/react'
import { useMemo, useState } from 'react'
import { LegalCard } from '../../components/ui/LegalCard'
import { legalReferencesByAttack, localizeJurisdictionProfiles, localizeLegalReferencesByAttack } from '../../data/legal'
import { useI18n } from '../../i18n'

const scenarios = [
  { id: 'unauthorized access', label: 'Unauthorized access', attack: 'sqli' },
  { id: 'ddos', label: 'DDoS', attack: 'sqli' },
  { id: 'data theft', label: 'Data theft', attack: 'xss' },
  { id: 'selling exploits', label: 'Selling exploits', attack: 'jwt' },
  { id: 'bug bounty gone wrong', label: 'Bug bounty gone wrong', attack: 'sqli' }
]

const jurisdictions = ['RU', 'UZ', 'US', 'EU'] as const

export default function LegalPage() {
  const { t, locale } = useI18n()
  const localizedProfiles = useMemo(() => localizeJurisdictionProfiles(locale), [locale])
  const localizedReferences = useMemo(() => localizeLegalReferencesByAttack(locale), [locale])
  const localizedScenarios =
    locale === 'ru'
      ? [
          { id: 'unauthorized access', label: 'Несанкционированный доступ', attack: 'sqli' },
          { id: 'ddos', label: 'DDoS-атака', attack: 'sqli' },
          { id: 'data theft', label: 'Кража данных', attack: 'xss' },
          { id: 'selling exploits', label: 'Продажа эксплойтов', attack: 'jwt' },
          { id: 'bug bounty gone wrong', label: 'Нарушение условий bug bounty из-за выхода за разрешённый периметр', attack: 'sqli' }
        ]
      : scenarios
  const localizedAttackTypes =
    locale === 'ru'
      ? {
          sqli: 'SQL-инъекция',
          xss: 'XSS',
          jwt: 'JWT'
        }
      : {
          sqli: 'SQL Injection',
          xss: 'XSS',
          jwt: 'JWT'
        }
  const [attackType, setAttackType] = useState<keyof typeof legalReferencesByAttack>('sqli')
  const [scenario, setScenario] = useState(localizedScenarios[0].id)
  const [jurisdiction, setJurisdiction] = useState<(typeof jurisdictions)[number]>('RU')

  const scenarioResult = useMemo(() => {
    const reference = localizedReferences[attackType].find((item) => item.jurisdiction === jurisdiction)
    return reference
  }, [attackType, jurisdiction, localizedReferences])

  return (
    <VStack align="stretch" spacing={6}>
      <Heading>{t('legal.title')}</Heading>
      <SimpleGrid columns={{ base: 1, md: 2, xl: 4 }} spacing={6} alignItems="start" sx={{ '& > *': { minW: 0 } }}>
        {localizedProfiles.map((profile) => (
          <LegalCard key={profile.id} profile={profile} />
        ))}
      </SimpleGrid>

      <SimpleGrid columns={{ base: 1, xl: 2 }} spacing={6} alignItems="start" sx={{ "&> *": { minW: 0 } }}>
        <VStack align="stretch" spacing={4} p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
          <Heading size="md">{t('legal.scenarioTitle')}</Heading>
          <Select value={scenario} onChange={(event) => setScenario(event.target.value)}>
            {localizedScenarios.map((item) => (
              <option key={item.id} value={item.id}>
                {item.label}
              </option>
            ))}
          </Select>
          <Select value={attackType} onChange={(event) => setAttackType(event.target.value as keyof typeof legalReferencesByAttack)}>
            {Object.keys(localizedReferences).map((key) => (
              <option key={key} value={key}>
                {localizedAttackTypes[key as keyof typeof localizedAttackTypes] ?? key}
              </option>
            ))}
          </Select>
          <Select value={jurisdiction} onChange={(event) => setJurisdiction(event.target.value as (typeof jurisdictions)[number])}>
            {jurisdictions.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </Select>
          {scenarioResult && (
            <Box p={5} borderRadius="xl" bg="rgba(255,255,255,0.02)">
              <Text fontFamily="heading" color="brand.300">
                {scenarioResult.article}
              </Text>
              <Text mt={2}>{scenarioResult.summary}</Text>
              <Text mt={3} color="warning.500">
                {t('legal.exposure')}: {scenarioResult.maxPenalty}
              </Text>
              <Text mt={2}>{t('legal.precedent')}: {scenarioResult.caseReference}</Text>
              <Text mt={4} color={jurisdiction === 'RU' || jurisdiction === 'UZ' ? 'danger.500' : 'warning.500'}>
                {t('legal.verdict')}: {t('legal.verdictValue')}
              </Text>
            </Box>
          )}
        </VStack>

        <VStack align="stretch" spacing={4} p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
          <Heading size="md">{t('legal.timelineTitle')}</Heading>
          {[
            locale === 'ru'
              ? ['Обнаружение', 'Исследователь подтверждает проблему в контролируемой среде.']
              : ['Discovery', 'Researcher validates the issue in a controlled environment.'],
            locale === 'ru'
              ? ['Приватный отчёт', 'Проблема передаётся владельцу платформы или вендору без публичного раскрытия.']
              : ['Private report', 'Issue is disclosed to the vendor or platform owner privately.'],
            locale === 'ru'
              ? ['Подтверждение получения', 'Владелец подтверждает получение и начинает первичный разбор инцидента.']
              : ['Vendor acknowledgment', 'Owner confirms receipt and begins triage.'],
            locale === 'ru'
              ? ['Разработка исправления', 'Проводится смягчение риска и проверка патча.']
              : ['Fix development', 'Mitigation and patch validation.'],
            locale === 'ru'
              ? ['Публичное раскрытие', 'Публикация после устранения проблемы или истечения согласованного эмбарго.']
              : ['Public disclosure', 'Publication after remediation or agreed embargo.']
          ].map(([title, description], index) => (
            <Box key={title} p={4} borderLeft="3px solid" borderColor={index < 2 ? 'brand.300' : index === 4 ? 'warning.500' : 'whiteAlpha.400'} bg="rgba(255,255,255,0.02)">
              <Text fontFamily="heading">{title}</Text>
              <Text color="whiteAlpha.750">{description}</Text>
            </Box>
          ))}
          <Text color="whiteAlpha.700">
            {t('legal.timeline.note')}
          </Text>
        </VStack>
      </SimpleGrid>

      <Box p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
        <Heading size="md" mb={4}>
          {t('legal.quizTitle')}
        </Heading>
        <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
          {((locale === 'ru'
            ? [
                'Исследователь использует найденный SQLi против рабочего сайта без уведомления.',
                'Студент тестирует учебный стенд преподавателя с разрешением.',
                'Разработчик выгружает данные пользователей для доказательства XSS без санкции.',
                'Участник bug bounty выходит за согласованный периметр и затрагивает соседний субдомен.'
              ]
            : [
                'A researcher uses a discovered SQLi against a production site without notice.',
                'A student tests an instructor sandbox with permission.',
                'A developer exports user data to prove XSS without authorization.',
                'A bug bounty participant exceeds the agreed scope and touches a neighboring subdomain.'
              ]
          )).map((question, index) => (
            <Box key={question} p={4} borderRadius="xl" bg="rgba(255,255,255,0.02)">
              <Text fontFamily="heading" color="brand.300">
                Q{index + 1}
              </Text>
              <Text mt={2}>{question}</Text>
              <Text mt={3} color="warning.500">
                {t('legal.quizExplanation')}
              </Text>
            </Box>
          ))}
        </SimpleGrid>
      </Box>
    </VStack>
  )
}
