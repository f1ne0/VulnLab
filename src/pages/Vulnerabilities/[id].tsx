import { Box, Button, Checkbox, HStack, Heading, Link as ChakraLink, SimpleGrid, Tab, TabList, TabPanel, TabPanels, Tabs, Text, VStack } from '@chakra-ui/react'
import { useMemo } from 'react'
import { Link as RouterLink, useParams } from 'react-router-dom'
import { AttackFlow } from '../../components/ui/AttackFlow'
import { CodeBlock } from '../../components/ui/CodeBlock'
import { CvssGauge } from '../../components/ui/CvssGauge'
import { LegalCard } from '../../components/ui/LegalCard'
import { RadarChart } from '../../components/charts/RadarChart'
import { jurisdictionProfiles } from '../../data/legal'
import { vulnerabilities } from '../../data/vulnerabilities'
import { useLocalStorage } from '../../hooks/useLocalStorage'
import { useI18n } from '../../i18n'
import { localizeVulnerability } from '../../localization'

export default function VulnerabilityDetailPage() {
  const { t, locale } = useI18n()
  const { id } = useParams()
  const vulnerability = localizeVulnerability(vulnerabilities.find((item) => item.id === id) ?? vulnerabilities[0], locale)
  const [checklist, setChecklist] = useLocalStorage<Record<string, boolean>>(`checklist:${vulnerability.id}`, {})

  const radarValues = useMemo(() => [vulnerability.cvss, vulnerability.prevalence / 10, vulnerability.detectionDifficulty / 10, vulnerability.exploitComplexity === 'Low' ? 8 : vulnerability.exploitComplexity === 'Medium' ? 6 : 4, 8], [vulnerability])

  return (
    <VStack align="stretch" spacing={6}>
      <SimpleGrid columns={{ base: 1, xl: 3 }} spacing={6} sx={{ '& > *': { minW: 0 } }}>
        <Box gridColumn={{ xl: 'span 2' }} p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)" minW={0}>
          <Text fontFamily="heading" color="brand.300">
            {vulnerability.owaspId} / {vulnerability.cwe}
          </Text>
          <Heading mt={2}>{vulnerability.name}</Heading>
          <Text mt={4} color="whiteAlpha.800">
            {vulnerability.overview}
          </Text>
        </Box>
        <Box p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)" minW={0} overflow="hidden">
          <CvssGauge value={vulnerability.cvss} size={120} />
          <Text mt={4} fontFamily="heading" color="brand.300" fontSize="xs" wordBreak="break-all">
            {vulnerability.cvssVector}
          </Text>
          <Text mt={2} color="warning.500" wordBreak="break-word">
            {t('detail.timeToFix')}: {vulnerability.timeToFix}
          </Text>
        </Box>
      </SimpleGrid>

      <Tabs variant="enclosed" isLazy>
        <TabList overflowX="auto">
          <Tab>Обзор</Tab>
          <Tab>Механизм атаки</Tab>
          <Tab>Лаборатория</Tab>
          <Tab>Правовой анализ</Tab>
          <Tab>Митигация</Tab>
          <Tab>Ресурсы</Tab>
        </TabList>
        <TabPanels pt={4}>
          <TabPanel px={0}>
            <SimpleGrid columns={{ base: 1, xl: 2 }} spacing={6} alignItems="start" sx={{ "&> *": { minW: 0 } }}>
              <Box p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
                <Heading size="md" mb={4}>
                  {t('detail.overview')}
                </Heading>
                <Text color="whiteAlpha.800">{vulnerability.attackMechanism}</Text>
                <Text mt={4}>{t('detail.affectedPlatforms')}: {vulnerability.affectedPlatforms.join(', ')}</Text>
                <Text mt={4}>{t('vulnerabilities.cveExamples')}: {vulnerability.cveExamples.map((entry) => `${entry.id} (${entry.year})`).join(', ')}</Text>
              </Box>
              <Box p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
                <Heading size="md" mb={4}>
                  {t('detail.cvssProfile')}
                </Heading>
                <RadarChart labels={locale === 'ru' ? ['Влияние', 'Распространённость', 'Обнаружение', 'Эксплуатируемость', 'Правовой риск'] : ['Impact', 'Prevalence', 'Detection', 'Exploitability', 'Legal risk']} values={radarValues} locale={locale} />
              </Box>
            </SimpleGrid>
          </TabPanel>
          <TabPanel px={0}>
            <SimpleGrid columns={{ base: 1, xl: 2 }} spacing={6} alignItems="start" sx={{ "&> *": { minW: 0 } }}>
              <Box p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
                <Heading size="md" mb={4}>
                  {t('detail.attackFlow')}
                </Heading>
                <AttackFlow steps={vulnerability.attackSteps} />
              </Box>
              <VStack align="stretch" spacing={6}>
                <Box p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
                  <Heading size="md" mb={3}>
                    {t('detail.attackerMindset')}
                  </Heading>
                  <Text color="whiteAlpha.800">{vulnerability.attackerMindset}</Text>
                </Box>
                <Box p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
                  <Heading size="md" mb={3}>
                    {t('detail.defenderMindset')}
                  </Heading>
                  <Text color="whiteAlpha.800">{vulnerability.defenderMindset}</Text>
                </Box>
              </VStack>
            </SimpleGrid>
          </TabPanel>
          <TabPanel px={0}>
            <Box p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
              <Text color="whiteAlpha.800" mb={4}>
                Deep link to the lab with the selected vulnerability context.
              </Text>
              <Button as={RouterLink} to="/lab" variant="terminal">
                {t('vulnerabilities.testInLab')}
              </Button>
            </Box>
          </TabPanel>
          <TabPanel px={0}>
            <SimpleGrid columns={{ base: 1, md: 2, xl: 4 }} spacing={6} alignItems="start" sx={{ '& > *': { minW: 0 } }}>
              {jurisdictionProfiles.map((profile) => (
                <LegalCard key={profile.id} profile={profile} />
              ))}
            </SimpleGrid>
          </TabPanel>
          <TabPanel px={0}>
            <SimpleGrid columns={{ base: 1, xl: 2 }} spacing={6} alignItems="start" sx={{ "&> *": { minW: 0 } }}>
              <VStack align="stretch" spacing={4} p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
                <Heading size="md">{t('detail.codeDiff')}</Heading>
                <Text color="danger.500">{t('detail.vulnerable')}</Text>
                <CodeBlock language={vulnerability.codeExample.language} code={vulnerability.codeExample.vulnerable} />
                <Text color="brand.300">{t('detail.secure')}</Text>
                <CodeBlock language={vulnerability.codeExample.language} code={vulnerability.codeExample.secure} />
              </VStack>
              <VStack align="stretch" spacing={4} p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
                <Heading size="md">{t('detail.fixChecklist')}</Heading>
                {vulnerability.mitigationChecklist.map((item) => (
                  <Checkbox
                    key={item}
                    isChecked={Boolean(checklist[item])}
                    onChange={(event) => setChecklist({ ...checklist, [item]: event.target.checked })}
                  >
                    {item}
                  </Checkbox>
                ))}
              </VStack>
            </SimpleGrid>
          </TabPanel>
          <TabPanel px={0}>
            <VStack align="stretch" spacing={4}>
              {vulnerability.resources.map((resource) => (
                <Box key={resource.url} p={5} borderRadius="xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)" minW={0} overflow="hidden">
                  <ChakraLink href={resource.url} isExternal color="brand.300" fontFamily="heading" wordBreak="break-word">
                    {resource.label}
                  </ChakraLink>
                  <Text fontSize="xs" color="whiteAlpha.600" mt={1} wordBreak="break-all">{resource.url}</Text>
                </Box>
              ))}
            </VStack>
          </TabPanel>
        </TabPanels>
      </Tabs>
    </VStack>
  )
}
