import { Box, Button, Heading, HStack, SimpleGrid, Text, VStack } from '@chakra-ui/react'
import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { TrendLine } from '../../components/charts/TrendLine'
import { owaspTop10 } from '../../data/owaspTop10'
import { useI18n } from '../../i18n'
import { localizeOwaspItem } from '../../localization'

export default function OwaspPage() {
  const { t, locale } = useI18n()
  const [year, setYear] = useState<'2017' | '2021'>('2021')
  const items = owaspTop10[year].map((item) => localizeOwaspItem(item, year, locale))

  const trendLabels = useMemo(() => owaspTop10['2021'].map((item) => item.id), [])
  const data2017 = useMemo(() => owaspTop10['2021'].map((item) => item.rank2017 ?? 10), [])
  const data2021 = useMemo(() => owaspTop10['2021'].map((item) => item.rank2021), [])

  return (
    <VStack align="stretch" spacing={6}>
      <HStack justify="space-between" flexWrap="wrap">
        <Heading>{t('owasp.title')}</Heading>
        <HStack>
          <Button variant={year === '2017' ? 'terminal' : 'ghost'} onClick={() => setYear('2017')}>
            2017
          </Button>
          <Button variant={year === '2021' ? 'terminal' : 'ghost'} onClick={() => setYear('2021')}>
            2021
          </Button>
        </HStack>
      </HStack>

      <SimpleGrid columns={{ base: 1, xl: 2 }} spacing={6} alignItems="start" sx={{ "&> *": { minW: 0 } }}>
        <Box p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
          <Heading size="md" mb={4}>
            {t('owasp.trendTitle')}
          </Heading>
          <TrendLine labels={trendLabels} data2017={data2017} data2021={data2021} />
        </Box>
        <Box p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
          <Heading size="md" mb={4}>
            {t('owasp.heatmapTitle')}
          </Heading>
          <SimpleGrid columns={3} spacing={2} sx={{ "& > *": { minW: 0 } }}>
            {(locale === 'ru'
              ? ['Финансы', 'Ритейл', 'Госсектор', 'SaaS', 'Здравоохранение', 'Образование', 'Облако', 'Медиа', 'Промышленность']
              : ['Finance', 'Retail', 'Gov', 'SaaS', 'Healthcare', 'Education', 'Cloud', 'Media', 'Industrial']
            ).map((industry, index) => (
              <Box key={industry} p={3} borderRadius="lg" bg={`rgba(0,255,178,${0.05 + (index % 5) * 0.04})`}>
                <Text fontSize="sm">{industry}</Text>
              </Box>
            ))}
          </SimpleGrid>
        </Box>
      </SimpleGrid>

      <SimpleGrid columns={{ base: 1, xl: 2 }} spacing={6} sx={{ '& > *': { minW: 0 } }}>
        {items.map((item) => (
          <Box key={item.id} p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)" minW={0} overflow="hidden">
            <HStack justify="space-between" align="flex-start" flexWrap="wrap" gap={2}>
              <VStack align="stretch" spacing={2} minW={0} flex="1 1 60%">
                <Text fontFamily="heading" color="brand.300">
                  {item.id}
                </Text>
                <Heading size="md" wordBreak="break-word">{item.title}</Heading>
              </VStack>
              <Text color="warning.500" flexShrink={0}>
                {item.rank2017 ? `${item.rank2017} → ${item.rank2021}` : `${t('owasp.new')} → ${item.rank2021}`}
              </Text>
            </HStack>
            <Text mt={3} color="whiteAlpha.800" wordBreak="break-word">
              {item.description}
            </Text>
            <Text mt={3}>{t('owasp.prevalence')}: {item.prevalence}</Text>
            <Text>{t('owasp.detectionDifficulty')}: {item.detectionDifficulty}</Text>
            <Text color="whiteAlpha.700" wordBreak="break-word">{t('owasp.industries')}: {item.industries.join(', ')}</Text>
            <Button as={Link} to="/lab" variant="terminal" size="sm" mt={4}>
              {t('vulnerabilities.testInLab')}
            </Button>
          </Box>
        ))}
      </SimpleGrid>
    </VStack>
  )
}
