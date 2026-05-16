import { Box, HStack, Input, Select, SimpleGrid, Text, VStack } from '@chakra-ui/react'
import { motion } from 'framer-motion'
import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { CvssGauge } from '../../components/ui/CvssGauge'
import { SeverityBadge } from '../../components/ui/SeverityBadge'
import { vulnerabilities } from '../../data/vulnerabilities'
import { useI18n } from '../../i18n'
import { localizeExploitComplexity, localizeVulnerability } from '../../localization'

const MotionBox = motion(Box)

export default function VulnerabilitiesPage() {
  const { t, locale } = useI18n()
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [sort, setSort] = useState('cvss')

  const filtered = useMemo(() => {
    const localizedVulnerabilities = vulnerabilities.map((item) => localizeVulnerability(item, locale))
    const next = localizedVulnerabilities.filter((item) => {
      const matchesQuery = `${item.name} ${item.cwe} ${item.category}`.toLowerCase().includes(query.toLowerCase())
      const matchesSeverity = severity === 'all' || item.severity === severity
      return matchesQuery && matchesSeverity
    })

    return next.sort((left, right) => {
      if (sort === 'name') {
        return left.name.localeCompare(right.name)
      }
      if (sort === 'owasp') {
        return left.owaspRank - right.owaspRank
      }
      return right.cvss - left.cvss
    })
  }, [query, severity, sort, locale])

  return (
    <VStack align="stretch" spacing={6}>
      <Box>
        <Text fontFamily="heading" color="brand.300" mb={2}>
          {t('vulnerabilities.title')}
        </Text>
        <Text color="whiteAlpha.700">{t('vulnerabilities.subtitle')}</Text>
      </Box>
      <HStack flexWrap="wrap" spacing={4}>
        <Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t('vulnerabilities.search')} maxW="360px" minW="200px" />
        <Select value={severity} onChange={(event) => setSeverity(event.target.value)} maxW={{ base: '100%', md: '220px' }} minW="160px">
          <option value="all">{t('vulnerabilities.allSeverities')}</option>
          <option value="critical">{t('severity.critical')}</option>
          <option value="high">{t('severity.high')}</option>
          <option value="medium">{t('severity.medium')}</option>
          <option value="low">{t('severity.low')}</option>
        </Select>
        <Select value={sort} onChange={(event) => setSort(event.target.value)} maxW={{ base: '100%', md: '200px' }} minW="140px">
          <option value="cvss">{t('vulnerabilities.sort.cvss')}</option>
          <option value="name">{t('vulnerabilities.sort.name')}</option>
          <option value="owasp">{t('vulnerabilities.sort.owasp')}</option>
        </Select>
      </HStack>
      <SimpleGrid columns={{ base: 1, md: 2, xl: 3 }} spacing={6} sx={{ '& > *': { minW: 0 } }}>
        {filtered.map((item, index) => (
          <MotionBox
            key={item.id}
            as={Link}
            to={`/vulnerabilities/${item.id}`}
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.05 }}
            borderRadius="2xl"
            perspective="1200px"
            minW={0}
          >
            <Box
              position="relative"
              p={6}
              minH="320px"
              minW={0}
              overflow="hidden"
              borderRadius="2xl"
              border="1px solid rgba(0,255,178,0.08)"
              bg="rgba(255,255,255,0.03)"
              style={{ transformStyle: 'preserve-3d' }}
              transition="transform 0.4s ease"
              _hover={{ transform: 'rotateY(8deg) translateY(-4px)' }}
            >
              <Box position="absolute" top={0} left={0} right={0} h="4px" bg={item.severity === 'critical' ? '#FF3864' : item.severity === 'high' ? '#ff7b7b' : item.severity === 'medium' ? '#FFB800' : '#00FFB2'} />
              <HStack justify="space-between" align="flex-start" gap={2}>
                <VStack align="stretch" spacing={1} minW={0} flex="1 1 auto">
                  <Text fontFamily="heading" color="brand.300">
                    {item.owaspId}
                  </Text>
                  <Text fontSize="xs" color="whiteAlpha.600">
                    {item.cwe}
                  </Text>
                </VStack>
                <Box flexShrink={0}>
                  <CvssGauge value={item.cvss} size={84} />
                </Box>
              </HStack>
              <Text mt={4} fontSize="xl" fontWeight="700" wordBreak="break-word">
                {item.name}
              </Text>
              <Text mt={3} color="whiteAlpha.750" noOfLines={4} wordBreak="break-word">
                {item.shortDescription}
              </Text>
              <HStack mt={4} justify="space-between" align="center" flexWrap="wrap" gap={2}>
                <SeverityBadge severity={item.severity} />
                <Text fontSize="sm" color="whiteAlpha.700">
                  {t('vulnerabilities.exploitComplexity')}: {localizeExploitComplexity(item.exploitComplexity, locale)}
                </Text>
              </HStack>
              <Box mt={6} pt={4} borderTop="1px solid rgba(255,255,255,0.05)">
                <Text fontSize="sm" color="whiteAlpha.600" wordBreak="break-word">
                  {t('vulnerabilities.cveExamples')}: {item.cveExamples.map((entry) => entry.id).join(', ')}
                </Text>
              </Box>
            </Box>
          </MotionBox>
        ))}
      </SimpleGrid>
    </VStack>
  )
}
