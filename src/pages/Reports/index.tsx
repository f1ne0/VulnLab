import { Box, Button, Heading, HStack, SimpleGrid, Table, Tbody, Td, Text, Th, Thead, Tr, VStack } from '@chakra-ui/react'
import dayjs from 'dayjs'
import { useLabStore } from '../../store/labStore'
import { useI18n } from '../../i18n'

export default function ReportsPage() {
  const { t, locale } = useI18n()
  const sessions = useLabStore((state) => state.sessions)

  const localizeVulnType = (value: string) => {
    if (locale !== 'ru') return value

    const map: Record<string, string> = {
      'SQL Injection': 'SQL-инъекция',
      'Path Traversal': 'Обход директорий',
      Headers: 'Заголовки'
    }

    return map[value] ?? value
  }

  return (
    <VStack align="stretch" spacing={6}>
      <HStack justify="space-between" flexWrap="wrap">
        <Heading>{t('reports.title')}</Heading>
        <Button variant="terminal" onClick={() => window.print()}>
          {t('reports.print')}
        </Button>
      </HStack>
      <SimpleGrid columns={{ base: 1, xl: 2 }} spacing={6} alignItems="start" sx={{ '& > *': { minW: 0 } }}>
        <Box
          p={6}
          borderRadius="2xl"
          bg="rgba(255,255,255,0.03)"
          color="white"
          border="1px solid rgba(0,255,178,0.08)"
          className="print-report"
        >
          <Heading size="md">{t('reports.paper')}</Heading>
          <Text mt={3}>Тема: Анализ и моделирование уязвимостей веб‑приложений с оценкой правовых последствий их эксплуатации</Text>
          <Text mt={2}>{t('reports.summary')}</Text>
          <Box overflowX="auto" mt={4} maxW="100%">
            <Table size="sm">
              <Thead>
                <Tr>
                  <Th>{t('reports.timestamp')}</Th>
                  <Th>{t('reports.vulnerability')}</Th>
                  <Th>{t('reports.risk')}</Th>
                </Tr>
              </Thead>
              <Tbody>
                {sessions.slice(0, 8).map((session) => (
                  <Tr key={session.id}>
                    <Td whiteSpace="nowrap">{dayjs(session.timestamp).format('YYYY-MM-DD HH:mm')}</Td>
                    <Td wordBreak="break-word">{localizeVulnType(session.vulnType)}</Td>
                    <Td>{session.riskScore}</Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </Box>
          <Text mt={4}>{t('reports.notice')}</Text>
        </Box>
        <Box p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
          <Heading size="md" mb={4}>
            {t('reports.sessions')}
          </Heading>
          <VStack align="stretch" spacing={3}>
            {sessions.length === 0 ? (
              <Text color="whiteAlpha.700">{t('reports.empty')}</Text>
            ) : (
              sessions.map((session) => (
                <Box key={session.id} p={4} borderRadius="xl" bg="rgba(255,255,255,0.02)" minW={0} overflow="hidden">
                  <Text fontFamily="heading" color="brand.300" wordBreak="break-word">
                    {localizeVulnType(session.vulnType)}
                  </Text>
                  <Text fontSize="sm">{dayjs(session.timestamp).format('YYYY-MM-DD HH:mm:ss')}</Text>
                  <Text fontSize="sm" wordBreak="break-all" fontFamily="mono">
                    {t('reports.payloads')}: {session.payloadsUsed.join(' | ')}
                  </Text>
                  <Text fontSize="sm" color="warning.500">
                    {t('reports.riskScore')}: {session.riskScore}
                  </Text>
                </Box>
              ))
            )}
          </VStack>
        </Box>
      </SimpleGrid>
    </VStack>
  )
}
