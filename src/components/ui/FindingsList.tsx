import { Badge, Box, Flex, Text, Tooltip, VStack, Wrap, WrapItem } from '@chakra-ui/react'
import type { LabFinding, RiskBreakdown } from '../../types'
import { SeverityBadge } from './SeverityBadge'

interface FindingsListProps {
  findings: LabFinding[]
  riskScore?: number
  cvssVector?: string
  riskBreakdown?: RiskBreakdown
  recommendationLabel: string
  legalLabel: string
}

export function FindingsList({ findings, riskScore, cvssVector, riskBreakdown, recommendationLabel, legalLabel }: FindingsListProps) {
  return (
    <VStack align="stretch" spacing={3} minW={0}>
      {(riskScore !== undefined || cvssVector) && (
        <Flex gap={2} flexWrap="wrap" align="center" justify="space-between" minW={0}>
          {riskScore !== undefined && (
            <Badge colorScheme={riskScore >= 80 ? 'red' : riskScore >= 60 ? 'orange' : riskScore >= 30 ? 'yellow' : 'green'} fontSize="md" px={3} py={1} flexShrink={0}>
              risk {riskScore}/100
            </Badge>
          )}
          {cvssVector && (
            <Tooltip label={riskBreakdown ? `EXP ${riskBreakdown.exploitability} / IMP ${riskBreakdown.impact}` : cvssVector}>
              <Text fontSize="xs" fontFamily="mono" color="whiteAlpha.700" cursor="help" wordBreak="break-all" minW={0} flex="1 1 auto" textAlign={{ base: 'left', md: 'right' }}>
                {cvssVector}
              </Text>
            </Tooltip>
          )}
        </Flex>
      )}
      {findings.map((finding, idx) => (
        <Box key={`${finding.title}-${idx}`} p={3} bg="rgba(255,255,255,0.02)" borderRadius="lg" borderWidth="1px" borderColor="rgba(255,255,255,0.04)" minW={0} overflow="hidden">
          <Flex gap={2} flexWrap="wrap" align="flex-start" justify="space-between" mb={2}>
            <Text fontFamily="heading" flex="1 1 60%" minW={0} wordBreak="break-word">
              {finding.title}
            </Text>
            <Wrap spacing={1} flexShrink={0}>
              {finding.cwe && (
                <WrapItem>
                  <Badge variant="outline" fontSize="xs">
                    {finding.cwe}
                  </Badge>
                </WrapItem>
              )}
              <WrapItem>
                <SeverityBadge severity={finding.severity} />
              </WrapItem>
            </Wrap>
          </Flex>
          <Text fontSize="sm" wordBreak="break-word">{finding.description}</Text>
          {finding.evidence && (
            <Text fontSize="xs" fontFamily="mono" color="warning.500" wordBreak="break-all" mt={1}>
              evidence: {finding.evidence}
            </Text>
          )}
          <Text fontSize="sm" color="brand.300" wordBreak="break-word" mt={1}>
            {recommendationLabel}: {finding.recommendation}
          </Text>
          {finding.legalContext && finding.legalContext !== '—' && (
            <Text fontSize="xs" color="whiteAlpha.700" wordBreak="break-word" mt={1}>
              {legalLabel}: {finding.legalContext}
            </Text>
          )}
        </Box>
      ))}
    </VStack>
  )
}
