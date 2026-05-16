import { Box, Heading, SimpleGrid, Text, VStack } from '@chakra-ui/react'
import type { JurisdictionProfile } from '../../data/legal'

export function LegalCard({ profile }: { profile: JurisdictionProfile }) {
  return (
    <Box p={5} borderRadius="2xl" border="1px solid rgba(0,255,178,0.1)" bg="rgba(255,255,255,0.03)">
      <Heading size="md" mb={4}>
        {profile.title}
      </Heading>
      <VStack align="stretch" spacing={4}>
        {profile.laws.map((law) => (
          <Box key={law.article} p={4} borderRadius="xl" bg="rgba(255,255,255,0.02)" border="1px solid rgba(255,255,255,0.04)">
            <Text fontFamily="heading" color="brand.300" fontSize="sm">
              {law.article}
            </Text>
            <Text fontWeight="600" mt={1}>
              {law.title}
            </Text>
            <Text color="whiteAlpha.800" mt={2}>
              {law.summary}
            </Text>
            <Text color="warning.500" mt={2} fontSize="sm">
              {law.maxPenalty}
            </Text>
          </Box>
        ))}
      </VStack>
      <SimpleGrid columns={1} spacing={3} mt={5}>
        {profile.notableCases.map((caseItem) => (
          <Box key={caseItem.name} p={4} borderLeft="3px solid" borderColor="danger.500" bg="rgba(255,56,100,0.04)">
            <Text fontFamily="heading" fontSize="sm">
              {caseItem.name} · {caseItem.year}
            </Text>
            <Text color="whiteAlpha.800" mt={1}>
              {caseItem.summary}
            </Text>
          </Box>
        ))}
      </SimpleGrid>
    </Box>
  )
}
