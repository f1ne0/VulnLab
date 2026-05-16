import { Box, Flex, HStack, Text } from '@chakra-ui/react'
import type { PropsWithChildren } from 'react'

export function TerminalWindow({ title, children }: PropsWithChildren<{ title: string }>) {
  return (
    <Box borderRadius="2xl" overflow="hidden" border="1px solid rgba(0,255,178,0.12)" bg="rgba(6,9,16,0.9)" boxShadow="0 30px 90px rgba(0,0,0,0.35)" minW={0} maxW="100%">
      <Flex px={4} py={3} bg="rgba(255,255,255,0.03)" align="center" justify="space-between" borderBottom="1px solid rgba(0,255,178,0.08)" gap={2}>
        <HStack spacing={2} flexShrink={0}>
          <Box w={2.5} h={2.5} borderRadius="full" bg="#FF3864" />
          <Box w={2.5} h={2.5} borderRadius="full" bg="#FFB800" />
          <Box w={2.5} h={2.5} borderRadius="full" bg="#00FFB2" />
        </HStack>
        <Text fontFamily="heading" fontSize="xs" letterSpacing="0.18em" color="whiteAlpha.700" noOfLines={1} textAlign="right">
          {title}
        </Text>
      </Flex>
      <Box p={4} overflow="hidden" minW={0}>{children}</Box>
    </Box>
  )
}
