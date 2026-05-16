import { Box, HStack, Text, VStack } from '@chakra-ui/react'
import { motion } from 'framer-motion'
import type { AttackStep } from '../../types'

const MotionBox = motion(Box)

export function AttackFlow({ steps }: { steps: AttackStep[] }) {
  return (
    <VStack align="stretch" spacing={4}>
      {steps.map((step, index) => (
        <HStack key={step.title} align="stretch" spacing={4}>
          <VStack spacing={0}>
            <MotionBox
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ delay: index * 0.1 }}
              w="40px"
              h="40px"
              borderRadius="full"
              bg="rgba(0,255,178,0.12)"
              border="1px solid rgba(0,255,178,0.28)"
              display="flex"
              alignItems="center"
              justifyContent="center"
              fontFamily="heading"
              color="brand.300"
            >
              {index + 1}
            </MotionBox>
            {index < steps.length - 1 && <Box w="2px" flex="1" bg="linear-gradient(180deg, rgba(0,255,178,0.4), rgba(0,255,178,0.02))" minH="56px" />}
          </VStack>
          <MotionBox
            initial={{ opacity: 0, x: -12 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.12 + 0.08 }}
            flex="1"
            p={4}
            borderRadius="xl"
            border="1px solid rgba(0,255,178,0.08)"
            bg="rgba(255,255,255,0.03)"
          >
            <Text fontFamily="heading" fontSize="sm" color="brand.300" mb={2}>
              {step.title}
            </Text>
            <Text color="whiteAlpha.800">{step.description}</Text>
          </MotionBox>
        </HStack>
      ))}
    </VStack>
  )
}
