import { Box, Text, VStack } from '@chakra-ui/react'
import { motion } from 'framer-motion'

const MotionCircle = motion.circle

export function CvssGauge({ value, size = 92 }: { value: number; size?: number }) {
  const radius = size / 2 - 8
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (value / 10) * circumference

  return (
    <VStack spacing={1}>
      <Box as="svg" width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={size / 2} cy={size / 2} r={radius} stroke="rgba(255,255,255,0.08)" strokeWidth="8" fill="none" />
        <MotionCircle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="#00FFB2"
          strokeWidth="8"
          fill="none"
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 0.8, ease: 'easeOut' }}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
        />
      </Box>
      <Text fontFamily="heading" fontSize="sm" color="brand.300">
        CVSS {value.toFixed(1)}
      </Text>
    </VStack>
  )
}
