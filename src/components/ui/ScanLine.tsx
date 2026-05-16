import { Box } from '@chakra-ui/react'

export function ScanLine() {
  return (
    <Box
      position="absolute"
      insetX={0}
      top="-20%"
      h="120px"
      bg="linear-gradient(180deg, transparent, rgba(0,255,178,0.12), transparent)"
      filter="blur(10px)"
      pointerEvents="none"
      animation="scanline 8s linear infinite"
    />
  )
}
