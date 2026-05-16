import { Grid, GridItem, Text, VStack } from '@chakra-ui/react'

interface RiskCellItem {
  id: string
  label: string
  x: number
  y: number
}

export function RiskMatrixChart({ items }: { items: RiskCellItem[] }) {
  return (
    <Grid templateColumns="repeat(5, 1fr)" gap={2}>
      {Array.from({ length: 25 }).map((_, index) => {
        const x = (index % 5) + 1
        const y = 5 - Math.floor(index / 5)
        const cellItems = items.filter((item) => item.x === x && item.y === y)
        const intensity = (x + y) / 10

        return (
          <GridItem
            key={`${x}-${y}`}
            minH="88px"
            minW={0}
            borderRadius="lg"
            p={2}
            border="1px solid rgba(255,255,255,0.05)"
            bg={`rgba(255, ${Math.round(180 - intensity * 120)}, ${Math.round(178 - intensity * 150)}, ${0.08 + intensity * 0.14})`}
            overflow="hidden"
          >
            <Text fontSize="xs" color="whiteAlpha.700" mb={2}>
              {x}×{y}
            </Text>
            <VStack align="stretch" spacing={1}>
              {cellItems.map((item) => (
                <Text key={item.id} fontSize="xs" color="whiteAlpha.900" wordBreak="break-word" overflowWrap="anywhere" noOfLines={2}>
                  {item.label}
                </Text>
              ))}
            </VStack>
          </GridItem>
        )
      })}
    </Grid>
  )
}
