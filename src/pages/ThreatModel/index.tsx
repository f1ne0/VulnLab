import {
  Box,
  Button,
  FormControl,
  FormLabel,
  Grid,
  GridItem,
  Heading,
  HStack,
  Input,
  Select,
  SimpleGrid,
  Slider,
  SliderFilledTrack,
  SliderThumb,
  SliderTrack,
  Text,
  Textarea,
  VStack
} from '@chakra-ui/react'
import html2canvas from 'html2canvas'
import { useMemo, useRef, useState } from 'react'
import { RadarChart } from '../../components/charts/RadarChart'
import { RiskMatrixChart } from '../../components/charts/RiskMatrix'
import { useLocalStorage } from '../../hooks/useLocalStorage'
import type { AttackTreeNode, DreadValues, ThreatModelEntry } from '../../types'
import { useI18n } from '../../i18n'

const NODE_HALF_W = 60
const NODE_HALF_H = 24

function intersectRectEdge(cx: number, cy: number, tx: number, ty: number, hw: number, hh: number): [number, number] {
  const dx = tx - cx
  const dy = ty - cy
  if (dx === 0 && dy === 0) return [cx, cy]
  const sx = dx === 0 ? Infinity : hw / Math.abs(dx)
  const sy = dy === 0 ? Infinity : hh / Math.abs(dy)
  const s = Math.min(sx, sy)
  return [cx + dx * s, cy + dy * s]
}

function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value
}

export default function ThreatModelPage() {
  const { t, locale } = useI18n()
  const strideCategories = [
    t('threat.category.spoofing'),
    t('threat.category.tampering'),
    t('threat.category.repudiation'),
    t('threat.category.infoDisclosure'),
    t('threat.category.dos'),
    t('threat.category.eop')
  ]
  const [entries, setEntries] = useLocalStorage<ThreatModelEntry[]>('stride-entries', [])
  const [entry, setEntry] = useState<ThreatModelEntry>({
    id: crypto.randomUUID(),
    category: strideCategories[0],
    asset: '',
    threatDescription: '',
    currentControls: '',
    proposedMitigation: ''
  })
  const [nodes, setNodes] = useLocalStorage<AttackTreeNode[]>('attack-tree', [
    {
      id: 'root',
      type: 'root',
      label: t('threat.rootGoal'),
      x: 180,
      y: 50,
      probability: 0.8,
      cost: 7
    },
    { id: crypto.randomUUID(), type: 'sub-attack', label: t('threat.exploitSqli'), x: 80, y: 180, probability: 0.7, cost: 5, parentId: 'root' },
    { id: crypto.randomUUID(), type: 'defense', label: t('threat.paramQueries'), x: 280, y: 180, probability: 0.2, cost: 2, parentId: 'root' }
  ])
  const [matrixItems, setMatrixItems] = useLocalStorage<Array<{ id: string; label: string; x: number; y: number }>>('risk-matrix', [
    { id: 'sql', label: 'SQLi', x: 5, y: 5 },
    { id: 'xss', label: 'XSS', x: 4, y: 4 },
    { id: 'headers', label: locale === 'ru' ? 'Заголовки' : 'Headers', x: 2, y: 2 }
  ])
  const [dread, setDread] = useLocalStorage<DreadValues>('dread-values', {
    damage: 8,
    reproducibility: 7,
    exploitability: 8,
    affectedUsers: 7,
    discoverability: 6
  })
  const exportRef = useRef<HTMLDivElement | null>(null)

  const localizeMatrixLabel = (label: string) => {
    if (locale !== 'ru') {
      return label === 'Заголовки' ? 'Headers' : label
    }

    if (label === 'Headers') return 'Заголовки'
    return label
  }

  const attackFeasibility = useMemo(() => {
    if (nodes.length === 0) return 0
    const sum = nodes.reduce((acc, node) => acc + node.probability * 10 - node.cost, 0)
    return Math.max(0, Math.min(100, Math.round((sum / nodes.length) * 10)))
  }, [nodes])

  const dreadScore = useMemo(() => {
    const total = dread.damage + dread.reproducibility + dread.exploitability + dread.affectedUsers + dread.discoverability
    return Number((total / 5).toFixed(1))
  }, [dread])

  const addEntry = () => {
    setEntries([...entries, { ...entry, id: crypto.randomUUID() }])
    setEntry({
      id: crypto.randomUUID(),
      category: strideCategories[0],
      asset: '',
      threatDescription: '',
      currentControls: '',
      proposedMitigation: ''
    })
  }

  const addNode = () => {
    setNodes([
      ...nodes,
      {
        id: crypto.randomUUID(),
        type: 'sub-attack',
        label: `${t('threat.newNode')} ${nodes.length}`,
        x: 80 + nodes.length * 40,
        y: 260,
        probability: 0.5,
        cost: 4,
        parentId: 'root'
      }
    ])
  }

  const exportImage = async () => {
    if (!exportRef.current) return
    const canvas = await html2canvas(exportRef.current)
    const link = document.createElement('a')
    link.download = 'risk-matrix.png'
    link.href = canvas.toDataURL('image/png')
    link.click()
  }

  return (
    <VStack align="stretch" spacing={6}>
      <Heading>{t('threat.title')}</Heading>
      <SimpleGrid columns={{ base: 1, xl: 2 }} spacing={6} alignItems="start" sx={{ "&> *": { minW: 0 } }}>
        <VStack align="stretch" spacing={4} p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
          <Heading size="md">{t('threat.strideTitle')}</Heading>
          <Select value={entry.category} onChange={(event) => setEntry({ ...entry, category: event.target.value })}>
            {strideCategories.map((category) => (
              <option key={category} value={category}>
                {category}
              </option>
            ))}
          </Select>
          <Input placeholder={t('threat.asset')} value={entry.asset} onChange={(event) => setEntry({ ...entry, asset: event.target.value })} />
          <Textarea placeholder={t('threat.description')} value={entry.threatDescription} onChange={(event) => setEntry({ ...entry, threatDescription: event.target.value })} />
          <Textarea placeholder={t('threat.controls')} value={entry.currentControls} onChange={(event) => setEntry({ ...entry, currentControls: event.target.value })} />
          <Textarea placeholder={t('threat.mitigation')} value={entry.proposedMitigation} onChange={(event) => setEntry({ ...entry, proposedMitigation: event.target.value })} />
          <Button variant="terminal" onClick={addEntry}>
            {t('threat.save')}
          </Button>
          {entries.map((saved) => (
            <Box key={saved.id} p={4} borderRadius="xl" bg="rgba(255,255,255,0.02)">
              <Text fontFamily="heading" color="brand.300">
                {saved.category}
              </Text>
              <Text>{saved.asset}</Text>
              <Text fontSize="sm" color="whiteAlpha.700">
                {saved.threatDescription}
              </Text>
            </Box>
          ))}
        </VStack>

        <VStack align="stretch" spacing={4} p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
          <Heading size="md">{t('threat.attackTreeTitle')}</Heading>
          <Button variant="terminal" onClick={addNode} alignSelf="flex-start">
            {t('threat.addNode')}
          </Button>
          <Box border="1px solid rgba(0,255,178,0.08)" borderRadius="xl" p={4} overflow="hidden">
            <svg width="100%" height="360" viewBox="0 0 420 360" preserveAspectRatio="xMidYMid meet" style={{ maxWidth: '100%', display: 'block' }}>
              {nodes.map((node) => {
                if (!node.parentId) return null
                const parent = nodes.find((c) => c.id === node.parentId)
                if (!parent) return null
                const [sx, sy] = intersectRectEdge(parent.x, parent.y, node.x, node.y, NODE_HALF_W, NODE_HALF_H)
                const [ex, ey] = intersectRectEdge(node.x, node.y, parent.x, parent.y, NODE_HALF_W, NODE_HALF_H)
                return (
                  <line
                    key={`line-${node.id}`}
                    x1={sx}
                    y1={sy}
                    x2={ex}
                    y2={ey}
                    stroke="rgba(0,255,178,0.35)"
                    strokeWidth="2"
                  />
                )
              })}
              {nodes.map((node) => (
                <g key={node.id}>
                  <rect x={node.x - NODE_HALF_W} y={node.y - NODE_HALF_H} width={NODE_HALF_W * 2} height={NODE_HALF_H * 2} rx="12" fill="rgba(255,255,255,0.04)" stroke="rgba(0,255,178,0.2)" />
                  <text x={node.x} y={node.y - 2} textAnchor="middle" fill="#dffef4" fontSize="11" fontFamily="IBM Plex Mono">
                    {truncate(node.label, 18)}
                  </text>
                  <text x={node.x} y={node.y + 14} textAnchor="middle" fill="#00FFB2" fontSize="10" fontFamily="IBM Plex Mono">
                    p={node.probability.toFixed(1)} c={node.cost}
                  </text>
                </g>
              ))}
            </svg>
          </Box>
          <Text color="warning.500">{t('threat.overallScore')}: {attackFeasibility}/100</Text>
        </VStack>
      </SimpleGrid>

      <Grid templateColumns={{ base: '1fr', xl: '1.15fr 0.85fr' }} gap={6}>
        <GridItem>
          <Box ref={exportRef} p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
            <HStack justify="space-between" mb={4}>
              <Heading size="md">{t('threat.riskMatrix')}</Heading>
              <Button variant="terminal" size="sm" onClick={exportImage}>
                {t('threat.exportImage')}
              </Button>
            </HStack>
            <RiskMatrixChart items={matrixItems.map((item) => ({ ...item, label: localizeMatrixLabel(item.label) }))} />
          </Box>
        </GridItem>
        <GridItem>
          <VStack align="stretch" spacing={4} p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
            <Heading size="md">{t('threat.dreadTitle')}</Heading>
            {(Object.keys(dread) as Array<keyof DreadValues>).map((key) => (
              <FormControl key={key}>
                <FormLabel textTransform="capitalize">
                  {key === 'damage'
                    ? t('threat.damage')
                    : key === 'reproducibility'
                      ? t('threat.reproducibility')
                      : key === 'exploitability'
                        ? t('threat.exploitability')
                        : key === 'affectedUsers'
                          ? t('threat.affectedUsers')
                          : t('threat.discoverability')}
                  : {dread[key]}
                </FormLabel>
                <Slider min={0} max={10} step={1} value={dread[key]} onChange={(value) => setDread({ ...dread, [key]: value })}>
                  <SliderTrack>
                    <SliderFilledTrack bg="brand.300" />
                  </SliderTrack>
                  <SliderThumb />
                </Slider>
              </FormControl>
            ))}
            <Text fontFamily="heading" color="brand.300">
              {t('threat.dreadScore')}: {dreadScore} / 10
            </Text>
            <Text color={dreadScore >= 7 ? 'danger.500' : dreadScore >= 4 ? 'warning.500' : 'brand.300'}>
              {t('threat.classification')}: {dreadScore >= 7 ? t('threat.highRisk') : dreadScore >= 4 ? t('threat.moderateRisk') : t('threat.lowRisk')}
            </Text>
            <RadarChart
              labels={[
                t('threat.damage'),
                t('threat.reproducibility'),
                t('threat.exploitability'),
                t('threat.affectedUsers'),
                t('threat.discoverability')
              ]}
              values={Object.values(dread)}
              locale={locale}
            />
          </VStack>
        </GridItem>
      </Grid>
    </VStack>
  )
}
