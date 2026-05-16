import {
  Box,
  Button,
  Grid,
  GridItem,
  Heading,
  HStack,
  Icon,
  SimpleGrid,
  Stat,
  StatLabel,
  StatNumber,
  Text,
  VStack
} from '@chakra-ui/react'
import { motion } from 'framer-motion'
import { RiBugLine, RiFileChartLine, RiScalesLine } from 'react-icons/ri'
import { Link } from 'react-router-dom'
import { DecryptText } from '../../components/ui/DecryptText'
import { ScanLine } from '../../components/ui/ScanLine'
import { useCountUp } from '../../hooks/useCountUp'
import { vulnerabilities } from '../../data/vulnerabilities'
import { useI18n } from '../../i18n'

const MotionBox = motion(Box)

const recentResearch = [
  'CVE-2023-34362: эксплуатация MOVEit через SQLi и последствия массовой утечки',
  'Путаница алгоритмов в конвейерах проверки JWT',
  'Практика квалификации несанкционированного доступа по ст. 272 УК РФ',
  'Роль защитных заголовков как доказательной базы после раскрытия инцидента'
]

export default function HomePage() {
  const { t } = useI18n()
  const vulnCount = useCountUp(10)
  const jurisdictions = useCountUp(4)
  const owaspYear = useCountUp(2021)

  return (
    <VStack align="stretch" spacing={8}>
      <Box position="relative" overflow="hidden" borderRadius="3xl" border="1px solid rgba(0,255,178,0.1)" bg="rgba(255,255,255,0.02)" px={{ base: 6, md: 10 }} py={{ base: 10, md: 14 }}>
        <ScanLine />
        <Grid templateColumns={{ base: '1fr', xl: '1.2fr 0.8fr' }} gap={8} alignItems="center" maxW="100%">
          <GridItem minW={0} overflow="hidden">
            <Text fontFamily="heading" color="brand.300" letterSpacing="0.25em" fontSize="sm">
              {t('home.kicker')}
            </Text>
            <DecryptText
              text={t('home.title')}
              fontSize="clamp(1.25rem, 2.2vw, 2.25rem)"
              fontWeight="700"
              mt={4}
              w="100%"
              maxW="100%"
            />
            <Text mt={4} maxW="2xl" fontSize="lg" color="whiteAlpha.820">
              {t('home.subtitle')}
            </Text>
            <HStack mt={8} spacing={4} flexWrap="wrap">
              <Button as={Link} to="/lab" variant="terminal" size="lg" px={8} position="relative" _after={{ content: '""', position: 'absolute', inset: 0, borderRadius: 'inherit', boxShadow: '0 0 0 0 rgba(0,255,178,0.45)', animation: 'pulse 2.2s infinite' }}>
                {t('home.openLab')}
              </Button>
              <Button as={Link} to="/vulnerabilities" variant="ghost" color="whiteAlpha.800">
                {t('home.openDb')}
              </Button>
            </HStack>
          </GridItem>
          <GridItem minW={0}>
            <SimpleGrid columns={1} spacing={4} sx={{ "& > *": { minW: 0 } }}>
              <Stat p={5} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
                <StatLabel color="whiteAlpha.700">{t('home.stats.vulns')}</StatLabel>
                <StatNumber fontFamily="heading" color="brand.300">
                  {vulnCount}
                </StatNumber>
              </Stat>
              <Stat p={5} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
                <StatLabel color="whiteAlpha.700">{t('home.stats.jurisdictions')}</StatLabel>
                <StatNumber fontFamily="heading" color="brand.300">
                  {jurisdictions}
                </StatNumber>
              </Stat>
              <Stat p={5} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
                <StatLabel color="whiteAlpha.700">{t('home.stats.owasp')}</StatLabel>
                <StatNumber fontFamily="heading" color="brand.300">
                  {owaspYear}
                </StatNumber>
              </Stat>
            </SimpleGrid>
          </GridItem>
        </Grid>
      </Box>

      <Box overflow="hidden" borderRadius="full" border="1px solid rgba(0,255,178,0.08)" bg="rgba(255,255,255,0.02)" py={3}>
        <Box whiteSpace="nowrap" animation="ticker 22s linear infinite" display="inline-block" minW="200%">
          {Array.from({ length: 2 })
            .flatMap(() => vulnerabilities)
            .map((item, index) => (
              <Text key={`${item.id}-${index}`} display="inline-block" mx={6} fontFamily="heading" color="brand.300">
                {item.name} / {item.cwe} / {item.cvssVector}
              </Text>
            ))}
        </Box>
      </Box>

      <SimpleGrid columns={{ base: 1, lg: 3 }} spacing={6}>
        {[
          { title: t('home.features.sim'), text: 'SQLi, XSS, CSRF, JWT, headers и traversal работают полностью в браузере.', icon: RiBugLine },
          { title: t('home.features.legal'), text: 'Сопоставление РФ, США и ЕС с реальными нормами и судебным контекстом.', icon: RiScalesLine },
          { title: t('home.features.report'), text: 'Генерация формализованных материалов, пригодных для защиты и печати.', icon: RiFileChartLine }
        ].map((feature, index) => (
          <MotionBox
            key={feature.title}
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.12 * index }}
            p={6}
            borderRadius="2xl"
            bg="rgba(255,255,255,0.03)"
            border="1px solid rgba(0,255,178,0.08)"
            position="relative"
            overflow="hidden"
            _before={{
              content: '""',
              position: 'absolute',
              left: 0,
              top: 0,
              bottom: 0,
              width: '4px',
              bg: 'linear-gradient(180deg, transparent, #00FFB2, transparent)',
              backgroundSize: '100% 200%',
              animation: 'pulse-border 2s linear infinite'
            }}
          >
            <Icon as={feature.icon} boxSize={8} color="brand.300" />
            <Heading size="md" mt={4} mb={3}>
              {feature.title}
            </Heading>
            <Text color="whiteAlpha.800">{feature.text}</Text>
          </MotionBox>
        ))}
      </SimpleGrid>

      <Grid templateColumns={{ base: '1fr', xl: '1fr 0.9fr' }} gap={6}>
        <GridItem>
          <Box p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
            <Heading size="md" mb={4}>
              Последние исследования
            </Heading>
            <VStack align="stretch" spacing={3}>
              {recentResearch.map((item, index) => (
                <MotionBox key={item} initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: index * 0.08 }}>
                  <Box p={4} borderRadius="xl" bg="rgba(255,255,255,0.02)" border="1px solid rgba(255,255,255,0.04)">
                    <Text fontFamily="heading" fontSize="sm" color="brand.300" mb={1}>
                      RESEARCH-{index + 1}
                    </Text>
                    <Text color="whiteAlpha.850">{item}</Text>
                  </Box>
                </MotionBox>
              ))}
            </VStack>
          </Box>
        </GridItem>
        <GridItem>
          <Box p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
            <Heading size="md" mb={4}>
              Оперативная сводка
            </Heading>
            <VStack align="stretch" spacing={3}>
              <Text color="whiteAlpha.800">Платформа ориентирована на демонстрацию полного цикла: от моделирования техники до оценки состава правонарушения и рекомендаций по защите.</Text>
              <Text color="whiteAlpha.800">Все модули работают локально, не совершают реальных сетевых обращений и сохраняют исследовательские сессии в localStorage.</Text>
              <Text color="warning.500">Этический режим: обязательное подтверждение образовательного использования при первом входе.</Text>
            </VStack>
          </Box>
        </GridItem>
      </Grid>
    </VStack>
  )
}
