import { Box, Heading, ListItem, OrderedList, SimpleGrid, Text, VStack } from '@chakra-ui/react'
import { useI18n } from '../../i18n'

const bibliography = [
  'OWASP Top 10:2021, Open Worldwide Application Security Project.',
  'RFC 8725, JSON Web Token Best Current Practices.',
  'MITRE CWE-79, CWE-89, CWE-22, CWE-352, CWE-502, CWE-611.',
  'Directive 2013/40/EU on attacks against information systems.',
  '18 U.S.C. §1030, Computer Fraud and Abuse Act.',
  'Уголовный кодекс Российской Федерации, статьи 272-274.',
  'PortSwigger Web Security Academy research materials.',
  'NVD CVE-2021-41773, CVE-2023-34362, CVE-2015-9235.',
  'Morris, R. T., United States v. Morris.',
  'Academic literature on responsible disclosure and coordinated vulnerability disclosure.',
  'NIST SP 800-61r2, Computer Security Incident Handling Guide.',
  'OWASP Cheat Sheet Series: CSRF, SQL Injection, SSRF, File Upload.',
  'MDN Web Docs for HTTP security headers and SameSite cookies.',
  'Research publications on STRIDE, DREAD, and attack trees.',
  'Vendor advisories for Apache, Atlassian, Ghost CMS, and MOVEit.'
]

export default function AboutPage() {
  const { t, locale } = useI18n()
  const authorLabel = locale === 'ru' ? 'Автор' : 'Author'
  const supervisorLabel = locale === 'ru' ? 'Научный руководитель' : 'Supervisor'
  return (
    <VStack align="stretch" spacing={6}>
      <Heading>{t('about.title')}</Heading>
      <SimpleGrid columns={{ base: 1, xl: 2 }} spacing={6} alignItems="start" sx={{ "&> *": { minW: 0 } }}>
        <Box p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
          <Heading size="md" mb={4}>
            {t('about.methodology')}
          </Heading>
          <Text color="whiteAlpha.800">
            Методология платформы сочетает сравнительный анализ стандартов OWASP, CVE/CWE-ориентированную классификацию, локальное моделирование атак, risk scoring и юридическую квалификацию последствий эксплуатации.
          </Text>
          <Text mt={4} color="whiteAlpha.800">
            Архитектурно система реализована как SPA на React 18 + TypeScript strict с полным отсутствием реальных сетевых атакующих действий: все сценарии генерируются и интерпретируются в браузере.
          </Text>
        </Box>
        <Box p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
          <Heading size="md" mb={4}>
            {t('about.disclaimer')}
          </Heading>
          <Text color="warning.500">
            Платформа предназначена для учебных, научных и демонстрационных целей. Любое применение описанных техник к реальным информационным системам без прямого разрешения владельца может образовывать состав правонарушения или преступления.
          </Text>
          <Text mt={4}>{authorLabel}: {locale === 'ru' ? 'Даулетов Азамат' : 'Dauletov Azamat'}</Text>
          <Text>{supervisorLabel}: {locale === 'ru' ? 'научный руководитель (заполнитель)' : 'placeholder scientific advisor'}</Text>
        </Box>
      </SimpleGrid>
      <Box p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
        <Heading size="md" mb={4}>
          {t('about.architecture')}
        </Heading>
        <svg width="100%" height="280" viewBox="0 0 800 280" preserveAspectRatio="xMidYMid meet" style={{ maxWidth: '100%', display: 'block' }}>
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M0,0 L10,5 L0,10 z" fill="rgba(0,255,178,0.55)" />
            </marker>
          </defs>
          {/* connectors first so they sit behind cards */}
          <path d="M 226 120 H 268 V 80 H 304" fill="none" stroke="rgba(0,255,178,0.4)" strokeWidth="2.5" markerEnd="url(#arrow)" />
          <path d="M 226 120 H 268 V 200 H 304" fill="none" stroke="rgba(0,255,178,0.4)" strokeWidth="2.5" markerEnd="url(#arrow)" />
          <path d="M 496 80 H 538 V 120 H 574" fill="none" stroke="rgba(0,255,178,0.4)" strokeWidth="2.5" markerEnd="url(#arrow)" />
          <path d="M 496 200 H 538 V 120 H 574" fill="none" stroke="rgba(0,255,178,0.4)" strokeWidth="2.5" markerEnd="url(#arrow)" />

          <rect x="40" y="80" width="180" height="80" rx="18" fill="rgba(6,9,16,0.95)" stroke="rgba(0,255,178,0.25)" />
          <text x="130" y="112" fill="#00FFB2" textAnchor="middle" fontFamily="IBM Plex Mono" fontSize="15">
            {t('about.arch.ui')}
          </text>
          <foreignObject x="48" y="120" width="164" height="36">
            <div style={{ color: '#dffef4', fontSize: '10.5px', textAlign: 'center', lineHeight: 1.25, fontFamily: 'Instrument Sans, sans-serif', wordBreak: 'break-word' }}>
              {t('about.arch.uiDesc')}
            </div>
          </foreignObject>

          <rect x="310" y="40" width="180" height="80" rx="18" fill="rgba(6,9,16,0.95)" stroke="rgba(0,255,178,0.25)" />
          <text x="400" y="72" fill="#00FFB2" textAnchor="middle" fontFamily="IBM Plex Mono" fontSize="15">
            {t('about.arch.sim')}
          </text>
          <foreignObject x="318" y="80" width="164" height="36">
            <div style={{ color: '#dffef4', fontSize: '10.5px', textAlign: 'center', lineHeight: 1.25, fontFamily: 'Instrument Sans, sans-serif', wordBreak: 'break-word' }}>
              {t('about.arch.simDesc')}
            </div>
          </foreignObject>

          <rect x="310" y="160" width="180" height="80" rx="18" fill="rgba(6,9,16,0.95)" stroke="rgba(0,255,178,0.25)" />
          <text x="400" y="192" fill="#00FFB2" textAnchor="middle" fontFamily="IBM Plex Mono" fontSize="15">
            {t('about.arch.data')}
          </text>
          <foreignObject x="318" y="200" width="164" height="36">
            <div style={{ color: '#dffef4', fontSize: '10.5px', textAlign: 'center', lineHeight: 1.25, fontFamily: 'Instrument Sans, sans-serif', wordBreak: 'break-word' }}>
              {t('about.arch.dataDesc')}
            </div>
          </foreignObject>

          <rect x="580" y="80" width="180" height="80" rx="18" fill="rgba(6,9,16,0.95)" stroke="rgba(0,255,178,0.25)" />
          <text x="670" y="112" fill="#00FFB2" textAnchor="middle" fontFamily="IBM Plex Mono" fontSize="15">
            {t('about.arch.report')}
          </text>
          <foreignObject x="588" y="120" width="164" height="36">
            <div style={{ color: '#dffef4', fontSize: '10.5px', textAlign: 'center', lineHeight: 1.25, fontFamily: 'Instrument Sans, sans-serif', wordBreak: 'break-word' }}>
              {t('about.arch.reportDesc')}
            </div>
          </foreignObject>
        </svg>
      </Box>
      <Box p={6} borderRadius="2xl" bg="rgba(255,255,255,0.03)" border="1px solid rgba(0,255,178,0.08)">
        <Heading size="md" mb={4}>
          {t('about.bibliography')}
        </Heading>
        <OrderedList spacing={2}>
          {bibliography.map((item) => (
            <ListItem key={item}>{item}</ListItem>
          ))}
        </OrderedList>
      </Box>
    </VStack>
  )
}
