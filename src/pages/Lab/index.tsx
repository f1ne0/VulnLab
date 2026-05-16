import { Box, Heading, Tab, TabList, TabPanel, TabPanels, Tabs, Text, useToast } from '@chakra-ui/react'
import { useEffect } from 'react'
import { SQLiLab } from './SQLiLab'
import { XSSLab } from './XSSLab'
import { CSRFLab } from './CSRFLab'
import { JWTLab } from './JWTLab'
import { HeaderLab } from './HeaderLab'
import { PathTraversalLab } from './PathTraversalLab'
import { SsrfLab } from './SsrfLab'
import { SstiLab } from './SstiLab'
import { XxeLab } from './XxeLab'
import { CmdInjectionLab } from './CmdInjectionLab'
import { IdorLab } from './IdorLab'
import { OpenRedirectLab } from './OpenRedirectLab'
import { FileUploadLab } from './FileUploadLab'
import { ProtoPollutionLab } from './ProtoPollutionLab'
import { GraphqlLab } from './GraphqlLab'
import { LdapLab } from './LdapLab'
import { DeserializationLab } from './DeserializationLab'
import { ClickjackingLab } from './ClickjackingLab'
import { useI18n } from '../../i18n'

export default function LabPage() {
  const toast = useToast()
  const { t, locale } = useI18n()
  const isRu = locale === 'ru'

  useEffect(() => {
    const flag = window.sessionStorage.getItem('labEthicsToastShown')
    if (!flag) {
      toast({
        title: t('lab.toast.title'),
        description: t('lab.toast.body'),
        status: 'warning',
        duration: 5000
      })
      window.sessionStorage.setItem('labEthicsToastShown', 'true')
    }
  }, [toast, t])

  const tabs: Array<{ label: string; node: JSX.Element }> = [
    { label: isRu ? 'SQL-инъекция' : 'SQL Injection', node: <SQLiLab /> },
    { label: 'XSS', node: <XSSLab /> },
    { label: 'CSRF', node: <CSRFLab /> },
    { label: 'JWT', node: <JWTLab /> },
    { label: t('lab.tab.headers'), node: <HeaderLab /> },
    { label: isRu ? 'Обход директорий' : 'Path Traversal', node: <PathTraversalLab /> },
    { label: 'SSRF', node: <SsrfLab /> },
    { label: 'SSTI', node: <SstiLab /> },
    { label: 'XXE', node: <XxeLab /> },
    { label: isRu ? 'Command Injection' : 'Command Injection', node: <CmdInjectionLab /> },
    { label: 'IDOR', node: <IdorLab /> },
    { label: isRu ? 'Open Redirect' : 'Open Redirect', node: <OpenRedirectLab /> },
    { label: isRu ? 'File Upload' : 'File Upload', node: <FileUploadLab /> },
    { label: 'Prototype Pollution', node: <ProtoPollutionLab /> },
    { label: 'GraphQL', node: <GraphqlLab /> },
    { label: 'LDAP', node: <LdapLab /> },
    { label: isRu ? 'Десериализация' : 'Deserialization', node: <DeserializationLab /> },
    { label: 'Clickjacking', node: <ClickjackingLab /> }
  ]

  return (
    <Box>
      <Heading mb={2}>{t('lab.title')}</Heading>
      <Text color="whiteAlpha.700" mb={6}>
        {t('lab.subtitle')}
      </Text>
      <Tabs variant="enclosed" colorScheme="green" isLazy>
        <TabList
          overflowX="auto"
          overflowY="hidden"
          flexWrap={{ base: 'nowrap', md: 'wrap' }}
          css={{
            scrollbarWidth: 'thin',
            WebkitOverflowScrolling: 'touch',
            '&::-webkit-scrollbar': { height: '6px' },
            '&::-webkit-scrollbar-thumb': { background: 'rgba(0,255,178,0.2)', borderRadius: '3px' }
          }}
        >
          {tabs.map((t) => (
            <Tab key={t.label} whiteSpace="nowrap" flexShrink={0} fontSize={{ base: 'xs', md: 'sm' }} px={{ base: 3, md: 4 }}>
              {t.label}
            </Tab>
          ))}
        </TabList>
        <TabPanels pt={4}>
          {tabs.map((t) => (
            <TabPanel key={t.label} px={0}>
              {t.node}
            </TabPanel>
          ))}
        </TabPanels>
      </Tabs>
    </Box>
  )
}
