import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, Flex, HStack, Icon, Input, InputGroup, InputLeftElement, Kbd, Text } from '@chakra-ui/react'
import { useMemo } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { RiCommandLine, RiSearchLine } from 'react-icons/ri'
import { useUiStore } from '../store/uiStore'
import { LocaleToggle, useI18n } from '../i18n'
import { localizeBreadcrumb } from '../localization'

export function TopBar() {
  const location = useLocation()
  const { setSearchOpen } = useUiStore()
  const { t, locale } = useI18n()

  const crumbs = useMemo(() => {
    const segments = location.pathname.split('/').filter(Boolean)
    if (segments.length === 0) {
      return [{ label: t('nav.dashboard'), path: '/' }]
    }
    return segments.map((segment, index) => ({
      label: localizeBreadcrumb(decodeURIComponent(segment), locale),
      path: `/${segments.slice(0, index + 1).join('/')}`
    }))
  }, [location.pathname, t, locale])

  return (
    <Flex justify="space-between" align={{ base: 'flex-start', lg: 'center' }} direction={{ base: 'column', lg: 'row' }} gap={4}>
      <Breadcrumb color="whiteAlpha.700" separator="/">
        {crumbs.map((crumb) => (
          <BreadcrumbItem key={crumb.path}>
            <BreadcrumbLink as={Link} to={crumb.path}>
              {crumb.label}
            </BreadcrumbLink>
          </BreadcrumbItem>
        ))}
      </Breadcrumb>
      <HStack spacing={3} w={{ base: '100%', lg: 'auto' }}>
        <InputGroup maxW={{ base: '100%', lg: '360px' }} onClick={() => setSearchOpen(true)} cursor="pointer">
          <InputLeftElement pointerEvents="none">
            <Icon as={RiSearchLine} color="brand.300" />
          </InputLeftElement>
          <Input readOnly placeholder={t('search.placeholder')} borderColor="rgba(0,255,178,0.12)" bg="rgba(255,255,255,0.02)" />
        </InputGroup>
        <HStack color="whiteAlpha.600" spacing={2}>
          <LocaleToggle />
          <Icon as={RiCommandLine} />
          <Text fontSize="xs">{t('search.label')}</Text>
          <Kbd bg="rgba(255,255,255,0.06)">⌘K</Kbd>
        </HStack>
      </HStack>
    </Flex>
  )
}
