import { Box, Flex, Icon, IconButton, Text, Tooltip, VStack } from '@chakra-ui/react'
import { Link, useLocation } from 'react-router-dom'
import {
  RiBugLine,
  RiDashboardLine,
  RiFileTextLine,
  RiFlaskLine,
  RiInformationLine,
  RiListCheck2,
  RiScalesLine,
  RiShieldLine,
  RiMenuFoldLine,
  RiMenuUnfoldLine
} from 'react-icons/ri'
import { useUiStore } from '../store/uiStore'
import { useI18n } from '../i18n'

export function Sidebar() {
  const { pathname } = useLocation()
  const { sidebarCollapsed, toggleSidebar } = useUiStore()
  const { t } = useI18n()
  const navItems = [
    { label: t('nav.dashboard'), path: '/', icon: RiDashboardLine },
    { label: t('nav.lab'), path: '/lab', icon: RiFlaskLine },
    { label: t('nav.vulns'), path: '/vulnerabilities', icon: RiBugLine },
    { label: t('nav.threat'), path: '/threat-model', icon: RiShieldLine },
    { label: t('nav.legal'), path: '/legal', icon: RiScalesLine },
    { label: t('nav.owasp'), path: '/owasp', icon: RiListCheck2 },
    { label: t('nav.reports'), path: '/reports', icon: RiFileTextLine },
    { label: t('nav.about'), path: '/about', icon: RiInformationLine }
  ]

  return (
    <Box
      as="aside"
      position="sticky"
      top={0}
      h="100vh"
      w={sidebarCollapsed ? '72px' : '240px'}
      transition="width 0.2s ease"
      borderRight="1px solid rgba(0,255,178,0.08)"
      bg="rgba(4,7,13,0.88)"
      backdropFilter="blur(18px)"
      p={3}
    >
      <Flex align="center" justify="space-between" mb={6}>
        <Box>
          <Text fontFamily="heading" fontSize={sidebarCollapsed ? 'xs' : 'lg'} color="brand.300">
            {sidebarCollapsed ? 'VL' : 'VulnLab'}
          </Text>
          {!sidebarCollapsed && (
            <Text
              fontSize="xs"
              color="whiteAlpha.600"
              letterSpacing="0.12em"
              whiteSpace="nowrap"
              overflow="hidden"
              textOverflow="ellipsis"
              maxW="168px"
            >
              {t('shell.classifiedNode')}
            </Text>
          )}
        </Box>
        <IconButton
          aria-label="Toggle sidebar"
          size="sm"
          variant="ghost"
          color="brand.300"
          icon={sidebarCollapsed ? <RiMenuUnfoldLine /> : <RiMenuFoldLine />}
          onClick={toggleSidebar}
        />
      </Flex>
      <VStack align="stretch" spacing={2}>
        {navItems.map((item) => {
          const active = pathname === item.path || (item.path !== '/' && pathname.startsWith(item.path))
          const linkContent = (
            <Flex
              as={Link}
              to={item.path}
              align="center"
              gap={3}
              px={3}
              py={3}
              borderRadius="xl"
              position="relative"
              bg={active ? 'rgba(0,255,178,0.08)' : 'transparent'}
              _hover={{ bg: 'rgba(255,255,255,0.03)' }}
            >
              {active && (
                <Box
                  position="absolute"
                  left={0}
                  top={2}
                  bottom={2}
                  w="3px"
                  borderRadius="full"
                  bg="linear-gradient(180deg, rgba(0,255,178,0.15), #00FFB2, rgba(0,255,178,0.15))"
                  boxShadow="0 0 14px rgba(0,255,178,0.55)"
                />
              )}
              <Icon as={item.icon} boxSize={5} color={active ? 'brand.300' : 'whiteAlpha.700'} />
              {!sidebarCollapsed && (
                <Text
                  fontSize="sm"
                  color={active ? 'whiteAlpha.900' : 'whiteAlpha.700'}
                  whiteSpace="nowrap"
                  overflow="hidden"
                  textOverflow="ellipsis"
                >
                  {item.label}
                </Text>
              )}
            </Flex>
          )

          return sidebarCollapsed ? (
            <Tooltip key={item.path} label={item.label} placement="right">
              {linkContent}
            </Tooltip>
          ) : (
            <Box key={item.path}>{linkContent}</Box>
          )
        })}
      </VStack>
      <Box position="absolute" left={3} right={3} bottom={4}>
        {!sidebarCollapsed && (
          <>
            <Text fontFamily="heading" fontSize="xs" color="whiteAlpha.500">
              v2.0 | 2025–2026
            </Text>
            <Text
              fontSize="xs"
              color="warning.500"
              mt={1}
              noOfLines={2}
              lineHeight="1.25"
              maxW="168px"
            >
              {t('common.educationalOnly')}
            </Text>
          </>
        )}
      </Box>
    </Box>
  )
}
