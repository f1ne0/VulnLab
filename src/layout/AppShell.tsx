import {
  Box,
  Flex,
  Text,
  useDisclosure,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Button
} from '@chakra-ui/react'
import { useEffect } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'
import { GlobalSearch } from './GlobalSearch'
import { useUiStore } from '../store/uiStore'
import { useI18n } from '../i18n'

function CursorTelemetry() {
  const { coordinates, setCoordinates } = useUiStore()

  useEffect(() => {
    const onMove = (event: MouseEvent) => setCoordinates(event.clientX, event.clientY)
    window.addEventListener('mousemove', onMove)
    return () => window.removeEventListener('mousemove', onMove)
  }, [setCoordinates])

  return (
    <Box position="fixed" top={4} right={4} zIndex={50} pointerEvents="none">
      <Box border="1px solid rgba(0,255,178,0.18)" borderRadius="xl" px={3} py={2} bg="rgba(4,7,13,0.8)" backdropFilter="blur(8px)">
        <Text fontFamily="heading" fontSize="xs" color="brand.300">
          X:{coordinates.x.toString().padStart(4, '0')} Y:{coordinates.y.toString().padStart(4, '0')}
        </Text>
      </Box>
      <Box
        position="fixed"
        left={`${coordinates.x - 16}px`}
        top={`${coordinates.y - 16}px`}
        w="32px"
        h="32px"
        border="1px solid rgba(0,255,178,0.5)"
        borderRadius="full"
        _after={{
          content: '""',
          position: 'absolute',
          inset: '6px',
          bg: 'brand.300',
          borderRadius: 'full'
        }}
      />
    </Box>
  )
}

export function AppShell() {
  const location = useLocation()
  const { t } = useI18n()
  const { isOpen, onOpen, onClose } = useDisclosure({
    defaultIsOpen: window.localStorage.getItem('ethicsAgreed') !== 'true'
  })

  useEffect(() => {
    if (window.localStorage.getItem('ethicsAgreed') !== 'true') {
      onOpen()
    }
  }, [onOpen])

  useEffect(() => {
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }, [location.pathname])

  return (
    <Flex minH="100vh">
      <Sidebar />
      <Box flex="1" position="relative" minW={0}>
        <CursorTelemetry />
        <GlobalSearch />
        <Box px={{ base: 4, md: 8 }} py={6} minW={0} overflowX="hidden">
          <TopBar />
          <Box mt={6} minW={0} overflowX="hidden">
            <Outlet />
          </Box>
        </Box>
      </Box>
      <Modal isOpen={isOpen} onClose={() => undefined} isCentered closeOnEsc={false} closeOnOverlayClick={false}>
        <ModalOverlay bg="rgba(2,4,8,0.86)" />
        <ModalContent bg="#08111d" border="1px solid rgba(0,255,178,0.15)" position="relative" overflow="hidden">
          <Box
            position="absolute"
            right={6}
            top={6}
            px={4}
            py={1}
            border="1px solid rgba(255,56,100,0.4)"
            color="danger.500"
            fontFamily="heading"
            fontSize="xs"
            transform="rotate(-6deg)"
            animation="stamp 0.8s ease-out forwards"
          >
            {t('shell.ethicsStamp')}
          </Box>
          <ModalHeader fontFamily="heading" color="brand.300">
            {t('ethics.title')}
          </ModalHeader>
          <ModalBody color="whiteAlpha.850">
            {t('ethics.body')}
          </ModalBody>
          <ModalFooter>
            <Button
              variant="terminal"
              onClick={() => {
                window.localStorage.setItem('ethicsAgreed', 'true')
                onClose()
              }}
            >
              {t('ethics.confirm')}
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Flex>
  )
}
