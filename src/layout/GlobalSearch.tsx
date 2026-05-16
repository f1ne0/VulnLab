import {
  Box,
  Input,
  List,
  ListItem,
  Modal,
  ModalBody,
  ModalContent,
  ModalOverlay,
  Text,
  VStack
} from '@chakra-ui/react'
import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { vulnerabilities } from '../data/vulnerabilities'
import { jurisdictionProfiles } from '../data/legal'
import { payloadLibrary } from '../data/payloadLibrary'
import { useUiStore } from '../store/uiStore'
import { useI18n } from '../i18n'

interface SearchItem {
  id: string
  title: string
  subtitle: string
  path: string
}

export function GlobalSearch() {
  const navigate = useNavigate()
  const { searchOpen, setSearchOpen } = useUiStore()
  const [query, setQuery] = useState('')
  const { t } = useI18n()

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setSearchOpen(true)
      }
    }

    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [setSearchOpen])

  const items = useMemo<SearchItem[]>(() => {
    const vulnItems = vulnerabilities.map((item) => ({
      id: item.id,
      title: item.name,
      subtitle: `${item.owaspId} · ${item.category}`,
      path: `/vulnerabilities/${item.id}`
    }))
    const legalItems = jurisdictionProfiles.map((profile) => ({
      id: profile.id,
      title: profile.title,
      subtitle: profile.laws.map((law) => law.article).join(' · '),
      path: '/legal'
    }))
    const payloadItems = payloadLibrary.slice(0, 12).map((payload) => ({
      id: payload.id,
      title: payload.title,
      subtitle: `${payload.type.toUpperCase()} payload`,
      path: '/lab'
    }))
    return [...vulnItems, ...legalItems, ...payloadItems]
  }, [])

  const filtered = items.filter((item) => `${item.title} ${item.subtitle}`.toLowerCase().includes(query.toLowerCase()))

  return (
    <Modal isOpen={searchOpen} onClose={() => setSearchOpen(false)} size="xl" isCentered>
      <ModalOverlay bg="rgba(2,4,8,0.8)" backdropFilter="blur(8px)" />
      <ModalContent bg="#08111d" border="1px solid rgba(0,255,178,0.12)" overflow="hidden">
        <ModalBody p={0}>
          <Box p={4} borderBottom="1px solid rgba(0,255,178,0.08)">
            <Input
              autoFocus
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={t('search.placeholder')}
              variant="unstyled"
              fontSize="lg"
              color="white"
            />
          </Box>
          <List maxH="420px" overflowY="auto">
            {filtered.map((item) => (
              <ListItem
                key={item.id}
                px={4}
                py={3}
                borderBottom="1px solid rgba(255,255,255,0.03)"
                cursor="pointer"
                _hover={{ bg: 'rgba(0,255,178,0.06)' }}
                onClick={() => {
                  navigate(item.path)
                  setSearchOpen(false)
                }}
              >
                <VStack align="stretch" spacing={1} minW={0}>
                  <Text fontFamily="heading" color="brand.300" wordBreak="break-word">
                    {item.title}
                  </Text>
                  <Text fontSize="sm" color="whiteAlpha.700" wordBreak="break-word" noOfLines={2}>
                    {item.subtitle}
                  </Text>
                </VStack>
              </ListItem>
            ))}
          </List>
        </ModalBody>
      </ModalContent>
    </Modal>
  )
}
