import { Badge } from '@chakra-ui/react'
import type { Severity } from '../../types'
import { useI18n } from '../../i18n'
import { localizeSeverity } from '../../localization'

const palette: Record<Severity, string> = {
  critical: '#FF3864',
  high: '#ff6b6b',
  medium: '#FFB800',
  low: '#00FFB2',
  info: '#7dd3fc'
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const { locale } = useI18n()
  return (
    <Badge
      px={2.5}
      py={1}
      borderRadius="full"
      bg={`${palette[severity]}22`}
      color={palette[severity]}
      border="1px solid"
      borderColor={`${palette[severity]}55`}
      textTransform="uppercase"
      letterSpacing="0.12em"
    >
      {localizeSeverity(severity, locale)}
    </Badge>
  )
}
