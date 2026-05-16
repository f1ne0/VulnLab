import { Text, type TextProps } from '@chakra-ui/react'
import { useDecryptText } from '../../hooks/useDecryptText'

interface DecryptTextProps extends TextProps {
  text: string
  duration?: number
}

export function DecryptText({ text, duration, ...props }: DecryptTextProps) {
  const display = useDecryptText(text, duration)
  return (
    <Text
      {...props}
      fontFamily="heading"
      display="block"
      maxW="100%"
      whiteSpace="normal"
      overflowWrap="anywhere"
      wordBreak="break-word"
      lineHeight="0.95"
    >
      {display}
    </Text>
  )
}
