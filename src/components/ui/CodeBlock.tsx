import { Box } from '@chakra-ui/react'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism'

export function CodeBlock({ language, code }: { language: string; code: string }) {
  return (
    <Box border="1px solid rgba(0,255,178,0.1)" borderRadius="xl" overflow="hidden" maxW="100%" minW={0}>
      <SyntaxHighlighter
        language={language}
        style={oneDark}
        customStyle={{
          margin: 0,
          background: 'rgba(5, 9, 16, 0.92)',
          fontSize: '0.85rem',
          minHeight: '100%',
          maxWidth: '100%',
          overflowX: 'auto',
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word'
        }}
      >
        {code}
      </SyntaxHighlighter>
    </Box>
  )
}
