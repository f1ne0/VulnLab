import { extendTheme, type ThemeConfig } from '@chakra-ui/react'

const config: ThemeConfig = {
  initialColorMode: 'dark',
  useSystemColorMode: false
}

const theme = extendTheme({
  config,
  colors: {
    brand: {
      50: '#e0fff5',
      100: '#b3ffe3',
      200: '#66ffc5',
      300: '#00ffb2',
      400: '#00e5a0',
      500: '#00cc8f',
      600: '#00a373',
      700: '#007a56',
      800: '#00523a',
      900: '#00291d'
    },
    danger: { 500: '#FF3864' },
    warning: { 500: '#FFB800' },
    surface: { 700: '#0d1117', 800: '#0a0e14', 900: '#060910' }
  },
  fonts: {
    heading: "'IBM Plex Mono', monospace",
    body: "'Instrument Sans', sans-serif",
    mono: "'JetBrains Mono', monospace"
  },
  styles: {
    global: {
      body: {
        bg: 'surface.900',
        color: 'whiteAlpha.900'
      },
      pre: {
        whiteSpace: 'pre-wrap !important',
        wordBreak: 'break-word !important',
        maxWidth: '100%',
        overflowX: 'auto'
      }
    }
  },
  components: {
    Button: {
      variants: {
        terminal: {
          bg: 'transparent',
          border: '1px solid',
          borderColor: 'brand.500',
          color: 'brand.300',
          fontFamily: 'mono',
          letterSpacing: '0.08em',
          _hover: {
            bg: 'rgba(0,255,178,0.08)',
            boxShadow: '0 0 20px rgba(0,255,178,0.3)'
          }
        }
      }
    },
    Heading: {
      baseStyle: {
        whiteSpace: 'normal',
        overflowWrap: 'anywhere',
        wordBreak: 'break-word',
        maxWidth: '100%'
      }
    },
    Card: {
      baseStyle: {
        container: {
          bg: 'rgba(255,255,255,0.03)',
          border: '1px solid rgba(0,255,178,0.08)',
          backdropFilter: 'blur(10px)',
          transition: 'all 0.2s ease',
          _hover: {
            borderColor: 'rgba(0,255,178,0.25)',
            transform: 'translateY(-2px)'
          }
        }
      }
    },
    Tabs: {
      variants: {
        enclosed: {
          tab: {
            borderColor: 'rgba(0,255,178,0.12)',
            color: 'whiteAlpha.800',
            _selected: {
              bg: 'rgba(0,255,178,0.08)',
              color: 'brand.300'
            }
          }
        }
      }
    }
  }
})

export default theme
