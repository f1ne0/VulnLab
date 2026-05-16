import { useEffect, useMemo, useState } from 'react'

const CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#$%&?'

function randomChar() {
  return CHARSET[Math.floor(Math.random() * CHARSET.length)]
}

export function useDecryptText(text: string, duration = 1200) {
  const letters = useMemo(() => text.split(''), [text])
  const [displayText, setDisplayText] = useState(text)

  useEffect(() => {
    const start = performance.now()
    let frameId = 0

    const tick = (timestamp: number) => {
      const progress = Math.min((timestamp - start) / duration, 1)
      const resolved = Math.floor(progress * letters.length)

      const next = letters
        .map((character, index) => {
          if (character === ' ') {
            return ' '
          }

          return index < resolved ? character : randomChar()
        })
        .join('')

      setDisplayText(next)

      if (progress < 1) {
        frameId = window.requestAnimationFrame(tick)
      }
    }

    frameId = window.requestAnimationFrame(tick)
    return () => window.cancelAnimationFrame(frameId)
  }, [duration, letters, text])

  return displayText
}
