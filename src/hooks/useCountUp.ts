import { useEffect, useState } from 'react'

export function useCountUp(target: number, duration = 900) {
  const [value, setValue] = useState(0)

  useEffect(() => {
    const start = performance.now()
    let frameId = 0

    const tick = (timestamp: number) => {
      const progress = Math.min((timestamp - start) / duration, 1)
      setValue(Math.round(target * progress))
      if (progress < 1) {
        frameId = requestAnimationFrame(tick)
      }
    }

    frameId = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frameId)
  }, [duration, target])

  return value
}
