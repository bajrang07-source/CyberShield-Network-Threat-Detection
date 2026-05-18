import { useState, useEffect, useCallback, useRef } from 'react'
import { onRequestTick, offRequestTick } from '../lib/socket'
import { format } from 'date-fns'

const MAX_POINTS = 60

function getKey(date) {
  return format(new Date(date), 'HH:mm:ss')
}

export function useSocketFeed() {
  const [chartData, setChartData] = useState(() =>
    Array.from({ length: MAX_POINTS }, (_, i) => ({
      time: '',
      normal: 0,
      attack: 0,
    }))
  )
  const [recentAttacks, setRecentAttacks] = useState([])
  const bufferRef = useRef({})

  const handleTick = useCallback((data) => {
    const key = getKey(data.timestamp || new Date())
    const isAttack = data.is_attack || data.risk_score >= 40

    bufferRef.current[key] = bufferRef.current[key] || { time: key, normal: 0, attack: 0 }
    if (isAttack) {
      bufferRef.current[key].attack += 1
    } else {
      bufferRef.current[key].normal += 1
    }

    // Keep rolling 60-point window
    const keys = Object.keys(bufferRef.current).sort()
    while (keys.length > MAX_POINTS) {
      delete bufferRef.current[keys.shift()]
    }

    const points = keys.map(k => bufferRef.current[k])
    // Pad to MAX_POINTS
    const padded = [
      ...Array.from({ length: Math.max(0, MAX_POINTS - points.length) }, (_, i) => ({
        time: '', normal: 0, attack: 0,
      })),
      ...points,
    ]

    setChartData(padded)

    if (isAttack) {
      setRecentAttacks(prev => [data, ...prev].slice(0, 20))
    }
  }, [])

  useEffect(() => {
    onRequestTick(handleTick)
    return () => offRequestTick(handleTick)
  }, [handleTick])

  return { chartData, recentAttacks }
}
