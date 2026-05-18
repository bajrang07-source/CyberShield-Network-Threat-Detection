import { useEffect, useRef, useState } from 'react'
import { TrendingUp, TrendingDown, Minus } from 'lucide-react'
import { LineChart, Line, ResponsiveContainer } from 'recharts'
import clsx from 'clsx'

function useCountUp(target, duration = 800) {
  const [value, setValue] = useState(0)
  const raf = useRef(null)
  const startRef = useRef(null)
  const startValRef = useRef(0)

  useEffect(() => {
    const start = performance.now()
    const startVal = value
    startRef.current = start
    startValRef.current = startVal

    const animate = (now) => {
      const elapsed = now - startRef.current
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setValue(Math.round(startValRef.current + (target - startValRef.current) * eased))
      if (progress < 1) raf.current = requestAnimationFrame(animate)
    }

    raf.current = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(raf.current)
  }, [target])

  return value
}

// Empty flat sparkline — shown when no real traffic data is available yet
const EMPTY_SPARKLINE = Array.from({ length: 7 }, () => ({ v: 0 }))

/**
 * StatCard — displays real traffic-driven data only.
 * sparklineData: real rolling [{v: number}] points. Defaults to flat zero line (no random data).
 * trend: computed from real before/after values. Pass undefined = no trend indicator shown.
 */
export default function StatCard({ title, value, icon: Icon, trend, color = '#6366f1', sparklineData }) {
  const displayed = useCountUp(typeof value === 'number' ? value : 0)
  const sparkline = (sparklineData && sparklineData.length > 0) ? sparklineData : EMPTY_SPARKLINE

  return (
    <div className="glass-card p-6 flex flex-col gap-4 hover:border-indigo-500/30 transition-all duration-300 animate-fade-in">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-cyber-muted uppercase tracking-wider mb-1">{title}</p>
          <p className="text-3xl font-bold text-white tabular-nums">
            {typeof value === 'number' ? displayed.toLocaleString() : value ?? '—'}
          </p>
        </div>
        <div
          className="p-3 rounded-xl flex-shrink-0"
          style={{ backgroundColor: `${color}20`, border: `1px solid ${color}30` }}
        >
          <Icon className="w-5 h-5" style={{ color }} />
        </div>
      </div>

      <div className="flex items-end justify-between gap-3">
        <div className="h-10 flex-1">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={sparkline}>
              <Line
                type="monotone"
                dataKey="v"
                stroke={color}
                strokeWidth={1.5}
                dot={false}
                isAnimationActive={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Trend arrow — only shown when real comparison data is passed */}
        {trend !== undefined && trend !== null ? (
          <div
            className={clsx(
              'flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full',
              trend > 0 ? 'bg-success/10 text-success'
              : trend < 0 ? 'bg-danger/10 text-danger'
              : 'bg-cyber-muted/10 text-cyber-muted'
            )}
          >
            {trend > 0 ? <TrendingUp className="w-3 h-3" />
             : trend < 0 ? <TrendingDown className="w-3 h-3" />
             : <Minus className="w-3 h-3" />}
            {trend !== 0 ? `${Math.abs(trend)}%` : 'Stable'}
          </div>
        ) : null}
      </div>
    </div>
  )
}
