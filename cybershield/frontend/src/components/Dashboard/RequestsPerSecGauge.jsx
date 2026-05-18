import { Gauge } from 'lucide-react'
import clsx from 'clsx'
import useAppStore from '../../store/useAppStore'

/**
 * RequestsPerSecGauge — displays the rolling req/sec metric.
 * Updated in real-time by the 'req_per_sec' socket event.
 * Shows '—' when no traffic received yet.
 */
export default function RequestsPerSecGauge() {
  const rps                = useAppStore(s => s.reqPerSec)
  const hasReceivedTraffic = useAppStore(s => s.hasReceivedTraffic)
  const displayed          = hasReceivedTraffic ? rps.toFixed(2) : '—'

  // Color scale: green → yellow → red
  const color =
    rps === 0     ? '#64748b' :
    rps < 5       ? '#22c55e' :
    rps < 20      ? '#f59e0b' :
                    '#ef4444'

  // Arc fill: 0–100 req/s mapped to 0–100%
  const fillPct = Math.min((rps / 100) * 100, 100)
  const circumference = 2 * Math.PI * 36
  const dashOffset    = circumference * (1 - fillPct / 100)

  return (
    <div className="glass-card p-4 flex flex-col items-center gap-3">
      <div className="flex items-center gap-2 w-full">
        <Gauge className="w-4 h-4 text-cyber-cyan" />
        <h3 className="text-sm font-semibold text-white">Req / sec</h3>
      </div>

      {/* SVG arc gauge */}
      <div className="relative w-24 h-24">
        <svg viewBox="0 0 80 80" className="w-full h-full -rotate-90">
          {/* Background track */}
          <circle cx="40" cy="40" r="36" fill="none" stroke="#1e2433" strokeWidth="7" />
          {/* Fill arc */}
          <circle
            cx="40" cy="40" r="36"
            fill="none"
            stroke={color}
            strokeWidth="7"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={dashOffset}
            style={{ transition: 'stroke-dashoffset 0.5s ease, stroke 0.5s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className="text-xl font-bold tabular-nums leading-none"
            style={{ color }}
          >
            {displayed}
          </span>
          <span className="text-[9px] text-cyber-muted mt-0.5">req/s</span>
        </div>
      </div>

      <p className={clsx(
        'text-[10px] font-medium px-2 py-0.5 rounded-full',
        !hasReceivedTraffic ? 'text-cyber-muted bg-cyber-muted/10' :
        rps === 0           ? 'text-cyber-muted bg-cyber-muted/10' :
        rps < 5             ? 'text-green-400 bg-green-400/10' :
        rps < 20            ? 'text-yellow-400 bg-yellow-400/10' :
                              'text-red-400 bg-red-400/10'
      )}>
        {!hasReceivedTraffic ? 'No traffic' :
         rps === 0           ? 'Idle'        :
         rps < 5             ? 'Normal'      :
         rps < 20            ? 'Elevated'    :
                               'High load'}
      </p>
    </div>
  )
}
