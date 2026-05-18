import { useEffect, useRef } from 'react'
import { format } from 'date-fns'
import { Activity, Shield, ShieldAlert } from 'lucide-react'
import clsx from 'clsx'
import useAppStore from '../../store/useAppStore'

const METHOD_COLORS = {
  GET:    'text-blue-400 bg-blue-400/10',
  POST:   'text-green-400 bg-green-400/10',
  PUT:    'text-yellow-400 bg-yellow-400/10',
  DELETE: 'text-red-400 bg-red-400/10',
  PATCH:  'text-purple-400 bg-purple-400/10',
}

function RequestRow({ req, isNew }) {
  const methodStyle = METHOD_COLORS[req.method] || 'text-cyber-muted bg-cyber-muted/10'
  const isAttack = req.is_attack || req.risk_score >= 40

  return (
    <tr className={clsx('table-row-base text-xs transition-all duration-300', isNew && 'row-new')}>
      <td className="py-2 px-3 font-mono text-cyber-muted whitespace-nowrap">
        {format(new Date(req.timestamp || Date.now()), 'HH:mm:ss')}
      </td>
      <td className="py-2 px-3">
        <span className={clsx('px-1.5 py-0.5 rounded text-[10px] font-bold font-mono', methodStyle)}>
          {req.method}
        </span>
      </td>
      <td className="py-2 px-3 font-mono text-cyber-cyan truncate max-w-[160px]" title={req.path}>
        {req.path}
      </td>
      <td className="py-2 px-3 font-mono text-cyber-muted">{req.ip}</td>
      <td className="py-2 px-3">
        {isAttack ? (
          <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
        ) : (
          <Shield className="w-3.5 h-3.5 text-green-500/50" />
        )}
      </td>
      <td className="py-2 px-3">
        <span
          className={clsx(
            'text-[10px] font-bold tabular-nums',
            req.risk_score >= 80 ? 'text-red-400' :
            req.risk_score >= 60 ? 'text-orange-400' :
            req.risk_score >= 40 ? 'text-yellow-400' :
            'text-green-400'
          )}
        >
          {Math.round(req.risk_score ?? 0)}
        </span>
      </td>
    </tr>
  )
}

/**
 * LiveRequestFeed — real-time feed of ALL incoming requests.
 * Populated exclusively by the socket 'request_live' event.
 * Shows empty state when no traffic has been received.
 */
export default function LiveRequestFeed() {
  const liveRequests       = useAppStore(s => s.liveRequests)
  const hasReceivedTraffic = useAppStore(s => s.hasReceivedTraffic)
  const tbodyRef           = useRef(null)
  const newIdsRef          = useRef(new Set())
  const prevCountRef       = useRef(0)

  useEffect(() => {
    if (liveRequests.length > prevCountRef.current) {
      const newest = liveRequests[0]
      if (newest?.id) {
        newIdsRef.current.add(newest.id)
        setTimeout(() => newIdsRef.current.delete(newest.id), 1500)
      }
    }
    prevCountRef.current = liveRequests.length
  }, [liveRequests.length])

  if (!hasReceivedTraffic || liveRequests.length === 0) {
    return (
      <div className="glass-card p-6">
        <div className="flex items-center gap-2 mb-4">
          <Activity className="w-4 h-4 text-cyber-cyan" />
          <h3 className="text-sm font-semibold text-white">Live Request Feed</h3>
          <span className="ml-auto flex items-center gap-1.5 text-xs text-cyber-muted">
            <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
            Monitoring
          </span>
        </div>
        <div className="flex flex-col items-center justify-center py-10 text-cyber-muted">
          <Activity className="w-8 h-8 mb-3 opacity-30" />
          <p className="text-sm font-medium">No traffic detected</p>
          <p className="text-xs mt-1 opacity-60">Waiting for incoming requests…</p>
        </div>
      </div>
    )
  }

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-4 py-3 border-b border-bg-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyber-cyan" />
          <h3 className="text-sm font-semibold text-white">Live Request Feed</h3>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-cyber-muted">{liveRequests.length} captured</span>
          <span className="flex items-center gap-1.5 text-xs text-green-400">
            <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
            Live
          </span>
        </div>
      </div>

      <div className="overflow-auto max-h-64">
        <table className="w-full">
          <thead>
            <tr className="text-[10px] uppercase tracking-wider text-cyber-muted border-b border-bg-border">
              <th className="px-3 py-2 text-left font-medium">Time</th>
              <th className="px-3 py-2 text-left font-medium">Method</th>
              <th className="px-3 py-2 text-left font-medium">Path</th>
              <th className="px-3 py-2 text-left font-medium">IP</th>
              <th className="px-3 py-2 text-left font-medium">Threat</th>
              <th className="px-3 py-2 text-left font-medium">Risk</th>
            </tr>
          </thead>
          <tbody ref={tbodyRef}>
            {liveRequests.map((req, i) => (
              <RequestRow
                key={req.id || i}
                req={req}
                isNew={newIdsRef.current.has(req.id)}
              />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
