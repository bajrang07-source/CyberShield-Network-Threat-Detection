import { AlertTriangle, Flame } from 'lucide-react'
import clsx from 'clsx'
import useAppStore from '../../store/useAppStore'

/**
 * TopSuspiciousIPs — real-time leaderboard of most suspicious IPs.
 * Updated via 'top_ips_update' socket event (fires after medium+ threats).
 * Shows empty state when no suspicious activity has been detected.
 */
export default function TopSuspiciousIPs() {
  const topIPs             = useAppStore(s => s.topSuspiciousIPs)
  const hasReceivedTraffic = useAppStore(s => s.hasReceivedTraffic)

  if (!hasReceivedTraffic || topIPs.length === 0) {
    return (
      <div className="glass-card p-4">
        <div className="flex items-center gap-2 mb-4">
          <AlertTriangle className="w-4 h-4 text-yellow-400" />
          <h3 className="text-sm font-semibold text-white">Top Suspicious IPs</h3>
        </div>
        <div className="flex flex-col items-center justify-center py-6 text-cyber-muted">
          <AlertTriangle className="w-7 h-7 mb-2 opacity-25" />
          <p className="text-xs font-medium">
            {hasReceivedTraffic ? 'No suspicious IPs detected' : 'No traffic detected'}
          </p>
          <p className="text-[10px] mt-1 opacity-60">
            {hasReceivedTraffic
              ? 'All traffic appears normal so far'
              : 'Waiting for incoming requests…'}
          </p>
        </div>
      </div>
    )
  }

  const maxScore = Math.max(...topIPs.map(ip => ip.behavioral_score || 0), 1)

  return (
    <div className="glass-card p-4">
      <div className="flex items-center gap-2 mb-4">
        <AlertTriangle className="w-4 h-4 text-yellow-400" />
        <h3 className="text-sm font-semibold text-white">Top Suspicious IPs</h3>
        <span className="ml-auto text-[10px] text-cyber-muted">{topIPs.length} tracked</span>
      </div>

      <div className="space-y-3">
        {topIPs.map((entry, i) => {
          const pct   = Math.min(((entry.behavioral_score || 0) / maxScore) * 100, 100)
          const color =
            entry.behavioral_score >= 70 ? '#ef4444' :
            entry.behavioral_score >= 40 ? '#f59e0b' :
                                           '#22c55e'

          return (
            <div key={entry.ip}>
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2">
                  {i === 0 && <Flame className="w-3 h-3 text-red-400 flex-shrink-0" />}
                  <span className="text-xs font-mono text-cyber-cyan truncate max-w-[130px]">
                    {entry.ip}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  {/* Signal badges */}
                  {entry.burst_count > 20 && (
                    <span className="text-[9px] px-1 py-0.5 rounded bg-red-500/15 text-red-400">burst</span>
                  )}
                  {entry.scan_count > 10 && (
                    <span className="text-[9px] px-1 py-0.5 rounded bg-orange-500/15 text-orange-400">scan</span>
                  )}
                  {entry.login_fail_count > 5 && (
                    <span className="text-[9px] px-1 py-0.5 rounded bg-purple-500/15 text-purple-400">brute</span>
                  )}
                  <span
                    className="text-[10px] font-bold tabular-nums"
                    style={{ color }}
                  >
                    {Math.round(entry.behavioral_score)}
                  </span>
                </div>
              </div>
              {/* Progress bar */}
              <div className="h-1 bg-bg-border rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-700"
                  style={{ width: `${pct}%`, backgroundColor: color }}
                />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
