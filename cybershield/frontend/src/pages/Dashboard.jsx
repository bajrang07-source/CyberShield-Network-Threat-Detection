import { Activity, AlertTriangle, Ban, BarChart2, Wifi } from 'lucide-react'
import { useStats } from '../hooks/useStats'
import { useSocketFeed } from '../hooks/useSocketFeed'
import useAppStore from '../store/useAppStore'

import StatCard             from '../components/Dashboard/StatCard'
import LiveTrafficChart     from '../components/Dashboard/LiveTrafficChart'
import ThreatBreakdown      from '../components/Dashboard/ThreatBreakdown'
import ThreatFeed           from '../components/Dashboard/ThreatFeed'
import LiveRequestFeed      from '../components/Dashboard/LiveRequestFeed'
import RequestsPerSecGauge  from '../components/Dashboard/RequestsPerSecGauge'
import TopSuspiciousIPs     from '../components/Dashboard/TopSuspiciousIPs'
import ResponseTimeGraph    from '../components/Dashboard/ResponseTimeGraph'

export default function Dashboard() {
  const { data: stats, isLoading: statsLoading } = useStats()
  const { chartData, recentAttacks }              = useSocketFeed()
  const liveAttacks        = useAppStore(s => s.liveAttacks)
  const connectionCount    = useAppStore(s => s.connectionCount)
  const hasReceivedTraffic = useAppStore(s => s.hasReceivedTraffic)

  // Prefer socket-pushed stats (from store) over REST-polled stats
  const storeStats = useAppStore(s => s.stats)
  const s = {
    ...(stats || {}),
    // Socket-pushed values take precedence when traffic has been received
    total_requests:   hasReceivedTraffic ? (storeStats.total_requests   || stats?.total_requests   || 0) : (stats?.total_requests   ?? 0),
    attacks_detected: hasReceivedTraffic ? (storeStats.attacks_detected || stats?.attacks_detected || 0) : (stats?.attacks_detected ?? 0),
    blocked_ips:      hasReceivedTraffic ? (storeStats.blocked_ips      || stats?.blocked_ips      || 0) : (stats?.blocked_ips      ?? 0),
    avg_risk_score:   stats?.avg_risk_score ?? 0,
  }

  const attacks = liveAttacks.length > 0 ? liveAttacks : recentAttacks

  return (
    <div className="space-y-6">

      {/* Row 1: Stat Cards — no hardcoded trends, real data only */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          title="Total Requests"
          value={s.total_requests}
          icon={Activity}
          color="#6366f1"
        />
        <StatCard
          title="Attacks Detected"
          value={s.attacks_detected}
          icon={AlertTriangle}
          color="#ef4444"
        />
        <StatCard
          title="Blocked IPs"
          value={s.blocked_ips}
          icon={Ban}
          color="#f59e0b"
        />
        <StatCard
          title="Avg Risk Score"
          value={Math.round(s.avg_risk_score)}
          icon={BarChart2}
          color="#22c55e"
        />
      </div>

      {/* Row 2: Req/sec gauge + Live chart + Threat breakdown */}
      <div className="grid grid-cols-12 gap-4">
        {/* Gauge */}
        <div className="col-span-2">
          <RequestsPerSecGauge />
        </div>
        {/* Chart (wider) */}
        <div className="col-span-7">
          <LiveTrafficChart data={chartData} />
        </div>
        {/* Breakdown */}
        <div className="col-span-3">
          <ThreatBreakdown />
        </div>
      </div>

      {/* Row 3: Top Suspicious IPs + Response Time */}
      <div className="grid grid-cols-2 gap-4">
        <TopSuspiciousIPs />
        <ResponseTimeGraph />
      </div>

      {/* Row 4: Live Request Feed (all traffic) */}
      <LiveRequestFeed />

      {/* Row 5: Threat Feed (attacks only) */}
      <ThreatFeed attacks={attacks} />

      {/* Connection status footer */}
      {connectionCount > 0 && (
        <div className="flex items-center justify-end gap-2 text-xs text-cyber-muted">
          <Wifi className="w-3 h-3 text-green-400" />
          <span>{connectionCount} dashboard client{connectionCount !== 1 ? 's' : ''} connected</span>
        </div>
      )}

    </div>
  )
}
