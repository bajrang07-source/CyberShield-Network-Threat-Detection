import { Clock } from 'lucide-react'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid,
} from 'recharts'
import { format } from 'date-fns'
import useAppStore from '../../store/useAppStore'

/**
 * ResponseTimeGraph — sparkline of per-request response latency.
 * Only active when proxy mode is used (response times are captured there).
 * Shown with empty state when no response time data is available.
 */
export default function ResponseTimeGraph() {
  const responseTimes      = useAppStore(s => s.responseTimes)
  const hasReceivedTraffic = useAppStore(s => s.hasReceivedTraffic)

  // Format data for Recharts
  const chartData = responseTimes.map(entry => ({
    t:  entry.t,
    ms: Math.round(entry.ms ?? 0),
    label: entry.t ? format(new Date(entry.t), 'HH:mm:ss') : '',
  }))

  const avg = chartData.length > 0
    ? Math.round(chartData.reduce((s, d) => s + d.ms, 0) / chartData.length)
    : null
  const max = chartData.length > 0
    ? Math.max(...chartData.map(d => d.ms))
    : null

  if (!hasReceivedTraffic || responseTimes.length === 0) {
    return (
      <div className="glass-card p-4">
        <div className="flex items-center gap-2 mb-3">
          <Clock className="w-4 h-4 text-cyber-cyan" />
          <h3 className="text-sm font-semibold text-white">Response Times</h3>
          <span className="ml-auto text-[10px] text-cyber-muted px-1.5 py-0.5 rounded bg-cyber-muted/10">
            Proxy mode only
          </span>
        </div>
        <div className="flex flex-col items-center justify-center py-6 text-cyber-muted">
          <Clock className="w-7 h-7 mb-2 opacity-25" />
          <p className="text-xs font-medium">No latency data</p>
          <p className="text-[10px] mt-1 opacity-60">
            Response times are captured when using proxy mode
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="glass-card p-4">
      <div className="flex items-center gap-2 mb-3">
        <Clock className="w-4 h-4 text-cyber-cyan" />
        <h3 className="text-sm font-semibold text-white">Response Times</h3>
        <div className="ml-auto flex items-center gap-3 text-[10px] text-cyber-muted">
          {avg !== null && (
            <span>avg <strong className="text-white">{avg}ms</strong></span>
          )}
          {max !== null && (
            <span>max <strong className="text-orange-400">{max}ms</strong></span>
          )}
        </div>
      </div>

      <div className="h-28">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
            <defs>
              <linearGradient id="rtGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor="#6366f1" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#6366f1" stopOpacity={0}   />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e2433" vertical={false} />
            <XAxis dataKey="label" tick={false} axisLine={false} tickLine={false} />
            <YAxis
              tick={{ fill: '#64748b', fontSize: 9 }}
              axisLine={false}
              tickLine={false}
              tickFormatter={v => `${v}ms`}
            />
            <Tooltip
              contentStyle={{
                background: '#0d1117',
                border: '1px solid #1e2433',
                borderRadius: 6,
                fontSize: 11,
              }}
              labelStyle={{ color: '#94a3b8' }}
              itemStyle={{ color: '#6366f1' }}
              formatter={(v) => [`${v}ms`, 'Response time']}
            />
            <Area
              type="monotone"
              dataKey="ms"
              stroke="#6366f1"
              strokeWidth={1.5}
              fill="url(#rtGrad)"
              dot={false}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
