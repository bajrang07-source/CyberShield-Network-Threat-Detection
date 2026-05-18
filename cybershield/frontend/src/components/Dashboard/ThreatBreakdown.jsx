import { useQuery } from '@tanstack/react-query'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import api from '../../lib/api'

const TYPE_COLORS = {
  SQL_INJECTION: '#ef4444',
  XSS: '#f59e0b',
  BRUTE_FORCE: '#8b5cf6',
  ANOMALY: '#3b82f6',
  COMMAND_INJECTION: '#ec4899',
  PATH_TRAVERSAL: '#f97316',
  HONEYPOT_TRAP: '#14b8a6',
  NORMAL: '#22c55e',
  UNKNOWN: '#6b7280',
}

function CustomTooltip({ active, payload }) {
  if (!active || !payload?.length) return null
  const { type, count, percentage } = payload[0].payload
  return (
    <div className="bg-bg-surface border border-bg-border rounded-lg px-3 py-2 text-xs shadow-xl">
      <p className="text-white font-medium">{type}</p>
      <p className="text-cyber-muted">{count} attacks ({percentage}%)</p>
    </div>
  )
}

export default function ThreatBreakdown() {
  const { data, isLoading } = useQuery({
    queryKey: ['threat-breakdown'],
    queryFn: async () => {
      const res = await api.get('/threat-breakdown')
      return res.data
    },
    refetchInterval: 30000,
  })

  const items = data?.by_type || []
  const total = items.reduce((sum, i) => sum + i.count, 0)

  return (
    <div className="glass-card p-6 flex flex-col h-full">
      <div className="mb-4">
        <h3 className="text-base font-semibold text-white">Threat Breakdown</h3>
        <p className="text-xs text-cyber-muted mt-0.5">Attack type distribution (24h)</p>
      </div>

      {isLoading ? (
        <div className="flex-1 flex items-center justify-center">
          <div className="w-8 h-8 border-2 border-accent border-t-transparent rounded-full animate-spin" />
        </div>
      ) : items.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center text-cyber-muted text-sm">
          <span className="text-3xl mb-2">🛡️</span>
          <p>No threats detected</p>
        </div>
      ) : (
        <>
          {/* Donut chart */}
          <div className="relative flex items-center justify-center" style={{ height: 180 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={items}
                  dataKey="count"
                  nameKey="type"
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={80}
                  strokeWidth={2}
                  stroke="transparent"
                >
                  {items.map((entry, i) => (
                    <Cell
                      key={entry.type}
                      fill={TYPE_COLORS[entry.type] || '#6b7280'}
                    />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
            {/* Center label */}
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <p className="text-2xl font-bold text-white">{total}</p>
              <p className="text-xs text-cyber-muted">Attacks</p>
            </div>
          </div>

          {/* Legend */}
          <div className="mt-4 space-y-2 flex-1 overflow-auto">
            {items.map(item => (
              <div key={item.type} className="flex items-center gap-2.5 text-xs">
                <span
                  className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                  style={{ backgroundColor: TYPE_COLORS[item.type] || '#6b7280' }}
                />
                <span className="text-white flex-1 font-medium">{item.type}</span>
                <span className="text-cyber-muted tabular-nums">{item.count}</span>
                <span
                  className="text-xs font-semibold tabular-nums w-10 text-right"
                  style={{ color: TYPE_COLORS[item.type] || '#6b7280' }}
                >
                  {item.percentage}%
                </span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
