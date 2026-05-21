import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts'

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-bg-surface border border-bg-border rounded-lg px-3 py-2 text-xs shadow-xl">
      <p className="text-cyber-muted mb-1 font-mono">{label}</p>
      {payload.map(p => (
        <div key={p.name} className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full" style={{ backgroundColor: p.color }} />
          <span className="text-white font-medium">{p.name}:</span>
          <span style={{ color: p.color }}>{p.value}</span>
        </div>
      ))}
    </div>
  )
}

export default function LiveTrafficChart({ data }) {
  const displayData = data || []

  // Show every 10th label on x-axis
  const tickFormatter = (val, idx) => {
    if (!val) return ''
    if (idx % 10 !== 0) return ''
    return val
  }

  return (
    <div className="glass-card p-6" style={{ height: '300px' }}>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-base font-semibold text-white">Live Traffic</h3>
          <p className="text-xs text-cyber-muted mt-0.5">Real-time request feed — last 60 seconds</p>
        </div>
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 bg-indigo-400 rounded" />
            <span className="text-cyber-muted">Normal</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 bg-red-400 rounded" />
            <span className="text-cyber-muted">Attacks</span>
          </div>
        </div>
      </div>

      <ResponsiveContainer width="100%" height={280}>
        <AreaChart data={displayData} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="colorNormal" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="colorAttack" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(31,41,55,0.8)" vertical={false} />
          <XAxis
            dataKey="time"
            tick={{ fill: '#6b7280', fontSize: 10, fontFamily: 'JetBrains Mono' }}
            tickLine={false}
            axisLine={false}
            tickFormatter={tickFormatter}
          />
          <YAxis
            tick={{ fill: '#6b7280', fontSize: 10 }}
            tickLine={false}
            axisLine={false}
          />
          <Tooltip content={<CustomTooltip />} />
          <Area
            type="monotone"
            dataKey="normal"
            name="Normal"
            stroke="#818cf8"
            strokeWidth={1.5}
            fill="url(#colorNormal)"
            isAnimationActive
            animationDuration={300}
          />
          <Area
            type="monotone"
            dataKey="attack"
            name="Attacks"
            stroke="#f87171"
            strokeWidth={1.5}
            fill="url(#colorAttack)"
            isAnimationActive
            animationDuration={300}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
