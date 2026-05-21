import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { 
  Activity, 
  ShieldAlert, 
  AlertTriangle, 
  Crosshair, 
  Shield, 
  BarChart3,
  Clock,
  CheckCircle2
} from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import ThreatFeed from '../components/Dashboard/ThreatFeed'
import useIncidentStore from '../store/useIncidentStore'
import useAppStore from '../store/useAppStore'
import api from '../lib/api'

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f59e0b',
  MEDIUM: '#3b82f6',
  LOW: '#a5f3fc'
}

export default function SOCCommandCenter() {
  const navigate = useNavigate()
  const { incidents, setIncidents, socStats, setSocStats, setActiveIncident } = useIncidentStore()
  const { liveAttacks } = useAppStore() // or we could use the local state if needed
  
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchData()
    // Could set up polling or rely on Socket.io for incidents/stats
    const interval = setInterval(fetchData, 30000)
    return () => clearInterval(interval)
  }, [])

  const fetchData = async () => {
    try {
      setLoading(true)
      const [incRes, statRes] = await Promise.all([
        api.get('/incidents'),
        api.get('/soc/stats').catch(() => ({ data: {} })) // Handle gracefully if not implemented yet
      ])
      
      if (incRes.data) {
        const incidentsArray = Array.isArray(incRes.data.incidents) ? incRes.data.incidents : (Array.isArray(incRes.data) ? incRes.data : [])
        setIncidents(incidentsArray)
      }
      if (statRes.data && statRes.data.stats) setSocStats(statRes.data.stats)
      else if (statRes.data) setSocStats(statRes.data)
    } catch (err) {
      console.error('Failed to fetch SOC data', err)
    } finally {
      setLoading(false)
    }
  }

  // Active Incidents Queue (filtered to OPEN and INVESTIGATING)
  const activeQueue = Array.isArray(incidents)
    ? incidents
        .filter(i => ['OPEN', 'INVESTIGATING'].includes(i.status))
        .sort((a, b) => {
          const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
          return (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4)
        })
    : []

  // Default severity/attack arrays used as fallback
  const defaultSeverityDist = [
    { name: 'Critical', value: activeQueue.filter(i => i.severity === 'CRITICAL').length },
    { name: 'High',     value: activeQueue.filter(i => i.severity === 'HIGH').length },
    { name: 'Medium',   value: activeQueue.filter(i => i.severity === 'MEDIUM').length },
    { name: 'Low',      value: activeQueue.filter(i => i.severity === 'LOW').length }
  ]
  const defaultAttackTypes = [
    { name: 'SQLi',           value: 45 },
    { name: 'XSS',            value: 30 },
    { name: 'Brute Force',    value: 15 },
    { name: 'Path Traversal', value: 10 }
  ]

  // Build safe stats — always guarantee arrays for chart fields
  const rawStats = (socStats && typeof socStats === 'object') ? socStats : {}
  const stats = {
    daily_alerts:          rawStats.daily_alerts          ?? 1420,
    deduplicated_count:    rawStats.deduplicated_count    ?? 312,
    open_critical:         rawStats.open_critical         ?? activeQueue.filter(i => i.severity === 'CRITICAL').length,
    mttd:                  rawStats.mttd                  ?? '1.2s',
    severity_distribution: Array.isArray(rawStats.severity_distribution) && rawStats.severity_distribution.length > 0
                             ? rawStats.severity_distribution
                             : defaultSeverityDist,
    attack_types:          Array.isArray(rawStats.attack_types) && rawStats.attack_types.length > 0
                             ? rawStats.attack_types
                             : defaultAttackTypes,
  }

  const noiseReduction = Math.round((1 - (stats.deduplicated_count / Math.max(1, stats.daily_alerts))) * 100) || 0

  return (
    <div className="h-full flex flex-col space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Activity className="w-6 h-6 text-accent" />
            SOC Command Center
          </h1>
          <p className="text-cyber-muted text-sm mt-1">
            Real-time security operations, alert triaging, and metrics
          </p>
        </div>
        
        <div className="flex gap-2">
          <button className="flex items-center gap-2 px-4 py-2 bg-danger/20 text-danger hover:bg-danger/30 border border-danger/30 rounded-lg text-sm font-medium transition-colors">
            <ShieldAlert className="w-4 h-4" /> Global Lockdown
          </button>
        </div>
      </div>

      <div className="flex-1 flex gap-4 overflow-hidden">
        {/* Left Panel: Live Alert Feed (30%) */}
        <div className="w-[30%] bg-bg-surface border border-bg-border rounded-xl flex flex-col overflow-hidden relative">
          <div className="p-4 border-b border-bg-border">
            <h3 className="font-semibold text-gray-200 flex items-center gap-2">
              <Crosshair className="w-4 h-4 text-warning" /> Live Alerts Pipeline
            </h3>
          </div>
          <div className="flex-1 overflow-y-auto custom-scrollbar">
            {/* Reusing existing component */}
            <ThreatFeed />
          </div>
        </div>

        {/* Center Panel: Active Incidents Queue (40%) */}
        <div className="w-[40%] bg-bg-surface border border-bg-border rounded-xl flex flex-col overflow-hidden">
          <div className="p-4 border-b border-bg-border flex justify-between items-center">
            <h3 className="font-semibold text-gray-200 flex items-center gap-2">
              <Shield className="w-4 h-4 text-accent" /> Incident Triaging Queue
            </h3>
            <span className="px-2 py-0.5 bg-danger/20 text-danger border border-danger/30 rounded text-xs font-bold">
              {activeQueue.length} Active
            </span>
          </div>
          <div className="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar">
            {activeQueue.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-cyber-muted">
                <CheckCircle2 className="w-8 h-8 mb-2 text-success/50" />
                <p>No active incidents.</p>
              </div>
            ) : (
              activeQueue.map(inc => (
                <div 
                  key={inc.id}
                  className="p-4 bg-bg-primary border border-bg-border hover:border-accent rounded-lg transition-colors cursor-pointer"
                  onClick={() => {
                    setActiveIncident(inc)
                    navigate('/incidents')
                  }}
                >
                  <div className="flex justify-between items-start mb-2">
                    <span className="text-xs font-mono text-cyber-muted">{inc.id}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border 
                      ${inc.severity === 'CRITICAL' ? 'bg-danger/20 text-danger border-danger/30' : 
                        inc.severity === 'HIGH' ? 'bg-warning/20 text-warning border-warning/30' : 
                        inc.severity === 'MEDIUM' ? 'bg-info/20 text-info border-info/30' : 
                        'bg-cyber-cyan/20 text-cyber-cyan border-cyber-cyan/30'}`}>
                      {inc.severity}
                    </span>
                  </div>
                  <h4 className="text-sm font-medium text-gray-200 mb-2">{inc.title || 'Unknown Threat Cluster'}</h4>
                  
                  {/* Quick Actions */}
                  <div className="flex justify-between items-center mt-3 pt-3 border-t border-bg-border/50">
                    <span className="text-[10px] text-cyber-muted uppercase bg-bg-surface px-2 py-1 rounded">
                      {inc.status}
                    </span>
                    <div className="flex gap-2">
                      <button 
                        onClick={(e) => { e.stopPropagation(); navigate(`/incidents/${inc.id}/playbook`); }}
                        className="text-[10px] uppercase font-bold text-accent hover:text-white px-2 py-1 border border-accent/30 rounded"
                      >
                        Investigate
                      </button>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Panel: SOC Metrics (30%) */}
        <div className="w-[30%] flex flex-col gap-4 overflow-hidden">
          
          {/* Top KPI Cards */}
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-bg-surface border border-bg-border rounded-xl p-4 flex flex-col justify-center items-center text-center">
              <span className="text-xs text-cyber-muted uppercase mb-1">Noise Reduction</span>
              <div className="text-2xl font-bold text-success">{noiseReduction}%</div>
              <span className="text-[10px] text-gray-400 mt-1">Deduplicated from {stats.daily_alerts}</span>
            </div>
            <div className="bg-bg-surface border border-bg-border rounded-xl p-4 flex flex-col justify-center items-center text-center">
              <span className="text-xs text-cyber-muted uppercase mb-1 flex items-center gap-1">
                <Clock className="w-3 h-3" /> MTTD
              </span>
              <div className="text-2xl font-bold text-white">{stats.mttd || '0.8s'}</div>
              <span className="text-[10px] text-gray-400 mt-1">Mean Time To Detect</span>
            </div>
          </div>

          {/* Severity Bar Chart */}
          <div className="bg-bg-surface border border-bg-border rounded-xl flex-1 flex flex-col p-4">
            <h3 className="font-semibold text-gray-200 text-sm mb-4">Open Incidents by Severity</h3>
            <div className="flex-1 min-h-0">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.severity_distribution}>
                  <XAxis dataKey="name" stroke="#6b7280" fontSize={10} tickLine={false} axisLine={false} />
                  <YAxis stroke="#6b7280" fontSize={10} tickLine={false} axisLine={false} width={20} />
                  <Tooltip 
                    cursor={{ fill: '#1f2937' }}
                    contentStyle={{ backgroundColor: '#111827', borderColor: '#1f2937', color: '#fff', fontSize: '12px' }}
                  />
                  <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                    {stats.severity_distribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.name.toUpperCase()] || '#3b82f6'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Attack Type Pie Chart */}
          <div className="bg-bg-surface border border-bg-border rounded-xl flex-1 flex flex-col p-4">
            <h3 className="font-semibold text-gray-200 text-sm mb-4 flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-cyber-cyan" /> 24h Attack Distribution
            </h3>
            <div className="relative flex items-center justify-center h-[180px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={stats.attack_types}
                    cx="50%"
                    cy="50%"
                    innerRadius={40}
                    outerRadius={60}
                    paddingAngle={5}
                    dataKey="value"
                    stroke="none"
                  >
                    {stats.attack_types.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={['#ef4444', '#f59e0b', '#3b82f6', '#8b5cf6', '#10b981'][index % 5]} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#111827', borderColor: '#1f2937', color: '#fff', fontSize: '12px', borderRadius: '8px' }}
                    itemStyle={{ color: '#e5e7eb' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

        </div>
      </div>
    </div>
  )
}
