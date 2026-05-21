import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { format } from 'date-fns'
import { 
  AlertTriangle, 
  ShieldAlert, 
  Clock, 
  CheckCircle2, 
  ChevronRight,
  Search,
  Filter,
  Activity,
  Server,
  BookOpen,
  XCircle,
  ArrowUpRight
} from 'lucide-react'
import useIncidentStore from '../store/useIncidentStore'
import api from '../lib/api'

const SEVERITY_COLORS = {
  CRITICAL: 'bg-danger/20 text-danger border-danger/30',
  HIGH: 'bg-warning/20 text-warning border-warning/30',
  MEDIUM: 'bg-info/20 text-info border-info/30',
  LOW: 'bg-cyber-cyan/20 text-cyber-cyan border-cyber-cyan/30'
}

const STATUS_COLORS = {
  OPEN: 'bg-danger/10 text-danger border-danger/20',
  INVESTIGATING: 'bg-warning/10 text-warning border-warning/20',
  CONTAINED: 'bg-info/10 text-info border-info/20',
  RESOLVED: 'bg-success/10 text-success border-success/20',
  DISMISSED: 'bg-gray-500/10 text-gray-400 border-gray-500/20'
}

export default function IncidentCenter() {
  const navigate = useNavigate()
  const { incidents, setIncidents, activeIncident, setActiveIncident } = useIncidentStore()
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [severityFilter, setSeverityFilter] = useState('ALL')

  useEffect(() => {
    fetchIncidents()
  }, [])

  const fetchIncidents = async () => {
    try {
      setLoading(true)
      const res = await api.get('/incidents')
      if (res.data) {
        const incidentsArray = Array.isArray(res.data.incidents) ? res.data.incidents : (Array.isArray(res.data) ? res.data : [])
        setIncidents(incidentsArray)
        if (incidentsArray.length > 0 && !activeIncident) {
          setActiveIncident(incidentsArray[0])
        }
      }
    } catch (err) {
      console.error('Failed to fetch incidents', err)
    } finally {
      setLoading(false)
    }
  }

  const handleAction = async (id, action) => {
    try {
      await api.post(`/incidents/${id}/action`, { action })
      // Refresh incidents or update locally
      fetchIncidents()
    } catch (err) {
      console.error('Action failed', err)
    }
  }

  const filteredIncidents = incidents.filter(inc => {
    const matchesSearch = inc.title?.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          inc.id.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesStatus = statusFilter === 'ALL' || inc.status === statusFilter
    const matchesSeverity = severityFilter === 'ALL' || inc.severity === severityFilter
    return matchesSearch && matchesStatus && matchesSeverity
  })

  return (
    <div className="h-full flex flex-col space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-danger" />
            Incident Center
          </h1>
          <p className="text-cyber-muted text-sm mt-1">
            Correlated security events and autonomous response tracking
          </p>
        </div>
      </div>

      <div className="flex-1 flex gap-4 overflow-hidden">
        {/* Left Panel: Incident List (40%) */}
        <div className="w-[40%] flex flex-col bg-bg-surface border border-bg-border rounded-xl overflow-hidden">
          <div className="p-4 border-b border-bg-border space-y-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
              <input
                type="text"
                placeholder="Search incidents by ID or title..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-bg-primary border border-bg-border rounded-lg pl-9 pr-4 py-2 text-sm text-gray-200 focus:outline-none focus:border-accent"
              />
            </div>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-3 h-3 text-cyber-muted" />
                <select 
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="w-full bg-bg-primary border border-bg-border rounded-lg pl-8 pr-4 py-1.5 text-xs text-gray-300 focus:outline-none appearance-none"
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>
              <div className="relative flex-1">
                <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-3 h-3 text-cyber-muted" />
                <select 
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="w-full bg-bg-primary border border-bg-border rounded-lg pl-8 pr-4 py-1.5 text-xs text-gray-300 focus:outline-none appearance-none"
                >
                  <option value="ALL">All Statuses</option>
                  <option value="OPEN">Open</option>
                  <option value="INVESTIGATING">Investigating</option>
                  <option value="CONTAINED">Contained</option>
                  <option value="RESOLVED">Resolved</option>
                </select>
              </div>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto p-2 space-y-2 custom-scrollbar">
            {loading ? (
              <div className="flex items-center justify-center h-32 text-cyber-muted">
                <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-accent mr-2"></div>
                Loading incidents...
              </div>
            ) : filteredIncidents.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-32 text-cyber-muted">
                <CheckCircle2 className="w-8 h-8 mb-2 text-success/50" />
                <p>No incidents found.</p>
              </div>
            ) : (
              filteredIncidents.map(inc => (
                <div 
                  key={inc.id}
                  onClick={() => setActiveIncident(inc)}
                  className={`p-4 rounded-lg border cursor-pointer transition-colors ${
                    activeIncident?.id === inc.id 
                      ? 'bg-bg-primary border-accent' 
                      : 'bg-bg-primary/50 border-bg-border hover:border-cyber-muted'
                  }`}
                >
                  <div className="flex justify-between items-start mb-2">
                    <span className="text-xs font-mono text-cyber-muted">{inc.id.split('-')[0]}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${SEVERITY_COLORS[inc.severity]}`}>
                      {inc.severity}
                    </span>
                  </div>
                  <h3 className="text-sm font-medium text-gray-200 mb-2 line-clamp-2">
                    {inc.title || 'Untitled Incident'}
                  </h3>
                  <div className="flex items-center justify-between mt-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${STATUS_COLORS[inc.status]}`}>
                      {inc.status}
                    </span>
                    <span className="text-[10px] text-cyber-muted flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {inc.created_at ? format(new Date(inc.created_at), 'HH:mm:ss') : 'Unknown'}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Panel: Incident Detail Drawer (60%) */}
        <div className="w-[60%] bg-bg-surface border border-bg-border rounded-xl flex flex-col overflow-hidden relative">
          {activeIncident ? (
            <>
              {/* Header */}
              <div className="p-6 border-b border-bg-border bg-bg-primary/30">
                <div className="flex justify-between items-start mb-4">
                  <div>
                    <h2 className="text-xl font-bold text-white mb-2">{activeIncident.title || 'Incident Details'}</h2>
                    <div className="flex items-center gap-3">
                      <span className={`px-2 py-1 rounded text-xs font-bold border ${SEVERITY_COLORS[activeIncident.severity]}`}>
                        {activeIncident.severity}
                      </span>
                      <span className={`px-2 py-1 rounded text-xs font-bold border ${STATUS_COLORS[activeIncident.status]}`}>
                        {activeIncident.status}
                      </span>
                      <span className="text-xs text-cyber-muted font-mono">ID: {activeIncident.id}</span>
                    </div>
                  </div>
                </div>

                {/* MITRE Badges */}
                {activeIncident.mitre_tactics && activeIncident.mitre_tactics.length > 0 && (
                  <div className="mt-4 flex flex-wrap gap-2">
                    {activeIncident.mitre_tactics.map((t, idx) => (
                      <div key={idx} className="group relative">
                        <span className="px-2 py-1 bg-purple-500/10 text-purple-400 border border-purple-500/20 rounded text-xs cursor-help flex items-center gap-1">
                          <Activity className="w-3 h-3" />
                          {t.technique_id}
                        </span>
                        <div className="absolute bottom-full left-0 mb-2 w-48 p-2 bg-gray-800 text-xs text-gray-200 rounded opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-10">
                          {t.name || 'Unknown Technique'}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Body */}
              <div className="flex-1 overflow-y-auto p-6 space-y-6 custom-scrollbar">
                {/* Entities */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="p-4 bg-bg-primary rounded-lg border border-bg-border">
                    <h4 className="text-xs font-semibold text-cyber-muted uppercase mb-3 flex items-center gap-2">
                      <Server className="w-4 h-4" /> Affected Entities
                    </h4>
                    <div className="flex flex-wrap gap-2">
                      {activeIncident.affected_ips?.map((ip, i) => (
                        <span key={i} className="px-2 py-1 bg-bg-surface border border-bg-border rounded text-xs font-mono text-gray-300">
                          {ip}
                        </span>
                      ))}
                      {(!activeIncident.affected_ips || activeIncident.affected_ips.length === 0) && (
                        <span className="text-xs text-cyber-muted">No specific IPs logged.</span>
                      )}
                    </div>
                  </div>
                  <div className="p-4 bg-bg-primary rounded-lg border border-bg-border">
                    <h4 className="text-xs font-semibold text-cyber-muted uppercase mb-3 flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4" /> Threat Indicators
                    </h4>
                    <div className="flex flex-wrap gap-2">
                      {activeIncident.indicators?.map((ind, i) => (
                        <span key={i} className="px-2 py-1 bg-danger/10 border border-danger/20 rounded text-xs font-mono text-danger">
                          {ind}
                        </span>
                      ))}
                      {(!activeIncident.indicators || activeIncident.indicators.length === 0) && (
                        <span className="text-xs text-cyber-muted">No specific indicators.</span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Timeline */}
                <div>
                  <h4 className="text-sm font-semibold text-gray-200 mb-4 border-b border-bg-border pb-2">Event Timeline</h4>
                  <div className="space-y-4 pl-2">
                    {activeIncident.events?.map((evt, idx) => (
                      <div key={idx} className="relative pl-6 pb-4 border-l-2 border-bg-border last:border-0 last:pb-0">
                        <div className="absolute -left-[5px] top-1 w-2 h-2 rounded-full bg-accent"></div>
                        <div className="flex items-start justify-between">
                          <div>
                            <p className="text-sm text-gray-300">{evt.description || 'Security Event'}</p>
                            <p className="text-xs text-cyber-muted mt-1 font-mono">
                              {evt.source_ip} {evt.path && `→ ${evt.path}`}
                            </p>
                          </div>
                          <span className="text-xs text-cyber-muted">
                            {evt.timestamp ? format(new Date(evt.timestamp), 'HH:mm:ss') : ''}
                          </span>
                        </div>
                      </div>
                    ))}
                    {(!activeIncident.events || activeIncident.events.length === 0) && (
                      <p className="text-sm text-cyber-muted">No timeline events available.</p>
                    )}
                  </div>
                </div>
              </div>

              {/* Action Footer */}
              <div className="p-4 border-t border-bg-border bg-bg-primary flex items-center justify-between">
                <button 
                  onClick={() => navigate(`/incidents/${activeIncident.id}/playbook`)}
                  className="flex items-center gap-2 px-4 py-2 bg-accent hover:bg-accent/80 text-white rounded-lg text-sm font-medium transition-colors"
                >
                  <BookOpen className="w-4 h-4" />
                  View IR Playbook
                </button>
                <div className="flex gap-2">
                  <button 
                    onClick={() => handleAction(activeIncident.id, 'resolve')}
                    className="flex items-center gap-1 px-3 py-1.5 border border-success/30 text-success hover:bg-success/10 rounded-lg text-sm transition-colors"
                  >
                    <CheckCircle2 className="w-4 h-4" /> Resolve
                  </button>
                  <button 
                    onClick={() => handleAction(activeIncident.id, 'escalate')}
                    className="flex items-center gap-1 px-3 py-1.5 border border-warning/30 text-warning hover:bg-warning/10 rounded-lg text-sm transition-colors"
                  >
                    <ArrowUpRight className="w-4 h-4" /> Escalate
                  </button>
                  <button 
                    onClick={() => handleAction(activeIncident.id, 'dismiss')}
                    className="flex items-center gap-1 px-3 py-1.5 border border-gray-500/30 text-gray-400 hover:bg-gray-500/10 rounded-lg text-sm transition-colors"
                  >
                    <XCircle className="w-4 h-4" /> Dismiss
                  </button>
                </div>
              </div>
            </>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-cyber-muted">
              <ShieldAlert className="w-12 h-12 mb-4 opacity-20" />
              <p>Select an incident to view details.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
