import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ChevronDown, ChevronUp, Download, Filter, X } from 'lucide-react'
import { format } from 'date-fns'
import clsx from 'clsx'
import api from '../lib/api'
import AttackDetailDrawer from '../components/Attacks/AttackDetailDrawer'

const ATTACK_TYPES = ['SQL_INJECTION', 'XSS', 'BRUTE_FORCE', 'PATH_TRAVERSAL', 'COMMAND_INJECTION', 'ANOMALY', 'HONEYPOT_TRAP']

function RiskPill({ score }) {
  if (score >= 80) return <span className="risk-critical">{score?.toFixed(0)}</span>
  if (score >= 60) return <span className="risk-high">{score?.toFixed(0)}</span>
  if (score >= 40) return <span className="risk-medium">{score?.toFixed(0)}</span>
  return <span className="risk-low">{score?.toFixed(0)}</span>
}

function SkeletonRow() {
  return (
    <tr>
      {Array.from({ length: 8 }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="skeleton h-4 rounded w-full" />
        </td>
      ))}
    </tr>
  )
}

function Pagination({ page, pages, onPage }) {
  return (
    <div className="flex items-center gap-2">
      <button
        onClick={() => onPage(page - 1)}
        disabled={page <= 1}
        className="btn-ghost px-2 py-1 text-xs disabled:opacity-30"
      >← Prev</button>
      <span className="text-xs text-cyber-muted">Page {page} / {pages}</span>
      <button
        onClick={() => onPage(page + 1)}
        disabled={page >= pages}
        className="btn-ghost px-2 py-1 text-xs disabled:opacity-30"
      >Next →</button>
    </div>
  )
}

export default function Attacks() {
  const [page, setPage] = useState(1)
  const [filters, setFilters] = useState({ attack_type: '', ip: '', min_severity: 0 })
  const [expandedRow, setExpandedRow] = useState(null)
  const [selectedAttack, setSelectedAttack] = useState(null)
  const [showFilters, setShowFilters] = useState(false)

  const { data, isLoading } = useQuery({
    queryKey: ['attacks', page, filters],
    queryFn: async () => {
      const params = { page, per_page: 20 }
      if (filters.attack_type) params.attack_type = filters.attack_type
      if (filters.ip) params.ip = filters.ip
      if (filters.min_severity > 0) params.min_severity = filters.min_severity
      const res = await api.get('/attacks', { params })
      return res.data
    },
    staleTime: 5000,
  })

  const exportCSV = async () => {
    try {
      const res = await api.get('/attacks', { params: { per_page: 100, ...filters } })
      const items = res.data.items
      const headers = ['id', 'timestamp', 'ip_address', 'method', 'path', 'risk_score', 'attack_type', 'is_blocked']
      const rows = items.map(a => headers.map(h => a[h] ?? '').join(','))
      const csv = [headers.join(','), ...rows].join('\n')
      const blob = new Blob([csv], { type: 'text/csv' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `attacks-${format(new Date(), 'yyyy-MM-dd')}.csv`
      a.click()
    } catch (e) {
      console.error(e)
    }
  }

  const clearFilters = () => setFilters({ attack_type: '', ip: '', min_severity: 0 })

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="glass-card p-4">
        <div className="flex items-center gap-3 flex-wrap">
          <button
            onClick={() => setShowFilters(s => !s)}
            className={clsx('btn-ghost flex items-center gap-2 text-sm', showFilters && 'text-accent')}
          >
            <Filter className="w-4 h-4" /> Filters
          </button>

          <input
            type="text"
            placeholder="Filter by IP…"
            value={filters.ip}
            onChange={e => setFilters(f => ({ ...f, ip: e.target.value }))}
            className="input-field w-44 py-1.5 text-sm"
          />

          <select
            value={filters.attack_type}
            onChange={e => setFilters(f => ({ ...f, attack_type: e.target.value }))}
            className="input-field w-48 py-1.5 text-sm"
          >
            <option value="">All Types</option>
            {ATTACK_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
          </select>

          <div className="flex items-center gap-2 text-sm">
            <span className="text-cyber-muted text-xs">Min Risk:</span>
            <input
              type="range"
              min={0}
              max={100}
              step={10}
              value={filters.min_severity}
              onChange={e => setFilters(f => ({ ...f, min_severity: +e.target.value }))}
              className="w-24 accent-accent"
            />
            <span className="text-white text-xs font-mono w-6">{filters.min_severity}</span>
          </div>

          {(filters.attack_type || filters.ip || filters.min_severity > 0) && (
            <button onClick={clearFilters} className="btn-ghost flex items-center gap-1 text-xs text-danger">
              <X className="w-3 h-3" /> Clear
            </button>
          )}

          <div className="ml-auto">
            <button onClick={exportCSV} className="btn-ghost flex items-center gap-2 text-sm">
              <Download className="w-4 h-4" /> Export CSV
            </button>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="glass-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs uppercase tracking-wider text-cyber-muted border-b border-bg-border">
                <th className="px-4 py-3 text-left">#</th>
                <th className="px-4 py-3 text-left">Time</th>
                <th className="px-4 py-3 text-left">IP</th>
                <th className="px-4 py-3 text-left">Type</th>
                <th className="px-4 py-3 text-left">Path</th>
                <th className="px-4 py-3 text-left">Risk</th>
                <th className="px-4 py-3 text-left">ML Score</th>
                <th className="px-4 py-3 text-left">Action</th>
                <th className="px-4 py-3 text-left"></th>
              </tr>
            </thead>
            <tbody>
              {isLoading
                ? Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} />)
                : (data?.items || []).map(attack => (
                  <>
                    <tr
                      key={attack.id}
                      className="table-row-base"
                      onClick={() => setSelectedAttack(attack)}
                    >
                      <td className="px-4 py-3 text-cyber-muted font-mono text-xs">{attack.id}</td>
                      <td className="px-4 py-3 font-mono text-xs text-cyber-muted">
                        {attack.timestamp ? format(new Date(attack.timestamp), 'MM/dd HH:mm:ss') : '—'}
                      </td>
                      <td className="px-4 py-3 font-mono text-cyber-cyan text-xs">{attack.ip_address}</td>
                      <td className="px-4 py-3">
                        <span className="text-xs font-medium text-warning">{attack.attack_type || '—'}</span>
                      </td>
                      <td className="px-4 py-3 text-xs text-cyber-muted font-mono truncate max-w-[180px]">
                        {attack.path}
                      </td>
                      <td className="px-4 py-3"><RiskPill score={attack.risk_score} /></td>
                      <td className="px-4 py-3 font-mono text-xs text-cyber-muted">
                        {attack.ml_score != null ? (attack.ml_score * 100).toFixed(0) + '%' : '—'}
                      </td>
                      <td className="px-4 py-3">
                        <span className={clsx('text-xs px-2 py-0.5 rounded font-medium',
                          attack.is_blocked ? 'bg-red-500/20 text-red-400' :
                          attack.risk_score >= 60 ? 'bg-orange-500/20 text-orange-400' :
                          'bg-yellow-500/20 text-yellow-400'
                        )}>
                          {attack.is_blocked ? 'Blocked' : attack.risk_score >= 60 ? 'Rate-Limited' : 'Alerted'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <button
                          onClick={e => { e.stopPropagation(); setExpandedRow(expandedRow === attack.id ? null : attack.id) }}
                          className="p-1 hover:bg-bg-border rounded"
                        >
                          {expandedRow === attack.id
                            ? <ChevronUp className="w-3 h-3 text-cyber-muted" />
                            : <ChevronDown className="w-3 h-3 text-cyber-muted" />}
                        </button>
                      </td>
                    </tr>
                    {expandedRow === attack.id && (
                      <tr key={`expand-${attack.id}`} className="bg-bg-primary/50">
                        <td colSpan={9} className="px-6 py-3">
                          <div className="text-xs space-y-1">
                            {attack.payload_snippet && (
                              <div>
                                <span className="text-cyber-muted">Payload: </span>
                                <code className="font-mono text-cyber-cyan">{attack.payload_snippet}</code>
                              </div>
                            )}
                            {attack.matched_pattern && (
                              <div>
                                <span className="text-cyber-muted">Pattern: </span>
                                <code className="font-mono text-warning">{attack.matched_pattern}</code>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {data && (
          <div className="px-4 py-3 border-t border-bg-border flex items-center justify-between text-xs text-cyber-muted">
            <span>{data.total} total attacks</span>
            <Pagination page={data.page} pages={data.pages} onPage={setPage} />
          </div>
        )}
      </div>

      {selectedAttack && (
        <AttackDetailDrawer attack={selectedAttack} onClose={() => setSelectedAttack(null)} />
      )}
    </div>
  )
}
