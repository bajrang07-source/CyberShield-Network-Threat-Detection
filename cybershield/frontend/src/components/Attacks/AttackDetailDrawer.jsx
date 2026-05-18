import { useEffect, useState } from 'react'
import { X, Shield, ShieldAlert, Clock, Globe, Terminal, Key, Zap, Ban, ExternalLink } from 'lucide-react'
import { format } from 'date-fns'
import clsx from 'clsx'
import api from '../../lib/api'

function RiskBar({ label, value, color }) {
  return (
    <div>
      <div className="flex justify-between text-xs mb-1">
        <span className="text-cyber-muted">{label}</span>
        <span className="font-mono text-white">{(value * 100).toFixed(0)}%</span>
      </div>
      <div className="h-2 bg-bg-primary rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${Math.min(value * 100, 100)}%`, backgroundColor: color }}
        />
      </div>
    </div>
  )
}

export default function AttackDetailDrawer({ attack, onClose, onBlock }) {
  const [detail, setDetail] = useState(null)
  const [blocking, setBlocking] = useState(false)
  const riskScore = attack?.risk_score || 0

  useEffect(() => {
    if (!attack?.id) return
    // Fetch full detail if numeric id (from DB)
    const id = parseInt(attack.id)
    if (!isNaN(id)) {
      api.get(`/attacks/${id}`).then(r => setDetail(r.data)).catch(() => {})
    }
  }, [attack?.id])

  const handleBlock = async () => {
    setBlocking(true)
    try {
      await api.post('/blocked-ips/block', {
        ip: attack.ip,
        reason: `Manual block: ${attack.attack_type || 'suspicious activity'}`,
        duration_hours: 24,
      })
      onBlock?.(attack.ip)
    } catch (e) {
      console.error(e)
    } finally {
      setBlocking(false)
    }
  }

  const severityColor = {
    CRITICAL: 'text-red-400 bg-red-500/20 border-red-500/30',
    HIGH: 'text-orange-400 bg-orange-500/20 border-orange-500/30',
    MEDIUM: 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30',
    LOW: 'text-green-400 bg-green-500/20 border-green-500/30',
  }[attack?.severity] || ''

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50"
        onClick={onClose}
      />

      {/* Drawer */}
      <div className="fixed right-0 top-0 h-screen w-[480px] bg-bg-surface border-l border-bg-border z-50 drawer-enter flex flex-col overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-bg-border flex items-center justify-between flex-shrink-0">
          <div className="flex items-center gap-3">
            <ShieldAlert className="w-5 h-5 text-danger" />
            <div>
              <h3 className="font-semibold text-white">Attack Detail</h3>
              <p className="text-xs text-cyber-muted">{attack?.id}</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 hover:bg-bg-border rounded-lg transition-colors text-cyber-muted hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {/* Severity + type + timestamp */}
          <div className="flex items-center gap-3 flex-wrap">
            <span className={clsx('attack-badge border px-3 py-1 rounded-full text-sm font-semibold', severityColor)}>
              {attack?.severity || '—'}
            </span>
            <span className="attack-badge bg-bg-primary border border-bg-border text-white text-sm">
              {attack?.attack_type || 'Unknown'}
            </span>
            <span className="flex items-center gap-1 text-xs text-cyber-muted ml-auto">
              <Clock className="w-3 h-3" />
              {attack?.timestamp ? format(new Date(attack.timestamp), 'MMM d, HH:mm:ss') : '—'}
            </span>
          </div>

          {/* Request Info */}
          <div className="glass-card p-4 space-y-2.5">
            <p className="text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-3">Request Info</p>
            <div className="flex items-center gap-2 text-sm">
              <Globe className="w-4 h-4 text-cyber-muted" />
              <span className="text-cyber-muted">IP:</span>
              <span className="font-mono text-cyber-cyan">{attack?.ip}</span>
              {attack?.geo_info?.country && (
                <span className="text-cyber-muted text-xs">· {attack.geo_info.city}, {attack.geo_info.country}</span>
              )}
            </div>
            <div className="flex items-center gap-2 text-sm">
              <span className="text-cyber-muted text-xs w-4 text-center font-bold">{attack?.method?.[0] || 'G'}</span>
              <span className="text-cyber-muted">Method:</span>
              <span className="font-mono text-white">{attack?.method}</span>
            </div>
            <div className="flex items-start gap-2 text-sm">
              <span className="text-cyber-muted mt-0.5">Path:</span>
              <span className="font-mono text-white break-all text-xs">{attack?.path}</span>
            </div>
            {attack?.user_agent && (
              <div className="flex items-start gap-2 text-sm">
                <span className="text-cyber-muted mt-0.5 text-xs">UA:</span>
                <span className="text-cyber-muted text-xs break-all">{attack.user_agent}</span>
              </div>
            )}
          </div>

          {/* Payload Snippet */}
          {attack?.payload_snippet && (
            <div>
              <p className="text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-2">Payload</p>
              <pre className="bg-bg-primary border border-bg-border rounded-lg p-3 text-xs font-mono text-cyber-cyan overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                {attack.payload_snippet}
              </pre>
            </div>
          )}

          {/* Detection Breakdown */}
          <div className="glass-card p-4 space-y-3">
            <p className="text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-3">Detection Scores</p>
            <RiskBar label="ML Score" value={attack?.ml_score || 0} color="#6366f1" />
            <RiskBar label="Overall Risk" value={(riskScore / 100)} color={
              riskScore >= 80 ? '#ef4444' : riskScore >= 60 ? '#f97316' : riskScore >= 40 ? '#f59e0b' : '#22c55e'
            } />
            {attack?.matched_pattern && (
              <div className="pt-2 border-t border-bg-border">
                <p className="text-xs text-cyber-muted mb-1">Matched Pattern</p>
                <code className="text-xs text-warning font-mono">{attack.matched_pattern}</code>
              </div>
            )}
          </div>

          {/* IP Timeline */}
          {(detail?.timeline?.length > 0) && (
            <div>
              <p className="text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-2">Recent from this IP</p>
              <div className="space-y-1.5">
                {detail.timeline.map((t, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs bg-bg-primary rounded px-3 py-2">
                    <span className="text-cyber-muted font-mono">{format(new Date(t.timestamp), 'HH:mm:ss')}</span>
                    <span className="text-cyber-muted">{t.method}</span>
                    <span className="text-white font-mono flex-1 truncate">{t.path}</span>
                    <span className={clsx(
                      'font-semibold',
                      t.risk_score >= 80 ? 'text-red-400' :
                      t.risk_score >= 60 ? 'text-orange-400' :
                      t.risk_score >= 40 ? 'text-yellow-400' : 'text-green-400'
                    )}>{t.risk_score.toFixed(0)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="px-6 py-4 border-t border-bg-border flex items-center gap-3 flex-shrink-0">
          <button
            id="block-ip-btn"
            onClick={handleBlock}
            disabled={blocking}
            className="btn-danger flex items-center gap-2 flex-1"
          >
            <Ban className="w-4 h-4" />
            {blocking ? 'Blocking…' : 'Block IP (24h)'}
          </button>
          {detail?.id && (
            <a
              href={`/attacks?ip=${attack?.ip}`}
              className="btn-ghost flex items-center gap-2"
            >
              <ExternalLink className="w-4 h-4" />
              Full Details
            </a>
          )}
        </div>
      </div>
    </>
  )
}
