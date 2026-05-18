import { useState, useRef, useEffect } from 'react'
import { format } from 'date-fns'
import { ShieldAlert, Zap, Key, Terminal, Globe, Activity } from 'lucide-react'
import clsx from 'clsx'
import AttackDetailDrawer from '../Attacks/AttackDetailDrawer'

const ATTACK_ICONS = {
  SQL_INJECTION: { icon: Key, color: '#ef4444', bg: 'bg-red-500/10', text: 'text-red-400' },
  XSS: { icon: Zap, color: '#f59e0b', bg: 'bg-yellow-500/10', text: 'text-yellow-400' },
  BRUTE_FORCE: { icon: ShieldAlert, color: '#8b5cf6', bg: 'bg-purple-500/10', text: 'text-purple-400' },
  COMMAND_INJECTION: { icon: Terminal, color: '#ec4899', bg: 'bg-pink-500/10', text: 'text-pink-400' },
  PATH_TRAVERSAL: { icon: Globe, color: '#f97316', bg: 'bg-orange-500/10', text: 'text-orange-400' },
  ANOMALY: { icon: Activity, color: '#3b82f6', bg: 'bg-blue-500/10', text: 'text-blue-400' },
  HONEYPOT_TRAP: { icon: ShieldAlert, color: '#14b8a6', bg: 'bg-teal-500/10', text: 'text-teal-400' },
}

function RiskPill({ score }) {
  if (score >= 80) return <span className="risk-critical">{score.toFixed(0)}</span>
  if (score >= 60) return <span className="risk-high">{score.toFixed(0)}</span>
  if (score >= 40) return <span className="risk-medium">{score.toFixed(0)}</span>
  return <span className="risk-low">{score.toFixed(0)}</span>
}

function AttackRow({ attack, isNew, onClick }) {
  const meta = ATTACK_ICONS[attack.attack_type] || ATTACK_ICONS['ANOMALY']
  const Icon = meta.icon

  return (
    <tr
      className={clsx(
        'table-row-base text-sm',
        isNew && 'row-new'
      )}
      onClick={() => onClick(attack)}
    >
      <td className="py-3 px-4 text-cyber-muted font-mono text-xs">
        {format(new Date(attack.timestamp || Date.now()), 'HH:mm:ss')}
      </td>
      <td className="py-3 px-4 font-mono text-cyber-cyan text-xs">{attack.ip}</td>
      <td className="py-3 px-4">
        {attack.attack_type ? (
          <span className={clsx('attack-badge', meta.bg, meta.text)}>
            <Icon className="w-3 h-3" />
            {attack.attack_type}
          </span>
        ) : (
          <span className="text-cyber-muted text-xs">—</span>
        )}
      </td>
      <td className="py-3 px-4 text-cyber-muted text-xs font-mono truncate max-w-[200px]">
        {attack.path}
      </td>
      <td className="py-3 px-4">
        <RiskPill score={attack.risk_score || 0} />
      </td>
      <td className="py-3 px-4">
        <span className={clsx(
          'text-xs font-medium px-2 py-0.5 rounded',
          attack.risk_score >= 80 ? 'bg-red-500/20 text-red-400' :
          attack.risk_score >= 60 ? 'bg-orange-500/20 text-orange-400' :
          attack.risk_score >= 40 ? 'bg-yellow-500/20 text-yellow-400' :
          'bg-green-500/20 text-green-400'
        )}>
          {attack.risk_score >= 80 ? 'Blocked' :
           attack.risk_score >= 60 ? 'Rate-Limited' :
           attack.risk_score >= 40 ? 'Alerted' : 'Logged'}
        </span>
      </td>
    </tr>
  )
}

export default function ThreatFeed({ attacks = [] }) {
  const [selectedAttack, setSelectedAttack] = useState(null)
  const newIdsRef = useRef(new Set())
  const prevCountRef = useRef(attacks.length)

  // Track new rows
  useEffect(() => {
    if (attacks.length > prevCountRef.current) {
      const newOnes = attacks.slice(0, attacks.length - prevCountRef.current)
      newOnes.forEach(a => newIdsRef.current.add(a.id))
      setTimeout(() => {
        newOnes.forEach(a => newIdsRef.current.delete(a.id))
      }, 2100)
    }
    prevCountRef.current = attacks.length
  }, [attacks.length])

  if (attacks.length === 0) {
    return (
      <div className="glass-card p-6">
        <h3 className="text-base font-semibold text-white mb-4">Threat Feed</h3>
        <div className="flex flex-col items-center justify-center py-12 text-cyber-muted">
          <div className="w-12 h-12 rounded-full bg-success/10 border border-success/20 flex items-center justify-center mb-3">
            <span className="live-dot w-3 h-3 rounded-full bg-success" />
          </div>
          <p className="text-sm font-medium">No threats detected</p>
          <p className="text-xs mt-1">System monitoring active</p>
        </div>
      </div>
    )
  }

  return (
    <>
      <div className="glass-card overflow-hidden">
        <div className="px-6 py-4 border-b border-bg-border flex items-center justify-between">
          <div>
            <h3 className="text-base font-semibold text-white">Threat Feed</h3>
            <p className="text-xs text-cyber-muted mt-0.5">Live attack events</p>
          </div>
          <span className="text-xs text-cyber-muted">{attacks.length} events</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs uppercase tracking-wider text-cyber-muted border-b border-bg-border">
                <th className="px-4 py-3 text-left font-medium">Time</th>
                <th className="px-4 py-3 text-left font-medium">IP</th>
                <th className="px-4 py-3 text-left font-medium">Type</th>
                <th className="px-4 py-3 text-left font-medium">Path</th>
                <th className="px-4 py-3 text-left font-medium">Risk</th>
                <th className="px-4 py-3 text-left font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {attacks.map(attack => (
                <AttackRow
                  key={attack.id}
                  attack={attack}
                  isNew={newIdsRef.current.has(attack.id)}
                  onClick={setSelectedAttack}
                />
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {selectedAttack && (
        <AttackDetailDrawer
          attack={selectedAttack}
          onClose={() => setSelectedAttack(null)}
        />
      )}
    </>
  )
}
