import { useState, useEffect } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Ban, Plus, Search, Trash2, X } from 'lucide-react'
import { format } from 'date-fns'
import clsx from 'clsx'
import api from '../lib/api'

function CountdownTimer({ expiresAt, isPermanent }) {
  const [remaining, setRemaining] = useState('')
  useEffect(() => {
    if (isPermanent) { setRemaining('∞ Permanent'); return }
    const update = () => {
      const diff = new Date(expiresAt) - new Date()
      if (diff <= 0) { setRemaining('Expired'); return }
      const h = Math.floor(diff / 3600000)
      const m = Math.floor((diff % 3600000) / 60000)
      const s = Math.floor((diff % 60000) / 1000)
      setRemaining(`${h}h ${m}m ${s}s`)
    }
    update()
    const id = setInterval(update, 1000)
    return () => clearInterval(id)
  }, [expiresAt, isPermanent])
  return <span className={clsx('font-mono text-xs', isPermanent ? 'text-purple-400' : 'text-cyber-muted')}>{remaining}</span>
}

function UnblockModal({ ip, reason, onConfirm, onCancel, loading }) {
  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="glass-card w-full max-w-sm p-6 space-y-4 animate-fade-in">
        <h3 className="font-semibold text-white">Unblock IP: <span className="font-mono text-cyber-cyan">{ip}</span></h3>
        {reason && <p className="text-xs text-cyber-muted">Blocked for: {reason}</p>}
        <div className="flex gap-3">
          <button onClick={onCancel} className="btn-ghost flex-1">Cancel</button>
          <button onClick={onConfirm} disabled={loading} className="btn-primary flex-1">
            {loading ? 'Unblocking…' : 'Confirm'}
          </button>
        </div>
      </div>
    </div>
  )
}

function BlockModal({ onClose, onConfirm }) {
  const [ip, setIp] = useState('')
  const [reason, setReason] = useState('')
  const [duration, setDuration] = useState('24')
  const [loading, setLoading] = useState(false)
  const submit = async () => {
    if (!ip.trim()) return
    setLoading(true)
    try { await onConfirm(ip.trim(), reason, parseInt(duration)); onClose() }
    finally { setLoading(false) }
  }
  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="glass-card w-full max-w-sm p-6 space-y-4 animate-fade-in">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-white">Block IP Manually</h3>
          <button onClick={onClose}><X className="w-4 h-4 text-cyber-muted" /></button>
        </div>
        <input placeholder="IP Address" value={ip} onChange={e => setIp(e.target.value)} className="input-field" />
        <input placeholder="Reason (optional)" value={reason} onChange={e => setReason(e.target.value)} className="input-field" />
        <select value={duration} onChange={e => setDuration(e.target.value)} className="input-field">
          <option value="1">1 Hour</option>
          <option value="6">6 Hours</option>
          <option value="24">24 Hours</option>
          <option value="0">Permanent</option>
        </select>
        <div className="flex gap-3">
          <button onClick={onClose} className="btn-ghost flex-1">Cancel</button>
          <button onClick={submit} disabled={loading || !ip} className="btn-danger flex-1">
            {loading ? 'Blocking…' : 'Block IP'}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function BlockedIPs() {
  const qc = useQueryClient()
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState(new Set())
  const [unblocking, setUnblocking] = useState(null)
  const [unblockLoading, setUnblockLoading] = useState(false)
  const [showBlockModal, setShowBlockModal] = useState(false)

  const { data: ips = [] } = useQuery({
    queryKey: ['blocked-ips'],
    queryFn: async () => { const res = await api.get('/blocked-ips'); return res.data },
    refetchInterval: 30000,
  })

  const filtered = ips.filter(ip =>
    ip.ip_address.includes(search) || (ip.reason || '').toLowerCase().includes(search.toLowerCase())
  )

  const doUnblock = async (ip) => {
    setUnblockLoading(true)
    try { await api.post('/blocked-ips/unblock', { ip }); qc.invalidateQueries(['blocked-ips']); setUnblocking(null) }
    finally { setUnblockLoading(false) }
  }

  const doBlock = async (ip, reason, durationHours) => {
    await api.post('/blocked-ips/block', { ip, reason, duration_hours: durationHours })
    qc.invalidateQueries(['blocked-ips'])
  }

  const bulkUnblock = async () => {
    for (const ip of selected) await api.post('/blocked-ips/unblock', { ip })
    qc.invalidateQueries(['blocked-ips'])
    setSelected(new Set())
  }

  return (
    <div className="space-y-4">
      <div className="glass-card p-4 flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search…" className="input-field pl-9" />
        </div>
        {selected.size > 0 && (
          <button onClick={bulkUnblock} className="btn-primary text-sm">Unblock Selected ({selected.size})</button>
        )}
        <div className="ml-auto">
          <button onClick={() => setShowBlockModal(true)} className="btn-danger flex items-center gap-2 text-sm">
            <Plus className="w-4 h-4" /> Block IP
          </button>
        </div>
      </div>

      <div className="glass-card overflow-hidden">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-cyber-muted">
            <Ban className="w-12 h-12 mb-3 opacity-20" />
            <p className="font-medium">No blocked IPs</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs uppercase tracking-wider text-cyber-muted border-b border-bg-border">
                <th className="px-4 py-3 w-8">
                  <input type="checkbox" className="accent-accent"
                    checked={selected.size === filtered.length}
                    onChange={e => setSelected(e.target.checked ? new Set(filtered.map(i => i.ip_address)) : new Set())} />
                </th>
                <th className="px-4 py-3 text-left">IP</th>
                <th className="px-4 py-3 text-left">Country</th>
                <th className="px-4 py-3 text-left">Blocked At</th>
                <th className="px-4 py-3 text-left">Reason</th>
                <th className="px-4 py-3 text-left">Type</th>
                <th className="px-4 py-3 text-left">Expires In</th>
                <th className="px-4 py-3 text-left">Action</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(ip => (
                <tr key={ip.ip_address} className="table-row-base">
                  <td className="px-4 py-3">
                    <input type="checkbox" className="accent-accent" checked={selected.has(ip.ip_address)}
                      onChange={() => setSelected(s => { const n = new Set(s); n.has(ip.ip_address) ? n.delete(ip.ip_address) : n.add(ip.ip_address); return n })} />
                  </td>
                  <td className="px-4 py-3 font-mono text-cyber-cyan">{ip.ip_address}</td>
                  <td className="px-4 py-3 text-xs text-cyber-muted">{ip.country || '—'}</td>
                  <td className="px-4 py-3 text-xs font-mono text-cyber-muted">
                    {ip.blocked_at ? format(new Date(ip.blocked_at), 'MM/dd HH:mm') : '—'}
                  </td>
                  <td className="px-4 py-3 text-xs text-white max-w-[180px] truncate">{ip.reason || '—'}</td>
                  <td className="px-4 py-3 text-xs text-warning font-medium">{ip.attack_type || '—'}</td>
                  <td className="px-4 py-3"><CountdownTimer expiresAt={ip.expires_at} isPermanent={ip.is_permanent} /></td>
                  <td className="px-4 py-3">
                    <button onClick={() => setUnblocking(ip)} className="btn-ghost px-2 py-1 text-xs text-success flex items-center gap-1">
                      <Trash2 className="w-3 h-3" /> Unblock
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {unblocking && (
        <UnblockModal ip={unblocking.ip_address} reason={unblocking.reason}
          onConfirm={() => doUnblock(unblocking.ip_address)} onCancel={() => setUnblocking(null)} loading={unblockLoading} />
      )}
      {showBlockModal && <BlockModal onClose={() => setShowBlockModal(false)} onConfirm={doBlock} />}
    </div>
  )
}
