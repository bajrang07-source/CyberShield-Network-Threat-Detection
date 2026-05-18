import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'
import useAppStore from '../store/useAppStore'
import AddSiteModal from '../components/Sites/AddSiteModal'
import ApiKeyReveal from '../components/Sites/ApiKeyReveal'

function StatusBadge({ status }) {
  const color = status === 'active' ? 'text-emerald-400 bg-emerald-400/10 border-emerald-400/30'
    : 'text-slate-400 bg-slate-400/10 border-slate-500/30'
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${color}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${status === 'active' ? 'bg-emerald-400' : 'bg-slate-500'}`} />
      {status}
    </span>
  )
}

function SiteCard({ site, onDelete, onRotateKey }) {
  const [expanded, setExpanded] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden hover:border-slate-700 transition-colors">
      {/* Header */}
      <div className="p-5 flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-3 mb-1">
            <h3 className="text-base font-semibold text-white truncate">{site.name}</h3>
            <StatusBadge status={site.status} />
          </div>
          <p className="text-sm text-slate-400 truncate">{site.origin_url}</p>
          <p className="text-xs text-slate-600 mt-1">
            Created {new Date(site.created_at).toLocaleDateString()}
          </p>
        </div>

        {/* Stats mini */}
        <div className="flex gap-4 flex-shrink-0 text-center">
          <div>
            <p className="text-lg font-bold text-white">{site.request_count ?? 0}</p>
            <p className="text-xs text-slate-500">Requests</p>
          </div>
          {site.has_webhook && (
            <div>
              <p className="text-lg">🔔</p>
              <p className="text-xs text-slate-500">Webhook</p>
            </div>
          )}
        </div>
      </div>

      {/* Actions */}
      <div className="px-5 pb-4 flex items-center gap-2">
        <button
          onClick={() => setExpanded(e => !e)}
          className="px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors"
        >
          {expanded ? 'Hide Details' : 'Details'}
        </button>
        <button
          onClick={() => onRotateKey(site.id)}
          className="px-3 py-1.5 text-xs font-medium text-amber-400 hover:text-amber-300 bg-amber-400/10 hover:bg-amber-400/20 rounded-lg transition-colors"
        >
          Rotate Key
        </button>
        {confirmDelete ? (
          <div className="flex items-center gap-2 ml-auto">
            <span className="text-xs text-red-400">Confirm delete?</span>
            <button onClick={() => onDelete(site.id)} className="px-3 py-1.5 text-xs font-medium text-white bg-red-600 hover:bg-red-500 rounded-lg transition-colors">Yes</button>
            <button onClick={() => setConfirmDelete(false)} className="px-3 py-1.5 text-xs font-medium text-slate-400 bg-slate-800 rounded-lg transition-colors">No</button>
          </div>
        ) : (
          <button onClick={() => setConfirmDelete(true)} className="ml-auto px-3 py-1.5 text-xs font-medium text-red-400 hover:text-red-300 bg-red-400/10 hover:bg-red-400/20 rounded-lg transition-colors">
            Delete
          </button>
        )}
      </div>

      {/* Expanded: Site ID + integration snippet */}
      {expanded && (
        <div className="px-5 pb-5 border-t border-slate-800 pt-4 space-y-3">
          <div>
            <p className="text-xs text-slate-500 mb-1">Site ID</p>
            <code className="text-xs text-cyan-400 bg-slate-950 px-2 py-1 rounded">{site.id}</code>
          </div>
          <div>
            <p className="text-xs text-slate-500 mb-1.5">Node.js Integration</p>
            <pre className="text-xs text-slate-300 bg-slate-950 p-3 rounded-lg overflow-x-auto">{`const cybershield = require('cybershield-agent')
app.use(cybershield({ apiKey: 'cs_live_<your-key>' }))`}</pre>
          </div>
        </div>
      )}
    </div>
  )
}

export default function Sites() {
  const [showAdd, setShowAdd] = useState(false)
  const [rotateResult, setRotateResult] = useState(null)  // { apiKey }
  const { setSites, removeSite } = useAppStore()
  const qc = useQueryClient()

  const { data: sites = [], isLoading } = useQuery({
    queryKey: ['sites'],
    queryFn: () => api.get('/sites').then(r => r.data),
    onSuccess: (data) => setSites(data),
  })

  const deleteMutation = useMutation({
    mutationFn: (siteId) => api.delete(`/sites/${siteId}`),
    onSuccess: (_, siteId) => {
      removeSite(siteId)
      qc.invalidateQueries(['sites'])
    },
  })

  async function handleRotateKey(siteId) {
    try {
      const res = await api.post(`/sites/${siteId}/keys`, { label: 'Rotated' })
      setRotateResult(res.data)
    } catch {
      alert('Failed to rotate key.')
    }
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Connected Sites</h1>
          <p className="text-slate-400 text-sm mt-1">
            Manage your external sites and API keys.
          </p>
        </div>
        <button
          onClick={() => setShowAdd(true)}
          className="flex items-center gap-2 px-4 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-sm font-semibold transition-all shadow-lg shadow-cyan-600/20"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Add Site
        </button>
      </div>

      {/* Sites grid */}
      {isLoading ? (
        <div className="text-center py-16 text-slate-500">Loading sites...</div>
      ) : sites.length === 0 ? (
        <div className="text-center py-20 space-y-4">
          <div className="text-6xl">🌐</div>
          <h3 className="text-xl font-semibold text-slate-300">No sites connected yet</h3>
          <p className="text-slate-500">Add your first site to start monitoring external traffic.</p>
          <button onClick={() => setShowAdd(true)}
            className="inline-flex items-center gap-2 px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-sm font-semibold transition-colors">
            + Add Your First Site
          </button>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {sites.map(site => (
            <SiteCard
              key={site.id}
              site={site}
              onDelete={(id) => deleteMutation.mutate(id)}
              onRotateKey={handleRotateKey}
            />
          ))}
        </div>
      )}

      {/* SDK Download section */}
      <div className="border-t border-slate-800 pt-6">
        <h2 className="text-base font-semibold text-slate-300 mb-4">Integration SDKs</h2>
        <div className="grid gap-3 sm:grid-cols-3">
          {[
            { icon: '⬡', label: 'Node.js SDK', desc: 'Express / Fastify / Koa', file: 'cybershield-agent' },
            { icon: '🐍', label: 'Python SDK', desc: 'Flask / Django / FastAPI / WSGI', file: 'cybershield_python' },
            { icon: '🌐', label: 'Browser Snippet', desc: 'Drop-in analytics <script>', file: 'cybershield.js' },
          ].map(sdk => (
            <div key={sdk.label} className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex items-center gap-4">
              <span className="text-3xl">{sdk.icon}</span>
              <div>
                <p className="font-medium text-slate-200 text-sm">{sdk.label}</p>
                <p className="text-xs text-slate-500">{sdk.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Modals */}
      {showAdd && (
        <AddSiteModal
          onClose={() => setShowAdd(false)}
          onCreated={() => qc.invalidateQueries(['sites'])}
        />
      )}

      {rotateResult && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg bg-slate-900 border border-slate-700 rounded-2xl p-6">
            <h2 className="text-lg font-semibold text-white mb-4">New API Key Generated</h2>
            <ApiKeyReveal apiKey={rotateResult.api_key} onDone={() => setRotateResult(null)} />
          </div>
        </div>
      )}
    </div>
  )
}
