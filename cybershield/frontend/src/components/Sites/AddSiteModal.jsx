import { useState } from 'react'
import api from '../../lib/api'
import useAppStore from '../../store/useAppStore'
import ApiKeyReveal from './ApiKeyReveal'

/**
 * AddSiteModal — shown during onboarding and from Sites page.
 */
export default function AddSiteModal({ onClose, onCreated }) {
  const { addSite, setOnboardingComplete } = useAppStore()

  const [step, setStep] = useState('form')   // 'form' | 'key'
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [createdSite, setCreatedSite] = useState(null)

  const [form, setForm] = useState({ name: '', origin_url: '' })

  function handleChange(e) {
    setForm(f => ({ ...f, [e.target.name]: e.target.value }))
  }

  async function handleSubmit(e) {
    e.preventDefault()
    if (!form.name.trim() || !form.origin_url.trim()) {
      setError('Both fields are required.')
      return
    }
    setLoading(true)
    setError('')
    try {
      const res = await api.post('/sites', {
        name: form.name.trim(),
        origin_url: form.origin_url.trim(),
      })
      const { site, api_key } = res.data
      setApiKey(api_key)
      setCreatedSite(site)
      addSite(site)
      setOnboardingComplete(true)
      setStep('key')
      if (onCreated) onCreated(site, api_key)
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to create site.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="w-full max-w-lg bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="px-6 py-5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white">
              {step === 'form' ? 'Connect Your Website' : 'Your API Key'}
            </h2>
            <p className="text-sm text-slate-400 mt-0.5">
              {step === 'form'
                ? 'Add a site to start monitoring external traffic.'
                : `Site "${createdSite?.name}" created successfully.`}
            </p>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300 transition-colors">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Form step */}
        {step === 'form' && (
          <form onSubmit={handleSubmit} className="p-6 space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">Site Name</label>
              <input
                name="name"
                value={form.name}
                onChange={handleChange}
                placeholder="My Production App"
                className="w-full px-4 py-2.5 bg-slate-800 border border-slate-600 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">Origin URL</label>
              <input
                name="origin_url"
                value={form.origin_url}
                onChange={handleChange}
                placeholder="https://myapp.com"
                className="w-full px-4 py-2.5 bg-slate-800 border border-slate-600 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
              />
            </div>

            {error && (
              <div className="px-4 py-3 bg-red-950/50 border border-red-800 rounded-lg text-red-400 text-sm">
                {error}
              </div>
            )}

            <div className="flex gap-3 pt-2">
              <button type="button" onClick={onClose}
                className="flex-1 px-4 py-2.5 bg-slate-800 text-slate-300 rounded-lg hover:bg-slate-700 transition-colors text-sm font-medium">
                Cancel
              </button>
              <button type="submit" disabled={loading}
                className="flex-1 px-4 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors text-sm font-semibold disabled:opacity-50 disabled:cursor-not-allowed">
                {loading ? 'Creating...' : 'Create Site'}
              </button>
            </div>
          </form>
        )}

        {/* API Key reveal step */}
        {step === 'key' && (
          <div className="p-6">
            <ApiKeyReveal apiKey={apiKey} onDone={onClose} />
          </div>
        )}
      </div>
    </div>
  )
}
