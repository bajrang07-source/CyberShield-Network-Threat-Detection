import { useState } from 'react'

/**
 * ApiKeyReveal — shows the plaintext API key ONCE with copy button.
 */
export default function ApiKeyReveal({ apiKey, onDone }) {
  const [copied, setCopied] = useState(false)

  function handleCopy() {
    navigator.clipboard.writeText(apiKey).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 3000)
    })
  }

  return (
    <div className="space-y-4">
      {/* Warning */}
      <div className="flex gap-3 p-4 bg-amber-950/40 border border-amber-700/60 rounded-xl">
        <span className="text-xl flex-shrink-0">⚠️</span>
        <div>
          <p className="text-amber-400 font-semibold text-sm">This key will not be shown again.</p>
          <p className="text-amber-500/80 text-xs mt-1">
            Copy and store it securely. You can rotate it from Site Settings if lost.
          </p>
        </div>
      </div>

      {/* Key display */}
      <div className="flex items-center gap-2 p-3 bg-slate-950 border border-slate-700 rounded-lg font-mono text-sm">
        <span className="flex-1 text-cyan-400 break-all select-all">{apiKey}</span>
        <button
          onClick={handleCopy}
          className={`flex-shrink-0 px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
            copied
              ? 'bg-emerald-600 text-white'
              : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
          }`}
        >
          {copied ? '✓ Copied' : 'Copy'}
        </button>
      </div>

      {/* Quick integration guide */}
      <div className="space-y-2">
        <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Quick Integration</p>

        {/* Node.js */}
        <div className="p-3 bg-slate-800/60 rounded-lg">
          <p className="text-xs text-slate-500 mb-1.5">Node.js / Express</p>
          <pre className="text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap break-all">{`const cybershield = require('cybershield-agent')
app.use(cybershield({ apiKey: '${apiKey}' }))`}</pre>
        </div>

        {/* Python */}
        <div className="p-3 bg-slate-800/60 rounded-lg">
          <p className="text-xs text-slate-500 mb-1.5">Python / Flask</p>
          <pre className="text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap break-all">{`from cybershield_python import CyberShieldMiddleware
app.wsgi_app = CyberShieldMiddleware(app.wsgi_app, api_key='${apiKey}')`}</pre>
        </div>

        {/* Browser */}
        <div className="p-3 bg-slate-800/60 rounded-lg">
          <p className="text-xs text-slate-500 mb-1.5">Browser Snippet</p>
          <pre className="text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap break-all">{`<script src="cybershield.js" data-api-key="${apiKey}"></script>`}</pre>
        </div>
      </div>

      <button
        onClick={onDone}
        className="w-full py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-semibold transition-colors"
      >
        I've saved my key — Continue
      </button>
    </div>
  )
}
