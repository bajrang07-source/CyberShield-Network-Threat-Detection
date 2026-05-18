import { useState } from 'react'
import AddSiteModal from '../components/Sites/AddSiteModal'

/**
 * Onboarding — shown after first login when no sites exist.
 * Guides user through creating their first site and getting their API key.
 */
export default function Onboarding({ onComplete }) {
  const [showModal, setShowModal] = useState(false)

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
      {/* Subtle animated grid bg */}
      <div className="fixed inset-0 bg-[radial-gradient(ellipse_at_top,_rgba(6,182,212,0.08)_0%,_transparent_60%)] pointer-events-none" />

      <div className="w-full max-w-2xl text-center space-y-8 relative">
        {/* Badge */}
        <div className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-500/10 border border-cyan-500/30 rounded-full text-cyan-400 text-sm font-medium">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
          CyberShield Universal
        </div>

        {/* Heading */}
        <div className="space-y-4">
          <h1 className="text-4xl md:text-5xl font-bold text-white leading-tight">
            Welcome to{' '}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">
              CyberShield
            </span>
          </h1>
          <p className="text-slate-400 text-lg max-w-xl mx-auto">
            Connect any website in minutes. Real-time threat detection powered by
            ML + rule engine, scoped per site.
          </p>
        </div>

        {/* Steps */}
        <div className="grid sm:grid-cols-3 gap-4 text-left">
          {[
            {
              step: '01',
              title: 'Add Your Site',
              desc: 'Register your website origin URL to get a unique API key.',
              icon: '🌐',
            },
            {
              step: '02',
              title: 'Install SDK',
              desc: 'Drop in our Node.js, Python, or browser snippet — 2 lines of code.',
              icon: '⚡',
            },
            {
              step: '03',
              title: 'Monitor Live',
              desc: 'Watch real-time threat analysis per site on your dashboard.',
              icon: '🛡️',
            },
          ].map(({ step, title, desc, icon }) => (
            <div key={step} className="p-5 bg-slate-900 border border-slate-800 rounded-2xl">
              <div className="flex items-center gap-3 mb-3">
                <span className="text-2xl">{icon}</span>
                <span className="text-xs font-mono text-cyan-500 font-semibold">{step}</span>
              </div>
              <h3 className="font-semibold text-slate-200 mb-1">{title}</h3>
              <p className="text-sm text-slate-500">{desc}</p>
            </div>
          ))}
        </div>

        {/* CTA */}
        <div className="flex flex-col sm:flex-row gap-3 justify-center">
          <button
            onClick={() => setShowModal(true)}
            className="px-8 py-3.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl font-semibold text-base shadow-lg shadow-cyan-600/25 transition-all hover:scale-105"
          >
            + Add Your First Site
          </button>
          <button
            onClick={onComplete}
            className="px-8 py-3.5 text-slate-400 hover:text-slate-200 rounded-xl font-medium text-base transition-colors"
          >
            Skip for now →
          </button>
        </div>

        <p className="text-xs text-slate-600">
          Your existing local traffic monitoring continues to work uninterrupted.
        </p>
      </div>

      {showModal && (
        <AddSiteModal
          onClose={() => setShowModal(false)}
          onCreated={() => {
            setShowModal(false)
            onComplete()
          }}
        />
      )}
    </div>
  )
}
