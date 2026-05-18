import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Brain, Shield, Zap, Key, Terminal, Globe, ShieldAlert, Plus, Trash2, Play } from 'lucide-react'
import clsx from 'clsx'
import api from '../lib/api'

/* ── Reusable UI primitives ─────────────────────────────────────────────── */
function Switch({ checked, onChange, id }) {
  return (
    <button
      id={id}
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={clsx(
        'relative w-11 h-6 rounded-full transition-colors duration-200 focus:outline-none',
        checked ? 'bg-accent' : 'bg-bg-border'
      )}
    >
      <span className={clsx(
        'absolute top-1 w-4 h-4 bg-white rounded-full shadow transition-transform duration-200',
        checked ? 'translate-x-6' : 'translate-x-1'
      )} />
    </button>
  )
}

function SectionCard({ title, children }) {
  return (
    <div className="glass-card p-6 space-y-5">
      <h2 className="text-base font-semibold text-white border-b border-bg-border pb-3">{title}</h2>
      {children}
    </div>
  )
}

function RuleToggleCard({ icon: Icon, title, description, settingKey, settings, onToggle, color = '#6366f1' }) {
  const enabled = settings[settingKey] !== 'false'
  return (
    <div className={clsx(
      'flex items-center gap-4 p-4 rounded-xl border transition-all duration-200',
      enabled ? 'bg-bg-primary border-bg-border' : 'bg-bg-primary/50 border-bg-border/50 opacity-60'
    )}>
      <div className="p-2.5 rounded-lg" style={{ backgroundColor: `${color}20`, border: `1px solid ${color}30` }}>
        <Icon className="w-4 h-4" style={{ color }} />
      </div>
      <div className="flex-1">
        <p className="text-sm font-medium text-white">{title}</p>
        <p className="text-xs text-cyber-muted mt-0.5">{description}</p>
      </div>
      <Switch checked={enabled} onChange={() => onToggle(settingKey, !enabled)} id={`toggle-${settingKey}`} />
    </div>
  )
}

/* ── Main Settings Page ─────────────────────────────────────────────────── */
export default function SettingsPage() {
  const qc = useQueryClient()
  const [simType, setSimType] = useState('SQL_INJECTION')
  const [simResult, setSimResult] = useState(null)
  const [simLoading, setSimLoading] = useState(false)
  const [whitelistIp, setWhitelistIp] = useState('')
  const [whitelistNote, setWhitelistNote] = useState('')
  const [saving, setSaving] = useState(false)

  const { data: settings = {}, isLoading } = useQuery({
    queryKey: ['settings'],
    queryFn: async () => { const res = await api.get('/settings'); return res.data },
  })

  const { data: whitelist = [] } = useQuery({
    queryKey: ['whitelist'],
    queryFn: async () => { const res = await api.get('/whitelist'); return res.data },
  })

  // Optimistic update
  const updateSetting = async (key, value) => {
    setSaving(true)
    const prev = settings[key]
    qc.setQueryData(['settings'], s => ({ ...s, [key]: String(value) }))
    try {
      await api.put('/settings', { [key]: String(value) })
    } catch {
      qc.setQueryData(['settings'], s => ({ ...s, [key]: prev }))
    } finally {
      setSaving(false)
    }
  }

  const runSimulation = async () => {
    setSimLoading(true)
    setSimResult(null)
    try {
      const res = await api.post('/simulate-attack', { attack_type: simType })
      setSimResult(res.data)
    } catch (e) {
      setSimResult({ error: 'Simulation failed' })
    } finally {
      setSimLoading(false)
    }
  }

  const addWhitelist = async () => {
    if (!whitelistIp.trim()) return
    await api.post('/whitelist', { ip: whitelistIp.trim(), note: whitelistNote })
    qc.invalidateQueries(['whitelist'])
    setWhitelistIp(''); setWhitelistNote('')
  }

  const removeWhitelist = async (ip) => {
    await api.delete(`/whitelist/${ip}`)
    qc.invalidateQueries(['whitelist'])
  }

  const mlWeight = parseInt(settings.ML_WEIGHT_PCT || '60')
  const critThresh = parseInt(settings.CRITICAL_THRESHOLD || '80')
  const highThresh = parseInt(settings.HIGH_THRESHOLD || '60')
  const medThresh = parseInt(settings.MEDIUM_THRESHOLD || '40')

  if (isLoading) return (
    <div className="flex items-center justify-center h-64">
      <div className="w-8 h-8 border-2 border-accent border-t-transparent rounded-full animate-spin" />
    </div>
  )

  return (
    <div className="max-w-3xl space-y-6">

      {/* ── Section 1: Detection Thresholds ─────────────────────────────── */}
      <SectionCard title="Detection Thresholds">
        {[
          { label: 'CRITICAL Threshold', key: 'CRITICAL_THRESHOLD', val: critThresh, color: '#ef4444' },
          { label: 'HIGH Threshold', key: 'HIGH_THRESHOLD', val: highThresh, color: '#f97316' },
          { label: 'MEDIUM Threshold', key: 'MEDIUM_THRESHOLD', val: medThresh, color: '#f59e0b' },
        ].map(({ label, key, val, color }) => (
          <div key={key}>
            <div className="flex justify-between text-sm mb-2">
              <span className="text-cyber-muted">{label}</span>
              <span className="font-mono font-bold" style={{ color }}>{val}</span>
            </div>
            <input
              type="range" min={10} max={100} step={5} value={val}
              onChange={e => updateSetting(key, e.target.value)}
              className="w-full accent-accent"
            />
          </div>
        ))}
        <div className="flex items-center justify-between pt-2">
          <div>
            <p className="text-sm text-white font-medium">Auto-block on CRITICAL</p>
            <p className="text-xs text-cyber-muted">Automatically block IPs that hit critical threshold</p>
          </div>
          <Switch
            id="auto-block-toggle"
            checked={settings.AUTO_BLOCK !== 'false'}
            onChange={v => updateSetting('AUTO_BLOCK', v)}
          />
        </div>
      </SectionCard>

      {/* ── Section 2: Rule Engine ───────────────────────────────────────── */}
      <SectionCard title="Rule Engine">
        <RuleToggleCard icon={Key} title="SQL Injection" description="Detect UNION SELECT, DROP TABLE, SLEEP() patterns" settingKey="ENABLE_RULES_SQLI" settings={settings} onToggle={updateSetting} color="#ef4444" />
        <RuleToggleCard icon={Zap} title="XSS Detection" description="Detect <script>, onerror=, javascript: patterns" settingKey="ENABLE_RULES_XSS" settings={settings} onToggle={updateSetting} color="#f59e0b" />
        <RuleToggleCard icon={Globe} title="Path Traversal" description="Detect ../../, %2e%2e, /etc/passwd patterns" settingKey="ENABLE_RULES_PATH_TRAVERSAL" settings={settings} onToggle={updateSetting} color="#f97316" />
        <RuleToggleCard icon={Shield} title="Brute Force" description="Detect high-rate login attempts" settingKey="ENABLE_RULES_BRUTE_FORCE" settings={settings} onToggle={updateSetting} color="#8b5cf6" />
        <RuleToggleCard icon={Terminal} title="Command Injection" description="Detect shell commands in requests" settingKey="ENABLE_RULES_CMD_INJECTION" settings={settings} onToggle={updateSetting} color="#ec4899" />
        <RuleToggleCard icon={ShieldAlert} title="Honeypot Traps" description="Flag access to /admin, /.env, /.git/config" settingKey="ENABLE_HONEYPOT" settings={settings} onToggle={updateSetting} color="#14b8a6" />

        <div className="pt-3 border-t border-bg-border">
          <label className="text-sm text-cyber-muted mb-2 block">Brute Force Rate Limit (req/min)</label>
          <input
            type="number" min={1} max={200}
            value={settings.BRUTE_FORCE_RATE_LIMIT || '10'}
            onChange={e => updateSetting('BRUTE_FORCE_RATE_LIMIT', e.target.value)}
            className="input-field w-32"
          />
        </div>
      </SectionCard>

      {/* ── Section 3: ML Engine ─────────────────────────────────────────── */}
      <SectionCard title="ML Engine">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-white font-medium">Enable ML Layer</p>
            <p className="text-xs text-cyber-muted">Use IsolationForest + LogisticRegression ensemble</p>
          </div>
          <Switch id="ml-toggle" checked={settings.ENABLE_ML !== 'false'} onChange={v => updateSetting('ENABLE_ML', v)} />
        </div>

        <div>
          <div className="flex justify-between text-sm mb-2">
            <span className="text-cyber-muted">ML Weight</span>
            <span className="font-mono text-accent font-bold">{mlWeight}%</span>
          </div>
          <input
            type="range" min={0} max={100} step={5} value={mlWeight}
            onChange={e => updateSetting('ML_WEIGHT_PCT', e.target.value)}
            className="w-full accent-accent"
          />
          <p className="text-xs text-cyber-muted mt-2 font-mono">
            Risk = {100 - mlWeight}% Rule + {mlWeight}% ML
          </p>
        </div>

        {/* Simulation panel */}
        <div className="pt-3 border-t border-bg-border space-y-3">
          <p className="text-sm font-medium text-white">Run Test Detection</p>
          <div className="flex gap-3">
            <select value={simType} onChange={e => setSimType(e.target.value)} className="input-field flex-1">
              {['SQL_INJECTION','XSS','BRUTE_FORCE','PATH_TRAVERSAL','COMMAND_INJECTION','CLEAN'].map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
            <button onClick={runSimulation} disabled={simLoading} className="btn-primary flex items-center gap-2 px-4">
              <Play className="w-4 h-4" />
              {simLoading ? 'Running…' : 'Run'}
            </button>
          </div>

          {simResult && !simResult.error && (
            <div className="bg-bg-primary border border-bg-border rounded-xl p-4 space-y-3 animate-fade-in">
              <div className="flex items-center gap-2 flex-wrap">
                <span className={clsx('text-xs font-bold px-3 py-1 rounded-full',
                  simResult.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                  simResult.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                  simResult.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' : 'bg-green-500/20 text-green-400'
                )}>{simResult.severity}</span>
                <span className="text-xs text-warning font-medium">{simResult.attack_type}</span>
                <span className="text-xs font-mono text-white ml-auto">Risk: <strong className="text-accent">{simResult.risk_score}</strong></span>
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="bg-bg-surface rounded p-2">
                  <p className="text-cyber-muted mb-1">ML Score</p>
                  <p className="font-mono font-bold text-indigo-400">{(simResult.ml_score * 100).toFixed(1)}%</p>
                </div>
                <div className="bg-bg-surface rounded p-2">
                  <p className="text-cyber-muted mb-1">Rule Severity</p>
                  <p className="font-mono font-bold text-warning">{simResult.rule_result?.severity}/10</p>
                </div>
              </div>
              {simResult.matched_pattern && (
                <code className="block text-xs font-mono text-warning bg-bg-surface rounded p-2 break-all">
                  {simResult.matched_pattern}
                </code>
              )}
            </div>
          )}
        </div>
      </SectionCard>

      {/* ── Section 4: Webhook ───────────────────────────────────────────── */}
      <SectionCard title="Webhook Alerts">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-white font-medium">Enable Webhooks</p>
            <p className="text-xs text-cyber-muted">POST JSON alerts to Slack or custom URL</p>
          </div>
          <Switch id="webhook-toggle" checked={settings.ENABLE_WEBHOOK !== 'false'} onChange={v => updateSetting('ENABLE_WEBHOOK', v)} />
        </div>
        <div>
          <label className="text-xs text-cyber-muted mb-2 block">Webhook URL</label>
          <div className="flex gap-2">
            <input
              value={settings.WEBHOOK_URL || ''}
              onChange={e => updateSetting('WEBHOOK_URL', e.target.value)}
              placeholder="https://hooks.slack.com/services/..."
              className="input-field flex-1"
            />
            <button
              onClick={async () => {
                try {
                  await api.post('/simulate-attack', { attack_type: 'SQL_INJECTION' })
                  alert('Test webhook sent!')
                } catch { alert('Webhook test failed') }
              }}
              className="btn-ghost text-sm px-3"
            >
              Test
            </button>
          </div>
        </div>
      </SectionCard>

      {/* ── Section 5: IP Whitelist ──────────────────────────────────────── */}
      <SectionCard title="IP Whitelist">
        <div className="flex gap-3">
          <input
            value={whitelistIp}
            onChange={e => setWhitelistIp(e.target.value)}
            placeholder="IP Address"
            className="input-field w-44"
          />
          <input
            value={whitelistNote}
            onChange={e => setWhitelistNote(e.target.value)}
            placeholder="Note (optional)"
            className="input-field flex-1"
          />
          <button onClick={addWhitelist} disabled={!whitelistIp.trim()} className="btn-primary flex items-center gap-2">
            <Plus className="w-4 h-4" /> Add
          </button>
        </div>

        {whitelist.length > 0 ? (
          <div className="space-y-2 mt-1">
            {whitelist.map(entry => (
              <div key={entry.ip_address} className="flex items-center gap-3 px-3 py-2.5 bg-bg-primary rounded-lg">
                <span className="font-mono text-cyber-cyan text-sm flex-1">{entry.ip_address}</span>
                {entry.note && <span className="text-xs text-cyber-muted">{entry.note}</span>}
                <button onClick={() => removeWhitelist(entry.ip_address)} className="text-danger hover:text-red-300 p-1">
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-cyber-muted text-center py-4">No whitelisted IPs</p>
        )}
      </SectionCard>

      {saving && (
        <div className="fixed bottom-6 right-6 flex items-center gap-2 bg-accent text-white text-sm px-4 py-2 rounded-full shadow-lg animate-fade-in">
          <span className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
          Saving…
        </div>
      )}
    </div>
  )
}
