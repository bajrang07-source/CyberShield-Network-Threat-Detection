import { useState, useEffect, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { 
  ArrowLeft, 
  CheckSquare, 
  Square, 
  Download, 
  Send, 
  CheckCircle2,
  Activity,
  UserCircle2
} from 'lucide-react'
import useIncidentStore from '../store/useIncidentStore'
import api from '../lib/api'

export default function PlaybookViewer() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { incidents, pendingPlaybooks } = useIncidentStore()
  
  const [incident, setIncident] = useState(null)
  const [playbookContent, setPlaybookContent] = useState('')
  const [isStreaming, setIsStreaming] = useState(false)
  const [checklist, setChecklist] = useState([])

  const streamRef = useRef(null)

  useEffect(() => {
    // Find incident locally or we would fetch it
    const inc = incidents.find(i => i.id === id)
    if (inc) {
      setIncident(inc)
    } else {
      // In a real app we'd fetch the specific incident if not in store
      api.get(`/incidents/${id}`).then(res => setIncident(res.data)).catch(console.error)
    }

    fetchPlaybook()
  }, [id])

  // Watch for streaming updates
  useEffect(() => {
    const pending = pendingPlaybooks.find(p => p.incidentId === id)
    if (pending) {
      setIsStreaming(true)
      setPlaybookContent(pending.content)
      parseChecklist(pending.content)
      
      // Auto-scroll
      if (streamRef.current) {
        streamRef.current.scrollTop = streamRef.current.scrollHeight
      }
    } else if (incident && incident.playbook) {
      setIsStreaming(false)
      setPlaybookContent(incident.playbook)
      parseChecklist(incident.playbook)
    }
  }, [pendingPlaybooks, incident, id])

  const fetchPlaybook = async () => {
    try {
      const res = await api.get(`/incidents/${id}/playbook`)
      if (res.status === 202) {
        setIsStreaming(true)
        // Socket will handle the rest via 'playbook_stream'
      } else if (res.data && res.data.playbook) {
        setIsStreaming(false)
        setPlaybookContent(res.data.playbook)
        parseChecklist(res.data.playbook)
      }
    } catch (err) {
      console.error('Failed to fetch playbook', err)
    }
  }

  // Simple parser to extract numbered steps from markdown
  const parseChecklist = (content) => {
    if (!content) return
    const lines = content.split('\n')
    const steps = []
    let currentStep = ''
    
    lines.forEach(line => {
      // Match lines like "1. Do this" or "- Do that"
      if (/^(\d+\.|\-|\*)\s/.test(line)) {
        if (currentStep) steps.push({ text: currentStep, checked: false, notes: '', assignee: '' })
        currentStep = line.replace(/^(\d+\.|\-|\*)\s/, '').trim()
      } else if (currentStep && line.trim()) {
        currentStep += ' ' + line.trim()
      }
    })
    if (currentStep) steps.push({ text: currentStep, checked: false, notes: '', assignee: '' })
    
    setChecklist(steps)
  }

  const handleToggleCheck = (index) => {
    const newList = [...checklist]
    newList[index].checked = !newList[index].checked
    setChecklist(newList)
  }

  if (!incident) return <div className="p-8 text-cyber-muted">Loading incident details...</div>

  return (
    <div className="h-full flex flex-col space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button 
            onClick={() => navigate('/incidents')}
            className="p-2 hover:bg-bg-surface rounded-lg text-cyber-muted hover:text-white transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <h1 className="text-2xl font-bold text-white">IR Playbook</h1>
            <p className="text-cyber-muted text-sm mt-1">Incident: {incident.id}</p>
          </div>
        </div>
        <div className="flex gap-2">
          <button className="flex items-center gap-2 px-4 py-2 bg-bg-surface border border-bg-border hover:border-cyber-muted text-gray-200 rounded-lg text-sm transition-colors">
            <Send className="w-4 h-4" /> Send to Analyst
          </button>
          <button className="flex items-center gap-2 px-4 py-2 bg-bg-surface border border-bg-border hover:border-cyber-muted text-gray-200 rounded-lg text-sm transition-colors">
            <Download className="w-4 h-4" /> Export PDF
          </button>
          <button 
            className="flex items-center gap-2 px-4 py-2 bg-success hover:bg-success/80 text-white rounded-lg text-sm font-medium transition-colors"
          >
            <CheckCircle2 className="w-4 h-4" /> Approve & Close
          </button>
        </div>
      </div>

      {/* Top Banner: Threat Category, Confidence, MITRE */}
      <div className="bg-bg-surface border border-bg-border rounded-xl p-4 flex flex-wrap gap-6 items-center">
        <div>
          <span className="text-xs text-cyber-muted uppercase block mb-1">Threat Category</span>
          <span className={`px-2 py-1 rounded text-xs font-bold border bg-danger/10 text-danger border-danger/20`}>
            {incident.severity || 'UNKNOWN'}
          </span>
        </div>
        <div>
          <span className="text-xs text-cyber-muted uppercase block mb-1">Confidence</span>
          <span className="text-lg font-mono text-white">{incident.confidence || '98'}%</span>
        </div>
        <div className="flex-1">
          <span className="text-xs text-cyber-muted uppercase block mb-1">MITRE Techniques</span>
          <div className="flex gap-2">
            {incident.mitre_tactics?.map((t, i) => (
              <span key={i} className="px-2 py-1 bg-purple-500/10 text-purple-400 border border-purple-500/20 rounded text-xs flex items-center gap-1">
                <Activity className="w-3 h-3" /> {t.technique_id}
              </span>
            ))}
            {(!incident.mitre_tactics || incident.mitre_tactics.length === 0) && (
              <span className="text-sm text-gray-400">N/A</span>
            )}
          </div>
        </div>
      </div>

      <div className="flex-1 flex gap-4 overflow-hidden">
        {/* Left Panel: Raw Stream / Context */}
        <div className="w-[40%] bg-bg-surface border border-bg-border rounded-xl flex flex-col overflow-hidden">
          <div className="p-4 border-b border-bg-border flex justify-between items-center">
            <h3 className="font-semibold text-gray-200">Playbook Source</h3>
            {isStreaming && (
              <span className="flex items-center gap-2 text-xs text-accent">
                <div className="w-2 h-2 bg-accent rounded-full animate-pulse"></div>
                Generating...
              </span>
            )}
          </div>
          <div 
            ref={streamRef}
            className="flex-1 overflow-y-auto p-4 custom-scrollbar bg-bg-primary/50 font-mono text-sm text-gray-300 whitespace-pre-wrap"
          >
            {playbookContent || 'Awaiting playbook generation...'}
          </div>
        </div>

        {/* Right Panel: Interactive Checklist */}
        <div className="w-[60%] bg-bg-surface border border-bg-border rounded-xl flex flex-col overflow-hidden">
          <div className="p-4 border-b border-bg-border">
            <h3 className="font-semibold text-gray-200">Action Items</h3>
          </div>
          <div className="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar">
            {checklist.length === 0 ? (
              <div className="text-cyber-muted text-sm">
                {isStreaming ? 'Extracting action items...' : 'No actionable steps found in playbook.'}
              </div>
            ) : (
              checklist.map((step, idx) => (
                <div key={idx} className="p-4 bg-bg-primary border border-bg-border rounded-lg transition-colors hover:border-cyber-muted">
                  <div className="flex items-start gap-3">
                    <button onClick={() => handleToggleCheck(idx)} className="mt-0.5 text-cyber-muted hover:text-accent transition-colors">
                      {step.checked ? <CheckSquare className="w-5 h-5 text-success" /> : <Square className="w-5 h-5" />}
                    </button>
                    <div className="flex-1">
                      <p className={`text-sm ${step.checked ? 'text-cyber-muted line-through' : 'text-gray-200'}`}>
                        {step.text}
                      </p>
                      
                      {/* Action Inputs */}
                      <div className="mt-3 flex gap-3">
                        <div className="flex-1">
                          <input 
                            type="text" 
                            placeholder="Add execution notes..." 
                            className="w-full bg-bg-surface border border-bg-border rounded py-1.5 px-3 text-xs text-gray-300 focus:outline-none focus:border-accent"
                          />
                        </div>
                        <div className="w-48 relative">
                          <UserCircle2 className="absolute left-2 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
                          <select className="w-full bg-bg-surface border border-bg-border rounded py-1.5 pl-8 pr-2 text-xs text-gray-300 focus:outline-none appearance-none">
                            <option value="">Assign to...</option>
                            <option value="analyst1">SOC Analyst 1</option>
                            <option value="analyst2">SOC Analyst 2</option>
                            <option value="l2">L2 Responder</option>
                          </select>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
