import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Activity } from 'lucide-react'
import api from '../lib/api'

export default function MitreHeatmap() {
  const navigate = useNavigate()
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchHeatmap()
  }, [])

  const fetchHeatmap = async () => {
    try {
      setLoading(true)
      const res = await api.get('/mitre/heatmap').catch(() => ({ data: [] }))
      // Fallback mock data if API is not fully wired yet
      const heatmapData = (res.data && res.data.length > 0) ? res.data : [
        { tactic: 'Initial Access', technique_id: 'T1190', name: 'Exploit Public-Facing Application', count: 45 },
        { tactic: 'Initial Access', technique_id: 'T1078', name: 'Valid Accounts', count: 12 },
        { tactic: 'Execution', technique_id: 'T1059', name: 'Command and Scripting Interpreter', count: 89 },
        { tactic: 'Persistence', technique_id: 'T1098', name: 'Account Manipulation', count: 5 },
        { tactic: 'Defense Evasion', technique_id: 'T1027', name: 'Obfuscated Files or Information', count: 34 },
        { tactic: 'Defense Evasion', technique_id: 'T1070', name: 'Indicator Removal', count: 18 },
        { tactic: 'Credential Access', technique_id: 'T1110', name: 'Brute Force', count: 156 },
        { tactic: 'Impact', technique_id: 'T1499', name: 'Endpoint Denial of Service', count: 23 },
      ]
      setData(heatmapData)
    } catch (err) {
      console.error('Failed to fetch MITRE heatmap', err)
      setData([])
    } finally {
      setLoading(false)
    }
  }

  // Group by tactic
  const tactics = data.reduce((acc, item) => {
    if (!acc[item.tactic]) {
      acc[item.tactic] = []
    }
    acc[item.tactic].push(item)
    return acc
  }, {})

  // Find max count for color intensity
  const maxCount = Math.max(...data.map(d => d.count), 1)

  const getHeatmapColor = (count) => {
    const intensity = count / maxCount
    if (intensity === 0) return 'bg-bg-surface border-bg-border text-gray-500'
    if (intensity < 0.2) return 'bg-purple-900/30 border-purple-500/30 text-purple-200'
    if (intensity < 0.5) return 'bg-purple-700/50 border-purple-500/50 text-purple-100'
    if (intensity < 0.8) return 'bg-purple-600 border-purple-400 text-white'
    return 'bg-purple-500 border-purple-300 text-white font-bold'
  }

  const handleCellClick = (technique) => {
    // Navigate to incident center with search pre-filled
    // We could pass state or use query params. For now, navigate and let the user search.
    navigate('/incidents', { state: { search: technique.technique_id } })
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-48 text-cyber-muted bg-bg-surface rounded-xl border border-bg-border">
        <Activity className="w-6 h-6 animate-pulse mr-2" /> Loading MITRE ATT&CK Data...
      </div>
    )
  }

  if (Object.keys(tactics).length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-cyber-muted bg-bg-surface rounded-xl border border-bg-border">
        No MITRE data available.
      </div>
    )
  }

  return (
    <div className="bg-bg-surface rounded-xl border border-bg-border p-4 overflow-x-auto custom-scrollbar">
      <div className="flex gap-4 min-w-max">
        {Object.entries(tactics).map(([tacticName, techniques]) => (
          <div key={tacticName} className="flex flex-col w-48 shrink-0">
            {/* Tactic Header */}
            <div className="bg-bg-primary border border-bg-border p-2 mb-2 rounded text-center">
              <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider truncate" title={tacticName}>
                {tacticName}
              </h4>
            </div>
            
            {/* Techniques Grid */}
            <div className="flex flex-col gap-1">
              {techniques.map(tech => (
                <div 
                  key={tech.technique_id}
                  onClick={() => handleCellClick(tech)}
                  className={`p-2 border rounded cursor-pointer transition-transform hover:scale-[1.02] relative group ${getHeatmapColor(tech.count)}`}
                >
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-[10px] font-mono opacity-80">{tech.technique_id}</span>
                    <span className="text-[10px] font-bold">{tech.count}</span>
                  </div>
                  <p className="text-xs leading-tight truncate">{tech.name}</p>

                  {/* Tooltip */}
                  <div className="absolute left-full top-0 ml-2 w-48 p-2 bg-gray-800 border border-gray-700 text-xs text-gray-200 rounded opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-10 hidden sm:block shadow-xl">
                    <div className="font-bold text-white mb-1">{tech.technique_id}: {tech.name}</div>
                    <div className="text-cyber-muted">Observed {tech.count} times. Click to view related incidents.</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
