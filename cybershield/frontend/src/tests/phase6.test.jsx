import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import IncidentCenter from '../pages/IncidentCenter'
import PlaybookViewer from '../pages/PlaybookViewer'
import SOCCommandCenter from '../pages/SOCCommandCenter'
import MitreHeatmap from '../components/MitreHeatmap'
import LiveTrafficChart from '../components/Dashboard/LiveTrafficChart'
import useIncidentStore from '../store/useIncidentStore'

// Mock the API
vi.mock('../lib/api', () => ({
  default: {
    get: vi.fn((url) => {
      if (url === '/incidents') {
        return Promise.resolve({
          data: [
            { id: 'INC-1', title: 'Test Incident', severity: 'CRITICAL', status: 'OPEN' }
          ]
        })
      }
      if (url === '/incidents/INC-1/playbook') {
        return Promise.resolve({ data: { playbook: '1. Block IP' } })
      }
      if (url === '/soc/stats') {
        return Promise.resolve({ data: { daily_alerts: 100 } })
      }
      if (url === '/mitre/heatmap') {
        return Promise.resolve({ data: [] })
      }
      return Promise.resolve({ data: [] })
    }),
    post: vi.fn(() => Promise.resolve({}))
  }
}))

// Mock Recharts to avoid ResizeObserver issues in tests
vi.mock('recharts', async () => {
  const OriginalModule = await vi.importActual('recharts')
  return {
    ...OriginalModule,
    ResponsiveContainer: ({ children }) => <div style={{ width: '100px', height: '100px' }}>{children}</div>
  }
})

describe('Phase 6: Incident Management & SOC Views', () => {

  beforeEach(() => {
    vi.clearAllMocks()
    useIncidentStore.setState({ incidents: [], activeIncident: null, pendingPlaybooks: [], socStats: {} })
  })

  it('IncidentCenter renders incident list and severity badges', async () => {
    render(
      <MemoryRouter>
        <IncidentCenter />
      </MemoryRouter>
    )
    
    // Check title
    expect(screen.getByText('Incident Center')).toBeInTheDocument()
    
    // Check if incident list loads
    await waitFor(() => {
      expect(screen.getByText('Test Incident')).toBeInTheDocument()
    })
    
    // Check severity badge
    const badge = screen.getAllByText('CRITICAL')[0]
    expect(badge).toBeInTheDocument()
    expect(badge.className).toContain('bg-danger')
  })

  it('PlaybookViewer shows content', async () => {
    render(
      <MemoryRouter initialEntries={['/incidents/INC-1/playbook']}>
        <Routes>
          <Route path="/incidents/:id/playbook" element={<PlaybookViewer />} />
        </Routes>
      </MemoryRouter>
    )
    
    expect(screen.getByText(/IR Playbook/i)).toBeInTheDocument()
    
    // Check if playbook content loads
    await waitFor(() => {
      expect(screen.getByText('1. Block IP')).toBeInTheDocument()
    })
  })

  it('SOCCommandCenter renders all three panels', async () => {
    render(
      <MemoryRouter>
        <SOCCommandCenter />
      </MemoryRouter>
    )
    
    expect(screen.getByText('SOC Command Center')).toBeInTheDocument()
    
    // Check left panel (ThreatFeed should render something)
    expect(screen.getByText(/Live Alerts Pipeline/i)).toBeInTheDocument()
    
    // Check center panel (Queue)
    expect(screen.getByText(/Incident Triaging Queue/i)).toBeInTheDocument()
    
    // Check right panel (Metrics)
    expect(screen.getByText(/Open Incidents by Severity/i)).toBeInTheDocument()
  })

  it('MitreHeatmap renders without crash on empty data', async () => {
    render(
      <MemoryRouter>
        <MitreHeatmap />
      </MemoryRouter>
    )
    
    await waitFor(() => {
      expect(screen.getByText(/No MITRE data available/i)).toBeInTheDocument()
    })
  })

  it('Existing LiveTrafficChart renders correctly (regression test)', () => {
    render(
      <MemoryRouter>
        <LiveTrafficChart />
      </MemoryRouter>
    )
    
    expect(screen.getByText(/Live Traffic Analysis/i)).toBeInTheDocument()
  })
})
