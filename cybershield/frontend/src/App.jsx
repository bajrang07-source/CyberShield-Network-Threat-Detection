import { Routes, Route, Navigate } from 'react-router-dom'
import { useEffect } from 'react'
import AppLayout from './components/Layout/AppLayout'
import PrivateRoute from './components/PrivateRoute'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Attacks from './pages/Attacks'
import BlockedIPs from './pages/BlockedIPs'
import SettingsPage from './pages/Settings'
import Sites from './pages/Sites'
import Onboarding from './pages/Onboarding'
import IncidentCenter from './pages/IncidentCenter'
import PlaybookViewer from './pages/PlaybookViewer'
import SOCCommandCenter from './pages/SOCCommandCenter'
import useAppStore from './store/useAppStore'
import api from './lib/api'
// Initialize socket on app load
import './lib/socket'

function AppInit() {
  const { setModelStatus, setSites, setOnboardingComplete } = useAppStore(s => ({
    setModelStatus: s.setModelStatus,
    setSites: s.setSites,
    setOnboardingComplete: s.setOnboardingComplete,
  }))

  useEffect(() => {
    // Poll health to set model status
    const check = async () => {
      try {
        const res = await api.get('/health')
        setModelStatus(res.data.model_loaded ? 'active' : 'offline')
      } catch {
        setModelStatus('offline')
      }
    }
    check()
    const id = setInterval(check, 30000)

    // Pre-fetch sites list only if a token exists (avoid 401 before login)
    const fetchSites = async () => {
      const token = localStorage.getItem('cs_token')
      if (!token) return
      try {
        const res = await api.get('/sites')
        setSites(res.data)
        if (res.data.length > 0) {
          setOnboardingComplete(true)
        }
      } catch {
        // Token invalid or expired — Login page will handle it
      }
    }
    fetchSites()

    return () => clearInterval(id)
  }, [])

  return null
}

/**
 * Onboarding gate: wraps authenticated routes.
 * If no sites exist AND onboarding is not complete, shows Onboarding page.
 */
function OnboardingGate({ children }) {
  const { onboardingComplete, sites, setOnboardingComplete } = useAppStore(s => ({
    onboardingComplete: s.onboardingComplete,
    sites: s.sites,
    setOnboardingComplete: s.setOnboardingComplete,
  }))

  // If user has sites or has completed onboarding, go straight to app
  if (onboardingComplete || sites.length > 0) {
    return children
  }

  return (
    <Onboarding
      onComplete={() => setOnboardingComplete(true)}
    />
  )
}

export default function App() {
  return (
    <>
      <AppInit />
      <Routes>
        <Route path="/login" element={<Login />} />

        {/* All protected routes go through OnboardingGate */}
        <Route
          path="/"
          element={
            <PrivateRoute>
              <OnboardingGate>
                <AppLayout><Dashboard /></AppLayout>
              </OnboardingGate>
            </PrivateRoute>
          }
        />
        <Route
          path="/attacks"
          element={
            <PrivateRoute>
              <OnboardingGate>
                <AppLayout><Attacks /></AppLayout>
              </OnboardingGate>
            </PrivateRoute>
          }
        />
        <Route
          path="/blocked-ips"
          element={
            <PrivateRoute>
              <OnboardingGate>
                <AppLayout><BlockedIPs /></AppLayout>
              </OnboardingGate>
            </PrivateRoute>
          }
        />
        <Route
          path="/sites"
          element={
            <PrivateRoute>
              <AppLayout><Sites /></AppLayout>
            </PrivateRoute>
          }
        />
        <Route
          path="/settings"
          element={
            <PrivateRoute>
              <OnboardingGate>
                <AppLayout><SettingsPage /></AppLayout>
              </OnboardingGate>
            </PrivateRoute>
          }
        />
        <Route
          path="/incidents"
          element={
            <PrivateRoute>
              <OnboardingGate>
                <AppLayout><IncidentCenter /></AppLayout>
              </OnboardingGate>
            </PrivateRoute>
          }
        />
        <Route
          path="/incidents/:id/playbook"
          element={
            <PrivateRoute>
              <OnboardingGate>
                <AppLayout><PlaybookViewer /></AppLayout>
              </OnboardingGate>
            </PrivateRoute>
          }
        />
        <Route
          path="/soc"
          element={
            <PrivateRoute>
              <OnboardingGate>
                <AppLayout><SOCCommandCenter /></AppLayout>
              </OnboardingGate>
            </PrivateRoute>
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </>
  )
}
