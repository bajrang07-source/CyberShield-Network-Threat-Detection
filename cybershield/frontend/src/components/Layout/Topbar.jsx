import { useEffect, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { Moon, Sun, Brain } from 'lucide-react'
import { format } from 'date-fns'
import useAppStore from '../../store/useAppStore'
import SiteSwitcher from '../Sites/SiteSwitcher'
import clsx from 'clsx'

const PAGE_TITLES = {
  '/': 'Dashboard',
  '/attacks': 'Attack Log',
  '/blocked-ips': 'Blocked IPs',
  '/sites': 'Connected Sites',
  '/settings': 'Settings',
}

export default function Topbar() {
  const location = useLocation()
  const title = PAGE_TITLES[location.pathname] || 'CyberShield'

  const { darkMode, toggleDark, modelStatus } = useAppStore(s => ({
    darkMode: s.darkMode,
    toggleDark: s.toggleDark,
    modelStatus: s.modelStatus,
  }))

  const [time, setTime] = useState(new Date())
  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(id)
  }, [])

  return (
    <header className="fixed top-0 left-60 right-0 h-14 bg-bg-surface/80 backdrop-blur-sm border-b border-bg-border z-30 flex items-center px-6 gap-4">
      {/* Page title */}
      <h1 className="text-base font-semibold text-white flex-shrink-0">{title}</h1>

      {/* Center: site switcher + system live + time */}
      <div className="flex-1 flex items-center justify-center gap-4">
        {/* Site Switcher */}
        <SiteSwitcher />

        <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-success/10 border border-success/20">
          <span className="w-1.5 h-1.5 rounded-full bg-success live-dot" />
          <span className="text-xs font-semibold text-success tracking-wider">SYSTEM LIVE</span>
        </div>
        <span className="text-xs font-mono text-cyber-muted">
          {format(time, 'HH:mm:ss')} UTC
        </span>
      </div>

      {/* Right: model badge + dark mode toggle */}
      <div className="flex items-center gap-3">
        {/* ML Model badge */}
        <div
          className={clsx(
            'flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border',
            modelStatus === 'active'
              ? 'bg-success/10 text-success border-success/20'
              : 'bg-warning/10 text-warning border-warning/20'
          )}
        >
          <Brain className="w-3 h-3" />
          {modelStatus === 'active' ? 'Model Active' : 'Model Offline'}
        </div>

        {/* Dark mode toggle */}
        <button
          id="dark-mode-toggle"
          onClick={toggleDark}
          className="p-1.5 rounded-lg hover:bg-bg-border transition-colors text-cyber-muted hover:text-white"
          aria-label="Toggle dark mode"
        >
          {darkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>
      </div>
    </header>
  )
}
