import { NavLink } from 'react-router-dom'
import {
  Shield, LayoutDashboard, AlertTriangle, Ban, Settings, Wifi, WifiOff, Globe
} from 'lucide-react'
import useAppStore from '../../store/useAppStore'
import clsx from 'clsx'

const NAV_ITEMS = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', exact: true },
  { to: '/attacks', icon: AlertTriangle, label: 'Attacks' },
  { to: '/blocked-ips', icon: Ban, label: 'Blocked IPs' },
  { to: '/sites', icon: Globe, label: 'Sites' },
  { to: '/settings', icon: Settings, label: 'Settings' },
]

export default function Sidebar() {
  const { wsConnected, sites, activeSiteId } = useAppStore(s => ({
    wsConnected: s.wsConnected,
    sites: s.sites,
    activeSiteId: s.activeSiteId,
  }))

  const activeSite = activeSiteId ? sites.find(s => s.id === activeSiteId) : null

  return (
    <aside className="fixed top-0 left-0 h-screen w-60 bg-bg-surface border-r border-bg-border z-40 flex flex-col">
      {/* Logo */}
      <div className="flex items-center gap-3 px-5 py-5 border-b border-bg-border">
        <div className="p-2 bg-indigo-500/20 rounded-lg border border-indigo-500/30">
          <Shield className="w-5 h-5 text-indigo-400" />
        </div>
        <div>
          <span className="font-bold text-white tracking-tight">CyberShield</span>
          <p className="text-[10px] text-cyber-muted font-mono uppercase tracking-widest">
            Universal v2.0
          </p>
        </div>
      </div>

      {/* Active site pill */}
      {activeSite && (
        <div className="mx-3 mt-3 px-3 py-2 bg-cyan-500/10 border border-cyan-500/20 rounded-lg">
          <p className="text-[10px] text-cyan-500 font-semibold uppercase tracking-wider mb-0.5">Viewing Site</p>
          <p className="text-xs text-cyan-300 font-medium truncate">{activeSite.name}</p>
        </div>
      )}

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {NAV_ITEMS.map(({ to, icon: Icon, label, exact }) => (
          <NavLink
            key={to}
            to={to}
            end={exact}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200',
                isActive
                  ? 'text-white bg-indigo-500/20 border border-indigo-500/20'
                  : 'text-cyber-muted hover:text-white hover:bg-indigo-500/10'
              )
            }
          >
            <Icon className="w-4 h-4 flex-shrink-0" />
            <span>{label}</span>
            {label === 'Sites' && sites.length > 0 && (
              <span className="ml-auto text-[10px] font-bold bg-indigo-500/30 text-indigo-300 px-1.5 py-0.5 rounded-full">
                {sites.length}
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Connection status */}
      <div className="px-4 py-4 border-t border-bg-border">
        <div className="flex items-center gap-2.5 px-3 py-2 rounded-lg bg-bg-primary">
          <span
            className={clsx(
              'w-2 h-2 rounded-full flex-shrink-0',
              wsConnected ? 'bg-success live-dot' : 'bg-danger'
            )}
          />
          <span
            className={clsx(
              'text-xs font-medium',
              wsConnected ? 'text-success' : 'text-danger'
            )}
          >
            {wsConnected ? 'Live' : 'Disconnected'}
          </span>
          {wsConnected ? (
            <Wifi className="w-3 h-3 text-success ml-auto" />
          ) : (
            <WifiOff className="w-3 h-3 text-danger ml-auto" />
          )}
        </div>
      </div>
    </aside>
  )
}
