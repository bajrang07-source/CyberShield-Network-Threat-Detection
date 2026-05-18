import { useEffect, useState } from 'react'
import api from '../../lib/api'
import useAppStore from '../../store/useAppStore'
import { joinSiteRoom, leaveSiteRoom } from '../../lib/socket'

/**
 * SiteSwitcher — shown in the Topbar.
 * Lets the user switch between "All Sites" and individual sites.
 */
export default function SiteSwitcher() {
  const { sites, activeSiteId, setSites, setActiveSiteId } = useAppStore()
  const [open, setOpen] = useState(false)

  useEffect(() => {
    api.get('/sites')
      .then(res => setSites(res.data))
      .catch(() => {})
  }, [])

  const activeSite = sites.find(s => s.id === activeSiteId)

  function handleSelect(siteId) {
    setOpen(false)
    if (siteId === activeSiteId) return

    // Leave old room, join new room
    if (activeSiteId) leaveSiteRoom()
    if (siteId) {
      joinSiteRoom(siteId)
      setActiveSiteId(siteId)
    } else {
      leaveSiteRoom()
      setActiveSiteId(null)
    }
  }

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(o => !o)}
        className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 hover:border-cyan-500 transition-all text-sm font-medium text-slate-200"
      >
        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
        <span className="max-w-[140px] truncate">
          {activeSite ? activeSite.name : 'All Sites'}
        </span>
        <svg className={`w-4 h-4 text-slate-400 transition-transform ${open ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {open && (
        <div className="absolute top-full mt-2 right-0 w-64 bg-slate-900 border border-slate-700 rounded-xl shadow-2xl shadow-black/50 z-50 overflow-hidden">
          <div className="p-2">
            {/* All Sites option */}
            <button
              onClick={() => handleSelect(null)}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                !activeSiteId ? 'bg-cyan-600/20 text-cyan-400' : 'text-slate-300 hover:bg-slate-800'
              }`}
            >
              <span className="text-lg">🌐</span>
              <span>All Sites</span>
              {!activeSiteId && <span className="ml-auto text-xs text-cyan-500">Active</span>}
            </button>

            {sites.length > 0 && (
              <div className="my-2 h-px bg-slate-800" />
            )}

            {/* Individual sites */}
            {sites.map(site => (
              <button
                key={site.id}
                onClick={() => handleSelect(site.id)}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                  activeSiteId === site.id ? 'bg-cyan-600/20 text-cyan-400' : 'text-slate-300 hover:bg-slate-800'
                }`}
              >
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${site.status === 'active' ? 'bg-emerald-400' : 'bg-slate-500'}`} />
                <div className="flex flex-col items-start min-w-0">
                  <span className="truncate font-medium">{site.name}</span>
                  <span className="text-xs text-slate-500 truncate">{site.origin_url}</span>
                </div>
                {activeSiteId === site.id && <span className="ml-auto text-xs text-cyan-500 flex-shrink-0">Active</span>}
              </button>
            ))}

            <div className="my-2 h-px bg-slate-800" />

            <a
              href="/sites"
              className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
              onClick={() => setOpen(false)}
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              Manage Sites
            </a>
          </div>
        </div>
      )}
    </div>
  )
}
