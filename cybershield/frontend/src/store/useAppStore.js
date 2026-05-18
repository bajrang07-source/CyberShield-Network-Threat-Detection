import { create } from 'zustand'
import { persist } from 'zustand/middleware'

const MAX_LIVE_ATTACKS   = 50
const MAX_LIVE_REQUESTS  = 100  // raw request feed (all traffic)
const MAX_RESPONSE_TIMES = 60   // rolling response time history

const useAppStore = create(
  persist(
    (set, get) => ({
      // ── UI state ──────────────────────────────────────────────────────────
      sidebarOpen: true,
      darkMode: true,

      // ── System status ─────────────────────────────────────────────────────
      systemStatus: 'online',
      modelStatus: 'unknown',
      currentTime: new Date(),
      wsConnected: false,
      connectionCount: 0,        // live socket client count

      // ── Multi-tenant: Sites ───────────────────────────────────────────────
      sites: [],
      activeSiteId: null,
      onboardingComplete: false,

      // ── Attack data ───────────────────────────────────────────────────────
      liveAttacks: [],
      blockedIPs: [],

      // ── NEW: Real-time traffic data (all requests, not just attacks) ──────
      liveRequests: [],          // raw feed of every request
      reqPerSec: 0,              // rolling req/sec
      topSuspiciousIPs: [],      // top 5 suspicious IPs leaderboard
      responseTimes: [],         // [{t: timestamp, ms: number}]
      hasReceivedTraffic: false, // gates empty-state UI

      // ── Stats (traffic-driven, updated by socket) ─────────────────────────
      stats: {
        total_requests: 0,
        attacks_detected: 0,
        blocked_ips: 0,
        avg_risk_score: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        top_attack_types: [],
        requests_per_hour: [],
      },
      settings: {},

      // ── Actions: UI ──────────────────────────────────────────────────────
      toggleSidebar: () => set(s => ({ sidebarOpen: !s.sidebarOpen })),
      toggleDark:    () => set(s => ({ darkMode: !s.darkMode })),
      setCurrentTime:  (time)    => set({ currentTime: time }),
      setWsConnected:  (v)       => set({ wsConnected: v }),
      setModelStatus:  (status)  => set({ modelStatus: status }),
      setConnectionCount: (n)    => set({ connectionCount: n }),

      // ── Actions: Sites ───────────────────────────────────────────────────
      setSites:       (sites) => set({ sites }),
      addSite:        (site)  => set(s => ({ sites: [site, ...s.sites], onboardingComplete: true })),
      updateSite:     (siteId, patch) => set(s => ({
        sites: s.sites.map(site => site.id === siteId ? { ...site, ...patch } : site),
      })),
      removeSite:     (siteId) => set(s => ({
        sites: s.sites.filter(site => site.id !== siteId),
        activeSiteId: s.activeSiteId === siteId ? null : s.activeSiteId,
      })),
      setActiveSiteId:       (siteId) => set({ activeSiteId: siteId }),
      setOnboardingComplete: (val)    => set({ onboardingComplete: val }),
      getActiveSite: () => {
        const { sites, activeSiteId } = get()
        return activeSiteId ? sites.find(s => s.id === activeSiteId) || null : null
      },

      // ── Actions: Attacks (threat-level events only) ───────────────────────
      addAttack: (attack) => set(s => ({
        liveAttacks: [attack, ...s.liveAttacks].slice(0, MAX_LIVE_ATTACKS),
        hasReceivedTraffic: true,
      })),
      getLiveAttacks: () => {
        const { liveAttacks, activeSiteId } = get()
        if (!activeSiteId) return liveAttacks
        return liveAttacks.filter(a => a.site_id === activeSiteId)
      },

      // ── Actions: Raw request feed (ALL requests) ──────────────────────────
      addLiveRequest: (req) => set(s => ({
        liveRequests: [req, ...s.liveRequests].slice(0, MAX_LIVE_REQUESTS),
        hasReceivedTraffic: true,
      })),

      // ── Actions: Req/sec ──────────────────────────────────────────────────
      setReqPerSec: (rps) => set({ reqPerSec: rps }),

      // ── Actions: Top suspicious IPs ───────────────────────────────────────
      setTopSuspiciousIPs: (ips) => set({ topSuspiciousIPs: ips }),

      // ── Actions: Response times ───────────────────────────────────────────
      addResponseTime: (entry) => set(s => ({
        responseTimes: [...s.responseTimes, entry].slice(-MAX_RESPONSE_TIMES),
      })),

      // ── Actions: Stats (socket-pushed, traffic-driven) ────────────────────
      updateStats: (incoming) => set(s => ({
        stats: {
          ...s.stats,
          ...incoming,
          // Preserve computed fields if not included in delta
          avg_risk_score:  incoming.avg_risk_score  ?? s.stats.avg_risk_score,
          top_attack_types: incoming.top_attack_types ?? s.stats.top_attack_types,
          requests_per_hour: incoming.requests_per_hour ?? s.stats.requests_per_hour,
        },
        hasReceivedTraffic: true,
      })),

      // ── Actions: Blocked IPs ─────────────────────────────────────────────
      setBlocked: (blockedIPs) => set({ blockedIPs }),
      addBlockedIP: (ip) => set(s => ({
        blockedIPs: [ip, ...s.blockedIPs],
        stats: { ...s.stats, blocked_ips: s.stats.blocked_ips + 1 },
      })),

      // ── Actions: Settings ────────────────────────────────────────────────
      setSettings:    (settings) => set({ settings }),
      updateSetting:  (key, value) => set(s => ({ settings: { ...s.settings, [key]: value } })),

      // ── Actions: Reset ────────────────────────────────────────────────────
      clearAttacks: () => set({ liveAttacks: [] }),
      clearAll:     () => set({
        liveAttacks: [], liveRequests: [], blockedIPs: [],
        reqPerSec: 0, topSuspiciousIPs: [], responseTimes: [],
        hasReceivedTraffic: false,
      }),
    }),
    {
      name: 'cybershield-store',
      partialize: (state) => ({
        darkMode:           state.darkMode,
        sidebarOpen:        state.sidebarOpen,
        activeSiteId:       state.activeSiteId,
        onboardingComplete: state.onboardingComplete,
      }),
    }
  )
)

export default useAppStore
