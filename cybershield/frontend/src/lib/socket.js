import { io } from 'socket.io-client'
import useAppStore from '../store/useAppStore'

const socket = io('/', {
  transports: ['websocket', 'polling'],
  autoConnect: true,
})

// ── Connection lifecycle ──────────────────────────────────────────────────────
socket.on('connect', () => {
  useAppStore.getState().setWsConnected(true)
  console.log('[Socket] Connected:', socket.id)
  const activeSiteId = useAppStore.getState().activeSiteId
  if (activeSiteId) joinSiteRoom(activeSiteId)
})

socket.on('disconnect', () => {
  useAppStore.getState().setWsConnected(false)
  console.log('[Socket] Disconnected')
})

// ── Existing events (preserved) ───────────────────────────────────────────────

socket.on('new_attack', (data) => {
  useAppStore.getState().addAttack(data)
})

socket.on('ip_blocked', (data) => {
  useAppStore.getState().addBlockedIP(data)
})

socket.on('stats_update', (data) => {
  useAppStore.getState().updateStats(data)
})

socket.on('room_joined', (data) => {
  console.log('[Socket] Joined room:', data.room)
})

// ── NEW: request_live — raw feed of ALL requests ──────────────────────────────
socket.on('request_live', (data) => {
  useAppStore.getState().addLiveRequest(data)
  // Also add response time if available
  if (data.response_ms != null) {
    useAppStore.getState().addResponseTime({
      t:  data.timestamp,
      ms: data.response_ms,
    })
  }
})

// ── NEW: req_per_sec — rolling requests/second counter ───────────────────────
socket.on('req_per_sec', (data) => {
  useAppStore.getState().setReqPerSec(data.rps ?? 0)
})

// ── NEW: top_ips_update — top suspicious IP leaderboard ──────────────────────
socket.on('top_ips_update', (data) => {
  if (Array.isArray(data.top_ips)) {
    useAppStore.getState().setTopSuspiciousIPs(data.top_ips)
  }
})

// ── NEW: connection_count — live socket client count ─────────────────────────
socket.on('connection_count', (data) => {
  useAppStore.getState().setConnectionCount(data.count ?? 0)
})

// ── request_tick — pub/sub for chart hook ─────────────────────────────────────
const tickListeners = new Set()

socket.on('request_tick', (data) => {
  tickListeners.forEach(cb => cb(data))
})

export function onRequestTick(cb)  { tickListeners.add(cb) }
export function offRequestTick(cb) { tickListeners.delete(cb) }

// ── Site room management ──────────────────────────────────────────────────────
let _currentRoom = null

export function joinSiteRoom(siteId) {
  if (_currentRoom && _currentRoom !== siteId) {
    socket.emit('leave_site', { site_id: _currentRoom })
  }
  if (siteId) {
    socket.emit('join_site', { site_id: siteId })
    _currentRoom = siteId
  } else {
    _currentRoom = null
  }
}

export function leaveSiteRoom() {
  if (_currentRoom) {
    socket.emit('leave_site', { site_id: _currentRoom })
    _currentRoom = null
  }
}

export { socket }
export default socket
