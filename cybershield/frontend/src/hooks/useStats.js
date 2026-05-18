import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import api from '../lib/api'
import { socket } from '../lib/socket'

/**
 * useStats — loads stats from REST API on mount, then stays live via socket.
 * When stats_update arrives via socket, the React Query cache is updated immediately
 * (no need to wait for the 10-second refetch interval).
 * Zero traffic = no socket updates = stats stay at whatever the DB returns.
 */
export function useStats() {
  const queryClient = useQueryClient()

  // Keep socket delta updates in sync with React Query cache
  useEffect(() => {
    const handler = (data) => {
      queryClient.setQueryData(['stats'], (prev) => {
        if (!prev) return prev
        return { ...prev, ...data }
      })
    }
    socket.on('stats_update', handler)
    return () => socket.off('stats_update', handler)
  }, [queryClient])

  return useQuery({
    queryKey: ['stats'],
    queryFn: async () => {
      const res = await api.get('/stats')
      return res.data
    },
    refetchInterval: 30000,  // reduced: socket keeps it fresh in real-time
    staleTime: 10000,
  })
}
