import { create } from 'zustand'

const useIncidentStore = create((set) => ({
  incidents: [],
  activeIncident: null,
  pendingPlaybooks: [],
  socStats: {},

  setIncidents: (incidents) => set({ incidents }),
  
  updateIncident: (updated) => set((state) => ({
    incidents: state.incidents.map(i => i.id === updated.id ? { ...i, ...updated } : i),
    activeIncident: state.activeIncident?.id === updated.id ? { ...state.activeIncident, ...updated } : state.activeIncident
  })),

  setActiveIncident: (incident) => set({ activeIncident: incident }),

  appendPlaybookChunk: (incidentId, chunk) => set((state) => {
    const existing = state.pendingPlaybooks.find(p => p.incidentId === incidentId);
    if (existing) {
      return {
        pendingPlaybooks: state.pendingPlaybooks.map(p => 
          p.incidentId === incidentId ? { ...p, content: p.content + chunk } : p
        )
      };
    } else {
      return {
        pendingPlaybooks: [...state.pendingPlaybooks, { incidentId, content: chunk }]
      };
    }
  }),

  setSocStats: (stats) => set({ socStats: stats }),
}))

export default useIncidentStore
