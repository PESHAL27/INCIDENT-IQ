import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react'
import * as api from '../services/api'

const InvestigationContext = createContext(null)

// Deep-clone helper
function safeClone(obj) {
  try { return JSON.parse(JSON.stringify(obj)) } catch { return obj }
}

export function InvestigationProvider({ children }) {
  const [investigations, setInvestigations] = useState([])
  const [reports, setReports] = useState([])
  const [activeInvestigationId, setActiveInvestigationId] = useState(null)
  const [backendOnline, setBackendOnline] = useState(false)
  const [loading, setLoading] = useState(true)

  const investigationsRef = useRef(investigations)
  useEffect(() => { investigationsRef.current = investigations }, [investigations])

  // ── Bootstrap: load data from backend on mount ─────────────
  useEffect(() => {
    let mounted = true

    async function bootstrap() {
      try {
        // Check backend health first
        await api.checkHealth()
        setBackendOnline(true)

        const [invData, rptData] = await Promise.all([
          api.listInvestigations(),
          api.listReports().catch(() => ({ reports: [] })),
        ])

        if (!mounted) return

        const invs = invData.investigations || []
        const rpts = rptData.reports || []

        setInvestigations(invs)
        setReports(rpts)
        investigationsRef.current = invs
        console.log(`[Context] Loaded ${invs.length} investigations, ${rpts.length} reports from backend`)
      } catch (err) {
        // Backend offline — fall back to localStorage
        console.warn('[Context] Backend offline, using localStorage:', err.message)
        setBackendOnline(false)
        try {
          const stored = localStorage.getItem('incidentiq_investigations')
          const storedReports = localStorage.getItem('incidentiq_reports')
          if (mounted) {
            const invs = stored ? JSON.parse(stored) : []
            const rpts = storedReports ? JSON.parse(storedReports) : []
            setInvestigations(invs)
            setReports(rpts)
            investigationsRef.current = invs
          }
        } catch {}
      } finally {
        if (mounted) setLoading(false)
      }
    }

    bootstrap()
    return () => { mounted = false }
  }, [])

  // ── Sync to localStorage as fast session cache ─────────────
  useEffect(() => {
    if (!loading) {
      try { localStorage.setItem('incidentiq_investigations', JSON.stringify(investigations)) } catch {}
    }
  }, [investigations, loading])

  useEffect(() => {
    if (!loading) {
      try { localStorage.setItem('incidentiq_reports', JSON.stringify(reports)) } catch {}
    }
  }, [reports, loading])

  // ── Create investigation via API ───────────────────────────
  const createInvestigation = useCallback(async ({ name, description, files, events, parsingSummary }) => {
    const now = new Date().toISOString()

    if (backendOnline) {
      try {
        const data = await api.createInvestigation({ name, description })
        const inv = {
          ...data.investigation,
          files: files || [],
          events: events || [],
          parsingSummary: parsingSummary || null,
          recommendations: [],
          report: null,
        }
        setInvestigations(prev => [inv, ...prev])
        investigationsRef.current = [inv, ...investigationsRef.current]
        setActiveInvestigationId(inv.id)
        return inv.id
      } catch (err) {
        console.error('[Context] createInvestigation API error:', err.message)
      }
    }

    // Fallback: local-only
    const num = Math.floor(1000 + Math.random() * 9000)
    const id = `INC-${num}`
    const inv = {
      id, name, description,
      files: files || [], events: events || [],
      analysisResult: null, recommendations: [],
      report: null, status: 'idle',
      parsingSummary: parsingSummary || null,
      createdAt: now, updatedAt: now,
    }
    setInvestigations(prev => [inv, ...prev])
    investigationsRef.current = [inv, ...investigationsRef.current]
    setActiveInvestigationId(id)
    return id
  }, [backendOnline])

  // ── Update investigation via API ───────────────────────────
  const updateInvestigation = useCallback(async (id, updates) => {
    const cloned = safeClone(updates)
    const now = new Date().toISOString()

    // Optimistic local update first for instant UI response
    const applyLocal = (prev) => prev.map(inv =>
      inv.id === id ? { ...inv, ...cloned, updatedAt: now } : inv
    )
    setInvestigations(applyLocal)
    investigationsRef.current = applyLocal(investigationsRef.current)

    if (backendOnline) {
      try {
        // Only send structured fields the backend knows about
        const payload = {}
        if (cloned.status !== undefined) payload.status = cloned.status
        if (cloned.analysisResult !== undefined) payload.analysisResult = cloned.analysisResult
        if (cloned.parsingSummary !== undefined) payload.parsingSummary = cloned.parsingSummary

        if (Object.keys(payload).length > 0) {
          await api.updateInvestigation(id, payload)
        }
      } catch (err) {
        console.warn('[Context] updateInvestigation API error:', err.message)
      }
    }
  }, [backendOnline])

  // ── Get investigation (from ref for sync access) ───────────
  const getInvestigation = useCallback((id) => {
    return investigationsRef.current.find(inv => inv.id === id) || null
  }, [])

  // ── Refresh single investigation from backend ──────────────
  const refreshInvestigation = useCallback(async (id) => {
    if (!backendOnline) return null
    try {
      const data = await api.getInvestigation(id)
      const inv = data.investigation
      if (!inv) return null
      setInvestigations(prev => prev.map(i => i.id === id ? { ...i, ...inv } : i))
      investigationsRef.current = investigationsRef.current.map(i => i.id === id ? { ...i, ...inv } : i)
      return inv
    } catch (err) {
      console.warn('[Context] refreshInvestigation error:', err.message)
      return null
    }
  }, [backendOnline])

  // ── Save report via API ────────────────────────────────────
  const saveReport = useCallback(async (investigation) => {
    const severity = investigation.analysisResult?.verdict?.severity
                  || investigation.analysisResult?.severity
                  || investigation.report?.severity
                  || null

    const report = {
      ...safeClone(investigation.report),
      incidentId: investigation.id,
      incidentName: investigation.name,
      severity,
      confidence: investigation.analysisResult?.verdict?.confidence || investigation.report?.confidence || 0,
      savedAt: new Date().toISOString(),
    }

    setReports(prev => {
      const existing = prev.findIndex(r => r.incidentId === investigation.id)
      if (existing >= 0) {
        const updated = [...prev]; updated[existing] = report; return updated
      }
      return [report, ...prev]
    })

    if (backendOnline) {
      try {
        await api.saveReport(investigation.id, report)
      } catch (err) {
        console.warn('[Context] saveReport API error:', err.message)
      }
    }

    return report
  }, [backendOnline])

  // ── Delete investigation via API ───────────────────────────
  const deleteInvestigation = useCallback(async (id) => {
    setInvestigations(prev => prev.filter(inv => inv.id !== id))
    investigationsRef.current = investigationsRef.current.filter(inv => inv.id !== id)
    if (activeInvestigationId === id) setActiveInvestigationId(null)

    if (backendOnline) {
      try {
        await api.deleteInvestigation(id)
      } catch (err) {
        console.warn('[Context] deleteInvestigation API error:', err.message)
      }
    }
  }, [activeInvestigationId, backendOnline])

  // ── Derived stats ──────────────────────────────────────────
  const stats = {
    total: investigations.length,
    active: investigations.filter(i => i.status === 'analyzing' || i.status === 'idle').length,
    critical: investigations.filter(i =>
      (i.analysisResult?.verdict?.severity || i.analysisResult?.severity) === 'CRITICAL'
    ).length,
    evidenceItems: investigations.reduce((sum, i) => sum + (i.files?.length || 0), 0),
    completed: investigations.filter(i => i.status === 'complete').length,
  }

  return (
    <InvestigationContext.Provider value={{
      investigations,
      reports,
      activeInvestigationId,
      setActiveInvestigationId,
      createInvestigation,
      updateInvestigation,
      getInvestigation,
      refreshInvestigation,
      saveReport,
      deleteInvestigation,
      stats,
      backendOnline,
      loading,
    }}>
      {children}
    </InvestigationContext.Provider>
  )
}

export function useInvestigation() {
  const ctx = useContext(InvestigationContext)
  if (!ctx) throw new Error('useInvestigation must be used within InvestigationProvider')
  return ctx
}
