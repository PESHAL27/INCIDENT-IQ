import { useState, useCallback, useRef, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { useInvestigation } from '../context/InvestigationContext'
import { ingestFiles, normalizeEvents, buildEvidenceBundle } from '../services/evidenceParser'
import { runAnalysisPipeline } from '../services/gemini'
import { uploadEvidenceFiles, uploadSampleFiles, persistAnalysis } from '../services/api'
import StepNav from '../components/investigate/StepNav'
import EvidenceUpload from '../components/investigate/EvidenceUpload'
import AnalysisPipeline from '../components/investigate/AnalysisPipeline'
import IncidentVerdict from '../components/investigate/IncidentVerdict'
import FindingsList from '../components/investigate/FindingsList'
import AttackTimeline from '../components/investigate/AttackTimeline'
import Recommendations from '../components/investigate/Recommendations'
import GenerateReport from '../components/investigate/GenerateReport'
import EvidenceLedger from '../components/investigate/EvidenceLedger'
import './Investigate.css'

function scrollTo(id) {
  setTimeout(() => {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }, 60)
}

export default function Investigate() {
  const { id: urlId } = useParams()
  const {
    createInvestigation,
    updateInvestigation,
    getInvestigation,
    saveReport,
    setActiveInvestigationId,
  } = useInvestigation()

  // ── Form fields ──────────────────────────────────────────
  const [incidentName, setIncidentName] = useState('')
  const [incidentDesc, setIncidentDesc] = useState('')
  const [uploadedFiles, setUploadedFiles] = useState([])

  // ── Workflow state ────────────────────────────────────────
  const [workflowState, setWorkflowState] = useState('idle') // idle | analyzing | complete | error
  const [analysisError, setAnalysisError] = useState(null)
  const [pipelineStages, setPipelineStages] = useState([])

  // ── Investigation result (single source of truth) ────────
  const [investigation, setInvestigation] = useState(null)

  // ── Step nav ──────────────────────────────────────────────
  const [currentStep, setCurrentStep] = useState('evidence')
  const [completedSteps, setCompletedSteps] = useState([])

  // Keep a ref to current invId so async callbacks can close over it
  const invIdRef = useRef(null)

  // ── Load existing investigation when navigated via /investigate/:id
  useEffect(() => {
    if (!urlId) return
    const inv = getInvestigation(urlId)
    if (!inv) return

    setInvestigation(inv)
    setIncidentName(inv.name)
    setIncidentDesc(inv.description || '')

    if (inv.status === 'complete') {
      setWorkflowState('complete')
      setCurrentStep('findings')
      setCompletedSteps(['evidence', 'analysis', 'findings', 'response'])
    }
  }, [urlId]) // eslint-disable-line react-hooks/exhaustive-deps

  // ── Pipeline stage updater (called from async pipeline) ──
  const updateStage = useCallback((update) => {
    setPipelineStages(prev => {
      const idx = prev.findIndex(s => s.stageKey === update.stageKey)
      if (idx >= 0) {
        const next = [...prev]
        next[idx] = update
        return next
      }
      return [...prev, update]
    })
  }, [])

  // ── Main analyze handler ──────────────────────────────────
  const handleAnalyze = useCallback(async () => {
    if (!incidentName.trim()) return
    const validCandidateFiles = uploadedFiles.filter(f => f.status !== 'error')
    if (validCandidateFiles.length === 0) return

    setAnalysisError(null)
    setPipelineStages([])
    setWorkflowState('analyzing')
    setCurrentStep('analysis')
    setCompletedSteps(['evidence'])
    scrollTo('analysis-section')

    try {
      // ── Step 1: Real Ingestion & Multi-Format Parsing (Stage 1) ───────
      updateStage({ stageKey: 'parsed', status: 'running' })
      const filesToIngest = validCandidateFiles.map(f => f.rawFile || f)
      const parsedResults = await ingestFiles(filesToIngest)

      const validFiles = parsedResults.filter(f => f.status === 'ok' && Array.isArray(f.events) && f.events.length > 0)
      const failedFiles = parsedResults.filter(f => f.status === 'error').map(f => ({ name: f.name, reason: f.error }))

      if (validFiles.length === 0) {
        const failureReason = failedFiles.length > 0
          ? failedFiles.map(f => `${f.name}: ${f.reason}`).join('; ')
          : 'No readable evidence could be parsed from files.'
        updateStage({ stageKey: 'parsed', status: 'error', data: { error: failureReason } })
        throw new Error(`Evidence parsing failed: ${failureReason}`)
      }
      updateStage({ stageKey: 'parsed', status: 'complete', data: { fileCount: validFiles.length } })

      // ── Step 2: Events Extracted (Stage 2) ─────────────────────────────
      updateStage({ stageKey: 'extracted', status: 'running' })
      const rawExtractedCount = validFiles.reduce((acc, f) => acc + f.events.length, 0)
      await new Promise(r => setTimeout(r, 120))
      updateStage({ stageKey: 'extracted', status: 'complete', data: { eventCount: rawExtractedCount } })

      // ── Step 3: Event Normalization (Stage 3) ──────────────────────────
      updateStage({ stageKey: 'normalized', status: 'running' })
      const { events, summary } = normalizeEvents(parsedResults)
      await new Promise(r => setTimeout(r, 120))
      updateStage({ stageKey: 'normalized', status: 'complete', data: { eventCount: events.length } })

      // ── Step 4: Create investigation record & store events ─────────────
      const invId = await createInvestigation({
        name: incidentName.trim(),
        description: incidentDesc.trim(),
        files: validFiles.map(f => ({ name: f.name, type: f.type, size: f.size })),
        events,
        parsingSummary: summary,
      })
      invIdRef.current = invId
      setActiveInvestigationId(invId)
      updateInvestigation(invId, { status: 'analyzing', events, parsingSummary: summary })

      // ── Step 4b: Upload evidence files to backend for persistence ────────
      try {
        const realFiles = validCandidateFiles
          .map(f => f.rawFile)
          .filter(f => f instanceof File)

        const sampleFileItems = validCandidateFiles.filter(f => {
          const rf = f.rawFile
          return rf && !(rf instanceof File) && rf.content !== undefined
        })

        if (realFiles.length > 0) {
          await uploadEvidenceFiles(invId, realFiles)
        }
        if (sampleFileItems.length > 0) {
          const samplePayload = sampleFileItems.map(f => ({
            name: f.name,
            content: f.content || f.rawFile?.content || '',
            type: f.type,
            size: f.size,
          }))
          await uploadSampleFiles(invId, samplePayload)
        }
        console.log('[Investigate] Evidence persisted to backend')
      } catch (uploadErr) {
        // Backend persistence failed but analysis can still run in-memory
        console.warn('[Investigate] Evidence backend upload failed (continuing in-memory):', uploadErr.message)
      }

      // ── Step 5: Build evidence context for AI ──────────────────────────
      const evidenceBundle = buildEvidenceBundle(validFiles)

      // ── Step 6: Run AI Analysis Pipeline (Stages 4, 5, 6, 7) ───────────
      const pipelineResult = await runAnalysisPipeline(
        evidenceBundle,
        validFiles,
        updateStage,
        { events, summary },
      )

      // ── Step 7: Assemble structured analysis result ────────────────────
      const analysisResult = {
        verdict:           pipelineResult.verdict,
        findings:          pipelineResult.findings,
        timeline:          pipelineResult.timeline,
        attackChain:       pipelineResult.attackChain,
        events:            pipelineResult.events,
        extractionSummary: pipelineResult.extractionSummary || summary,
        incidentType:      pipelineResult.verdict?.incidentType,
        severity:          pipelineResult.verdict?.severity,
        confidence:        pipelineResult.verdict?.confidence,
        keyIndicators:     pipelineResult.verdict?.keyIndicators || [],
        recommendations:   pipelineResult.recommendations || [],
      }

      // ── Step 8: Persist to context + backend ──────────────────────────
      updateInvestigation(invId, {
        status:          'complete',
        events:          pipelineResult.events,
        analysisResult,
        recommendations: pipelineResult.recommendations,
        parsingSummary:  summary,
      })

      // ── Step 8b: Persist full analysis result to backend ────────────────
      try {
        await persistAnalysis(invId, {
          analysisResult,
          recommendations: pipelineResult.recommendations,
          parsingSummary: summary,
          status: 'complete',
        })
        console.log('[Investigate] Analysis persisted to backend')
      } catch (persistErr) {
        console.warn('[Investigate] Analysis backend persist failed (data in localStorage):', persistErr.message)
      }

      // ── Step 9: Build local investigation object ───────────────────────
      const finalInv = {
        id:              invId,
        name:            incidentName.trim(),
        description:     incidentDesc.trim(),
        files:           validFiles.map(f => ({ name: f.name, type: f.type, size: f.size })),
        events:          pipelineResult.events,
        analysisResult,
        recommendations: pipelineResult.recommendations,
        parsingSummary:  summary,
        report:          null,
        status:          'complete',
        createdAt:       new Date().toISOString(),
        updatedAt:       new Date().toISOString(),
      }

      setInvestigation(finalInv)
      setWorkflowState('complete')
      setCurrentStep('findings')
      setCompletedSteps(['evidence', 'analysis', 'findings', 'response'])
      scrollTo('findings-section')

    } catch (err) {
      console.error('[IncidentIQ] Analysis pipeline error:', err)
      const msg = err.message === 'GEMINI_API_KEY_MISSING'
        ? 'Gemini API key is missing. Add VITE_GEMINI_API_KEY to your .env file and restart the dev server.'
        : err.message

      setAnalysisError(msg)
      setWorkflowState('error')

      if (invIdRef.current) {
        updateInvestigation(invIdRef.current, { status: 'error' })
      }
    }
  }, [incidentName, incidentDesc, uploadedFiles, createInvestigation, updateInvestigation, setActiveInvestigationId, updateStage])

  // ── Report generated callback ─────────────────────────────
  const handleReportGenerated = useCallback((report) => {
    setInvestigation(prev => {
      if (!prev) return prev
      const updated = { ...prev, report }
      updateInvestigation(prev.id, { report })
      saveReport(updated)
      return updated
    })
    setCompletedSteps(['evidence', 'analysis', 'findings', 'response'])
    setCurrentStep('response')
    scrollTo('generate-report-section')
  }, [updateInvestigation, saveReport])

  // ── Reset to start a new investigation ────────────────────
  const handleReset = useCallback(() => {
    setWorkflowState('idle')
    setAnalysisError(null)
    setPipelineStages([])
    setInvestigation(null)
    setIncidentName('')
    setIncidentDesc('')
    setUploadedFiles([])
    setCurrentStep('evidence')
    setCompletedSteps([])
    invIdRef.current = null
    scrollTo('evidence-section')
  }, [])

  // ── Step nav click handler ────────────────────────────────
  const handleStepClick = useCallback((stepId) => {
    setCurrentStep(stepId)
    const map = {
      evidence: 'evidence-section',
      analysis: 'analysis-section',
      findings: 'findings-section',
      response: 'timeline-section',
    }
    if (map[stepId]) scrollTo(map[stepId])
  }, [])

  // ── Event Traceability Navigation & Highlighting ─────────
  const [highlightedEventId, setHighlightedEventId] = useState(null)

  const handleEventClick = useCallback((eventId) => {
    if (!eventId) return
    setHighlightedEventId(eventId)

    // Smoothly scroll to the target event in the Ingested Evidence Ledger or Attack Timeline
    setTimeout(() => {
      const el = document.getElementById(`evidence-event-${eventId}`) ||
                 document.getElementById(`timeline-event-${eventId}`)
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'center' })
      } else {
        scrollTo('evidence-section')
      }
    }, 40)

    // Clear active pulse after 3.5 seconds
    setTimeout(() => {
      setHighlightedEventId(prev => (prev === eventId ? null : prev))
    }, 3500)
  }, [])

  // ── Derived data ──────────────────────────────────────────
  const isIdle      = workflowState === 'idle' || workflowState === 'error'
  const isAnalyzing = workflowState === 'analyzing'
  const isComplete  = workflowState === 'complete'

  const verdict         = investigation?.analysisResult?.verdict
  const findings        = investigation?.analysisResult?.findings || []
  const timeline        = investigation?.analysisResult?.timeline || []
  const recommendations = investigation?.recommendations || []
  const events          = investigation?.events || []
  const parsingSummary  = investigation?.parsingSummary

  const activeId = investigation?.id || 'INC-1024'
  const activeTitle = investigation?.name || incidentName || 'Suspicious Server Activity'

  return (
    <div className="investigate-console-wrapper">
      {/* ── TOP: Console Header Bar ────────────────────────── */}
      <header className="investigate-console-header">
        <div className="console-identity-col">
          <div className="console-meta-row font-mono">
            <span className="console-type-label">INVESTIGATION</span>
            <span className="console-id-badge">{activeId}</span>
            <div className="console-status-indicator">
              <span className={`status-dot ${isAnalyzing ? 'analyzing' : isComplete ? 'complete' : 'ready'}`} />
              <span className="console-status-text">
                {isAnalyzing ? 'ANALYZING' : isComplete ? 'COMPLETED' : 'INVESTIGATING'}
              </span>
            </div>
          </div>
          <h1 className="console-incident-title">{activeTitle}</h1>
        </div>

        {/* Compact Workflow Step Indicator */}
        <div className="console-workflow-steps font-mono">
          <div
            className={`workflow-step ${currentStep === 'evidence' ? 'active' : ''} ${completedSteps.includes('evidence') ? 'done' : ''}`}
            onClick={() => handleStepClick('evidence')}
          >
            <span className="wf-num">01</span>
            <span className="wf-label">EVIDENCE</span>
          </div>
          <span className="wf-sep">→</span>
          <div
            className={`workflow-step ${currentStep === 'analysis' ? 'active' : ''} ${completedSteps.includes('analysis') ? 'done' : ''}`}
            onClick={() => handleStepClick('analysis')}
          >
            <span className="wf-num">02</span>
            <span className="wf-label">ANALYSIS</span>
          </div>
          <span className="wf-sep">→</span>
          <div
            className={`workflow-step ${currentStep === 'findings' ? 'active' : ''} ${completedSteps.includes('findings') ? 'done' : ''}`}
            onClick={() => handleStepClick('findings')}
          >
            <span className="wf-num">03</span>
            <span className="wf-label">FINDINGS</span>
          </div>
          <span className="wf-sep">→</span>
          <div
            className={`workflow-step ${currentStep === 'response' ? 'active' : ''} ${completedSteps.includes('response') ? 'done' : ''}`}
            onClick={() => handleStepClick('response')}
          >
            <span className="wf-num">04</span>
            <span className="wf-label">RESPONSE</span>
          </div>

          {isComplete && (
            <button className="btn btn-secondary btn-sm console-reset-btn" onClick={handleReset}>
              + NEW INVESTIGATION
            </button>
          )}
        </div>
      </header>

      {/* ── THREE-ZONE INVESTIGATION WORKSPACE ─────────────── */}
      <div className="investigate-workspace-layout">

        {/* ZONE 1 (LEFT): Compact Navigation / Context ──────── */}
        <StepNav
          currentStep={currentStep}
          completedSteps={completedSteps}
          onStepClick={handleStepClick}
          investigation={investigation}
        />

        {/* ZONE 2 (CENTER): Main Investigation Content ──────── */}
        <main className="investigate-main-zone">
          <div className="investigate-main-scroll-content">

            {/* ── SECTION 01: EVIDENCE ──────────────────────── */}
            <section id="evidence-section" className="investigate-section-block">
              {isIdle && (
                <EvidenceUpload
                  incidentName={incidentName}
                  setIncidentName={setIncidentName}
                  incidentDesc={incidentDesc}
                  setIncidentDesc={setIncidentDesc}
                  files={uploadedFiles}
                  setFiles={setUploadedFiles}
                  onAnalyze={handleAnalyze}
                  isLoading={false}
                />
              )}

              {/* Error banner */}
              {analysisError && (
                <div className="error-banner animate-fade-in">
                  <strong>Analysis Error</strong>
                  <p>{analysisError}</p>
                </div>
              )}

              {/* Completed Evidence Summary Bar */}
              {isComplete && investigation && (
                <div className="evidence-summary-container animate-fade-in">
                  <div className="evidence-summary-bar">
                    {(investigation.files || []).map(f => (
                      <div key={f.name} className="evidence-chip">
                        <span className="evidence-chip-name">{f.name}</span>
                        <span className="evidence-chip-type font-mono">{f.type?.toUpperCase()}</span>
                      </div>
                    ))}
                  </div>
                  {parsingSummary && (
                    <div className="parsing-summary-metrics font-mono">
                      <span className="metric-pill">
                        <strong>{parsingSummary.totalEvents}</strong> events extracted
                      </span>
                      {parsingSummary.authEvents > 0 && (
                        <span className="metric-pill">{parsingSummary.authEvents} auth</span>
                      )}
                      {parsingSummary.networkEvents > 0 && (
                        <span className="metric-pill">{parsingSummary.networkEvents} network</span>
                      )}
                      {parsingSummary.endpointEvents > 0 && (
                        <span className="metric-pill">{parsingSummary.endpointEvents} endpoint</span>
                      )}
                      {parsingSummary.alertEvents > 0 && (
                        <span className="metric-pill">{parsingSummary.alertEvents} alert</span>
                      )}
                    </div>
                  )}

                  {/* Ingested Evidence Ledger with Normalized Events and Raw Inspector */}
                  {events.length > 0 && (
                    <EvidenceLedger
                      events={events}
                      highlightedEventId={highlightedEventId}
                    />
                  )}
                </div>
              )}
            </section>

            {/* ── SECTION 02: ANALYSIS PIPELINE ─────────────── */}
            {(isAnalyzing || (pipelineStages.length > 0 && !isComplete)) && (
              <section id="analysis-section" className="investigate-section-block">
                <AnalysisPipeline stages={pipelineStages} />
              </section>
            )}

            {/* ── SECTION 03: FINDINGS ──────────────────────── */}
            {isComplete && findings.length > 0 && (
              <section id="findings-section" className="investigate-section-block">
                <FindingsList
                  findings={findings}
                  events={events}
                  onEventClick={handleEventClick}
                />
              </section>
            )}

            {/* ── SECTION 04: RESPONSE ──────────────────────── */}
            {isComplete && (
              <section id="response-section" className="investigate-section-block">
                {/* Attack Timeline */}
                {timeline.length > 0 && (
                  <div id="timeline-section">
                    <AttackTimeline
                      timeline={timeline}
                      highlightedEventId={highlightedEventId}
                      onEventClick={handleEventClick}
                    />
                  </div>
                )}

                {/* Recommended Investigation */}
                {recommendations.length > 0 && (
                  <div id="recommendations-section" style={{ marginTop: 'var(--space-4)' }}>
                    <Recommendations recommendations={recommendations} />
                  </div>
                )}

                {/* Report Generation Action */}
                <GenerateReport
                  investigation={investigation}
                  onReportGenerated={handleReportGenerated}
                />
              </section>
            )}

          </div>
        </main>

        {/* ZONE 3 (RIGHT): Incident Verdict Sidebar ─────────── */}
        {isComplete && verdict && (
          <aside className="investigate-verdict-zone">
            <div className="verdict-sidebar-inner">
              <IncidentVerdict verdict={verdict} />

              <div className="verdict-quick-stats font-mono">
                <div className="quick-stat-box">
                  <span className="quick-stat-val">{findings.length}</span>
                  <span className="quick-stat-lbl">FINDINGS</span>
                </div>
                <div className="quick-stat-box">
                  <span className="quick-stat-val">{timeline.length}</span>
                  <span className="quick-stat-lbl">EVENTS</span>
                </div>
                <div className="quick-stat-box">
                  <span className="quick-stat-val">{recommendations.length}</span>
                  <span className="quick-stat-lbl">ACTIONS</span>
                </div>
              </div>
            </div>
          </aside>
        )}

      </div>
    </div>
  )
}
