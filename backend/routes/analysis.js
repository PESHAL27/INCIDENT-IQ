/**
 * IncidentIQ — Analysis Routes
 * PATCH /api/investigations/:id/analysis — store full analysis result
 * GET   /api/investigations/:id/findings
 * GET   /api/investigations/:id/timeline
 * GET   /api/investigations/:id/recommendations
 */

import { Router } from 'express'
import { getDb } from '../db.js'
import { validateInvestigationId } from '../middleware/validation.js'

const router = Router({ mergeParams: true })

// ── PATCH /api/investigations/:id/analysis ────────────────────
router.patch('/', validateInvestigationId, (req, res) => {
  try {
    const db = getDb()
    const invRow = db.prepare('SELECT id FROM investigations WHERE id = ?').get(req.params.id)
    if (!invRow) return res.status(404).json({ error: 'Investigation not found.' })

    const { analysisResult, recommendations, parsingSummary, status } = req.body || {}
    if (!analysisResult) return res.status(400).json({ error: 'Missing analysisResult in request body.' })

    const now = new Date().toISOString()
    const updates = {
      analysis_result: JSON.stringify(analysisResult),
      updated_at: now,
    }

    if (status) updates.status = status
    if (analysisResult.verdict?.severity) updates.severity = analysisResult.verdict.severity
    if (analysisResult.verdict?.confidence) updates.confidence = analysisResult.verdict.confidence
    if (analysisResult.verdict?.incidentType) updates.incident_type = analysisResult.verdict.incidentType
    if (analysisResult.verdict?.keyIndicators) updates.key_indicators = JSON.stringify(analysisResult.verdict.keyIndicators)
    if (parsingSummary) updates.parsing_summary = JSON.stringify(parsingSummary)

    // Store recommendations inside analysis_result (already in there), but also denormalize
    if (recommendations && Array.isArray(recommendations)) {
      const merged = { ...analysisResult, recommendations }
      updates.analysis_result = JSON.stringify(merged)
    }

    const setClauses = Object.keys(updates).map(k => `${k} = ?`).join(', ')
    const values = [...Object.values(updates), req.params.id]
    db.prepare(`UPDATE investigations SET ${setClauses} WHERE id = ?`).run(...values)

    console.log(`[analysis] ${req.params.id}: analysis persisted`)
    res.json({ success: true, investigationId: req.params.id })
  } catch (err) {
    console.error('[analysis] PATCH error:', err.message)
    res.status(500).json({ error: 'Failed to persist analysis.' })
  }
})

// ── GET /api/investigations/:id/findings ─────────────────────
router.get('/findings', validateInvestigationId, (req, res) => {
  try {
    const db = getDb()
    const row = db.prepare('SELECT analysis_result FROM investigations WHERE id = ?').get(req.params.id)
    if (!row) return res.status(404).json({ error: 'Investigation not found.' })
    const analysis = row.analysis_result ? JSON.parse(row.analysis_result) : {}
    res.json({ findings: analysis.findings || [] })
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch findings.' })
  }
})

// ── GET /api/investigations/:id/timeline ─────────────────────
router.get('/timeline', validateInvestigationId, (req, res) => {
  try {
    const db = getDb()
    const row = db.prepare('SELECT analysis_result FROM investigations WHERE id = ?').get(req.params.id)
    if (!row) return res.status(404).json({ error: 'Investigation not found.' })
    const analysis = row.analysis_result ? JSON.parse(row.analysis_result) : {}
    res.json({ timeline: analysis.timeline || [] })
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch timeline.' })
  }
})

// ── GET /api/investigations/:id/recommendations ───────────────
router.get('/recommendations', validateInvestigationId, (req, res) => {
  try {
    const db = getDb()
    const row = db.prepare('SELECT analysis_result FROM investigations WHERE id = ?').get(req.params.id)
    if (!row) return res.status(404).json({ error: 'Investigation not found.' })
    const analysis = row.analysis_result ? JSON.parse(row.analysis_result) : {}
    res.json({ recommendations: analysis.recommendations || [] })
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch recommendations.' })
  }
})

// ── GET /api/investigations/:id/events ────────────────────────
router.get('/events', validateInvestigationId, (req, res) => {
  try {
    const db = getDb()
    const invRow = db.prepare('SELECT id FROM investigations WHERE id = ?').get(req.params.id)
    if (!invRow) return res.status(404).json({ error: 'Investigation not found.' })

    const events = db.prepare('SELECT * FROM events WHERE investigation_id = ? ORDER BY timestamp ASC, created_at ASC').all(req.params.id)
      .map(r => ({
        eventId: r.event_id,
        timestamp: r.timestamp,
        source: r.source,
        eventType: r.event_type,
        username: r.username,
        sourceIp: r.source_ip,
        destinationIp: r.destination_ip,
        port: r.port,
        action: r.action,
        process: r.process,
        message: r.message,
        severity: r.severity,
        raw: r.raw,
        evidenceFile: r.source,
        evidenceFileId: r.evidence_file_id,
      }))

    res.json({ events })
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch events.' })
  }
})

export default router
