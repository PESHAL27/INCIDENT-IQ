/**
 * IncidentIQ — Reports Routes
 * POST /api/investigations/:id/report — store a generated report
 * GET  /api/reports — list all reports
 * GET  /api/reports/:reportId — get single report
 */

import { Router } from 'express'
import { randomUUID } from 'crypto'
import { getDb } from '../db.js'
import { validateInvestigationId } from '../middleware/validation.js'

const router = Router()

// ── POST /api/investigations/:id/report ──────────────────────
router.post('/investigations/:id/report', validateInvestigationId, (req, res) => {
  try {
    const db = getDb()
    const invRow = db.prepare('SELECT id FROM investigations WHERE id = ?').get(req.params.id)
    if (!invRow) return res.status(404).json({ error: 'Investigation not found.' })

    const report = req.body?.report
    if (!report) return res.status(400).json({ error: 'Missing report in request body.' })

    const now = new Date().toISOString()
    const reportId = report.reportId || `RPT-${req.params.id}`

    // Upsert: replace existing report for this investigation
    const existing = db.prepare('SELECT id FROM reports WHERE investigation_id = ?').get(req.params.id)

    if (existing) {
      db.prepare('UPDATE reports SET report_json = ?, created_at = ? WHERE investigation_id = ?')
        .run(JSON.stringify(report), now, req.params.id)
    } else {
      db.prepare('INSERT INTO reports (id, report_id, investigation_id, report_json, created_at) VALUES (?, ?, ?, ?, ?)')
        .run(randomUUID(), reportId, req.params.id, JSON.stringify(report), now)
    }

    // Sync report onto investigation row too
    db.prepare('UPDATE investigations SET report = ?, status = ?, updated_at = ? WHERE id = ?')
      .run(JSON.stringify(report), 'complete', now, req.params.id)

    console.log(`[reports] Saved report for ${req.params.id}`)
    res.status(201).json({ success: true, reportId })
  } catch (err) {
    console.error('[reports] POST error:', err.message)
    res.status(500).json({ error: 'Failed to save report.' })
  }
})

// ── GET /api/reports ──────────────────────────────────────────
router.get('/reports', (req, res) => {
  try {
    const db = getDb()
    const rows = db.prepare('SELECT r.*, i.incident_name FROM reports r LEFT JOIN investigations i ON r.investigation_id = i.id ORDER BY r.created_at DESC').all()
    const reports = rows.map(r => {
      const parsed = JSON.parse(r.report_json)
      return {
        ...parsed,
        incidentId: r.investigation_id,
        incidentName: r.incident_name || parsed.incidentName,
        savedAt: r.created_at,
      }
    })
    res.json({ reports })
  } catch (err) {
    console.error('[reports] GET / error:', err.message)
    res.status(500).json({ error: 'Failed to fetch reports.' })
  }
})

export default router
