/**
 * IncidentIQ — Investigations Routes
 * CRUD for investigations. Evidence and events are stored separately.
 */

import { Router } from 'express'
import { randomUUID } from 'crypto'
import { getDb } from '../db.js'
import { validateInvestigationId } from '../middleware/validation.js'

const router = Router()

// ── Helpers ──────────────────────────────────────────────────

function generateId() {
  const num = Math.floor(1000 + Math.random() * 9000)
  return `INC-${num}`
}

function rowToInvestigation(row) {
  if (!row) return null
  return {
    id: row.id,
    name: row.incident_name,
    description: row.description || '',
    status: row.status,
    severity: row.severity || null,
    confidence: row.confidence || null,
    incidentType: row.incident_type || null,
    keyIndicators: row.key_indicators ? JSON.parse(row.key_indicators) : [],
    analysisResult: row.analysis_result ? JSON.parse(row.analysis_result) : null,
    parsingSummary: row.parsing_summary ? JSON.parse(row.parsing_summary) : null,
    report: row.report ? JSON.parse(row.report) : null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}

function getEvidenceForInvestigation(db, invId) {
  return db.prepare('SELECT * FROM evidence_files WHERE investigation_id = ? ORDER BY upload_timestamp ASC').all(invId)
    .map(r => ({
      id: r.id,
      investigationId: r.investigation_id,
      filename: r.filename,
      name: r.filename,
      fileType: r.file_type,
      type: r.file_type,
      fileSize: r.file_size,
      size: r.file_size,
      uploadTimestamp: r.upload_timestamp,
      charCount: r.char_count,
      parsedEventsCount: r.parsed_events_count,
    }))
}

function getEventsForInvestigation(db, invId) {
  return db.prepare('SELECT * FROM events WHERE investigation_id = ? ORDER BY created_at ASC').all(invId)
    .map(r => ({
      eventId: r.event_id,
      id: r.event_id,
      investigationId: r.investigation_id,
      evidenceFileId: r.evidence_file_id,
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
    }))
}

// ── List all investigations ────────────────────────────────────
router.get('/', (req, res) => {
  try {
    const db = getDb()
    const rows = db.prepare('SELECT * FROM investigations ORDER BY created_at DESC').all()
    const investigations = rows.map(row => {
      const inv = rowToInvestigation(row)
      inv.files = getEvidenceForInvestigation(db, row.id)
      inv.events = getEventsForInvestigation(db, row.id)
      return inv
    })
    res.json({ investigations })
  } catch (err) {
    console.error('[investigations] GET / error:', err.message)
    res.status(500).json({ error: 'Failed to fetch investigations.' })
  }
})

// ── Get single investigation ───────────────────────────────────
router.get('/:id', validateInvestigationId, (req, res) => {
  try {
    const db = getDb()
    const row = db.prepare('SELECT * FROM investigations WHERE id = ?').get(req.params.id)
    if (!row) return res.status(404).json({ error: 'Investigation not found.' })

    const inv = rowToInvestigation(row)
    inv.files = getEvidenceForInvestigation(db, row.id)
    inv.events = getEventsForInvestigation(db, row.id)

    const reportRow = db.prepare('SELECT report_json FROM reports WHERE investigation_id = ? ORDER BY created_at DESC LIMIT 1').get(row.id)
    if (reportRow) inv.report = JSON.parse(reportRow.report_json)

    res.json({ investigation: inv })
  } catch (err) {
    console.error('[investigations] GET /:id error:', err.message)
    res.status(500).json({ error: 'Failed to fetch investigation.' })
  }
})

// ── Create investigation ───────────────────────────────────────
router.post('/', (req, res) => {
  try {
    const { name, description } = req.body || {}
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Missing required field: name' })
    }

    const db = getDb()
    const now = new Date().toISOString()
    let id = generateId()

    // Ensure unique ID
    while (db.prepare('SELECT 1 FROM investigations WHERE id = ?').get(id)) {
      id = generateId()
    }

    db.prepare(`
      INSERT INTO investigations (id, incident_name, description, status, created_at, updated_at)
      VALUES (?, ?, ?, 'idle', ?, ?)
    `).run(id, name.trim(), (description || '').trim(), now, now)

    const row = db.prepare('SELECT * FROM investigations WHERE id = ?').get(id)
    const inv = rowToInvestigation(row)
    inv.files = []
    inv.events = []

    console.log(`[investigations] Created ${id}: ${name.trim()}`)
    res.status(201).json({ investigation: inv })
  } catch (err) {
    console.error('[investigations] POST / error:', err.message)
    res.status(500).json({ error: 'Failed to create investigation.' })
  }
})

// ── Update investigation (status, analysis, parsing summary) ──
router.patch('/:id', validateInvestigationId, (req, res) => {
  try {
    const db = getDb()
    const row = db.prepare('SELECT * FROM investigations WHERE id = ?').get(req.params.id)
    if (!row) return res.status(404).json({ error: 'Investigation not found.' })

    const { status, analysisResult, parsingSummary, report } = req.body || {}
    const now = new Date().toISOString()

    const updates = { updated_at: now }
    if (status !== undefined) updates.status = status
    if (analysisResult !== undefined) {
      updates.analysis_result = JSON.stringify(analysisResult)
      if (analysisResult.verdict?.severity) updates.severity = analysisResult.verdict.severity
      if (analysisResult.verdict?.confidence) updates.confidence = analysisResult.verdict.confidence
      if (analysisResult.verdict?.incidentType) updates.incident_type = analysisResult.verdict.incidentType
      if (analysisResult.verdict?.keyIndicators) updates.key_indicators = JSON.stringify(analysisResult.verdict.keyIndicators)
    }
    if (parsingSummary !== undefined) updates.parsing_summary = JSON.stringify(parsingSummary)
    if (report !== undefined) updates.report = JSON.stringify(report)

    const setClauses = Object.keys(updates).map(k => `${k} = ?`).join(', ')
    const values = [...Object.values(updates), req.params.id]
    db.prepare(`UPDATE investigations SET ${setClauses} WHERE id = ?`).run(...values)

    const updated = db.prepare('SELECT * FROM investigations WHERE id = ?').get(req.params.id)
    const inv = rowToInvestigation(updated)
    inv.files = getEvidenceForInvestigation(db, req.params.id)
    inv.events = getEventsForInvestigation(db, req.params.id)

    res.json({ investigation: inv })
  } catch (err) {
    console.error('[investigations] PATCH /:id error:', err.message)
    res.status(500).json({ error: 'Failed to update investigation.' })
  }
})

// ── Delete investigation ───────────────────────────────────────
router.delete('/:id', validateInvestigationId, (req, res) => {
  try {
    const db = getDb()
    const row = db.prepare('SELECT 1 FROM investigations WHERE id = ?').get(req.params.id)
    if (!row) return res.status(404).json({ error: 'Investigation not found.' })

    db.prepare('DELETE FROM investigations WHERE id = ?').run(req.params.id)
    console.log(`[investigations] Deleted ${req.params.id}`)
    res.json({ success: true, id: req.params.id })
  } catch (err) {
    console.error('[investigations] DELETE /:id error:', err.message)
    res.status(500).json({ error: 'Failed to delete investigation.' })
  }
})

export default router
