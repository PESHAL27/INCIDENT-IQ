/**
 * IncidentIQ — Evidence Upload & Retrieval Routes
 * POST /api/investigations/:id/evidence — receives files, validates, parses, normalizes, stores
 * GET  /api/investigations/:id/evidence — list evidence files
 */

import { Router } from 'express'
import multer from 'multer'
import { randomUUID } from 'crypto'
import { getDb } from '../db.js'
import { validateInvestigationId, validateUploadedFile, sanitizeFilename } from '../middleware/validation.js'
import { parseFileContent, normalizeEvents } from '../parser/evidenceParser.js'

const router = Router({ mergeParams: true })

// multer: store in memory, enforce 5 MB per file, up to 10 files
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 10 },
  fileFilter: (_req, file, cb) => {
    const ext = (file.originalname.split('.').pop() || '').toLowerCase()
    if (['log', 'txt', 'json', 'csv'].includes(ext)) cb(null, true)
    else cb(null, false) // silently reject; validation step will report proper error
  },
})

// ── POST /api/investigations/:id/evidence ─────────────────────
router.post('/', validateInvestigationId, upload.array('files', 10), (req, res) => {
  try {
    const db = getDb()
    const invRow = db.prepare('SELECT id FROM investigations WHERE id = ?').get(req.params.id)
    if (!invRow) return res.status(404).json({ error: 'Investigation not found.' })

    const receivedFiles = req.files || []

    // Also support sample incident: JSON body with { sampleFiles: [{name, content, type, size}] }
    const sampleFiles = req.body?.sampleFiles
      ? (typeof req.body.sampleFiles === 'string' ? JSON.parse(req.body.sampleFiles) : req.body.sampleFiles)
      : []

    if (receivedFiles.length === 0 && sampleFiles.length === 0) {
      return res.status(400).json({ error: 'No files received.' })
    }

    const results = []
    const now = new Date().toISOString()

    // Process real uploaded files
    for (const file of receivedFiles) {
      const filename = sanitizeFilename(file.originalname)
      const validation = validateUploadedFile(file.buffer, filename, file.mimetype)

      if (!validation.valid) {
        results.push({ name: filename, status: 'error', error: validation.error, events: [] })
        continue
      }

      const text = validation.text
      let events = []
      try {
        events = parseFileContent(filename, text)
      } catch (parseErr) {
        results.push({ name: filename, status: 'error', error: parseErr.message, events: [] })
        continue
      }

      if (events.length === 0) {
        results.push({ name: filename, status: 'error', error: 'No recognizable security events found in file.', events: [] })
        continue
      }

      const fileId = randomUUID()
      const ext = (filename.split('.').pop() || 'log').toLowerCase()
      const sizeStr = file.buffer.length < 1024 ? `${file.buffer.length} B`
        : file.buffer.length < 1024 * 1024 ? `${(file.buffer.length / 1024).toFixed(1)} KB`
        : `${(file.buffer.length / (1024 * 1024)).toFixed(1)} MB`

      db.prepare(`
        INSERT INTO evidence_files (id, investigation_id, filename, file_type, file_size, upload_timestamp, content, char_count, parsed_events_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(fileId, req.params.id, filename, ext, sizeStr, now, text, text.length, events.length)

      results.push({ name: filename, type: ext, size: sizeStr, status: 'ok', events, fileId, content: text, charCount: text.length })
    }

    // Process sample files (sent as JSON body)
    for (const sf of sampleFiles) {
      const filename = sanitizeFilename(sf.name || 'sample.log')
      const text = sf.content || ''
      const ext = (filename.split('.').pop() || 'log').toLowerCase()

      if (!text.trim()) {
        results.push({ name: filename, status: 'error', error: 'Sample file is empty.', events: [] })
        continue
      }

      let events = []
      try {
        events = parseFileContent(filename, text)
      } catch (parseErr) {
        results.push({ name: filename, status: 'error', error: parseErr.message, events: [] })
        continue
      }

      if (events.length === 0) {
        results.push({ name: filename, status: 'error', error: 'No recognizable events found.', events: [] })
        continue
      }

      const fileId = randomUUID()
      const sizeStr = sf.size || `${text.length} B`

      db.prepare(`
        INSERT INTO evidence_files (id, investigation_id, filename, file_type, file_size, upload_timestamp, content, char_count, parsed_events_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(fileId, req.params.id, filename, ext, sizeStr, now, text, text.length, events.length)

      results.push({ name: filename, type: ext, size: sizeStr, status: 'ok', events, fileId, content: text, charCount: text.length })
    }

    // Normalize all valid events across all files together
    const validResults = results.filter(r => r.status === 'ok')
    const failedResults = results.filter(r => r.status === 'error')

    if (validResults.length === 0) {
      const reasons = failedResults.map(r => `${r.name}: ${r.error}`).join('; ')
      return res.status(400).json({
        error: `Evidence parsing failed: ${reasons}`,
        files: results.map(r => ({ name: r.name, status: r.status, error: r.error || null })),
      })
    }

    const { events: normalizedEvents, summary } = normalizeEvents(validResults)

    // Store normalized events in DB (linked to their evidence file)
    const insertEvent = db.prepare(`
      INSERT INTO events (id, event_id, investigation_id, evidence_file_id, timestamp, source, event_type, username, source_ip, destination_ip, port, action, process, message, severity, raw, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)

    // Match events back to their evidence file IDs for proper linking
    const fileIdMap = {}
    validResults.forEach(r => { fileIdMap[r.name] = r.fileId })

    const insertMany = db.transaction((evs) => {
      for (const ev of evs) {
        insertEvent.run(
          randomUUID(), ev.eventId, req.params.id,
          fileIdMap[ev.evidenceFile] || null,
          ev.timestamp || null, ev.source || null, ev.eventType || null,
          ev.username || null, ev.sourceIp || null, ev.destinationIp || null,
          ev.port || null, ev.action || null, ev.process || null,
          ev.message || null, ev.severity || 'INFO', ev.raw || null,
          now,
        )
      }
    })
    insertMany(normalizedEvents)

    // Update investigation status and parsing summary
    db.prepare(`
      UPDATE investigations SET status = 'analyzing', parsing_summary = ?, updated_at = ? WHERE id = ?
    `).run(JSON.stringify(summary), now, req.params.id)

    console.log(`[evidence] ${req.params.id}: ${normalizedEvents.length} events stored from ${validResults.length} file(s)`)

    res.status(201).json({
      investigationId: req.params.id,
      filesProcessed: validResults.length,
      filesFailed: failedResults.length,
      totalEvents: normalizedEvents.length,
      parsingSummary: summary,
      events: normalizedEvents,
      files: results.map(r => ({
        name: r.name,
        type: r.type,
        size: r.size,
        status: r.status,
        error: r.error || null,
        fileId: r.fileId || null,
        parsedEventsCount: r.events?.length || 0,
      })),
    })
  } catch (err) {
    console.error('[evidence] POST error:', err.message)
    res.status(500).json({ error: 'Evidence ingestion failed.' })
  }
})

// ── GET /api/investigations/:id/evidence ──────────────────────
router.get('/', validateInvestigationId, (req, res) => {
  try {
    const db = getDb()
    const invRow = db.prepare('SELECT id FROM investigations WHERE id = ?').get(req.params.id)
    if (!invRow) return res.status(404).json({ error: 'Investigation not found.' })

    const files = db.prepare('SELECT * FROM evidence_files WHERE investigation_id = ? ORDER BY upload_timestamp ASC').all(req.params.id)
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

    res.json({ files })
  } catch (err) {
    console.error('[evidence] GET error:', err.message)
    res.status(500).json({ error: 'Failed to fetch evidence files.' })
  }
})

export default router
