/**
 * IncidentIQ — Express API Server
 * Runs on port 3001. Vite proxy forwards /api/* from port 5173.
 *
 * Security notes:
 *   - No API keys are handled here (Gemini key stays in frontend .env only)
 *   - File paths are never accepted from client
 *   - Investigation IDs are validated before DB queries
 *   - File content stored in SQLite, not on disk
 */

import express from 'express'
import cors from 'cors'
import { requestLogger } from './middleware/logger.js'
import investigationsRouter from './routes/investigations.js'
import evidenceRouter from './routes/evidence.js'
import analysisRouter from './routes/analysis.js'
import reportsRouter from './routes/reports.js'

const app = express()
const PORT = process.env.PORT || 3001

// ── Middleware ─────────────────────────────────────────────────
app.use(cors({
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173'],
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
}))

// JSON body parsing (for analysis updates, report saves)
app.use(express.json({ limit: '10mb' }))
app.use(express.urlencoded({ extended: true }))

app.use(requestLogger)

// ── Health check ───────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', service: 'IncidentIQ API', timestamp: new Date().toISOString() })
})

// ── Routes ─────────────────────────────────────────────────────
app.use('/api/investigations', investigationsRouter)
app.use('/api/investigations/:id/evidence', evidenceRouter)
app.use('/api/investigations/:id/analysis', analysisRouter)
app.use('/api', reportsRouter)  // handles /api/reports and /api/investigations/:id/report

// ── 404 catch-all ──────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.path}` })
})

// ── Global error handler ───────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('[SERVER ERROR]', err.message)
  res.status(500).json({ error: 'Internal server error.' })
})

// ── Start ──────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[IncidentIQ API] Server running on http://localhost:${PORT}`)
  console.log(`[IncidentIQ API] Health: http://localhost:${PORT}/api/health`)
})

export default app
