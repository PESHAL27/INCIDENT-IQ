/**
 * IncidentIQ — Frontend API Client
 * All communication with the Express backend goes through this module.
 * Uses /api/* paths which are proxied by Vite in development.
 */

const BASE = '/api'

// ── Helper ────────────────────────────────────────────────────

async function request(method, path, body) {
  const opts = {
    method,
    headers: {},
  }

  if (body !== undefined && !(body instanceof FormData)) {
    opts.headers['Content-Type'] = 'application/json'
    opts.body = JSON.stringify(body)
  } else if (body instanceof FormData) {
    opts.body = body
    // Do NOT set Content-Type — browser sets it with boundary
  }

  const res = await fetch(`${BASE}${path}`, opts)
  const data = await res.json().catch(() => ({}))

  if (!res.ok) {
    const msg = data.error || `API error: ${res.status} ${res.statusText}`
    throw new Error(msg)
  }

  return data
}

// ── Investigations ────────────────────────────────────────────

export async function listInvestigations() {
  return request('GET', '/investigations')
}

export async function getInvestigation(id) {
  return request('GET', `/investigations/${id}`)
}

export async function createInvestigation({ name, description }) {
  return request('POST', '/investigations', { name, description })
}

export async function updateInvestigation(id, updates) {
  return request('PATCH', `/investigations/${id}`, updates)
}

export async function deleteInvestigation(id) {
  return request('DELETE', `/investigations/${id}`)
}

// ── Evidence Upload ───────────────────────────────────────────

/**
 * Upload real File objects to the backend.
 * @param {string} invId
 * @param {File[]} files - browser File objects
 */
export async function uploadEvidenceFiles(invId, files) {
  const form = new FormData()
  for (const f of files) {
    form.append('files', f, f.name)
  }
  return request('POST', `/investigations/${invId}/evidence`, form)
}

/**
 * Upload sample incident files (from SAMPLE_INCIDENT constant).
 * Sends them as JSON-encoded content so the backend parses them identically.
 * @param {string} invId
 * @param {Array<{name, content, type, size}>} sampleFiles
 */
export async function uploadSampleFiles(invId, sampleFiles) {
  const form = new FormData()
  form.append('sampleFiles', JSON.stringify(sampleFiles))
  return request('POST', `/investigations/${invId}/evidence`, form)
}

export async function getEvidence(invId) {
  return request('GET', `/investigations/${invId}/evidence`)
}

// ── Analysis ──────────────────────────────────────────────────

export async function persistAnalysis(invId, { analysisResult, recommendations, parsingSummary, status }) {
  return request('PATCH', `/investigations/${invId}/analysis`, {
    analysisResult,
    recommendations,
    parsingSummary,
    status,
  })
}

export async function getFindings(invId) {
  return request('GET', `/investigations/${invId}/analysis/findings`)
}

export async function getTimeline(invId) {
  return request('GET', `/investigations/${invId}/analysis/timeline`)
}

export async function getRecommendations(invId) {
  return request('GET', `/investigations/${invId}/analysis/recommendations`)
}

export async function getInvestigationEvents(invId) {
  return request('GET', `/investigations/${invId}/analysis/events`)
}

// ── Reports ───────────────────────────────────────────────────

export async function saveReport(invId, report) {
  return request('POST', `/investigations/${invId}/report`, { report })
}

export async function listReports() {
  return request('GET', '/reports')
}

// ── Health ────────────────────────────────────────────────────

export async function checkHealth() {
  return request('GET', '/health')
}
