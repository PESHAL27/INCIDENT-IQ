import { readFileSync, existsSync } from 'fs'
import { resolve } from 'path'

const BASE = 'http://localhost:3001/api'

async function jsonReq(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } }
  if (body) opts.body = JSON.stringify(body)
  const res = await fetch(BASE + path, opts)
  const data = await res.json().catch(() => null)
  return { status: res.status, data }
}

async function run() {
  console.log('\n=== Evidence Ingestion Test ===\n')
  const create = await jsonReq('POST', '/investigations', { name: 'Evidence Test', description: 'Test' })
  if (create.status !== 201) { console.error('FAIL create:', create.data); process.exit(1) }
  const invId = create.data.investigation.id
  console.log('[1] Created:', invId)

  const testLogPath = resolve('src/data/testEvidence/test2_failed_logins.log')
  if (!existsSync(testLogPath)) { console.error('Test file not found:', testLogPath); process.exit(1) }
  const logContent = readFileSync(testLogPath, 'utf8')
  const samplePayload = [{ name: 'test2_failed_logins.log', content: logContent, type: 'log', size: logContent.length + ' B' }]

  const form = new FormData()
  form.set('sampleFiles', JSON.stringify(samplePayload))

  const upload = await fetch(BASE + '/investigations/' + invId + '/evidence', { method: 'POST', body: form })
  const uploadData = await upload.json()
  console.log('[2] Evidence upload:', upload.status, '| events:', uploadData.totalEvents, '| files:', uploadData.filesProcessed)
  if (upload.status !== 201 || uploadData.totalEvents === 0) { console.error('FAIL upload:', uploadData); process.exit(1) }

  const get = await jsonReq('GET', '/investigations/' + invId)
  console.log('[3] Get inv: events in DB:', get.data.investigation.events?.length, '| evidence files:', get.data.investigation.files?.length)
  if (!get.data.investigation.events || get.data.investigation.events.length === 0) {
    console.error('FAIL: events not persisted')
    process.exit(1)
  }

  const analysisResult = {
    verdict: { severity: 'HIGH', incidentType: 'Test', confidence: 90, summary: 'Test', keyIndicators: [] },
    findings: [{ id: 'f-1', title: 'Test Finding', severity: 'HIGH', confidence: 85 }],
    timeline: [{ id: 't-1', timestamp: '2025-01-15T10:00:00Z', title: 'Test event', type: 'AUTH', severity: 'high' }],
    attackChain: []
  }
  const persist = await jsonReq('PATCH', '/investigations/' + invId + '/analysis', { analysisResult, status: 'complete' })
  console.log('[4] Persist analysis:', persist.status)

  const findings = await jsonReq('GET', '/investigations/' + invId + '/analysis/findings')
  console.log('[5] Findings:', findings.status, '->', findings.data.findings?.length, 'findings')

  await jsonReq('DELETE', '/investigations/' + invId)
  console.log('[6] Cleanup done')
  console.log('\n=== EVIDENCE TEST PASSED ===\n')
}

run().catch(err => { console.error('FATAL:', err.message); process.exit(1) })
