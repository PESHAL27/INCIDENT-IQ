// IncidentIQ API Integration Test — run: node backend/test_api.js
const BASE = 'http://localhost:3001/api'

async function req(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } }
  if (body) opts.body = JSON.stringify(body)
  const res = await fetch(`${BASE}${path}`, opts)
  return { status: res.status, data: await res.json() }
}

async function run() {
  console.log('\n=== IncidentIQ API Integration Test ===\n')

  const health = await req('GET', '/health')
  console.log('[1] Health:', health.status, '->', health.data.status)

  const create = await req('POST', '/investigations', { name: 'Test Investigation', description: 'API test' })
  console.log('[2] Create:', create.status)
  if (create.status !== 201) { console.error('FAIL create:', create.data); process.exit(1) }

  const invId = create.data.investigation.id
  console.log('    Investigation ID:', invId)

  const list = await req('GET', '/investigations')
  console.log('[3] List:', list.status, '->', list.data.investigations.length, 'investigations')

  const get = await req('GET', '/investigations/' + invId)
  console.log('[4] Get:', get.status, '-> name="' + get.data.investigation.name + '"')

  const patch = await req('PATCH', '/investigations/' + invId, { status: 'analyzing' })
  console.log('[5] Patch:', patch.status, '-> status="' + patch.data.investigation.status + '"')

  const reports = await req('GET', '/reports')
  console.log('[6] Reports:', reports.status, '->', reports.data.reports.length, 'reports')

  const del = await req('DELETE', '/investigations/' + invId)
  console.log('[7] Delete:', del.status, '->', del.data.success)

  const verify = await req('GET', '/investigations/' + invId)
  console.log('[8] Verify deleted:', verify.status, '(expect 404)')

  if (verify.status !== 404) { console.error('FAIL: expected 404 after delete'); process.exit(1) }

  console.log('\n=== ALL TESTS PASSED ===\n')
}

run().catch(err => { console.error('FATAL:', err.message); process.exit(1) })
