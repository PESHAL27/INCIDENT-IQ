/**
 * IncidentIQ — Gemini AI & Correlation Pipeline Service
 * =========================================================
 * Multi-stage structured analysis pipeline for cyber incident analysis.
 *
 * PIPELINE STAGES:
 *   1. Evidence Parsed
 *   2. Events Extracted
 *   3. Events Normalized
 *   4. Threat Patterns Analyzed
 *   5. Events Correlated
 *   6. Findings Generated
 *   7. Investigation Plan Generated
 *
 * Grounding & Traceability Guarantee:
 *   - Only reference event IDs that exist in the normalized evidence
 *   - Never fabricate IPs, usernames, timestamps, or processes
 *   - Traceability: AI FINDING → EVENT ID → ORIGINAL LOG ENTRY → SOURCE FILE
 *   - Resilient: Executes via Gemini 2.0 Flash when API key is present,
 *     with deterministic heuristic correlation fallback if key is missing/limited.
 * =========================================================
 */

const GEMINI_API_BASE = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent'
const OPENROUTER_API_BASE = 'https://openrouter.ai/api/v1/chat/completions'

export const PIPELINE_STAGES = [
  { key: 'parsed',     label: 'Evidence Parsed',              detail: 'Evidence files verified and read' },
  { key: 'extracted',  label: 'Events Extracted',             detail: 'Raw security events parsed from multi-format logs' },
  { key: 'normalized', label: 'Events Normalized',            detail: 'Consolidating common event schema and IDs' },
  { key: 'analyzed',   label: 'Threat Patterns Analyzed',     detail: 'Deep telemetry inspection & threat classification' },
  { key: 'correlated', label: 'Events Correlated',            detail: 'Cross-source multi-event attack correlation' },
  { key: 'findings',   label: 'Findings Generated',           detail: 'Generating evidence-backed findings' },
  { key: 'plan',       label: 'Investigation Plan Generated', detail: 'Prioritized analyst containment directives' },
]

function getApiKey() {
  const rawKey = import.meta.env.VITE_GEMINI_API_KEY || import.meta.env.VITE_AI_API_KEY || ''
  const cleanKey = String(rawKey).replace(/\s+/g, '').trim()
  return (cleanKey && cleanKey !== 'your_gemini_api_key_here') ? cleanKey : null
}

/**
 * Core AI API caller with retry logic.
 * Automatically supports both:
 *  - OpenRouter keys (sk-or-v1-..., sk-...) with Gemini 2.5 Flash
 *  - Native Google Gemini keys (AIzaSy...)
 */
async function callGemini(systemInstruction, userPrompt, retries = 1) {
  const apiKey = getApiKey()
  if (!apiKey) {
    throw new Error('GEMINI_API_KEY_MISSING')
  }

  const isOpenRouter = apiKey.startsWith('sk-')

  let url
  let headers
  let body

  if (isOpenRouter) {
    url = OPENROUTER_API_BASE
    headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
      'HTTP-Referer': 'http://localhost:5173',
      'X-Title': 'IncidentIQ Cyber Assistant',
    }
    body = JSON.stringify({
      model: 'google/gemini-2.5-flash',
      messages: [
        { role: 'system', content: systemInstruction },
        { role: 'user', content: userPrompt },
      ],
      temperature: 0.1,
      max_tokens: 1500,
    })
  } else {
    url = `${GEMINI_API_BASE}?key=${apiKey}`
    headers = { 'Content-Type': 'application/json' }
    body = JSON.stringify({
      system_instruction: { parts: [{ text: systemInstruction }] },
      contents: [{ role: 'user', parts: [{ text: userPrompt }] }],
      generationConfig: {
        temperature: 0.1,
        responseMimeType: 'application/json',
      },
    })
  }

  let lastError
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers,
        body,
      })

      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}))
        const msg = errBody?.error?.message || errBody?.message || `HTTP ${res.status}`
        throw new Error(`AI API error: ${msg}`)
      }

      const data = await res.json()
      let rawText = ''

      if (isOpenRouter) {
        rawText = data?.choices?.[0]?.message?.content || ''
      } else {
        rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text || ''
      }

      try { return JSON.parse(rawText) } catch { /* fall through */ }

      const fenced = rawText.match(/```(?:json)?\s*([\s\S]*?)```/s)
      if (fenced) {
        try { return JSON.parse(fenced[1].trim()) } catch { /* fall through */ }
      }

      const braceStart = rawText.indexOf('{')
      const braceEnd = rawText.lastIndexOf('}')
      if (braceStart !== -1 && braceEnd > braceStart) {
        try { return JSON.parse(rawText.slice(braceStart, braceEnd + 1)) } catch { /* fall through */ }
      }

      throw new Error(`AI returned non-JSON response. Raw: ${rawText.slice(0, 150)}`)
    } catch (err) {
      lastError = err
      if (attempt < retries) {
        await new Promise(r => setTimeout(r, 1000 * (attempt + 1)))
      }
    }
  }
  throw lastError
}

/* ============================================================
   FALLBACK HEURISTIC CORRELATION ENGINE
   Grounded strictly on the actual normalized events.
   ============================================================ */

export function heuristicThreatClassification(events) {
  return events.map(ev => {
    const type = (ev.eventType || '').toLowerCase()
    const msg = (ev.message || '').toLowerCase()
    const raw = (ev.raw || '').toLowerCase()

    let threatType = 'normal'
    let severity = ev.severity || 'INFO'
    let isSuspicious = false

    if (type.includes('auth') && (type.includes('fail') || ev.action === 'failed' || raw.includes('failed password'))) {
      threatType = 'brute_force'
      severity = 'HIGH'
      isSuspicious = true
    } else if (type.includes('privilege') || raw.includes('sudo:') || raw.includes('command=') || raw.includes('uid=0') || msg.includes('sudo')) {
      threatType = 'privilege_escalation'
      severity = (raw.includes('/etc/shadow') || raw.includes('bash') || raw.includes('root')) ? 'CRITICAL' : 'HIGH'
      isSuspicious = true
    } else if (raw.includes('4444') || ev.port === 4444 || raw.includes('nc ') || raw.includes('reverse') || type.includes('reverse_shell') || type.includes('c2')) {
      threatType = 'c2_communication'
      severity = 'CRITICAL'
      isSuspicious = true
    } else if (type.includes('exfiltration') || type.includes('transfer') || raw.includes('data_transfer') || (ev.port === 443 && raw.includes('transfer'))) {
      threatType = 'data_exfiltration'
      severity = 'CRITICAL'
      isSuspicious = true
    } else if (raw.includes('wget') || raw.includes('curl') || raw.includes('payload') || raw.includes('beacon') || raw.includes('/tmp')) {
      threatType = 'malware_execution'
      severity = 'HIGH'
      isSuspicious = true
    } else if (type.includes('auth') && (type.includes('success') || ev.action === 'accepted')) {
      threatType = 'credential_compromise'
      severity = 'MEDIUM'
      isSuspicious = false
    }

    return {
      id: ev.eventId,
      threatType,
      severity,
      isSuspicious,
      isInferred: false,
      threatNote: `Grounded in evidence from ${ev.source || ev.evidenceFile}`,
    }
  })
}

export function heuristicCorrelation(events, annotatedEvents = [], _evidenceSummary = '') {
  const findings = []
  let findingCount = 1

  // Helper to construct guaranteed valid supporting events and supportingEventIds
  const makeSupporting = (matchingEvents, max = 6, defaultNote = 'Direct telemetry evidence') => {
    const slice = matchingEvents.slice(0, max)
    return {
      supportingEvents: slice.map(ev => ({
        eventId: ev.eventId,
        description: ev.message || ev.raw,
        contributionNote: ev.source ? `From ${ev.source} (${ev.eventType || 'telemetry'})` : defaultNote,
      })),
      supportingEventIds: slice.map(ev => ev.eventId),
    }
  }

  // 1. Group failed authentication events
  const failedAuths = events.filter(e =>
    (e.eventType || '').includes('fail') ||
    e.action === 'failed' ||
    (e.raw || '').toLowerCase().includes('failed password') ||
    (e.message || '').toLowerCase().includes('failed')
  )

  // 2. Successful authentication events
  const successAuths = events.filter(e =>
    (e.eventType || '').includes('success') ||
    e.action === 'accepted' ||
    (e.raw || '').toLowerCase().includes('accepted password') ||
    (e.raw || '').toLowerCase().includes('session opened for user')
  )

  // Pattern 1: Brute-Force Authentication Attempt
  if (failedAuths.length > 0) {
    const srcIps = [...new Set(failedAuths.map(e => e.sourceIp).filter(Boolean))]
    const targetUsers = [...new Set(failedAuths.map(e => e.username).filter(Boolean))]
    const ipStr = srcIps.length > 0 ? srcIps.join(', ') : 'external source'
    const userStr = targetUsers.length > 0 ? targetUsers.join(', ') : 'targeted accounts'
    const support = makeSupporting(failedAuths, 6, 'Authentication failure telemetry')

    findings.push({
      id: `FIND-${String(findingCount++).padStart(3, '0')}`,
      title: 'Brute-Force Authentication Attempt',
      severity: failedAuths.length >= 4 ? 'HIGH' : 'MEDIUM',
      confidence: Math.min(98, 88 + failedAuths.length),
      shortExplanation: `${failedAuths.length} failed login attempt(s) detected targeting account(s) [${userStr}] from source IP(s) [${ipStr}].`,
      isInferred: false,
      supportingEvents: support.supportingEvents,
      supportingEventIds: support.supportingEventIds,
      inferenceNote: null,
    })
  }

  // Pattern 2: Compromised Account Authentication (successful login following failures)
  if (successAuths.length > 0) {
    const compromisedLogins = []

    for (const sa of successAuths) {
      const matchPriorFail = failedAuths.some(fa =>
        (fa.sourceIp && sa.sourceIp && fa.sourceIp === sa.sourceIp) ||
        (fa.username && sa.username && fa.username === sa.username)
      )
      if (matchPriorFail) {
        compromisedLogins.push(sa)
      }
    }

    if (compromisedLogins.length > 0) {
      const compUser = compromisedLogins[0].username || 'target account'
      const compIp = compromisedLogins[0].sourceIp || 'originating IP'
      const relatedFailed = failedAuths.filter(fa => fa.sourceIp === compIp || fa.username === compUser)
      const supportEvents = [...compromisedLogins, ...relatedFailed.slice(0, 3)]
      const support = makeSupporting(supportEvents, 6, 'Correlated authentication event')

      findings.push({
        id: `FIND-${String(findingCount++).padStart(3, '0')}`,
        title: 'Compromised Account Authentication',
        severity: 'CRITICAL',
        confidence: 94,
        shortExplanation: `Successful authentication confirmed for user "${compUser}" from source IP ${compIp} immediately following credential guessing attempts.`,
        isInferred: true,
        supportingEvents: support.supportingEvents,
        supportingEventIds: support.supportingEventIds,
        inferenceNote: `Adversary correlation: successful login originated from the identical source IP (${compIp}) that executed repeated password-guessing failures against "${compUser}".`,
      })
    }
  }

  // Pattern 3: Privilege Escalation
  const privEscs = events.filter(e =>
    (e.eventType || '').includes('privilege') ||
    (e.eventType || '').includes('sudo') ||
    (e.raw || '').toLowerCase().includes('sudo:') ||
    (e.raw || '').toLowerCase().includes('command=') ||
    (e.raw || '').toLowerCase().includes('user root') ||
    (e.raw || '').toLowerCase().includes('/etc/shadow') ||
    (e.message || '').toLowerCase().includes('sudo')
  )

  if (privEscs.length > 0) {
    const hasShadow = privEscs.some(e => (e.raw || '').includes('/etc/shadow') || (e.message || '').includes('shadow'))
    const hasRootShell = privEscs.some(e => (e.raw || '').includes('bash') || (e.message || '').includes('root'))
    const privUsers = [...new Set(privEscs.map(e => e.username).filter(Boolean))]
    const privUserStr = privUsers.length > 0 ? privUsers.join(', ') : 'authenticated user'
    const support = makeSupporting(privEscs, 6, 'Process and privilege escalation telemetry')

    findings.push({
      id: `FIND-${String(findingCount++).padStart(3, '0')}`,
      title: 'Unauthorized Privilege Escalation Activity',
      severity: (hasShadow || hasRootShell) ? 'CRITICAL' : 'HIGH',
      confidence: 96,
      shortExplanation: `Administrative elevation observed by user "${privUserStr}" obtaining root-level privileges.`,
      isInferred: false,
      supportingEvents: support.supportingEvents,
      supportingEventIds: support.supportingEventIds,
      inferenceNote: null,
    })
  }

  // Pattern 4: Command & Control (C2) / Reverse Shell
  const netEvents = events.filter(e => {
    const rawLower = (e.raw || '').toLowerCase()
    const msgLower = (e.message || '').toLowerCase()
    const typeLower = (e.eventType || '').toLowerCase()
    const isSusPort = e.port && [4444, 1337, 9001, 6667, 31337, 8888].includes(Number(e.port))
    const hasReverse = rawLower.includes('reverse') || rawLower.includes('nc ') || rawLower.includes('reverse_shell')
    const hasC2 = rawLower.includes('c2') || msgLower.includes('c2') || typeLower.includes('c2')
    const isExplicitC2 = (rawLower.includes('outbound_established') || rawLower.includes('beacon')) && isSusPort

    return isSusPort || hasReverse || hasC2 || isExplicitC2
  })

  if (netEvents.length > 0) {
    const c2Event = netEvents.find(e => e.port === 4444 || (e.raw || '').includes('4444') || (e.raw || '').includes('nc ')) || netEvents[0]
    const dstIp = c2Event.destinationIp || 'external host'
    const port = c2Event.port || '4444'
    const hasC2 = c2Event.port === 4444 || (c2Event.raw || '').includes('4444') || (c2Event.raw || '').includes('nc ')
    const support = makeSupporting(netEvents, 6, 'Network telemetry and firewall connection records')

    findings.push({
      id: `FIND-${String(findingCount++).padStart(3, '0')}`,
      title: hasC2 ? 'Suspicious Outbound C2 Channel & Network Activity' : 'Anomalous Outbound Network Telemetry',
      severity: hasC2 ? 'CRITICAL' : 'HIGH',
      confidence: hasC2 ? 96 : 90,
      shortExplanation: `Outbound connection established to external destination ${dstIp} on port ${port} indicating remote adversary communication.`,
      isInferred: false,
      supportingEvents: support.supportingEvents,
      supportingEventIds: support.supportingEventIds,
      inferenceNote: hasC2 ? `Port ${port} and process execution telemetry match persistent interactive reverse shell communications.` : null,
    })
  }

  // Pattern 5: Data Exfiltration / Unauthorized Egress
  const exfilEvents = events.filter(e =>
    (e.eventType || '').includes('exfiltration') ||
    (e.action || '').toLowerCase() === 'transfer' ||
    (e.raw || '').toLowerCase().includes('data_transfer') ||
    (e.raw || '').toLowerCase().includes('exfiltration') ||
    (e.message || '').toLowerCase().includes('exfiltration')
  )

  if (exfilEvents.length > 0) {
    const exfilEv = exfilEvents[0]
    const dstIp = exfilEv.destinationIp || 'external destination'
    const support = makeSupporting(exfilEvents, 6, 'Data egress and transfer telemetry')

    findings.push({
      id: `FIND-${String(findingCount++).padStart(3, '0')}`,
      title: 'Data Exfiltration & Unauthorized Transfer',
      severity: 'CRITICAL',
      confidence: 95,
      shortExplanation: `Unauthorized outbound data egress observed transferring archived data to external endpoint ${dstIp}.`,
      isInferred: false,
      supportingEvents: support.supportingEvents,
      supportingEventIds: support.supportingEventIds,
      inferenceNote: null,
    })
  }

  // Pattern 6: Suspicious Staging / Tool Download
  const stagingEvents = events.filter(e =>
    (e.raw || '').toLowerCase().includes('wget') ||
    (e.raw || '').toLowerCase().includes('curl') ||
    (e.raw || '').toLowerCase().includes('/tmp') ||
    (e.process || '').toLowerCase().includes('wget') ||
    (e.process || '').toLowerCase().includes('curl')
  )

  if (stagingEvents.length > 0 && !findings.some(f => f.title.includes('Staging'))) {
    const support = makeSupporting(stagingEvents, 6, 'Process execution and tool staging evidence')
    findings.push({
      id: `FIND-${String(findingCount++).padStart(3, '0')}`,
      title: 'Malware Staging & Tooling Download',
      severity: 'HIGH',
      confidence: 91,
      shortExplanation: `Tool invocation detected attempting to download and stage secondary payloads.`,
      isInferred: false,
      supportingEvents: support.supportingEvents,
      supportingEventIds: support.supportingEventIds,
      inferenceNote: null,
    })
  }

  // Pattern 7: Fallback finding if evidence is benign or insufficient (Requirement 11)
  if (findings.length === 0) {
    const support = makeSupporting(events, 5, 'Baseline operational telemetry')
    findings.push({
      id: 'FIND-001',
      title: 'Baseline Operational Activity Analyzed',
      severity: 'LOW',
      confidence: 92,
      shortExplanation: `Analyzed ${events.length} security event(s). Evidence is insufficient to determine or confirm any malicious attack actions or compromise.`,
      isInferred: false,
      supportingEvents: support.supportingEvents,
      supportingEventIds: support.supportingEventIds,
      inferenceNote: 'Evidence is insufficient to confirm malicious intent; telemetry matches expected operational baseline behavior.',
    })
  }

  // Build Chronological Timeline from actual events (Requirement 12)
  const sortedEvents = [...events].sort((a, b) => {
    if (!a.timestamp && !b.timestamp) return 0
    if (!a.timestamp) return 1
    if (!b.timestamp) return -1
    const da = new Date(a.timestamp).getTime()
    const db = new Date(b.timestamp).getTime()
    if (!isNaN(da) && !isNaN(db)) return da - db
    return String(a.timestamp).localeCompare(String(b.timestamp))
  })

  const timeline = sortedEvents.map(ev => {
    let displayTime = ev.timestamp || '—'
    if (displayTime.includes('T')) {
      displayTime = displayTime.split('T')[1]?.replace('Z', '')?.slice(0, 8) || displayTime
    } else if (displayTime.includes(' ')) {
      const parts = displayTime.split(' ')
      displayTime = parts[parts.length - 1] || displayTime
    }

    const ann = annotatedEvents.find(a => a.id === ev.eventId)
    return {
      timestamp: ev.timestamp,
      displayTime,
      eventId: ev.eventId,
      description: ev.message || ev.raw,
      severity: ev.severity || ann?.severity || 'INFO',
      threatType: ann?.threatType || ev.eventType || 'normal',
      source: ev.source,
      evidenceFile: ev.evidenceFile,
    }
  })

  // Build Attack Chain
  const attackChain = findings.map((f, idx) => ({
    step: idx + 1,
    label: f.title,
    findingId: f.id,
    description: f.shortExplanation,
  }))

  // Derived severity
  const severities = findings.map(f => f.severity)
  let maxSev = 'LOW'
  if (severities.includes('CRITICAL')) maxSev = 'CRITICAL'
  else if (severities.includes('HIGH')) maxSev = 'HIGH'
  else if (severities.includes('MEDIUM')) maxSev = 'MEDIUM'

  // Extract Key Indicators from actual events & findings
  const keyIndicators = []
  const seenIndicators = new Set()
  for (const ev of events) {
    if (ev.sourceIp && !seenIndicators.has(ev.sourceIp) && !ev.sourceIp.startsWith('127.')) {
      seenIndicators.add(ev.sourceIp)
      keyIndicators.push(`Source IP: ${ev.sourceIp}`)
    }
    if (ev.destinationIp && !seenIndicators.has(ev.destinationIp) && !ev.destinationIp.startsWith('127.')) {
      seenIndicators.add(ev.destinationIp)
      keyIndicators.push(`Destination IP: ${ev.destinationIp}`)
    }
    if (ev.port && [4444, 1337, 9001].includes(ev.port) && !seenIndicators.has(`port:${ev.port}`)) {
      seenIndicators.add(`port:${ev.port}`)
      keyIndicators.push(`C2 Port: ${ev.port}`)
    }
    if (ev.username && !['unknown', 'invalid'].includes(ev.username.toLowerCase()) && !seenIndicators.has(`user:${ev.username}`)) {
      seenIndicators.add(`user:${ev.username}`)
      keyIndicators.push(`Target User: ${ev.username}`)
    }
  }
  findings.forEach(f => {
    if (!keyIndicators.includes(f.title)) keyIndicators.push(f.title)
  })

  // Incident Type
  let incidentType = 'Routine System Telemetry Baseline'
  if (maxSev === 'CRITICAL') {
    incidentType = 'Multi-Stage Intrusion: Account Compromise, Privilege Escalation & C2 Activity'
  } else if (maxSev === 'HIGH') {
    incidentType = 'Targeted Brute-Force & Authentication Attack Anomaly'
  } else if (maxSev === 'MEDIUM') {
    incidentType = 'Suspicious Authentication Activity'
  }

  // Summary
  let summary = ''
  if (maxSev === 'LOW') {
    summary = `Evidence is insufficient to confirm any security compromise or malicious actor activity. Telemetry reflects normal baseline operations across ${events.length} ingested event(s).`
  } else {
    summary = findings.map(f => f.shortExplanation).slice(0, 2).join(' ')
  }

  const verdict = {
    severity: maxSev,
    incidentType,
    confidence: Math.round(findings.reduce((acc, f) => acc + (f.confidence || 90), 0) / findings.length),
    summary,
    keyIndicators: keyIndicators.slice(0, 8),
  }

  return { verdict, findings, timeline, attackChain }
}

export function heuristicRecommendations(findings, events) {
  const recs = []
  let recCount = 1

  for (const finding of findings) {
    const titleLower = finding.title.toLowerCase()
    const supportIds = finding.supportingEventIds || []

    if (titleLower.includes('brute-force')) {
      const relatedEv = events.find(e => supportIds.includes(e.eventId))
      const srcIp = relatedEv?.sourceIp || 'detected source'
      recs.push({
        id: `REC-${String(recCount++).padStart(3, '0')}`,
        priority: 'HIGH',
        action: `Block Inbound Traffic from Hostile Source IP (${srcIp}) at Perimeter Firewall`,
        reason: `Repeated automated failed authentication attempts detected from external IP ${srcIp}.`,
        relatedFindings: [finding.id],
        relatedEvents: supportIds.slice(0, 3),
        expectedOutcome: 'Halt automated credential guessing attempts and mitigate service degradation.',
      })
    } else if (titleLower.includes('compromised account')) {
      const relatedEv = events.find(e => supportIds.includes(e.eventId))
      const user = relatedEv?.username || 'targeted account'
      recs.push({
        id: `REC-${String(recCount++).padStart(3, '0')}`,
        priority: 'IMMEDIATE',
        action: `Revoke Active Sessions and Force Credential Reset for Account (${user})`,
        reason: `Successful authentication observed immediately following brute-force attempts targeting user ${user}.`,
        relatedFindings: [finding.id],
        relatedEvents: supportIds.slice(0, 3),
        expectedOutcome: 'Invalidate potential adversary session tokens and restore account credentials to known-good state.',
      })
    } else if (titleLower.includes('privilege escalation')) {
      recs.push({
        id: `REC-${String(recCount++).padStart(3, '0')}`,
        priority: 'IMMEDIATE',
        action: 'Terminate Unauthorized Elevated Root Sessions and Audit Sudoers Configuration',
        reason: 'Unauthorized administrative command execution and root session initialization detected.',
        relatedFindings: [finding.id],
        relatedEvents: supportIds.slice(0, 3),
        expectedOutcome: 'Revoke adversary root access and verify system configuration integrity.',
      })
    } else if (titleLower.includes('c2') || titleLower.includes('network')) {
      const relatedEv = events.find(e => supportIds.includes(e.eventId) && (e.port === 4444 || e.destinationIp))
      const dst = relatedEv?.destinationIp ? `${relatedEv.destinationIp}:${relatedEv.port || 4444}` : 'external endpoint'
      recs.push({
        id: `REC-${String(recCount++).padStart(3, '0')}`,
        priority: 'IMMEDIATE',
        action: `Isolate Endpoint and Sever External C2 Socket (${dst})`,
        reason: 'Active reverse shell or external C2 connection detected in network telemetry.',
        relatedFindings: [finding.id],
        relatedEvents: supportIds.slice(0, 3),
        expectedOutcome: 'Terminate active malicious communications and prevent further lateral movement or commands.',
      })
    } else if (titleLower.includes('exfiltration')) {
      recs.push({
        id: `REC-${String(recCount++).padStart(3, '0')}`,
        priority: 'IMMEDIATE',
        action: 'Apply Network Egress Filtering and Quarantine Staged Archives',
        reason: 'Unauthorized bulk outbound data transfer detected to external destination.',
        relatedFindings: [finding.id],
        relatedEvents: supportIds.slice(0, 3),
        expectedOutcome: 'Prevent further data egress and identify potential compromised intellectual property.',
      })
    } else if (titleLower.includes('baseline')) {
      recs.push({
        id: `REC-${String(recCount++).padStart(3, '0')}`,
        priority: 'LOW',
        action: 'Maintain Operational Baseline Telemetry Monitoring',
        reason: 'Analyzed evidence shows no confirmed indicators of compromise; continue routine SOC monitoring.',
        relatedFindings: [finding.id],
        relatedEvents: supportIds.slice(0, 3),
        expectedOutcome: 'Ensure ongoing audit log coverage without disrupting normal operations.',
      })
    }
  }

  // Fallback if no specific recommendations matched
  if (recs.length === 0) {
    recs.push({
      id: 'REC-001',
      priority: 'MEDIUM',
      action: 'Conduct Forensic Review of Correlated Telemetry',
      reason: 'Review security events to assess potential indicators of anomalous activity.',
      relatedFindings: findings.map(f => f.id),
      relatedEvents: events.slice(0, 3).map(e => e.eventId),
      expectedOutcome: 'Determine if additional evidence sources or endpoint captures are warranted.',
    })
  }

  return { recommendations: recs }
}

/* ============================================================
   AI ANALYSIS & GROUNDING SANITIZER
   ============================================================ */

function sanitizeAndGroundAnalysis(aiResult, events) {
  const eventMap = new Map(events.map(e => [e.eventId, e]))
  const validEventIds = new Set(events.map(e => e.eventId))

  // Validate and sanitize findings
  const rawFindings = Array.isArray(aiResult?.findings) ? aiResult.findings : []
  const groundedFindings = []

  for (let i = 0; i < rawFindings.length; i++) {
    const f = rawFindings[i]
    const fid = f.id || `FIND-${String(i + 1).padStart(3, '0')}`

    // Extract supporting event IDs
    let supportIds = []
    if (Array.isArray(f.supportingEventIds)) {
      supportIds = f.supportingEventIds.filter(id => validEventIds.has(id))
    }
    if (supportIds.length === 0 && Array.isArray(f.supportingEvents)) {
      supportIds = f.supportingEvents
        .map(se => (typeof se === 'string' ? se : se.eventId))
        .filter(id => validEventIds.has(id))
    }

    // Never accept finding with fabricated IDs
    if (supportIds.length === 0) {
      continue
    }

    const reconstructedSupportingEvents = supportIds.map(eid => {
      const realEv = eventMap.get(eid)
      return {
        eventId: eid,
        description: realEv.message || realEv.raw,
        contributionNote: `Grounding trace from ${realEv.source}`,
      }
    })

    groundedFindings.push({
      id: fid,
      title: f.title || 'Correlated Security Finding',
      severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(f.severity) ? f.severity : 'MEDIUM',
      confidence: typeof f.confidence === 'number' ? Math.min(100, Math.max(50, Math.round(f.confidence))) : 90,
      shortExplanation: f.shortExplanation || 'Evidence-grounded telemetry finding.',
      isInferred: Boolean(f.isInferred),
      supportingEvents: reconstructedSupportingEvents,
      supportingEventIds: supportIds,
      inferenceNote: f.isInferred ? (f.inferenceNote || 'AI logical inference correlated across event telemetry.') : null,
    })
  }

  // If AI returned 0 grounded findings, fallback to heuristic
  if (groundedFindings.length === 0) {
    return null
  }

  // Strict Chronological Timeline from actual events (Requirement 12)
  const sortedEvents = [...events].sort((a, b) => {
    if (!a.timestamp && !b.timestamp) return 0
    if (!a.timestamp) return 1
    if (!b.timestamp) return -1
    const da = new Date(a.timestamp).getTime()
    const db = new Date(b.timestamp).getTime()
    if (!isNaN(da) && !isNaN(db)) return da - db
    return String(a.timestamp).localeCompare(String(b.timestamp))
  })

  const timeline = sortedEvents.map(ev => {
    let displayTime = ev.timestamp || '—'
    if (displayTime.includes('T')) {
      displayTime = displayTime.split('T')[1]?.replace('Z', '')?.slice(0, 8) || displayTime
    }
    return {
      timestamp: ev.timestamp,
      displayTime,
      eventId: ev.eventId,
      description: ev.message || ev.raw,
      severity: ev.severity || 'INFO',
      threatType: ev.eventType || 'normal',
      source: ev.source,
      evidenceFile: ev.evidenceFile,
    }
  })

  // Attack chain from grounded findings
  const attackChain = groundedFindings.map((f, idx) => ({
    step: idx + 1,
    label: f.title,
    findingId: f.id,
    description: f.shortExplanation,
  }))

  const verdict = {
    severity: aiResult.verdict?.severity || groundedFindings[0]?.severity || 'MEDIUM',
    incidentType: aiResult.verdict?.incidentType || 'Correlated Multi-Source Incident',
    confidence: aiResult.verdict?.confidence || Math.round(groundedFindings.reduce((a, f) => a + f.confidence, 0) / groundedFindings.length),
    summary: aiResult.verdict?.summary || groundedFindings.map(f => f.shortExplanation).slice(0, 2).join(' '),
    keyIndicators: Array.isArray(aiResult.verdict?.keyIndicators) ? aiResult.verdict.keyIndicators : groundedFindings.map(f => f.title),
  }

  return { verdict, findings: groundedFindings, timeline, attackChain }
}

export async function classifyThreats(events) {
  const apiKey = getApiKey()
  if (!apiKey) {
    return { annotatedEvents: heuristicThreatClassification(events) }
  }

  const systemInstruction = `You are a cybersecurity threat analyst classifying security events.
STRICT RULES:
1. Classify only events from the input. Do not add new events.
2. Use exact event IDs from the input. Never fabricate IDs.
3. Set isInferred=true only when classification requires logical deduction.

Return ONLY this JSON:
{
  "annotatedEvents": [
    {
      "id": "AUTH-001",
      "threatType": "brute_force",
      "severity": "HIGH",
      "isSuspicious": true,
      "isInferred": false,
      "threatNote": "brief explanation"
    }
  ]
}

Valid threatTypes: brute_force | credential_compromise | privilege_escalation | lateral_movement | malware_execution | c2_communication | data_exfiltration | normal | suspicious_unknown`

  const prompt = `Classify these structured security events:\n${JSON.stringify(events, null, 2)}`
  try {
    const res = await callGemini(systemInstruction, prompt)
    if (res?.annotatedEvents) return res
  } catch (err) {
    console.warn('[IncidentIQ] AI classification fallback to heuristic:', err.message)
  }
  return { annotatedEvents: heuristicThreatClassification(events) }
}

export async function correlateAndGenerateFindings(events, annotatedEvents, evidenceSummary) {
  const apiKey = getApiKey()
  if (!apiKey) {
    return heuristicCorrelation(events, annotatedEvents, evidenceSummary)
  }

  const systemInstruction = `You are a senior cybersecurity incident response analyst.
Your task:
1. Correlate related events across sources to identify attack patterns.
2. Generate named, evidence-backed findings with per-finding confidence.
3. Produce an overall incident verdict.
4. Distinguish confirmed evidence from AI inference.

STRICT RULES — EVIDENCE GROUNDING:
- Every finding MUST list exact event IDs from the input in "supportingEventIds".
- NEVER reference event IDs not present in the input.
- NEVER fabricate IP addresses, usernames, timestamps, or process names.
- If evidence is insufficient to determine an attack, explicitly state that in the verdict and findings.

Return ONLY this JSON structure:
{
  "verdict": {
    "severity": "CRITICAL",
    "incidentType": "Incident Classification",
    "confidence": 94,
    "summary": "Evidence-grounded explanation",
    "keyIndicators": ["indicator 1", "indicator 2"]
  },
  "findings": [
    {
      "id": "FIND-001",
      "title": "Finding Title",
      "severity": "HIGH",
      "confidence": 95,
      "shortExplanation": "Evidence grounded summary",
      "isInferred": false,
      "supportingEventIds": ["AUTH-001"],
      "supportingEvents": [
        {
          "eventId": "AUTH-001",
          "description": "Event description",
          "contributionNote": "How it supports finding"
        }
      ],
      "inferenceNote": null
    }
  ]
}`

  const cappedContext = typeof evidenceSummary === 'string' ? evidenceSummary.slice(0, 4000) : ''
  const prompt = `Correlate events and generate findings:\nEVENTS:\n${JSON.stringify(events, null, 2)}\n\nANNOTATIONS:\n${JSON.stringify(annotatedEvents, null, 2)}\n\nCONTEXT:\n${cappedContext}`

  try {
    const res = await callGemini(systemInstruction, prompt)
    if (res?.verdict && Array.isArray(res?.findings)) {
      const grounded = sanitizeAndGroundAnalysis(res, events)
      if (grounded) return grounded
    }
  } catch (err) {
    console.warn('[IncidentIQ] AI correlation fallback to heuristic:', err.message)
  }
  return heuristicCorrelation(events, annotatedEvents, evidenceSummary)
}

export async function planInvestigation(verdict, findings, events) {
  const apiKey = getApiKey()
  if (!apiKey) {
    return heuristicRecommendations(findings, events)
  }

  const systemInstruction = `You are a cybersecurity incident response manager.
Generate prioritized response recommendations strictly based on findings and events provided.
Priority levels: IMMEDIATE | HIGH | MEDIUM | LOW
Do not execute destructive actions; recommendations must be advisory IR actions for the analyst.

Return ONLY this JSON:
{
  "recommendations": [
    {
      "id": "REC-001",
      "priority": "IMMEDIATE",
      "action": "Action title",
      "reason": "Why this action is needed",
      "relatedFindings": ["FIND-001"],
      "relatedEvents": ["AUTH-001"],
      "expectedOutcome": "Outcome"
    }
  ]
}`

  const prompt = `VERDICT:\n${JSON.stringify(verdict, null, 2)}\nFINDINGS:\n${JSON.stringify(findings, null, 2)}\nEVENTS:\n${JSON.stringify(events.slice(0, 15), null, 2)}`
  try {
    const res = await callGemini(systemInstruction, prompt)
    if (Array.isArray(res?.recommendations) && res.recommendations.length > 0) {
      return res
    }
  } catch (err) {
    console.warn('[IncidentIQ] AI planning fallback to heuristic:', err.message)
  }
  return heuristicRecommendations(findings, events)
}

export async function generateReportContent(investigation) {
  const { id, name, analysisResult, files } = investigation
  const verdict = analysisResult?.verdict || {}
  const findings = analysisResult?.findings || []

  const apiKey = getApiKey()
  if (apiKey) {
    const systemInstruction = `You are a cybersecurity incident response analyst writing a formal IR report.
STRICT RULES:
1. Use ONLY information from the investigation data provided.
2. Separate confirmed findings from suspected activity.
3. Acknowledge evidence limitations honestly.

Return ONLY this JSON:
{
  "executiveSummary": "2-3 paragraph professional summary",
  "affectedAssets": ["hosts, systems, accounts"],
  "evidenceSummary": "evidence analyzed",
  "confirmedFindings": ["confirmed findings"],
  "suspectedActivity": ["inferred activity"],
  "ioc": {
    "ipAddresses": [],
    "processes": [],
    "files": [],
    "domains": []
  },
  "limitations": "Evidence gaps statement",
  "aiConfidence": 94
}`

    const prompt = `Generate IR report for:\nID: ${id}\nNAME: ${name}\nVERDICT: ${JSON.stringify(verdict)}\nFINDINGS: ${JSON.stringify(findings)}\nFILES: ${(files || []).map(f => f.name).join(', ')}`
    try {
      const res = await callGemini(systemInstruction, prompt)
      if (res?.executiveSummary) return res
    } catch {
      // Fall through to deterministic report
    }
  }

  // Deterministic professional report generation
  const ips = new Set()
  const procs = new Set()
  const assets = new Set()

  findings.forEach(f => {
    f.supportingEvents?.forEach(se => {
      if (se.description) {
        const ipM = se.description.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)
        ipM?.forEach(ip => ips.add(ip))
      }
    })
  })

  ;(files || []).forEach(f => assets.add(f.name))

  return {
    executiveSummary: `Incident ${id} ("${name}") was identified with an overall severity rating of ${verdict.severity || 'MEDIUM'}. Analysis of ${files?.length || 0} evidence source(s) revealed ${findings.length} key security finding(s). ${verdict.summary || 'Telemetry indicates abnormal activity.'}\n\nImmediate containment actions have been prioritized to mitigate lateral movement and prevent unauthorized operational disruption.`,
    affectedAssets: Array.from(assets),
    evidenceSummary: `Ingested and normalized evidence across ${(files || []).map(f => f.name).join(', ')}.`,
    confirmedFindings: findings.filter(f => !f.isInferred).map(f => `${f.title}: ${f.shortExplanation}`),
    suspectedActivity: findings.filter(f => f.isInferred).map(f => `${f.title}: ${f.shortExplanation}`),
    ioc: {
      ipAddresses: Array.from(ips),
      processes: Array.from(procs),
      files: (files || []).map(f => f.name),
      domains: [],
    },
    limitations: 'Analysis is constrained to the supplied log files. Encrypted payloads and out-of-band communications may not be reflected in host-level logs.',
    aiConfidence: verdict.confidence || 92,
  }
}

/* ============================================================
   FULL PIPELINE ORCHESTRATOR
   ============================================================ */

export async function runAnalysisPipeline(evidenceBundle, files, onStageUpdate, normalizedData) {
  const notify = (stageKey, status, data = null) => {
    onStageUpdate?.({ stageKey, status, data })
  }

  const events = normalizedData?.events || []
  const summary = normalizedData?.summary || { totalEvents: events.length }

  // 4. Threat Patterns Analyzed
  notify('analyzed', 'running')
  const classificationResult = await classifyThreats(events)
  const annotatedEvents = classificationResult.annotatedEvents || []
  const suspiciousCount = annotatedEvents.filter(a => a.isSuspicious).length
  await new Promise(r => setTimeout(r, 140))
  notify('analyzed', 'complete', { threatCount: suspiciousCount })

  // 5. Events Correlated
  notify('correlated', 'running')
  const correlationResult = await correlateAndGenerateFindings(events, annotatedEvents, evidenceBundle)
  await new Promise(r => setTimeout(r, 150))
  notify('correlated', 'complete')

  // 6. Findings Generated
  notify('findings', 'running')
  await new Promise(r => setTimeout(r, 120))
  notify('findings', 'complete', { findingCount: correlationResult.findings?.length || 0 })

  // 7. Investigation Plan Generated
  notify('plan', 'running')
  const planResult = await planInvestigation(
    correlationResult.verdict,
    correlationResult.findings,
    events,
  )
  await new Promise(r => setTimeout(r, 120))
  notify('plan', 'complete', { recCount: planResult.recommendations?.length || 0 })

  return {
    events,
    annotatedEvents,
    verdict: correlationResult.verdict,
    findings: correlationResult.findings || [],
    timeline: correlationResult.timeline || [],
    attackChain: correlationResult.attackChain || [],
    recommendations: planResult.recommendations || [],
    extractionSummary: summary,
  }
}
