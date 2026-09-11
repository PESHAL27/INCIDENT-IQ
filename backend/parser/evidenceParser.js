/**
 * IncidentIQ — Backend Evidence Parser (Node.js)
 * Port of src/services/evidenceParser.js
 * Same parsing logic and output schema. No browser APIs.
 */

const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g

// ── LOG / TXT PARSER ─────────────────────────────────────────

function parseLogLine(line, filename) {
  const trimmed = line.trim()
  if (!trimmed) return null

  const event = {
    eventId: null,
    timestamp: null,
    source: filename,
    eventType: 'log_entry',
    username: null,
    sourceIp: null,
    destinationIp: null,
    port: null,
    action: null,
    process: null,
    message: trimmed,
    severity: 'INFO',
    evidenceFile: filename,
    raw: trimmed,
  }

  // Timestamps
  const isoMatch = trimmed.match(/\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/)
  if (isoMatch) {
    event.timestamp = isoMatch[0].replace(' ', 'T')
  } else {
    const syslogMatch = trimmed.match(/\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\b/i)
    if (syslogMatch) {
      event.timestamp = `${syslogMatch[1]} ${syslogMatch[2]} ${syslogMatch[3]}`
    } else {
      const timeMatch = trimmed.match(/\b\d{2}:\d{2}:\d{2}\b/)
      if (timeMatch) event.timestamp = timeMatch[0]
    }
  }

  // IPs
  const srcIpMatch = trimmed.match(/(?:from|SRC=|client(?:\s+ip)?[:=]?)\s*([0-9.]+)/i)
  const dstIpMatch = trimmed.match(/(?:to|DST=|server(?:\s+ip)?[:=]?)\s*([0-9.]+)/i)
  if (srcIpMatch && IPV4_REGEX.test(srcIpMatch[1])) event.sourceIp = srcIpMatch[1]
  if (dstIpMatch && IPV4_REGEX.test(dstIpMatch[1])) event.destinationIp = dstIpMatch[1]
  IPV4_REGEX.lastIndex = 0

  if (!event.sourceIp && !event.destinationIp) {
    const ips = trimmed.match(IPV4_REGEX)
    IPV4_REGEX.lastIndex = 0
    if (ips && ips.length > 0) {
      event.sourceIp = ips[0]
      if (ips.length > 1) event.destinationIp = ips[1]
    }
  }

  // Ports
  const dptMatch = trimmed.match(/(?:DPT=|dpt[:=]|port\s+)(\d+)/i)
  const sptMatch = trimmed.match(/(?:SPT=|spt[:=])\s*(\d+)/i)
  if (dptMatch) event.port = parseInt(dptMatch[1], 10)
  else if (sptMatch) event.port = parseInt(sptMatch[1], 10)

  // Username
  const userMatch = trimmed.match(/(?:for invalid user|for user|user|for)\s+([a-zA-Z0-9._-]+)/i)
    || trimmed.match(/USER=([a-zA-Z0-9._-]+)/i)
    || trimmed.match(/by\s+([a-zA-Z0-9._-]+)/i)
    || trimmed.match(/session opened for user\s+([a-zA-Z0-9._-]+)/i)
  if (userMatch && !['invalid', 'a', 'the', 'from', 'port', 'pts'].includes(userMatch[1].toLowerCase())) {
    event.username = userMatch[1]
  }

  // Process
  const procMatch = trimmed.match(/(?:sshd|sudo|cron|kernel|systemd-logind|audit|nginx|apache2|named)\[\d+\]/i)
    || trimmed.match(/comm="?([^"\s]+)"?/i)
    || trimmed.match(/exe="?([^"\s]+)"?/i)
    || trimmed.match(/COMMAND=([^\s;]+)/i)
    || trimmed.match(/process exec:\s*pid=\d+\s*comm="?([^"\s]+)"?/i)
  if (procMatch) event.process = procMatch[1] || procMatch[0].split('[')[0]

  // Event Type / Action / Severity
  const lower = trimmed.toLowerCase()

  if (lower.includes('failed password') || lower.includes('authentication failure') || lower.includes('login failed')) {
    event.eventType = 'authentication_failure'
    event.action = 'failed'
    event.severity = 'HIGH'
  } else if (lower.includes('accepted password') || lower.includes('session opened') || lower.includes('successful login')) {
    event.eventType = 'authentication_success'
    event.action = 'accepted'
    event.severity = lower.includes('root') ? 'MEDIUM' : 'LOW'
  } else if (lower.includes('sudo:') || lower.includes('command=') || lower.includes('session opened for user root')) {
    event.eventType = 'privilege_escalation'
    event.action = 'exec'
    event.severity = (lower.includes('/etc/shadow') || lower.includes('nc ')) ? 'CRITICAL' : 'HIGH'
  } else if (lower.includes('process exec') || lower.includes('apparmor="allowed"') || lower.includes('comm=') || lower.includes('exe=')) {
    event.eventType = 'process_execution'
    event.action = 'exec'
    event.severity = (lower.includes('/tmp') || lower.includes('nc ') || lower.includes('wget') || lower.includes('curl') || lower.includes('beacon')) ? 'HIGH' : 'MEDIUM'
  } else if (lower.includes('outbound_new') || lower.includes('outbound_established') || lower.includes('data_transfer') || /\bconnect(?:ion|ed)?\b/i.test(trimmed)) {
    event.eventType = 'network_connection'
    event.action = lower.includes('data_transfer') ? 'transfer' : 'connect'
    event.severity = (lower.includes('4444') || lower.includes('data_transfer') || (event.port && [4444, 1337, 6667, 31337].includes(event.port))) ? 'CRITICAL' : 'MEDIUM'
  } else if (lower.includes('inbound_rejected') || lower.includes('drop') || lower.includes('block') || lower.includes('denied')) {
    event.eventType = 'firewall_block'
    event.action = 'blocked'
    event.severity = 'MEDIUM'
  } else if (lower.includes('error') || lower.includes('alert') || lower.includes('warning')) {
    event.eventType = 'security_alert'
    event.severity = lower.includes('error') ? 'HIGH' : 'MEDIUM'
  }

  return event
}

export function parseLogFile(filename, text) {
  return text.split(/\r?\n/)
    .filter(l => l.trim())
    .map(line => parseLogLine(line, filename))
    .filter(Boolean)
}

// ── JSON PARSER ───────────────────────────────────────────────

export function parseJsonFile(filename, text) {
  let parsed
  try { parsed = JSON.parse(text) } catch { throw new Error('Invalid JSON evidence.') }

  let items = []
  if (Array.isArray(parsed)) {
    items = parsed
  } else if (typeof parsed === 'object' && parsed !== null) {
    const arrayKey = Object.keys(parsed).find(k => Array.isArray(parsed[k]))
    items = arrayKey ? parsed[arrayKey] : [parsed]
  } else {
    throw new Error('Invalid JSON evidence.')
  }

  return items.map(item => {
    if (typeof item !== 'object' || item === null) {
      return {
        eventId: null, timestamp: null, source: filename, eventType: 'json_record',
        username: null, sourceIp: null, destinationIp: null, port: null,
        action: null, process: null, message: String(item), severity: 'INFO',
        evidenceFile: filename, raw: String(item),
      }
    }
    const eventId = item.alert_id || item.alertId || item.event_id || item.eventId || item.id || null
    const timestamp = item.timestamp || item.time || item['@timestamp'] || item.date || item.datetime || null
    const eventType = item.rule || item.eventType || item.event_type || item.type || item.category || 'security_alert'
    const username = item.user || item.username || item.user_name || item.actor || null
    const sourceIp = item.source_ip || item.sourceIp || item.src_ip || item.src || null
    const destinationIp = item.destination_ip || item.destinationIp || item.dst_ip || item.dst || null
    const port = item.destination_port || item.dst_port || item.port || null
    const action = item.action || item.status || item.outcome || null
    const process = item.process || item.process_name || item.exe || item.command || null
    const message = item.description || item.message || item.details || item.msg || item.rule || 'JSON security event'
    const rawSev = (item.severity || item.level || item.priority || 'MEDIUM').toUpperCase()
    const severity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(rawSev) ? rawSev : 'MEDIUM'

    return {
      eventId, timestamp, source: filename,
      eventType: String(eventType).toLowerCase(),
      username: username ? String(username) : null,
      sourceIp: sourceIp ? String(sourceIp) : null,
      destinationIp: destinationIp ? String(destinationIp) : null,
      port: port ? (isNaN(port) ? port : parseInt(port, 10)) : null,
      action: action ? String(action).toLowerCase() : null,
      process: process ? String(process) : null,
      message: String(message), severity,
      evidenceFile: filename,
      raw: JSON.stringify(item),
    }
  })
}

// ── CSV PARSER ────────────────────────────────────────────────

function tokenizeCsvLine(line) {
  const result = []
  let cur = '', inQuotes = false
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') { cur += '"'; i++ } else inQuotes = !inQuotes
    } else if (ch === ',' && !inQuotes) { result.push(cur.trim()); cur = '' }
    else cur += ch
  }
  result.push(cur.trim())
  return result
}

export function parseCsvFile(filename, text) {
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean)
  if (lines.length < 2) throw new Error('CSV file contains insufficient data (header and rows required).')

  const rawHeaders = tokenizeCsvLine(lines[0])
  const headerMap = {}
  rawHeaders.forEach((h, idx) => { headerMap[h.toLowerCase().replace(/[^a-z0-9_]/g, '')] = idx })

  const findCol = (regex) => {
    const found = Object.keys(headerMap).find(k => regex.test(k))
    return found !== undefined ? headerMap[found] : null
  }

  const timeCol = findCol(/^(timestamp|time|date|datetime|event_time|createdat)$/)
  const srcIpCol = findCol(/^(srcip|sourceip|src|source_ip|clientip)$/)
  const dstIpCol = findCol(/^(dstip|destinationip|dst|dest_ip|serverip)$/)
  const userCol = findCol(/^(user|username|username|actor|account)$/)
  const typeCol = findCol(/^(event|event_type|eventtype|type|category|signature|rule)$/)
  const actCol = findCol(/^(action|status|result|outcome|disposition)$/)
  const procCol = findCol(/^(process|process_name|cmd|command|exe|app|application)$/)
  const portCol = findCol(/^(port|dst_port|destination_port|src_port|dpt|spt)$/)
  const msgCol = findCol(/^(message|description|details|msg|info|reason|summary)$/)
  const sevCol = findCol(/^(severity|level|priority)$/)

  const events = []
  for (let i = 1; i < lines.length; i++) {
    const row = tokenizeCsvLine(lines[i])
    if (row.length === 0 || (row.length === 1 && !row[0])) continue
    const g = (col) => (col !== null && row[col] !== undefined && row[col] !== '') ? row[col] : null

    const timestamp = g(timeCol)
    const sourceIp = g(srcIpCol)
    const destinationIp = g(dstIpCol)
    const username = g(userCol)
    const action = g(actCol)
    const process = g(procCol)
    const rawPort = g(portCol)
    const port = rawPort ? (isNaN(rawPort) ? rawPort : parseInt(rawPort, 10)) : null
    const message = g(msgCol) || lines[i]
    const rawSev = g(sevCol)
    const severity = rawSev ? rawSev.toUpperCase() : 'INFO'
    let eventType = g(typeCol)
    if (!eventType) {
      if (sourceIp && destinationIp) eventType = 'network_connection'
      else if (process) eventType = 'process_execution'
      else if (username) eventType = 'authentication_event'
      else eventType = 'csv_record'
    }

    events.push({
      eventId: null, timestamp,
      source: filename, eventType: eventType.toLowerCase(),
      username, sourceIp, destinationIp, port,
      action: action ? action.toLowerCase() : null,
      process, message,
      severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(severity) ? severity : 'INFO',
      evidenceFile: filename, raw: lines[i],
    })
  }
  return events
}

// ── DISPATCH ─────────────────────────────────────────────────

export function parseFileContent(filename, text) {
  const ext = (filename.split('.').pop() || '').toLowerCase()
  if (ext === 'json') return parseJsonFile(filename, text)
  if (ext === 'csv') return parseCsvFile(filename, text)
  return parseLogFile(filename, text)
}

// ── EVENT NORMALIZATION ───────────────────────────────────────

export function normalizeEvents(parsedFiles) {
  const validFiles = parsedFiles.filter(f => f.status === 'ok' && Array.isArray(f.events) && f.events.length > 0)
  const failedFiles = parsedFiles.filter(f => f.status === 'error').map(f => ({ name: f.name, reason: f.error }))

  const counters = { AUTH: 1, NET: 1, PROC: 1, ALERT: 1, LOG: 1, CSV: 1 }
  const allEvents = []

  validFiles.forEach(file => {
    file.events.forEach(ev => {
      let id = ev.eventId
      if (!id || typeof id !== 'string' || !/^[A-Z]+-\d+$/.test(id)) {
        let prefix = 'LOG'
        const type = (ev.eventType || '').toLowerCase()
        if (type.includes('auth') || type.includes('login') || type.includes('password')) prefix = 'AUTH'
        else if (type.includes('net') || type.includes('connection') || type.includes('outbound') || type.includes('firewall')) prefix = 'NET'
        else if (type.includes('proc') || type.includes('exec') || type.includes('sudo') || type.includes('escalation')) prefix = 'PROC'
        else if (file.type === 'json' || type.includes('alert') || type.includes('rule')) prefix = 'ALERT'
        else if (file.type === 'csv') prefix = 'CSV'
        id = `${prefix}-${String(counters[prefix]++).padStart(3, '0')}`
      }
      allEvents.push({ ...ev, eventId: id, source: ev.source || file.name, evidenceFile: ev.evidenceFile || file.name, raw: ev.raw || ev.message || '' })
    })
  })

  // Sort chronologically
  allEvents.sort((a, b) => {
    if (!a.timestamp && !b.timestamp) return 0
    if (!a.timestamp) return 1
    if (!b.timestamp) return -1
    const da = new Date(a.timestamp).getTime()
    const db = new Date(b.timestamp).getTime()
    if (!isNaN(da) && !isNaN(db)) return da - db
    return String(a.timestamp).localeCompare(String(b.timestamp))
  })

  const summary = {
    filesProcessed: validFiles.length,
    failedFiles,
    totalEvents: allEvents.length,
    authEvents: allEvents.filter(e => e.eventId.startsWith('AUTH-') || (e.eventType || '').includes('auth')).length,
    networkEvents: allEvents.filter(e => e.eventId.startsWith('NET-') || (e.eventType || '').includes('network')).length,
    endpointEvents: allEvents.filter(e => e.eventId.startsWith('PROC-') || (e.eventType || '').includes('proc')).length,
    alertEvents: allEvents.filter(e => e.eventId.startsWith('ALERT-') || (e.eventType || '').includes('alert')).length,
    otherEvents: 0,
  }
  summary.otherEvents = Math.max(0, summary.totalEvents - (summary.authEvents + summary.networkEvents + summary.endpointEvents + summary.alertEvents))

  return { events: allEvents, summary, validFiles, failedFiles }
}
