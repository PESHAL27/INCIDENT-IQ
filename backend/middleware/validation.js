/**
 * IncidentIQ — Validation Middleware
 */

const SUPPORTED_EXTENSIONS = ['log', 'txt', 'json', 'csv']
const MAX_FILE_SIZE = 5 * 1024 * 1024 // 5 MB

// Validate investigation ID format (INC-NNNN) — prevents path traversal
export function validateInvestigationId(req, res, next) {
  const { id } = req.params
  if (!id) return next()
  if (!/^INC-\d{4,6}$/.test(id)) {
    return res.status(404).json({ error: 'Investigation not found.' })
  }
  next()
}

// Validate uploaded file
export function validateUploadedFile(fileBuffer, filename, mimeType) {
  const ext = (filename.split('.').pop() || '').toLowerCase()

  if (!SUPPORTED_EXTENSIONS.includes(ext)) {
    return { valid: false, error: `Unsupported file type ".${ext}". Upload .log, .txt, .json or .csv.` }
  }

  if (!fileBuffer || fileBuffer.length === 0) {
    return { valid: false, error: 'File is empty and cannot be analyzed.' }
  }

  if (fileBuffer.length > MAX_FILE_SIZE) {
    const mb = (fileBuffer.length / (1024 * 1024)).toFixed(1)
    return { valid: false, error: `File size ${mb} MB exceeds the 5 MB limit.` }
  }

  const text = fileBuffer.toString('utf8')

  if (!text.trim()) {
    return { valid: false, error: 'File is empty and cannot be analyzed.' }
  }

  // JSON early parse check
  if (ext === 'json') {
    try {
      JSON.parse(text)
    } catch {
      return { valid: false, error: 'Invalid JSON format. Please check the file.' }
    }
  }

  // CSV minimum rows check
  if (ext === 'csv') {
    const lines = text.split(/\r?\n/).filter(l => l.trim())
    if (lines.length < 2) {
      return { valid: false, error: 'CSV file must contain a header row and at least one data row.' }
    }
  }

  return { valid: true, error: null, text }
}

// Sanitize filename — strip path components
export function sanitizeFilename(name) {
  return (name || 'evidence.log').replace(/[\\/:*?"<>|]/g, '_').split(/[\\/]/).pop()
}
