/**
 * IncidentIQ — Request Logger Middleware
 */

export function requestLogger(req, res, next) {
  const start = Date.now()
  const { method, path: reqPath } = req
  res.on('finish', () => {
    const d = Date.now() - start
    const s = res.statusCode
    const lvl = s >= 500 ? 'ERROR' : s >= 400 ? 'WARN' : 'INFO'
    console.log(`[${lvl}] ${method} ${reqPath} -> ${s} (${d}ms)`)
  })
  next()
}
