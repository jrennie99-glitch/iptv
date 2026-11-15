#!/usr/bin/env node
// Signal — a live TV player for the iptv-org playlists in ../streams.
// Zero runtime dependencies: Node's http server, a catalog built from the repo's
// .m3u files, an HLS relay, and the Threat Shield in front of every request.

import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'
import zlib from 'node:zlib'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { Shield } from './lib/shield.mjs'
import { buildCatalog } from './lib/catalog.mjs'
import { HlsProxy } from './lib/proxy.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const PUBLIC = path.join(here, 'public')
const DATA = path.join(here, 'data')
const PORT = Number(process.env.PORT) || 4173
const HOST = process.env.HOST || '127.0.0.1'
const PROD = process.env.NODE_ENV === 'production'

const log = {
  info: (...a) => console.log(new Date().toISOString(), ...a),
  warn: (...a) => console.warn(new Date().toISOString(), ...a),
  error: (...a) => console.error(new Date().toISOString(), ...a)
}

const shield = new Shield({
  dataDir: path.join(DATA, 'defense'),
  trustProxy: process.env.TRUST_PROXY === '1',
  policeLoopback: process.env.SHIELD_POLICE_LOOPBACK === '1',
  log
})

let catalog = await buildCatalog({ streamsDir: path.join(here, '..', 'streams'), cacheDir: path.join(DATA, 'cache'), log })
const proxy = new HlsProxy({ streams: catalog.streams, secret: process.env.PROXY_SECRET, log })

function packCatalog(c) {
  const body = Buffer.from(JSON.stringify({ channels: c.channels, countries: c.countries, categories: c.categories, builtAt: c.builtAt }))
  return { body, gz: zlib.gzipSync(body, { level: 9 }), etag: '"' + crypto.createHash('sha1').update(body).digest('base64url') + '"' }
}
let packed = packCatalog(catalog)

const CSP = [
  "default-src 'self'",
  "script-src 'self' https://cdnjs.cloudflare.com",
  "style-src 'self' https://fonts.googleapis.com",
  "font-src https://fonts.gstatic.com",
  "img-src 'self' https: data:",
  "media-src 'self' blob:",
  "connect-src 'self'",
  "worker-src 'self' blob:",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'"
].join('; ')

function securityHeaders(res) {
  res.setHeader('Content-Security-Policy', CSP)
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('Referrer-Policy', 'no-referrer')
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()')
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin')
  if (PROD) res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains')
}

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.png': 'image/png', '.webmanifest': 'application/manifest+json' }

function serveStatic(req, res, pathname) {
  const rel = pathname === '/' ? 'index.html' : pathname.slice(1)
  if (!/^[\w.\-/]+$/.test(rel) || rel.includes('..') || rel.endsWith('.map')) return notFound(res)
  const file = path.resolve(PUBLIC, rel)
  if (!file.startsWith(PUBLIC + path.sep)) return notFound(res)
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) return notFound(res)
    const type = MIME[path.extname(file)] || 'application/octet-stream'
    const etag = `"${st.size.toString(36)}-${Math.floor(st.mtimeMs).toString(36)}"`
    if (req.headers['if-none-match'] === etag) { res.writeHead(304, { ETag: etag }); return res.end() }
    res.writeHead(200, { 'Content-Type': type, 'Content-Length': st.size, ETag: etag, 'Cache-Control': 'no-cache' })
    if (req.method === 'HEAD') return res.end()
    fs.createReadStream(file).pipe(res)
  })
}

function json(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
  res.end(JSON.stringify(obj))
}
const notFound = res => json(res, 404, { error: 'not found' })

const server = http.createServer((req, res) => {
  securityHeaders(res)
  let url
  try { url = new URL(req.url, 'http://local') } catch { return json(res, 400, { error: 'bad request' }) }
  const { pathname, search } = url
  const isMedia = pathname.startsWith('/p/') || pathname.startsWith('/live/')
  const ip = shield.clientIp(req)

  if (!shield.operatorBypass(req)) {
    const verdict = shield.inspect(req, { pathname, search, isMedia })
    if (verdict.blocked) return json(res, verdict.status, { error: verdict.reason })
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.setHeader('Allow', 'GET, HEAD')
    return json(res, 405, { error: 'method not allowed' })
  }

  try {
    if (isMedia) return proxy.handle(req, res, pathname, ip)
    if (pathname === '/api/catalog') {
      if (req.headers['if-none-match'] === packed.etag) { res.writeHead(304); return res.end() }
      const gzip = /\bgzip\b/.test(req.headers['accept-encoding'] || '')
      const body = gzip ? packed.gz : packed.body
      res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': body.length, ETag: packed.etag, 'Cache-Control': 'no-cache', ...(gzip && { 'Content-Encoding': 'gzip', Vary: 'Accept-Encoding' }) })
      return res.end(req.method === 'HEAD' ? undefined : body)
    }
    if (pathname === '/healthz') return json(res, 200, { ok: true, channels: catalog.channels.length })
    if (pathname === '/robots.txt') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('User-agent: *\nDisallow: /p/\nDisallow: /live/\n') }
    return serveStatic(req, res, pathname)
  } catch (err) {
    log.error('[server] unhandled', err)
    if (!res.headersSent) json(res, 500, { error: 'internal error' })
  }
})

server.headersTimeout = 15_000
server.requestTimeout = 30_000
server.keepAliveTimeout = 10_000
server.maxHeadersCount = 64

// Rebuild the catalog daily so playlist updates (git pull) and fresh logos land without a restart.
setInterval(async () => {
  try {
    catalog = await buildCatalog({ streamsDir: path.join(here, '..', 'streams'), cacheDir: path.join(DATA, 'cache'), log })
    proxy.streams = catalog.streams
    packed = packCatalog(catalog)
  } catch (err) { log.error('[catalog] rebuild failed', err.message) }
}, 24 * 3600 * 1000).unref()

server.listen(PORT, HOST, () => log.info(`Signal is on air → http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`))

for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { server.close(); process.exit(0) })
