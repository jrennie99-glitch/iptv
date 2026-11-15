// HLS relay. Solves the three things that stop browser playback of public IPTV
// streams: missing CORS headers, http-only origins, and required Referer/UA.
//
// SSRF posture — this is NOT an open proxy:
//  • Entry points are catalog stream ids (/live/:sid), never caller-supplied URLs.
//  • Every child URL (variant, segment, key, map) is one the server itself read
//    out of an upstream manifest, and is HMAC-signed together with its stream id.
//    Unsigned or tampered URLs are refused before any network activity.
//  • Every hop — including each redirect — is resolved and refused if it lands on a
//    loopback, private, link-local, CGNAT, multicast or cloud-metadata address. The
//    check runs inside the socket's DNS lookup, so DNS rebinding can't swap it.
//  • Hard limits: timeouts, size caps, redirect cap, per-IP concurrency cap.

import http from 'node:http'
import https from 'node:https'
import dns from 'node:dns'
import net from 'node:net'
import zlib from 'node:zlib'
import crypto from 'node:crypto'

const BLOCKED = new net.BlockList()
for (const [a, p] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
]) BLOCKED.addSubnet(a, p, 'ipv4')
for (const [a, p] of [['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8], ['64:ff9b::', 96], ['2001:db8::', 32]]) BLOCKED.addSubnet(a, p, 'ipv6')

export function isPublicAddress(addr) {
  const fam = net.isIP(addr)
  if (!fam) return false
  const mapped = addr.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i)
  if (mapped) return !BLOCKED.check(mapped[1], 'ipv4')
  return !BLOCKED.check(addr, fam === 4 ? 'ipv4' : 'ipv6')
}

class Refused extends Error {}

function guardedLookup(hostname, options, cb) {
  dns.lookup(hostname, { ...options, all: true }, (err, addrs) => {
    if (err) return cb(err)
    const ok = addrs.filter(a => isPublicAddress(a.address))
    if (!ok.length) return cb(new Refused(`refused non-public address for ${hostname}`))
    if (options.all) return cb(null, ok)
    cb(null, ok[0].address, ok[0].family)
  })
}

const agentOpts = { keepAlive: true, maxSockets: 64, lookup: guardedLookup }
const httpAgent = new http.Agent(agentOpts)
const httpsAgent = new https.Agent(agentOpts)

const DEFAULT_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36'
const MANIFEST_MAX = 2 * 1024 * 1024
const SEGMENT_MAX = 64 * 1024 * 1024
const HEADER_TIMEOUT = 12_000
const IDLE_TIMEOUT = 20_000
const MAX_REDIRECTS = 5
const PER_IP_CONCURRENCY = 24
const SAFE_TYPES = /^(video\/|audio\/|application\/(octet-stream|mp2t|mp4|vnd\.apple\.mpegurl|x-mpegurl|dash\+xml)|binary\/octet-stream|text\/plain)/i

function openUpstream(url, stream, range, redirects = 0) {
  return new Promise((resolve, reject) => {
    let u
    try { u = new URL(url) } catch { return reject(new Refused('bad url')) }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return reject(new Refused('bad scheme'))
    if (u.username || u.password) return reject(new Refused('credentials in url'))
    const host = u.hostname.replace(/^\[|\]$/g, '')
    if (net.isIP(host) && !isPublicAddress(host)) return reject(new Refused('non-public address'))

    const headers = { 'user-agent': stream.userAgent || DEFAULT_UA, accept: '*/*', 'accept-encoding': 'identity' }
    if (stream.referrer) {
      headers.referer = stream.referrer
      try { headers.origin = new URL(stream.referrer).origin } catch { /* ignore */ }
    }
    if (range) headers.range = range

    const lib = u.protocol === 'https:' ? https : http
    const req = lib.request(u, { method: 'GET', headers, agent: u.protocol === 'https:' ? httpsAgent : httpAgent, timeout: HEADER_TIMEOUT }, res => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume()
        if (redirects >= MAX_REDIRECTS) return reject(new Refused('too many redirects'))
        let next
        try { next = new URL(res.headers.location, u).href } catch { return reject(new Refused('bad redirect')) }
        return openUpstream(next, stream, range, redirects + 1).then(resolve, reject)
      }
      res.finalUrl = u.href
      req.setTimeout(IDLE_TIMEOUT)
      resolve(res)
    })
    req.on('timeout', () => req.destroy(new Error('upstream timeout')))
    req.on('error', reject)
    req.end()
  })
}

function readCapped(res, max) {
  return new Promise((resolve, reject) => {
    let body = res
    const enc = String(res.headers['content-encoding'] || '').toLowerCase()
    if (enc === 'gzip') body = res.pipe(zlib.createGunzip())
    else if (enc === 'deflate') body = res.pipe(zlib.createInflate())
    else if (enc === 'br') body = res.pipe(zlib.createBrotliDecompress())
    const chunks = []
    let size = 0
    body.on('data', c => {
      size += c.length
      if (size > max) { res.destroy(); reject(new Error('manifest too large')) } else chunks.push(c)
    })
    body.on('end', () => resolve(Buffer.concat(chunks)))
    body.on('error', reject)
  })
}

export class HlsProxy {
  constructor({ streams, secret, log = console }) {
    this.streams = streams
    this.key = secret ? Buffer.from(secret) : crypto.randomBytes(32)
    this.log = log
    this.active = new Map()
  }

  sign(sid, url) {
    return crypto.createHmac('sha256', this.key).update(`${sid}\n${url}`).digest('base64url').slice(0, 27)
  }

  wrap(sid, url) {
    return `/p/${sid}/${this.sign(sid, url)}/${Buffer.from(url).toString('base64url')}`
  }

  verify(sid, sig, b64) {
    if (!/^[\w-]{1,4096}$/.test(b64) || !/^[\w-]{27}$/.test(sig)) return null
    const url = Buffer.from(b64, 'base64url').toString()
    const expected = Buffer.from(this.sign(sid, url))
    const got = Buffer.from(sig)
    return expected.length === got.length && crypto.timingSafeEqual(expected, got) ? url : null
  }

  rewrite(sid, text, base) {
    const abs = ref => {
      try {
        const u = new URL(ref.trim(), base)
        return u.protocol === 'http:' || u.protocol === 'https:' ? this.wrap(sid, u.href) : null
      } catch { return null }
    }
    return text.split(/\r?\n/).map(line => {
      if (!line.trim()) return line
      if (line.startsWith('#')) return line.replace(/URI="([^"]+)"/g, (m, ref) => { const w = abs(ref); return w ? `URI="${w}"` : m })
      return abs(line) || ''
    }).join('\n')
  }

  // Routes: /live/:sid  and  /p/:sid/:sig/:b64
  async handle(req, res, pathname, ip) {
    const live = pathname.match(/^\/live\/([\w-]{12})(?:\.m3u8)?$/)
    const child = pathname.match(/^\/p\/([\w-]{12})\/([\w-]+)\/([\w-]+)$/)
    let sid, url
    if (live) {
      sid = live[1]
      url = this.streams.get(sid)?.url
    } else if (child) {
      sid = child[1]
      if (this.streams.has(sid)) url = this.verify(sid, child[2], child[3])
    }
    const stream = this.streams.get(sid)
    if (!stream || !url) return this.#fail(res, 404, 'unknown stream')

    const n = this.active.get(ip) || 0
    if (n >= PER_IP_CONCURRENCY) return this.#fail(res, 429, 'too many concurrent streams')
    this.active.set(ip, n + 1)
    let released = false
    const release = () => {
      if (released) return
      released = true
      const v = (this.active.get(ip) || 1) - 1
      if (v <= 0) this.active.delete(ip); else this.active.set(ip, v)
    }
    res.on('close', release)

    try {
      const range = /^bytes=\d*-\d*$/.test(req.headers.range || '') ? req.headers.range : null
      const up = await openUpstream(url, stream, range)
      if (up.statusCode !== 200 && up.statusCode !== 206) {
        up.resume()
        return this.#fail(res, 502, `upstream ${up.statusCode}`)
      }
      const ctype = String(up.headers['content-type'] || '').toLowerCase()
      const looksManifest = /mpegurl/.test(ctype) || /\.m3u8?(\?|$)/i.test(new URL(up.finalUrl).pathname) || live

      res.setHeader('Content-Security-Policy', "sandbox; default-src 'none'")
      res.setHeader('X-Content-Type-Options', 'nosniff')
      res.setHeader('Cross-Origin-Resource-Policy', 'same-origin')

      if (looksManifest && !/^video\/|^audio\//.test(ctype)) {
        const buf = await readCapped(up, MANIFEST_MAX)
        const text = buf.toString('utf8')
        if (!text.trimStart().startsWith('#EXTM3U')) return this.#fail(res, 415, 'not an HLS stream')
        const out = this.rewrite(sid, text, up.finalUrl)
        res.writeHead(200, { 'Content-Type': 'application/vnd.apple.mpegurl', 'Cache-Control': 'no-store' })
        return res.end(out)
      }

      const headers = {
        'Content-Type': SAFE_TYPES.test(ctype) && !/text\/plain/.test(ctype) ? ctype : 'application/octet-stream',
        'Cache-Control': 'private, max-age=30'
      }
      if (up.headers['content-length']) headers['Content-Length'] = up.headers['content-length']
      if (up.statusCode === 206 && up.headers['content-range']) headers['Content-Range'] = up.headers['content-range']
      res.writeHead(up.statusCode, headers)
      let sent = 0
      up.on('data', c => {
        sent += c.length
        if (sent > SEGMENT_MAX) { up.destroy(); res.destroy() }
      })
      up.on('error', () => res.destroy())
      res.on('close', () => up.destroy())
      up.pipe(res)
    } catch (err) {
      const refused = err instanceof Refused
      if (refused) this.log.warn(`[proxy] refused ${ip} sid=${sid}: ${err.message}`)
      this.#fail(res, refused ? 403 : 502, refused ? 'refused' : 'upstream unavailable')
    }
  }

  #fail(res, status, msg) {
    if (res.headersSent) return res.destroy()
    res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
    res.end(JSON.stringify({ error: msg }))
  }
}
