// Threat Shield — honeypot + attack-signature WAF + rate limits + escalating bans.
// Port of the bbhunter defense.py reference. Judged cheapest-first:
//   blocklist → honeypot paths → scanner/ripper UA → signatures → rate → crawl.
// Bans escalate (15 min, doubling, capped at 7 days), auto-expire, persist across
// restarts, and every block is appended to an append-only JSONL log.

import fs from 'node:fs'
import path from 'node:path'
import net from 'node:net'

const HONEYPOT_PATHS = new Set([
  '/.env', '/.env.local', '/.env.prod', '/.git/config', '/.git/HEAD', '/wp-login.php',
  '/wp-admin', '/xmlrpc.php', '/wp-config.php', '/phpmyadmin', '/pma', '/adminer.php',
  '/administrator', '/admin.php', '/admin/config.php', '/config.php', '/configuration.php',
  '/.aws/credentials', '/.ssh/id_rsa', '/id_rsa', '/shell.php', '/cmd.php', '/c99.php',
  '/r57.php', '/webshell.php', '/backdoor.php', '/solr/admin', '/actuator/env',
  '/actuator/heapdump', '/.DS_Store', '/backup.zip', '/db.sql', '/dump.sql', '/.htpasswd',
  '/server-status', '/manager/html', '/backup.sql', '/phpinfo.php', '/info.php', '/test.php',
  '/credentials.json', '/aws.yml', '/api/v1/keys', '/telescope/requests',
  '/debug/default/view', '/.vscode/sftp.json'
])
const HONEYPOT_PREFIXES = [
  '/cgi-bin/', '/_ignition/', '/actuator/', '/wp-content/plugins/', '/vendor/phpunit/',
  '/libs/granite/', '/libs/cq/', '/crx/de/', '/system/console/', '/phpmyadmin/', '/pma/'
]
const HONEYPOT_SEGMENTS = ['.git', '.svn', '.hg', '.aws', '.ssh', 'wp-admin', 'wp-includes']
const SECRET_FILE_RE = new RegExp([
  String.raw`(^|/)[\w.\-]*\.env([.\-_~][\w.\-]*)?$`,
  String.raw`(^|/)\.env/`,
  String.raw`(^|/)\.(git|svn|hg|bzr)(/|$)`,
  String.raw`(^|/)\.(aws|ssh|docker|kube|npmrc|netrc)(/|$)`,
  String.raw`(^|/)wp-config\.\w+$`,
  String.raw`(^|/)[\w.\-]+\.(php|ini|yml|yaml|xml|json|conf)\.(bak|old|save|orig|copy|dist|swp|tmp|txt|\d+)$`,
  String.raw`(^|/)[\w.\-]+\.(php|ini|yml|yaml|xml|json|conf)~$`,
  String.raw`\.(sql|sqlite3?|mdb|db)(\.(gz|zip|bak|old|save|tar))?$`,
  String.raw`(^|/)terraform\.tfstate(\.backup)?$`,
  String.raw`(^|/)(heapdump|threaddump|thread-dump)$`
].join('|'), 'i')

export const HONEYPOT_FIELD = 'hp_website_url'

// Most specific first: the first match decides the score, so Log4Shell must win over generic ${…} SSTI.
const SIGNATURES = [
  ['log4shell', /\$\{jndi:(ldap|rmi|dns|ldaps|iiop)/i, 6],
  ['sqli', /(\bunion\b.{0,40}\bselect\b|\bor\b\s+1\s*=\s*1|'\s*or\s*'|;\s*drop\s+table|\bsleep\s*\(|\bbenchmark\s*\(|information_schema|\bwaitfor\s+delay)/i, 5],
  ['xss', /(<script\b|onerror\s*=|onload\s*=|javascript:\s*|document\.cookie|<svg[^>]+on\w+=)/i, 4],
  ['path_traversal', /(\.\.\/|\.\.\\|\/etc\/passwd|\/proc\/self\/environ|c:\\windows\\win\.ini|boot\.ini)/i, 5],
  ['cmd_injection', /(;\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b|\|\s*(cat|ls|id|whoami)\b|`[^`]+`|\$\([^)]+\)|&&\s*(cat|ls|id|whoami))/i, 5],
  ['cmd_exec_param', /[?&](cmd|exec|command|shell|execute|cmdline|system)=[+\s]*(hostname|whoami|uname|ifconfig|ipconfig|netstat|systeminfo|printenv|pwd|id|ls|dir|cat|ps|env|wget|curl|nc|bash|powershell)\b/i, 5],
  ['ssti', /(\{\{.*?\}\}|\$\{.*?\}|<%=.*?%>|#\{.*?\})/i, 3],
  ['nosqli', /(\$ne\b|\$gt\b|\$where\b|\$regex\b|\{\s*"\$\w)/i, 4],
  ['lfi_rfi', /(php:\/\/(input|filter)|data:\/\/text|expect:\/\/|file:\/\/\/|=https?:\/\/[^ ]+\.(txt|php)\?)/i, 4],
  ['crlf', /(%0d%0a|\r\n)(set-cookie|location|content-length)/i, 3]
]
const SCANNER_UA = /(sqlmap|nikto|nessus|acunetix|nmap|masscan|zgrab|dirbuster|gobuster|feroxbuster|wpscan|hydra|arachni|w3af|openvas|whatweb|nuclei|httpx\/|xsser|commix|joomscan)/i
const RIPPER_UA = /(httrack|webcopier|website ?ripper|sitesucker|teleport ?pro|offline ?explorer|webzip|webreaper|cyotek|getleft|pavuk|web2disk|blackwidow|websucker|wpull)/i
const GOOD_BOT_UA = /(googlebot|bingbot|duckduckbot|applebot|yandexbot|facebookexternalhit|twitterbot|slackbot|discordbot)/i

const BAN_BASE = 900
const BAN_MAX = 7 * 86400
const SCORE_BAN = 6
const SCORE_DECAY = 600
const RATE_WINDOW = 10
const RATE_MAX = 80 // app/API requests per 10s
const MEDIA_RATE_MAX = 400 // proxied HLS manifests + segments per 10s (a few concurrent viewers per IP)
const CRAWL_WINDOW = 30
const CRAWL_MAX = 40

const now = () => Date.now() / 1000

function safeDecode(s) {
  try { return decodeURIComponent(s.replace(/\+/g, ' ')) } catch { return s }
}

export function isTrapPath(p) {
  const forms = [p]
  const dec = safeDecode(p)
  if (dec !== p) forms.push(dec)
  for (const f of forms) {
    const norm = f.replace(/\/+$/, '') || '/'
    if (HONEYPOT_PATHS.has(norm)) return norm
    if (HONEYPOT_PREFIXES.some(h => f.startsWith(h) || norm === h.slice(0, -1))) return norm
    if (HONEYPOT_SEGMENTS.some(s => norm === '/' + s || norm.includes('/' + s + '/') || norm.endsWith('/' + s))) return norm
    if (SECRET_FILE_RE.test(norm)) return norm
  }
  return null
}

export class Shield {
  constructor({ dataDir, trustProxy = false, policeLoopback = false, log = console }) {
    this.trustProxy = trustProxy
    this.policeLoopback = policeLoopback
    this.log = log
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 })
    this.blocklistPath = path.join(dataDir, 'blocklist.json')
    this.logPath = path.join(dataDir, 'blocklog.jsonl')
    this.ips = new Map()
    this.allowlist = new Set()
    this.totalBlocked = 0
    this.#load()
    // Forget idle, unbanned IPs so memory can't be grown without bound.
    this.gc = setInterval(() => this.#sweep(), 60_000)
    this.gc.unref()
  }

  #state(ip) {
    let st = this.ips.get(ip)
    if (!st) {
      st = { score: 0, scoreAt: 0, bans: 0, until: 0, reason: '', hits: [], media: [], paths: [], seen: now() }
      this.ips.set(ip, st)
    }
    st.seen = now()
    return st
  }

  #sweep() {
    const t = now()
    for (const [ip, st] of this.ips) {
      if (st.until <= t && t - st.seen > 900) this.ips.delete(ip)
    }
  }

  #load() {
    try {
      const data = JSON.parse(fs.readFileSync(this.blocklistPath, 'utf8'))
      for (const [ip, rec] of Object.entries(data.bans || {})) {
        const st = this.#state(ip)
        st.until = Number(rec.until) || 0
        st.bans = Number(rec.bans) || 1
        st.reason = String(rec.reason || '')
      }
      this.allowlist = new Set(data.allowlist || [])
      this.totalBlocked = Number(data.total_blocked) || 0
    } catch { /* first boot: no blocklist yet */ }
  }

  #persist() {
    const bans = {}
    const t = now()
    for (const [ip, st] of this.ips) if (st.until > t) bans[ip] = { until: st.until, bans: st.bans, reason: st.reason }
    const tmp = this.blocklistPath + '.tmp'
    fs.writeFileSync(tmp, JSON.stringify({ bans, allowlist: [...this.allowlist], total_blocked: this.totalBlocked }, null, 2), { mode: 0o600 })
    fs.renameSync(tmp, this.blocklistPath)
  }

  #record(ip, event, detail, reqPath = '', extra = {}) {
    const rec = { ts: new Date().toISOString(), ip, event, detail, path: reqPath.slice(0, 512), ...extra }
    fs.appendFileSync(this.logPath, JSON.stringify(rec) + '\n', { mode: 0o600 })
    // Monitoring hook: one structured line per security event (pipe to your alerting).
    this.log.warn(`[shield] ${event} ${ip} — ${detail}`)
  }

  // Real client IP. Behind a trusted reverse proxy, take the RIGHTMOST
  // X-Forwarded-For entry (the one our proxy appended) — the leftmost is
  // attacker-supplied and would let anyone forge 127.0.0.1 or frame another IP.
  clientIp(req) {
    const sock = req.socket.remoteAddress || '0.0.0.0'
    if (this.trustProxy) {
      const xff = String(req.headers['x-forwarded-for'] || '')
      const parts = xff.split(',').map(s => s.trim()).filter(Boolean)
      const last = parts[parts.length - 1]
      if (last && net.isIP(last)) return last
    }
    return sock.replace(/^::ffff:/, '')
  }

  // The local operator (real loopback socket, no proxy in front) is not policed.
  operatorBypass(req) {
    if (this.trustProxy || this.policeLoopback) return false
    const sock = (req.socket.remoteAddress || '').replace(/^::ffff:/, '')
    return sock === '127.0.0.1' || sock === '::1'
  }

  isBanned(ip) {
    const st = this.ips.get(ip)
    return !!(st && st.until > now())
  }

  ban(ip, reason, reqPath = '', extra = {}) {
    if (this.allowlist.has(ip)) return
    const st = this.#state(ip)
    st.bans += 1
    const span = Math.min(BAN_BASE * 2 ** (st.bans - 1), BAN_MAX)
    st.until = now() + span
    st.reason = reason
    this.totalBlocked += 1
    this.#record(ip, 'ban', `${reason} (ban #${st.bans}, ${span}s)`, reqPath, extra)
    this.#persist()
  }

  #score(ip, pts, reason, reqPath) {
    const st = this.#state(ip)
    if (now() - st.scoreAt > SCORE_DECAY) st.score = 0
    st.score += pts
    st.scoreAt = now()
    this.#record(ip, 'signature', `+${pts} ${reason} (score=${st.score})`, reqPath)
    if (st.score >= SCORE_BAN) this.ban(ip, `threat score ${st.score} — ${reason}`, reqPath)
  }

  #windowCount(arr, windowSec, limitLen) {
    const t = now()
    arr.push(t)
    while (arr.length && arr[0] < t - windowSec) arr.shift()
    if (arr.length > limitLen) arr.splice(0, arr.length - limitLen)
    return arr.length
  }

  // Returns { blocked, status, reason }. `fingerprint` is captured on bans for
  // attacker intelligence (UA, method, headers subset) — never request bodies with secrets.
  inspect(req, { pathname, search, isMedia }) {
    const ip = this.clientIp(req)
    if (this.allowlist.has(ip)) return { blocked: false }
    if (this.isBanned(ip)) return { blocked: true, status: 403, reason: 'banned' }

    const ua = String(req.headers['user-agent'] || '')
    const fp = {
      method: req.method,
      ua: ua.slice(0, 256),
      accept: String(req.headers.accept || '').slice(0, 128),
      lang: String(req.headers['accept-language'] || '').slice(0, 64),
      httpVersion: req.httpVersion,
      tls: req.socket.encrypted ? (req.socket.getProtocol?.() || 'tls') : 'plain',
      cipher: req.socket.encrypted ? (req.socket.getCipher?.()?.name || '') : ''
    }

    const trap = isTrapPath(pathname)
    if (trap) {
      this.ban(ip, `honeypot: ${trap}`, pathname + search, { fp })
      return { blocked: true, status: 404, reason: 'not found' }
    }
    if (ua && SCANNER_UA.test(ua)) {
      this.ban(ip, `offensive scanner UA (${ua.slice(0, 40)})`, pathname, { fp })
      return { blocked: true, status: 403, reason: 'forbidden' }
    }
    if (ua && RIPPER_UA.test(ua)) {
      this.ban(ip, `site-cloner UA (${ua.slice(0, 40)})`, pathname, { fp })
      return { blocked: true, status: 403, reason: 'forbidden' }
    }

    // Decode twice so %252e%252e and %2e%2e both surface. Proxied media URLs are
    // opaque base64 + HMAC, so only the pathname is matched for them.
    const target = isMedia ? pathname : `${pathname}?${search.replace(/^\?/, '')}`
    const decoded = safeDecode(safeDecode(target))
    for (const [name, rx, pts] of SIGNATURES) {
      if (rx.test(decoded) || rx.test(target)) {
        this.#score(ip, pts, `${name} signature`, pathname + search)
        return { blocked: true, status: 400, reason: 'bad request' }
      }
    }

    const st = this.#state(ip)
    if (isMedia) {
      if (this.#windowCount(st.media, RATE_WINDOW, MEDIA_RATE_MAX + 5) > MEDIA_RATE_MAX) {
        this.ban(ip, 'media request flood (rate limit)', pathname, { fp })
        return { blocked: true, status: 429, reason: 'slow down' }
      }
      return { blocked: false }
    }
    if (this.#windowCount(st.hits, RATE_WINDOW, RATE_MAX + 5) > RATE_MAX) {
      this.ban(ip, 'request flood (rate limit)', pathname, { fp })
      return { blocked: true, status: 429, reason: 'slow down' }
    }
    if (!(ua && GOOD_BOT_UA.test(ua))) {
      const t = now()
      st.paths.push([t, pathname])
      while (st.paths.length && st.paths[0][0] < t - CRAWL_WINDOW) st.paths.shift()
      if (new Set(st.paths.map(p => p[1])).size > CRAWL_MAX) {
        this.ban(ip, 'mass crawl — site scrape', pathname, { fp })
        return { blocked: true, status: 403, reason: 'forbidden' }
      }
    }
    return { blocked: false }
  }

  snapshot() {
    const t = now()
    const active = []
    for (const [ip, st] of this.ips) if (st.until > t) active.push({ ip, reason: st.reason, bans: st.bans, expires_in: Math.round(st.until - t) })
    return { active_bans: active, total_blocked: this.totalBlocked }
  }
}
