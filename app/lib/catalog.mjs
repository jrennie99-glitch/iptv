// Builds the channel catalog from the repo's own streams/*.m3u files, enriched
// with logos, categories and country names from the iptv-org public API
// (cached on disk; the app still works offline with plain names).

import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'

const API = 'https://iptv-org.github.io/api'
const META_FILES = ['channels', 'logos', 'countries', 'categories']
const META_TTL_MS = 24 * 3600 * 1000

async function loadMeta(cacheDir, log) {
  fs.mkdirSync(cacheDir, { recursive: true })
  const out = {}
  await Promise.all(META_FILES.map(async name => {
    const file = path.join(cacheDir, `${name}.json`)
    let fresh = false
    try { fresh = Date.now() - fs.statSync(file).mtimeMs < META_TTL_MS } catch { /* no cache */ }
    if (!fresh) {
      try {
        const res = await fetch(`${API}/${name}.json`, { signal: AbortSignal.timeout(20_000) })
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const text = await res.text()
        JSON.parse(text) // validate before caching
        fs.writeFileSync(file, text)
      } catch (err) {
        log.warn(`[catalog] could not refresh ${name}.json (${err.message}); using cache if present`)
      }
    }
    try { out[name] = JSON.parse(fs.readFileSync(file, 'utf8')) } catch { out[name] = [] }
  }))
  return out
}

function parsePlaylist(text, fileCountry) {
  const entries = []
  let cur = null
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || line === '#EXTM3U') continue
    if (line.startsWith('#EXTINF')) {
      const comma = line.indexOf(',', line.lastIndexOf('"') + 1)
      const tvgId = (line.match(/tvg-id="([^"]*)"/) || [])[1] || ''
      const title = line.slice(comma + 1).trim()
      cur = { tvgId, title, referrer: null, userAgent: null, country: fileCountry }
    } else if (line.startsWith('#EXTVLCOPT:http-referrer=')) {
      if (cur) cur.referrer = line.split('=').slice(1).join('=')
    } else if (line.startsWith('#EXTVLCOPT:http-user-agent=')) {
      if (cur) cur.userAgent = line.split('=').slice(1).join('=')
    } else if (!line.startsWith('#') && cur) {
      cur.url = line
      entries.push(cur)
      cur = null
    }
  }
  return entries
}

// "CNN International (1080p) [Geo-blocked] [Not 24/7]" → parts
function splitTitle(title) {
  const tags = [...title.matchAll(/\[([^\]]+)\]/g)].map(m => m[1])
  let rest = title.replace(/\[[^\]]+\]/g, '').trim()
  const q = rest.match(/\((\d{3,4}[pi])\)\s*$/)
  const quality = q ? q[1] : null
  if (q) rest = rest.slice(0, q.index).trim()
  return { name: rest, quality, geo: tags.includes('Geo-blocked'), part: tags.includes('Not 24/7') }
}

const qualityRank = q => (q ? parseInt(q, 10) : 0)

export async function buildCatalog({ streamsDir, cacheDir, log = console }) {
  const meta = await loadMeta(cacheDir, log)
  const chMeta = new Map(meta.channels.map(c => [c.id, c]))
  const logos = new Map()
  for (const l of meta.logos) {
    if (l.feed || !l.url?.startsWith('https://')) continue
    if (!logos.has(l.channel)) logos.set(l.channel, l.url)
  }
  const countryNames = new Map(meta.countries.map(c => [c.code, { name: c.name, flag: c.flag }]))

  const streams = new Map() // sid → { url, referrer, userAgent }
  const channels = new Map() // key → channel
  const files = fs.readdirSync(streamsDir).filter(f => f.endsWith('.m3u'))

  for (const file of files) {
    const fileCountry = file.split(/[_.]/)[0].toUpperCase()
    const entries = parsePlaylist(fs.readFileSync(path.join(streamsDir, file), 'utf8'), fileCountry)
    for (const e of entries) {
      if (!/^https?:\/\//i.test(e.url) || /\.mpd(\?|$)/i.test(e.url)) continue // HLS players only
      const channelId = e.tvgId.split('@')[0]
      const m = chMeta.get(channelId)
      if (m?.is_nsfw) continue
      const t = splitTitle(e.title)
      const key = channelId || `${fileCountry}:${t.name.toLowerCase()}`
      const sid = crypto.createHash('sha256').update(e.url).digest('base64url').slice(0, 12)
      if (streams.has(sid)) continue
      streams.set(sid, { url: e.url, referrer: e.referrer, userAgent: e.userAgent })

      let ch = channels.get(key)
      if (!ch) {
        const country = (m?.country || fileCountry).toUpperCase()
        ch = {
          id: key,
          name: m?.name || t.name,
          logo: logos.get(channelId) || null,
          country,
          cats: m?.categories?.length ? m.categories : ['general'],
          network: m?.network || null,
          sources: []
        }
        channels.set(key, ch)
      }
      ch.sources.push({ sid, q: t.quality, geo: t.geo || undefined, part: t.part || undefined })
    }
  }

  // Best-first: always-on before part-time, ungeoblocked first, then resolution.
  for (const ch of channels.values()) {
    ch.sources.sort((a, b) => (!!a.part - !!b.part) || (!!a.geo - !!b.geo) || qualityRank(b.q) - qualityRank(a.q))
  }

  const list = [...channels.values()].sort((a, b) => a.name.localeCompare(b.name))
  const usedCountries = new Set(list.map(c => c.country))
  const usedCats = new Set(list.flatMap(c => c.cats))
  const countries = [...usedCountries]
    .map(code => ({ code, name: countryNames.get(code)?.name || code, flag: countryNames.get(code)?.flag || '' }))
    .sort((a, b) => a.name.localeCompare(b.name))
  const categories = meta.categories.filter(c => usedCats.has(c.id)).map(c => ({ id: c.id, name: c.name }))
  if (usedCats.has('general') && !categories.some(c => c.id === 'general')) categories.push({ id: 'general', name: 'General' })

  log.info(`[catalog] ${list.length} channels, ${streams.size} streams from ${files.length} playlists`)
  return { channels: list, countries, categories, streams, builtAt: new Date().toISOString() }
}
