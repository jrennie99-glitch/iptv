'use strict'

// ── tiny helpers ────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id)
const el = (tag, cls, text) => {
  const n = document.createElement(tag)
  if (cls) n.className = cls
  if (text != null) n.textContent = text
  return n
}
const fold = s => s.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase()
const store = {
  get(k, d) { try { const v = localStorage.getItem('signal:' + k); return v ? JSON.parse(v) : d } catch { return d } },
  set(k, v) { try { localStorage.setItem('signal:' + k, JSON.stringify(v)) } catch { /* private mode */ } }
}

const TUNE_TIMEOUT_MS = 18000
const ROW = 60

// ── state ───────────────────────────────────────────────────────────────────
const S = {
  all: [], byId: new Map(), countries: new Map(), categories: new Map(),
  view: 'all', cat: '', country: store.get('country', ''), q: '',
  filtered: [],
  favs: new Set(store.get('favs', [])),
  recent: store.get('recent', []),
  current: null, sourceIdx: 0, hls: null, tuneTimer: null, attempt: 0
}

const video = $('video')
const list = $('list')
const spacer = $('spacer')

// ── catalog ─────────────────────────────────────────────────────────────────
async function loadCatalog() {
  try {
    const res = await fetch('/api/catalog')
    if (!res.ok) throw new Error('HTTP ' + res.status)
    const data = await res.json()
    S.all = data.channels.map((c, i) => ({ ...c, n: i + 1, hay: fold(`${c.name} ${c.network || ''} ${c.id}`) }))
    S.all.forEach(c => S.byId.set(c.id, c))
    data.countries.forEach(c => S.countries.set(c.code, c))
    data.categories.forEach(c => S.categories.set(c.id, c.name))
    const n = S.all.length.toLocaleString()
    $('tagline').textContent = `${n} channels · ${data.countries.length} countries · live now`
    buildFilters()
    $('skeleton').remove()
    applyFilters()
    const fromHash = new URLSearchParams(location.hash.slice(1)).get('ch')
    const start = fromHash && S.byId.get(fromHash)
    if (start) tune(start)
  } catch (err) {
    $('skeleton').remove()
    showEmpty('The guide failed to load.', 'Check the server is running, then reload.', false)
    $('tagline').textContent = 'Off air'
  }
}

function buildFilters() {
  const sel = $('country')
  const counts = new Map()
  S.all.forEach(c => counts.set(c.country, (counts.get(c.country) || 0) + 1))
  for (const c of S.countries.values()) {
    const o = el('option', null, `${c.flag} ${c.name} (${counts.get(c.code) || 0})`)
    o.value = c.code
    sel.append(o)
  }
  if (!S.countries.has(S.country)) S.country = ''
  sel.value = S.country
  sel.addEventListener('change', () => { S.country = sel.value; store.set('country', S.country); applyFilters(true) })

  const catCounts = new Map()
  S.all.forEach(c => c.cats.forEach(k => catCounts.set(k, (catCounts.get(k) || 0) + 1)))
  const chips = $('chips')
  const mk = (id, label) => {
    const b = el('button', 'chip', label)
    b.dataset.cat = id
    b.setAttribute('aria-pressed', String(S.cat === id))
    b.addEventListener('click', () => {
      S.cat = S.cat === id && id ? '' : id
      chips.querySelectorAll('.chip').forEach(x => x.setAttribute('aria-pressed', String(x.dataset.cat === S.cat)))
      applyFilters(true)
    })
    chips.append(b)
  }
  mk('', 'All')
  ;[...S.categories.entries()].sort((a, b) => (catCounts.get(b[0]) || 0) - (catCounts.get(a[0]) || 0)).forEach(([id, name]) => mk(id, name))
}

function applyFilters(resetScroll) {
  const q = fold(S.q.trim())
  const terms = q ? q.split(/\s+/) : []
  let base = S.all
  if (S.view === 'fav') base = S.all.filter(c => S.favs.has(c.id))
  else if (S.view === 'recent') base = S.recent.map(id => S.byId.get(id)).filter(Boolean)
  S.filtered = base.filter(c =>
    (!S.cat || c.cats.includes(S.cat)) &&
    (!S.country || c.country === S.country) &&
    (!terms.length || terms.every(t => c.hay.includes(t) || fold(S.countries.get(c.country)?.name || '').includes(t)))
  )
  // Exact/prefix name matches float to the top when searching.
  if (q) S.filtered.sort((a, b) => (fold(b.name).startsWith(q) - fold(a.name).startsWith(q)))

  $('guideCount').textContent = `${S.filtered.length.toLocaleString()} ${S.filtered.length === 1 ? 'channel' : 'channels'}`
  spacer.style.height = S.filtered.length * ROW + 'px'
  if (resetScroll) list.scrollTop = 0
  if (!S.filtered.length) {
    const msg = S.view === 'fav' && !S.favs.size
      ? ['No favorites yet.', 'Tap the star while watching to keep a channel here.']
      : S.view === 'recent' && !S.recent.length
        ? ['Nothing watched yet.', 'Channels you tune into show up here.']
        : ['No channels on this frequency.', 'Try a different search or clear the filters.']
    showEmpty(...msg, S.view === 'all' || !!(S.q || S.cat || S.country))
  } else $('empty').hidden = true
  list.hidden = !S.filtered.length
  render()
}

function showEmpty(title, hint, canClear) {
  const e = $('empty')
  e.querySelector('.empty-title').textContent = title
  $('emptyHint').textContent = hint
  $('clearFilters').hidden = !canClear
  e.hidden = false
}

// ── virtualised guide ───────────────────────────────────────────────────────
const pool = new Map()
function render() {
  const top = list.scrollTop
  const h = list.clientHeight || 600
  const from = Math.max(0, Math.floor(top / ROW) - 6)
  const to = Math.min(S.filtered.length, Math.ceil((top + h) / ROW) + 6)
  const keep = new Set()
  for (let i = from; i < to; i++) {
    const c = S.filtered[i]
    const key = c.id
    keep.add(key)
    let row = pool.get(key)
    if (!row) { row = buildRow(c); pool.set(key, row); spacer.append(row) }
    row.style.transform = `translateY(${i * ROW}px)`
    row.classList.toggle('active', S.current?.id === c.id)
    row.setAttribute('aria-selected', String(S.current?.id === c.id))
    row.querySelector('.star')?.toggleAttribute('hidden', !S.favs.has(c.id))
  }
  for (const [key, row] of pool) if (!keep.has(key)) { row.remove(); pool.delete(key) }
}

function logoNode(c, cls = 'logo') {
  const box = el('div', cls)
  const mono = (c.name.match(/[\p{L}\p{N}]/u) || ['•'])[0].toUpperCase()
  if (c.logo) {
    const img = new Image()
    img.loading = 'lazy'
    img.decoding = 'async'
    img.referrerPolicy = 'no-referrer'
    img.alt = ''
    img.addEventListener('error', () => { img.remove(); box.textContent = mono }, { once: true })
    img.src = c.logo
    box.append(img)
  } else box.textContent = mono
  return box
}

function buildRow(c) {
  const row = el('div', 'row')
  row.setAttribute('role', 'option')
  row.dataset.id = c.id
  row.append(el('span', 'row-num', String(c.n).padStart(4, '0')))
  row.append(logoNode(c))
  const text = el('div', 'row-text')
  text.append(el('div', 'row-name', c.name))
  const country = S.countries.get(c.country)
  const cat = S.categories.get(c.cats[0]) || ''
  text.append(el('div', 'row-meta', `${country?.flag || ''} ${country?.name || c.country}${cat ? ' · ' + cat : ''}`))
  row.append(text)
  const side = el('div', 'row-side')
  const star = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
  star.setAttribute('viewBox', '0 0 24 24')
  star.classList.add('star')
  const p = document.createElementNS('http://www.w3.org/2000/svg', 'path')
  p.setAttribute('d', 'm12 3 2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1-4.4-4.3 6.1-.9z')
  star.append(p)
  star.toggleAttribute('hidden', !S.favs.has(c.id))
  side.append(star)
  const best = c.sources[0]?.q
  if (best && parseInt(best) >= 720) side.append(el('span', 'badge hd', parseInt(best) >= 1080 ? 'FHD' : 'HD'))
  if (c.sources.every(s => s.geo)) side.append(el('span', 'badge', 'GEO'))
  row.append(side)
  return row
}

list.addEventListener('scroll', () => requestAnimationFrame(render), { passive: true })
window.addEventListener('resize', () => requestAnimationFrame(render))
list.addEventListener('click', e => {
  const row = e.target.closest('.row')
  if (row) tune(S.byId.get(row.dataset.id))
})

// ── playback ────────────────────────────────────────────────────────────────
function overlay(mode, kicker, title, sub, retry = false) {
  const o = $('overlay')
  o.className = 'overlay ' + mode
  $('overlayKicker').textContent = kicker
  $('overlayTitle').textContent = title
  $('overlaySub').textContent = sub || ''
  $('overlayRetry').hidden = !retry
}

function teardown() {
  clearTimeout(S.tuneTimer)
  if (S.hls) { S.hls.destroy(); S.hls = null }
  video.removeAttribute('src')
  video.load()
  $('monitor').classList.remove('playing')
  $('onair').hidden = true
}

function tune(c, sourceIdx = 0) {
  if (!c) return
  const fresh = S.current?.id !== c.id
  S.current = c
  S.sourceIdx = sourceIdx
  S.attempt += 1
  const attempt = S.attempt
  teardown()
  updateNowOn()
  if (fresh) {
    S.recent = [c.id, ...S.recent.filter(id => id !== c.id)].slice(0, 24)
    store.set('recent', S.recent)
    renderRecent()
    history.replaceState(null, '', '#ch=' + encodeURIComponent(c.id))
  }
  render()
  scrollIntoGuide(c)

  const src = c.sources[sourceIdx]
  const feedNote = c.sources.length > 1 ? `Feed ${sourceIdx + 1} of ${c.sources.length}` : 'Single feed'
  overlay('tuning', 'Tuning', c.name, feedNote)
  const url = '/live/' + src.sid

  const failover = reason => {
    if (attempt !== S.attempt) return
    if (S.sourceIdx + 1 < c.sources.length) {
      tune(c, S.sourceIdx + 1)
    } else {
      teardown()
      overlay('offair', 'Off air', `${c.name} isn't broadcasting right now`,
        src.geo ? 'This feed may be blocked in your region.' : reason || 'Every feed for this channel failed. Try again later or pick another channel.', true)
    }
  }
  S.tuneTimer = setTimeout(() => failover('Timed out waiting for the signal.'), TUNE_TIMEOUT_MS)

  const onPlaying = () => {
    if (attempt !== S.attempt) return
    clearTimeout(S.tuneTimer)
    overlay('hidden', '', '', '')
    $('monitor').classList.add('playing')
    const oa = $('onair'); oa.hidden = false; oa.classList.remove('fade')
    setTimeout(() => oa.classList.add('fade'), 3500)
  }
  video.addEventListener('playing', onPlaying, { once: true })

  const start = () => video.play().catch(() => {
    // Autoplay with sound blocked: start muted so the picture still comes up.
    video.muted = true
    video.play().catch(() => {})
  })

  if (window.Hls && Hls.isSupported()) {
    const hls = new Hls({
      maxBufferLength: 30,
      backBufferLength: 30,
      manifestLoadingTimeOut: 12000,
      manifestLoadingMaxRetry: 1,
      levelLoadingTimeOut: 12000,
      fragLoadingTimeOut: 20000,
      enableWorker: true
    })
    S.hls = hls
    let recovered = false
    hls.on(Hls.Events.MANIFEST_PARSED, start)
    hls.on(Hls.Events.ERROR, (_, d) => {
      if (!d.fatal || attempt !== S.attempt) return
      if (d.type === Hls.ErrorTypes.MEDIA_ERROR && !recovered) { recovered = true; hls.recoverMediaError(); return }
      failover(d.type === Hls.ErrorTypes.NETWORK_ERROR ? 'The stream is unreachable.' : 'The stream format is not supported.')
    })
    hls.loadSource(url)
    hls.attachMedia(video)
  } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
    video.src = url
    video.addEventListener('error', () => failover('The stream is unreachable.'), { once: true })
    start()
  } else {
    overlay('offair', 'Unsupported', 'This browser can’t play live HLS', 'Try a recent Chrome, Firefox, Edge or Safari.')
  }
}

function updateNowOn() {
  const c = S.current
  const country = S.countries.get(c.country)
  const cats = c.cats.map(k => S.categories.get(k)).filter(Boolean).join(' / ')
  const src = c.sources[S.sourceIdx]
  $('nowMeta').textContent = [country && `${country.flag} ${country.name}`, cats, src?.q, c.network].filter(Boolean).join(' · ')
  const name = $('nowName'); name.textContent = c.name; name.title = c.name
  const slot = $('nowLogo'); slot.replaceWith(Object.assign(logoNode(c, 'nowon-logo'), { id: 'nowLogo' }))
  $('sourceLabel').textContent = `${S.sourceIdx + 1}/${c.sources.length}`
  $('btnSource').disabled = c.sources.length < 2
  for (const id of ['btnFav', 'btnPrev', 'btnNext', 'btnFull']) $(id).disabled = false
  $('btnPip').disabled = !document.pictureInPictureEnabled
  $('btnFav').setAttribute('aria-pressed', String(S.favs.has(c.id)))
  document.title = `${c.name} — Signal`
}

function scrollIntoGuide(c) {
  const i = S.filtered.indexOf(c)
  if (i < 0) return
  const y = i * ROW
  if (y < list.scrollTop || y + ROW > list.scrollTop + list.clientHeight) list.scrollTop = y - list.clientHeight / 2 + ROW / 2
}

function surf(dir) {
  if (!S.filtered.length) return
  let i = S.current ? S.filtered.indexOf(S.current) : -1
  i = i < 0 ? 0 : (i + dir + S.filtered.length) % S.filtered.length
  tune(S.filtered[i])
}

function toggleFav() {
  const c = S.current
  if (!c) return
  S.favs.has(c.id) ? S.favs.delete(c.id) : S.favs.add(c.id)
  store.set('favs', [...S.favs])
  $('btnFav').setAttribute('aria-pressed', String(S.favs.has(c.id)))
  $('favCount').textContent = S.favs.size
  if (S.view === 'fav') applyFilters(); else render()
}

function renderRecent() {
  const wrap = $('recentWrap'), strip = $('recent')
  const items = S.recent.map(id => S.byId.get(id)).filter(c => c && c !== S.current).slice(0, 12)
  wrap.hidden = !items.length
  strip.replaceChildren(...items.map(c => {
    const b = el('button', 'recent-card')
    b.append(logoNode(c), el('span', null, c.name))
    b.addEventListener('click', () => tune(c))
    return b
  }))
}

// ── controls & keyboard ─────────────────────────────────────────────────────
$('btnPrev').addEventListener('click', () => surf(-1))
$('btnNext').addEventListener('click', () => surf(1))
$('btnFav').addEventListener('click', toggleFav)
$('btnSource').addEventListener('click', () => S.current && tune(S.current, (S.sourceIdx + 1) % S.current.sources.length))
$('btnFull').addEventListener('click', () => {
  const m = $('monitor')
  if (document.fullscreenElement) document.exitFullscreen()
  else (m.requestFullscreen ? m.requestFullscreen() : video.webkitEnterFullscreen?.())
})
$('btnPip').addEventListener('click', async () => {
  try { document.pictureInPictureElement ? await document.exitPictureInPicture() : await video.requestPictureInPicture() } catch { /* not ready */ }
})
$('overlayRetry').addEventListener('click', () => S.current && tune(S.current, 0))
$('clearFilters').addEventListener('click', () => {
  S.q = ''; $('search').value = ''
  S.cat = ''; document.querySelectorAll('.chip').forEach(x => x.setAttribute('aria-pressed', String(x.dataset.cat === '')))
  S.country = ''; $('country').value = ''; store.set('country', '')
  setView('all')
})

let qTimer
$('search').addEventListener('input', e => {
  clearTimeout(qTimer)
  qTimer = setTimeout(() => { S.q = e.target.value.slice(0, 80); if (S.q && S.view !== 'all') setView('all'); else applyFilters(true) }, 120)
})
$('search').addEventListener('keydown', e => {
  if (e.key === 'Enter' && S.filtered[0]) { tune(S.filtered[0]); e.target.blur() }
  if (e.key === 'Escape') e.target.blur()
})

function setView(v) {
  S.view = v
  document.querySelectorAll('.tab').forEach(t => t.setAttribute('aria-selected', String(t.dataset.view === v)))
  applyFilters(true)
}
document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => setView(t.dataset.view)))

video.volume = store.get('volume', 1)
video.addEventListener('volumechange', () => store.set('volume', video.volume))

document.addEventListener('keydown', e => {
  if (e.target.matches('input, select, textarea') || e.metaKey || e.ctrlKey || e.altKey) return
  const k = e.key
  if (k === '/') { e.preventDefault(); $('search').focus() }
  else if (k === 'ArrowDown' || k === 'PageDown') { e.preventDefault(); surf(1) }
  else if (k === 'ArrowUp' || k === 'PageUp') { e.preventDefault(); surf(-1) }
  else if (k === 'f' || k === 'F') $('btnFull').click()
  else if (k === 'm' || k === 'M') video.muted = !video.muted
  else if ((k === 's' || k === 'S') && S.current) toggleFav()
  else if ((k === 'n' || k === 'N') && S.current) $('btnSource').click()
  else if (k === ' ' && S.current && e.target === document.body) { e.preventDefault(); video.paused ? video.play() : video.pause() }
})

$('favCount').textContent = S.favs.size
renderRecent()
loadCatalog()
