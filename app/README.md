# Signal — live TV player

A web app for watching the channels in this repo's `streams/*.m3u` playlists: about 12,000 channels from 180+ countries. You can search, filter by category and country, save favorites, go back to recently watched channels, and flip through channels with the keyboard. If a channel has several feeds and one fails, the app moves on to the next feed by itself.

## Run it

```bash
node app/server.mjs        # or: npm run tv
```

Open http://localhost:4173. It needs Node 20 or newer and no `npm install`.

| Env var | Default | Purpose |
|---|---|---|
| `PORT` / `HOST` | `4173` / `127.0.0.1` | Where the server listens. Set `HOST=0.0.0.0` to watch from other devices on your network. |
| `TRUST_PROXY=1` | off | Turn this on only behind a reverse proxy you control. The client IP is then read from the rightmost `X-Forwarded-For` entry. |
| `PROXY_SECRET` | random per boot | HMAC key used to sign relayed media URLs. Set it to keep URLs valid across restarts. |
| `NODE_ENV=production` | — | Adds the HSTS header. Use it only when the app is served over TLS. |

**Keys:** `↑`/`↓` change channel · `/` search · `F` fullscreen · `M` mute · `S` favorite · `N` next feed · `Space` pause

## How it works

- **Catalog** (`lib/catalog.mjs`): reads the local playlists and groups the feeds by channel id. It adds logos, categories and country names from the iptv-org public API, cached in `data/cache` for 24 hours. If that API can't be reached, the app still works with plain channel names. NSFW channels and DASH-only feeds are left out.
- **HLS relay** (`lib/proxy.mjs`): browsers can't play most of these streams directly. Many lack CORS headers, some are served over plain http, and some need a Referer or User-Agent header. The relay fetches each stream and rewrites its manifests so every variant, segment and key URL goes back through the server.
- **Player** (`public/`): uses hls.js 1.5.20, pinned with SRI, or native HLS on Safari. The channel list is virtualized and all rendering goes through DOM APIs (`textContent`), not `innerHTML`.

## Security

- **Threat Shield** (`lib/shield.mjs`): decoy paths ban an IP on the first request, including URL-encoded and deeper-path variants. A WAF matches attack signatures after URL-decoding (SQLi, XSS, traversal, command injection, SSTI, Log4Shell, NoSQLi, LFI/RFI, CRLF). Scanner and site-ripper user agents are banned. There are separate rate limits for app requests and media requests, plus mass-crawl detection. Bans start at 15 minutes, double on each repeat up to 7 days, expire on their own, and are saved to `data/defense/blocklist.json`. Every event is appended to `data/defense/blocklog.jsonl` with a request fingerprint.
- **The relay is not an open proxy.** It starts only from catalog stream ids. Every child URL must carry an HMAC signature tied to its stream. The server checks every connection, including each redirect, inside the DNS lookup and refuses private, loopback, link-local, CGNAT and metadata addresses. That check also blocks DNS rebinding. Relayed responses are sent with `CSP: sandbox`, `nosniff` and a safe content type, so they can never run as a page.
- **Response headers:** strict CSP (`connect-src 'self'`, no inline script), `X-Frame-Options: DENY`, `no-referrer`, a locked-down Permissions-Policy, and COOP. Only `GET` and `HEAD` are allowed. Errors are generic. Request headers and request time are capped.
- **Local operator:** requests from loopback (the person running the server on the same machine) are never policed. This doesn't apply when `TRUST_PROXY` is on, because then the client IP comes from a header, and headers can be forged.

### Security gate (N/A items)

- **No accounts, logins, sessions, payments, uploads, webhooks, database or AI.** That covers auth, MFA, CSRF, JWT, IDOR, tenancy, password reset, payment, upload, webhook and LLM checks. Favorites, recent channels and volume stay in the viewer's own `localStorage` and hold no tokens or PII.
- **Not yet wired:** sending shield events to CYBERCOM or another alert service. Each event is printed to stderr as a `[shield] …` line, ready to pipe there.

## Notes

Some streams are geo-blocked, part-time or offline at any given moment. The app labels geo-blocked feeds and tries the next feed when one fails. The playlists are public links collected by the iptv-org community.
