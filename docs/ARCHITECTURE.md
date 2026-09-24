# tor-scrape: architecture (draft v0.1)

> **Status:** proposal. It waits on answers to the open questions in §13.
> Defaults marked ⚙ are what gets built if nothing changes.

tor-scrape is a research-only crawler. It reaches publicly accessible v3 `.onion`
sites through Tor, pulls out every link and onion address those sites mention, and
stores the resulting service-level link graph for analysis.

---

## 1. Goals and non-goals

**Goals**

- Discover v3 onion services that are linked or mentioned somewhere reachable
  **without authentication**, and map which services link to which.
- Record lightweight metadata (liveness, title, language, content hashes) and export
  it to SQLite/PostgreSQL, Neo4j, JSONL, CSV and GraphML.
- Put a light load on the Tor network and on the sites being crawled.

**Non-goals.** The code enforces these; they are more than documentation.

| Out of scope | How it is enforced |
|---|---|
| Logging in, submitting forms, sending POST requests, solving CAPTCHAs, bypassing paywalls | The fetcher only issues `GET`/`HEAD`. It has no form-submission code path. When the gate detector sees a CAPTCHA, queue or login wall, it stops crawling that service. |
| Onion client authorization | SOCKS reply `0xF4`/`0xF5` marks the service `restricted`, and it is never retried. |
| Harvesting HSDir descriptors, brute-forcing addresses, attacking Tor or the services themselves | No such code exists. v3 blinded keys make enumeration infeasible by design anyway. |
| Deanonymizing operators or users | No server fingerprinting (`Server`/`ETag` banners, clearnet-leak probes, timing correlation) and no profiling of people. |
| Downloading images, video, archives or other binaries | A content-type allowlist is checked before the body is read. The renderer blocks media requests. |
| Rotating circuits to get around rate limits or bans | `NEWNYM` fires only on connectivity failure, never on 403/429. |

## 2. What "hard to find" can honestly mean

Nobody can list v3 onion addresses from the Tor network. That is a deliberate
property of the protocol. The only legitimate way to find a service is for someone
to have published or linked it. So "deep discovery" here comes from five things:

1. **Extraction from every channel.** Sources include `href`, `src`, `srcset`,
   `action`/`formaction` (recorded, never submitted), meta refresh, `data-*`
   attributes, JavaScript string literals, HTML comments, visible plain text,
   defanged forms (`xxxx[.]onion`, `xxxx dot onion`), `Onion-Location` headers and
   meta tags, `Link` headers, `sitemap.xml` (including indexes and gzip), and
   `Sitemap:` lines in `robots.txt`.
2. **Checksum validation.** A v3 address is `base32(PUBKEY ‖ CHECKSUM ‖ VERSION)`,
   where `CHECKSUM = SHA3-256(".onion checksum" ‖ PUBKEY ‖ 0x03)[:2]`. Checking it
   removes the false positives that regex-only crawlers collect, such as random
   56-character strings and mistyped addresses.
3. **Hub prioritization.** Link lists, directories, wikis, mirror pages and paste
   pages go to the front of the queue. New services outrank deeper pages of
   services already known.
4. **Novelty scoring.** A service counts as `in_known_index = false` when it is
   missing from the known-index snapshots you import (for example, a list exported
   from a public directory). This is a local comparison: discovered addresses are
   never sent to third-party search engines.
5. **Recrawling (phase 2).** Returning to hubs on a schedule catches new mirrors
   and rotated addresses.

The limitation needs to be stated plainly: a service that nobody links publicly
will not be found. That is Tor working as designed.

## 3. Data flow

```
 seeds.txt / imported lists
          │
          ▼
 ┌───────────────────┐        discovered URLs + onion mentions
 │ Normalizer        │◄──────────────────────────────────────────────┐
 │ + v3 validator    │                                               │
 └────────┬──────────┘                                               │
          ▼                                                          │
 ┌───────────────────┐  dedupe: Bloom pre-check → DB unique index    │
 │ Frontier          │  (SQLite table = source of truth → resumable) │
 └────────┬──────────┘                                               │
          ▼                                                          │
 ┌───────────────────┐  per-host "ready heap" (Mercator-style),      │
 │ Scheduler         │  priority score, per-service budgets          │
 └────────┬──────────┘                                               │
          ▼   N asyncio workers                                      │
 ┌──────────────────────────────────────────────────────────────┐    │
 │ 1. Safety policy: scope (onion-only), denylist               │    │
 │ 2. robots.txt (RFC 9309, cached; also yields Sitemap: URLs)  │    │
 │ 3. Fetcher: aiohttp → socks5h://tor:9050, GET only,          │    │
 │    content-type allowlist, byte caps, redirect checks        │    │
 │    └─ errors → classifier → retry / backoff / service status │    │
 │ 4. Gate detector: CAPTCHA / queue / login → mark + stop      │    │
 │ 5. Renderer (optional fallback): Playwright via Tor          │    │
 │ 6. Extractors: html · js · text · sitemap · headers          │────┘
 │ 7. Content policy: keyword quarantine (stop + flag)          │
 └────────┬─────────────────────────────────────────────────────┘
          ▼
 ┌───────────────────┐      async batched sink      ┌────────────┐
 │ Repository        │ ───────────────────────────► │ Neo4j      │ (optional)
 │ SQLite | Postgres │                              └────────────┘
 └────────┬──────────┘
          ▼
   Exporters: JSONL · CSV · GraphML (streamed)
```

**Tor topology (Docker)**

```
┌─ docker network "tor_internal" (internal: true, nothing published to host) ─┐
│                                                                             │
│  crawler (uid 10001) ── socks5h://tor:9050  user=<isolation token> ──► tor ─┼─► Tor network
│                     └─ control tor:9051 (stem: bootstrap, NEWNYM) ───┘      │
└─────────────────────────────────────────────────────────────────────────────┘
```

The crawler container reaches the internet only through the Tor container.

## 4. Components

| Module | Responsibility | Key decisions |
|---|---|---|
| `config.py` | Loads settings from YAML, overridable by `TORSCRAPE_*` environment variables | `pydantic-settings`, validated on startup; a config hash is recorded with each run |
| `logging.py` | Structured JSON logs | `structlog`. Logs never contain bodies or cookies, query strings are redacted and titles are truncated. |
| `onion.py` | v3 validation (length, alphabet, checksum, version) plus extraction regexes, including defanged forms | Pure functions, fully unit-tested |
| `urlnorm.py` | Canonical URLs, service key, scope checks | Lowercases scheme and host, drops default ports and fragments, resolves dot segments, sorts the query, strips tracking parameters. `www.<addr>.onion` maps to the same service key. |
| `tor/session.py` | The one factory for HTTP sessions | `aiohttp` with `aiohttp-socks` and `rdns=True`, so DNS resolves remotely and nothing leaks. **Fails closed:** it refuses to build a session without the proxy and never falls back to a direct connection. Each service gets its own SOCKS username, which isolates streams the way Tor Browser's first-party isolation does. |
| `tor/controller.py` | Bootstrap and health checks, rate-limited `NEWNYM` | `stem`, run through `asyncio.to_thread`. `NEWNYM` fires only after K consecutive circuit failures across different services, and at most once every ≥10 s (Tor's own limit). |
| `tor/errors.py` | Maps SOCKS5 replies (including Tor `ExtendedErrors` `0xF0`–`0xF7`) and HTTP statuses to an `ErrorClass` | See §6 |
| `fetch/fetcher.py` | Streams the GET and enforces caps | Checks the content-type allowlist before reading the body. Caps decompressed bytes (gzip-bomb safe). Allows up to 5 redirects, each re-checked against scope. Uses an ephemeral per-host cookie jar that is never persisted. |
| `fetch/retry.py` | Backoff and adaptive per-host delay | Exponential backoff with full jitter. Honors `Retry-After` (capped). AIMD: the host delay doubles on 429/503 and shrinks 10% on success, down to a floor. |
| `fetch/robots.py` | robots.txt cache and sitemap discovery | Follows RFC 9309: a 4xx means allow, a 5xx or network error means disallow for now and retry later. Disallowed paths are **recorded but never enqueued**. |
| `fetch/renderer.py` | JavaScript-rendering fallback | Playwright Chromium through Tor. Used only when heuristics flag a page as JS-built (few links, heavy script, `<noscript>` hints). Blocks image, media, font, stylesheet and websocket requests. WebRTC is disabled, the profile is ephemeral, downloads are off and the sandbox stays on. |
| `extract/html.py` | Pulls links out of HTML | `selectolax` (Lexbor, HTML5-compliant, roughly 10–30× faster than BeautifulSoup) |
| `extract/scripts.py` | URLs and onion addresses in inline and external JS string literals | Regex over string tokens; JS is never executed here |
| `extract/text.py` | Plain-text and defanged onion mentions in visible text and comments | Every candidate is checksum-validated |
| `extract/sitemap.py` | Sitemaps and sitemap indexes | `defusedxml` (XXE and billion-laughs safe), capped gzip, caps on depth and entry count |
| `extract/gate.py` | Detects CAPTCHA, DDoS queue and login walls | When it fires, the service is marked `gated` and crawling it stops. It is never bypassed. |
| `frontier/scheduler.py` | Priority plus per-host politeness | A per-host deque and a `(ready_at, host)` heap. Workers only take ready hosts. Enforces budgets for depth, pages per service and total. |
| `frontier/dedupe.py` | Visited check | An optional `rbloom` pre-check runs first. A Bloom "maybe" falls through to the DB unique index, so a false positive never drops a URL. |
| `frontier/memory.py`, `frontier/redis.py` | Queue backends | ⚙ In-process `asyncio` backed by the SQLite frontier table. Redis is for running several workers (phase 3). |
| `storage/{sqlite,postgres}.py` | Repository protocol implementations | ⚙ `aiosqlite` in WAL mode. `asyncpg` for scale. The relational DB is the **source of truth**. |
| `storage/neo4j.py` | Graph sink | Optional. Batched `MERGE` over the official async driver. Can be rebuilt from the relational DB at any time. |
| `safety/policy.py` | Denylist, keyword quarantine, content policy | See §8 |
| `export/*` | JSONL, CSV, GraphML | GraphML is written with a streaming XML writer, so it does not need `networkx` or the whole graph in memory |
| `crawler.py` | Orchestration | Worker pool, graceful shutdown (SIGINT/SIGTERM), in-flight work returned to `pending` on restart, run statistics |
| `cli.py` | `typer` CLI | Commands: `crawl`, `resume`, `status`, `export`, `check-tor`, `validate`, `import-known` |

## 5. Data model

**Relational (SQLite ⚙ / PostgreSQL)**

```sql
services (
  onion            TEXT PRIMARY KEY,      -- 56-char v3 label, no ".onion"
  status           TEXT NOT NULL,         -- unknown|online|offline|gated|restricted|
                                          -- quarantined|denylisted|invalid
  title            TEXT,                  -- truncated (200 chars)
  lang             TEXT,                  -- from <html lang>
  first_seen       TIMESTAMP NOT NULL,
  last_seen        TIMESTAMP,             -- last successful fetch
  last_checked     TIMESTAMP,
  pages_crawled    INTEGER DEFAULT 0,
  in_known_index   BOOLEAN DEFAULT FALSE,
  discovered_via   TEXT,                  -- channel of first discovery
  discovered_from  TEXT                   -- onion that first mentioned it
);

pages (
  id            INTEGER PRIMARY KEY,
  url           TEXT UNIQUE NOT NULL,     -- canonical
  onion         TEXT NOT NULL REFERENCES services(onion),
  depth         INTEGER NOT NULL,
  http_status   INTEGER,
  content_type  TEXT,
  bytes         INTEGER,
  sha256        TEXT,                     -- exact-duplicate detection
  simhash       INTEGER,                  -- near-duplicate / clone clustering
  title         TEXT,
  rendered      BOOLEAN DEFAULT FALSE,
  error_class   TEXT,
  fetched_at    TIMESTAMP
);

edges (
  src_page_id  INTEGER NOT NULL REFERENCES pages(id),
  dst_url      TEXT NOT NULL,
  dst_onion    TEXT,                      -- NULL for clearnet targets
  channel      TEXT NOT NULL,             -- href|src|action|meta_refresh|data_attr|js|
                                          -- text|comment|sitemap|robots|onion_location|header
  first_seen   TIMESTAMP NOT NULL,
  last_seen    TIMESTAMP NOT NULL,
  PRIMARY KEY (src_page_id, dst_url, channel)
);

frontier (
  url           TEXT PRIMARY KEY,
  onion         TEXT NOT NULL,
  depth         INTEGER NOT NULL,
  priority      REAL NOT NULL,            -- lower = sooner
  state         TEXT NOT NULL,            -- pending|in_flight|done|failed|skipped
  attempts      INTEGER DEFAULT 0,
  not_before    TIMESTAMP,                -- backoff / Retry-After
  discovered_from TEXT
);

runs (id, started_at, finished_at, config_hash, stats_json);
known_index (onion TEXT PRIMARY KEY, source TEXT, imported_at TIMESTAMP);
```

The pages table stores no raw HTML and no body text by default (see §8).

**Graph (Neo4j, optional)**

```
(:Service {onion, status, title, first_seen, last_seen, in_known_index})
(:Service)-[:LINKS_TO {count, channels, first_seen, last_seen}]->(:Service)
-- optional page level:
(:Page {url, http_status, fetched_at})-[:ON]->(:Service)
(:Page)-[:LINKS_TO {channel}]->(:Page)
```

The graph that matters for analysis is service to service. The page-level graph
gets large quickly and is off by default.

## 6. Error classification and retry policy

| Condition | Class | Action |
|---|---|---|
| SOCKS `0xF0` descriptor not found, `0xF1` descriptor invalid | `OFFLINE` | Retry after 1 h, 6 h and 24 h, then mark the service `offline` |
| SOCKS `0xF2` intro failed, `0xF3` rendezvous failed, `0xF7` intro timeout | `TRANSIENT` | Back off 30 s·2ⁿ with jitter, at most 3 attempts |
| SOCKS `0xF4`/`0xF5` client authorization missing or wrong | `RESTRICTED` | Never retry: authentication is out of scope |
| SOCKS `0xF6` invalid address | `INVALID` | Drop |
| SOCKS `0x01`, `0x04`, `0x06` (general failure, host unreachable, TTL expired) | `TRANSIENT` | Back off, at most 3 attempts |
| Tor SOCKS or control port unreachable | `FATAL` | Pause all workers and log loudly. **Never connect directly.** |
| Connect or read timeout | `TRANSIENT` | Back off, at most 3 attempts |
| HTTP 429, or 503 with `Retry-After` | `THROTTLED` | Honor `Retry-After` (capped at 1 h) and double the host delay |
| HTTP 401 / 403 | `DENIED` | Record it. No retry, no bypass. |
| HTTP 404 / 410 | `GONE` | Final |
| HTTP 5xx | `TRANSIENT` | At most 2 attempts |
| CAPTCHA, queue or login page detected | `GATED` | Mark the service `gated` and stop crawling it |
| Disallowed content type, or body over the cap | `SKIPPED` | Abort the stream and record it |

`ExtendedErrors` has to be set on the `SocksPort` in `torrc`, or Tor will not send
the `0xF*` codes.

## 7. Politeness defaults ⚙

```yaml
crawl:
  global_concurrency: 8          # onion circuits are expensive for relays; keep modest
  per_host_concurrency: 1
  per_host_delay_s: 10           # ±30% jitter; AIMD-adjusted
  max_depth: 3                   # within one service
  max_pages_per_service: 50      # breadth over depth: discovery is the goal
  max_total_pages: 100000
  recrawl_after_h: 168           # phase 2
http:
  connect_timeout_s: 45          # rendezvous setup is slow
  total_timeout_s: 90
  max_body_bytes: 2097152        # 2 MiB decompressed
  max_redirects: 5
  user_agent: "tor-scrape-research/0.1 (+contact: <you>)"
  allow_clearnet: false
robots:
  respect: true
  cache_ttl_h: 24
```

**User-agent tradeoff.** ⚙ The default is an honest user-agent that identifies the
crawler. Operators can then opt out through robots.txt, which is standard research
ethics. Copying the Tor Browser user-agent would blend in better, but it would also
work against operators' ability to refuse the crawler. It stays configurable.

**Expected throughput.** One Tor client usually manages about 1–3 pages/s. A first
contact with a new service takes several seconds for the descriptor fetch,
introduction and rendezvous. Treat these numbers as rough and measure your own.

## 8. Safety by design (content)

Crawling onion space means you **will** come across illegal material, including
CSAM, sometimes one hop from harmless pages. The design keeps you from collecting
any of it.

- **Text only.** The allowlist covers `text/html`, `application/xhtml+xml`,
  `text/plain`, `application/xml` and `text/xml`. Any other type is aborted before
  its body is read. The renderer drops `image`, `media` and `font` requests.
- **Metadata only by default.** Stored fields are the title (truncated), language,
  hashes, simhash, links and status. Raw HTML and body text are **not** stored.
  Storing text snippets can be turned on, with a retention TTL, if you decide you
  need it (question 4).
- **Denylist.** You maintain a list of onion addresses. Denylisted services are
  never fetched. Edges pointing at them are still recorded, so the graph stays
  truthful.
- **Keyword quarantine.** A configurable list of indicator terms is matched
  against URLs, titles and anchor text. On a match, crawling of that service stops
  at once, nothing from it is stored beyond the address and a `quarantined` status,
  and the event is logged for human review. The tool ships the **mechanism** with
  an empty list. Get indicator lists through appropriate channels.
- **Report, don't collect.** If you suspect CSAM, report the URL to the right
  hotline (NCMEC CyberTipline in the US, IWF in the UK, INHOPE members elsewhere).
  Do not download it, screenshot it or "preserve evidence" yourself.

## 9. Operator security (threats to you)

| Risk | Mitigation |
|---|---|
| IP or DNS leak | A single session factory, `socks5h` (remote DNS), fail-closed, no direct-connect code path. The crawler container sits on an `internal` network with Tor as its only egress. |
| Leaving the intended scope | Only `.onion` is allowed by default. Every redirect is re-checked. Clearnet links are recorded as edges and never fetched. |
| Malicious content aimed at parsers | `selectolax` does no I/O or script execution. `defusedxml` handles XML. Decompressed bytes, redirects and sitemap depth are capped. |
| Browser exploits (renderer) | Off by default. Runs in its own process or container with an ephemeral profile, WebRTC off, downloads off, service workers blocked and the Chromium sandbox **kept on**. Blocked resource types shrink the attack surface. |
| Container breakout or pivot | Non-root UID, read-only root filesystem, `cap_drop: [ALL]`, `no-new-privileges`, tmpfs `/tmp`, a single data volume, Tor ports never published to the host, control port protected by cookie or hashed-password auth. |
| Sensitive data at rest | The DB holds addresses of sites that may be criminal. Use an encrypted volume and restrict access. Logs carry no bodies, and their query strings are redacted. |
| Exposing an open SOCKS proxy | The Tor container binds SOCKS only on the internal Docker network and never on `0.0.0.0` of the host. |

## 10. Tradeoffs

| Decision | Chosen ⚙ | Alternative | Why |
|---|---|---|---|
| HTTP client | aiohttp + aiohttp-socks | httpx | Explicit `rdns`, mature streaming with byte caps, easy SOCKS-auth stream isolation. HTTP/2 gains little over onion. |
| Parser | selectolax | BeautifulSoup, lxml | Fast and HTML5-correct. BeautifulSoup is 10–30× slower. `lxml` stays only as an optional recovery parser. |
| Queue | asyncio + SQLite frontier | Redis | Resumes with no extra service. Redis only earns its place with several workers. |
| Store | SQLite (WAL) | PostgreSQL | No ops work, and fine for one process up to millions of rows. Move to Postgres for concurrent writers. |
| Graph | Relational edges + GraphML, Neo4j optional | Neo4j as primary | Neo4j is excellent for Cypher analytics but adds ops burden. Keeping the relational DB as the source of truth means the graph can be rebuilt. |
| JS rendering | Fallback only, off by default | Always render | Rendering costs roughly 10× the time and memory, adds attack surface and a ~400 MB image, and most onion sites are static. |
| Dedupe | DB unique index + optional Bloom | Bloom only | A Bloom filter alone drops URLs on false positives. As a pre-check it only saves DB lookups. |
| Circuit rotation | Per-service SOCKS isolation + rare `NEWNYM` | `NEWNYM` per request | Frequent `NEWNYM` loads the network, gains nothing for onion services and looks like evasion. |

## 11. Project layout

```
tor-scrape/
├── pyproject.toml
├── README.md
├── docker-compose.yml
├── config/
│   ├── config.example.yaml
│   ├── seeds.example.txt
│   └── denylist.example.txt
├── docker/
│   ├── Dockerfile              # crawler; non-root, slim
│   ├── Dockerfile.render       # optional Playwright variant
│   ├── Dockerfile.tor          # minimal Tor client
│   └── torrc
├── docs/
│   ├── ARCHITECTURE.md
│   ├── ETHICS.md
│   ├── ROADMAP.md
│   └── TROUBLESHOOTING.md
├── src/torscrape/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── config.py
│   ├── logging.py
│   ├── models.py
│   ├── onion.py
│   ├── urlnorm.py
│   ├── crawler.py
│   ├── tor/{session,controller,errors}.py
│   ├── fetch/{fetcher,retry,robots,renderer}.py
│   ├── extract/{html,scripts,text,sitemap,gate}.py
│   ├── frontier/{base,scheduler,dedupe,memory,redis}.py
│   ├── storage/{base,sqlite,postgres,neo4j}.py + schema.sql
│   ├── safety/policy.py
│   └── export/{jsonl,csv,graphml}.py
└── tests/
    ├── conftest.py
    ├── fixtures/pages/*.html
    ├── unit/                   # onion, urlnorm, extractors, retry, scheduler, errors
    └── integration/            # in-process fake SOCKS5 → mock onion site
```

**Integration testing without Tor.** The test suite starts an in-process SOCKS5
server. It routes any `*.onion` host to a local `aiohttp` test site built from
checksum-valid fake addresses. It can also inject Tor extended errors (`0xF0`,
`0xF4` and others) and slow rendezvous. This exercises the real SOCKS code path
deterministically. A separate live smoke test, marked `@pytest.mark.tor`, runs only
when `TORSCRAPE_LIVE=1`.

## 12. Build order

1. `pyproject.toml`, `config.py`, `logging.py`, `models.py`
2. `onion.py`, `urlnorm.py` and their unit tests
3. `tor/errors.py`, `tor/session.py`, `tor/controller.py`
4. `fetch/retry.py`, `fetch/robots.py`, `fetch/fetcher.py`
5. `extract/*` with fixture tests
6. `frontier/*` (scheduler, dedupe)
7. `storage/sqlite.py` and `schema.sql`
8. `crawler.py` and `cli.py`
9. Integration tests (fake SOCKS5 and mock onion site)
10. Exporters
11. Dockerfiles and `docker-compose.yml`
12. Optional extras: renderer, Postgres, Neo4j, Redis
13. Docs: ETHICS, ROADMAP, TROUBLESHOOTING, examples

## 13. Open questions

1. **Purpose and output.** Is this threat intelligence, academic measurement,
   brand or phishing-clone monitoring, or something else? The answer decides which
   metadata is worth keeping.
2. **Scale.** How many services or pages are you aiming for? One machine, or
   several workers?
3. **Storage and graph.** Is Neo4j required for the MVP, or are SQLite and a
   GraphML export (for Gephi) enough to start? Do you already run PostgreSQL?
4. **Content retention and jurisdiction.** Metadata only ⚙, or text snippets for
   keyword search? What retention period? Which jurisdiction, and has legal or an
   ethics board reviewed the work?
5. **Scope and seeds.** Onion only ⚙, or also clearnet seed sources fetched
   through Tor (public directories, code repositories, paste sites)? Do you have a
   seed list?
6. **JavaScript rendering.** Is it really needed, or can it be an off-by-default
   fallback ⚙?
7. **Deployment.** Docker on a laptop, a VM or a VPS? An existing Tor daemon, or
   the bundled container ⚙? Any hosting provider rules about Tor?
8. **Mode.** One-off discovery, or continuous monitoring (liveness checks, new
   mirror detection, alerts)?
