# tor-scrape: architecture (v0.2)

> **Status:** accepted. The scope decisions are recorded in §13, retention in
> §14 and the phase-2 extension points in §15. ⚙ marks a default that can be
> changed in `config/config.example.yaml`.

tor-scrape is a research-only crawler. It reaches publicly accessible v3 `.onion`
sites through Tor, pulls out every link and onion address those sites mention, and
stores the resulting service-level link graph for analysis.

---

## 1. Goals and non-goals

**Goals**

- Discover v3 onion services that are linked or mentioned somewhere reachable
  **without authentication**, and map which services link to which.
- Record metadata only: onion address, discovery source (channel and referring
  service), first and last seen, checksum validity, reachability status and
  index presence, plus content hashes for mirror detection. Export it to
  JSONL, CSV and GraphML. PostgreSQL and Neo4j are optional add-ons.
- Never store page HTML, text, titles, images or binaries.
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
| `logging.py` | Structured JSON logs | `structlog`. Logs never contain bodies, titles or cookies, and query strings are redacted. Optional file output rotates daily and keeps `retention.log_days` files. |
| `onion.py` | v3 validation (length, alphabet, checksum, version) plus extraction regexes, including defanged forms | Pure functions, fully unit-tested |
| `urlnorm.py` | Canonical URLs, service key, scope checks | Lowercases scheme and host, drops default ports and fragments, resolves dot segments, sorts the query, strips tracking parameters. `www.<addr>.onion` maps to the same service key. |
| `tor/session.py` | The one factory for HTTP sessions | `aiohttp` with `aiohttp-socks` and `rdns=True`, so DNS resolves remotely and nothing leaks. **Fails closed:** it refuses to build a session without the proxy and never falls back to a direct connection. Each service gets its own SOCKS username, which isolates streams the way Tor Browser's first-party isolation does. |
| `tor/controller.py` | Bootstrap and health checks, rate-limited `NEWNYM` | `stem`, run through `asyncio.to_thread`. `NEWNYM` fires only after K consecutive circuit failures across different services, and at most once every ≥10 s (Tor's own limit). |
| `tor/errors.py` | Maps SOCKS5 replies (including Tor `ExtendedErrors` `0xF0`–`0xF7`) and HTTP statuses to an `ErrorClass` | See §6 |
| `fetch/fetcher.py` | Streams the GET and enforces caps | Checks the content-type allowlist before reading the body. Caps decompressed bytes (gzip-bomb safe). Allows up to 5 redirects, each re-checked against scope. Uses an ephemeral per-host cookie jar that is never persisted. |
| `fetch/retry.py` | Backoff and adaptive per-host delay | Exponential backoff with full jitter. Honors `Retry-After` (capped). AIMD: the host delay doubles on 429/503 and shrinks 10% on success, down to a floor. |
| `fetch/robots.py` | robots.txt cache and sitemap discovery | Follows RFC 9309: a 4xx means allow, a 5xx or network error means disallow for now and retry later. Disallowed paths are **recorded but never enqueued**. |
| `fetch/renderer.py` | JavaScript-rendering fallback | Playwright Chromium through Tor. Used only for services on `render.allowed_services`, and only when heuristics flag a page as JS-built (few links, heavy script, `<noscript>` hints). Blocks image, media, font, stylesheet and websocket requests. WebRTC is disabled, the profile is ephemeral, downloads are off and the sandbox stays on. |
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

The tables fall into two retention classes (§14): **aggregate** tables are kept
until you purge them, and **raw** tables are purged after
`retention.raw_metadata_days` (90 by default).

```sql
-- AGGREGATE: one row per onion label ever seen, valid or not.
services (
  onion             TEXT PRIMARY KEY,     -- 56-char label, no ".onion"
  checksum_valid    BOOLEAN NOT NULL,     -- invalid rows are never fetched
  status            TEXT NOT NULL,        -- unknown|online|offline|gated|restricted|
                                          -- denied|quarantined|denylisted|invalid
  first_seen        TIMESTAMP NOT NULL,   -- first mention anywhere
  last_seen         TIMESTAMP,            -- last successful fetch (reachability)
  last_checked      TIMESTAMP,            -- last fetch attempt
  discovered_via    TEXT NOT NULL,        -- seed|known_index|href|src|action|meta_refresh|
                                          -- data_attr|js|text|comment|sitemap|robots|
                                          -- onion_location|header
  discovered_from   TEXT,                 -- onion label that first mentioned it
  in_known_index    BOOLEAN NOT NULL DEFAULT FALSE,
  known_index_sources TEXT,               -- which imported lists contain it
  pages_crawled     INTEGER NOT NULL DEFAULT 0,
  next_check_at     TIMESTAMP             -- phase 2: liveness scheduling
);

-- AGGREGATE: service-level link graph (the one exported to GraphML).
service_links (
  src_onion    TEXT NOT NULL REFERENCES services(onion),
  dst_onion    TEXT NOT NULL REFERENCES services(onion),
  channels     TEXT NOT NULL,             -- set of channels seen, e.g. "href,text"
  forms        TEXT,                      -- plain|defanged|bare, for text mentions
  mention_count INTEGER NOT NULL DEFAULT 1,
  first_seen   TIMESTAMP NOT NULL,
  last_seen    TIMESTAMP NOT NULL,
  PRIMARY KEY (src_onion, dst_onion)
);

-- RAW: one row per fetched URL. Hashes only, never content.
pages (
  id            INTEGER PRIMARY KEY,
  url           TEXT UNIQUE NOT NULL,     -- canonical
  onion         TEXT NOT NULL REFERENCES services(onion),
  depth         INTEGER NOT NULL,
  http_status   INTEGER,
  content_type  TEXT,
  bytes         INTEGER,
  sha256        TEXT,                     -- exact duplicates
  simhash       INTEGER,                  -- near duplicates / mirror clusters (phase 2)
  rendered      BOOLEAN NOT NULL DEFAULT FALSE,
  error_class   TEXT,
  fetched_at    TIMESTAMP
);

-- RAW: page-level edges; rolled up into service_links as they are written.
edges (
  src_page_id  INTEGER NOT NULL REFERENCES pages(id),
  dst_url      TEXT NOT NULL,             -- canonical onion URL (or bare host)
  dst_onion    TEXT NOT NULL,
  channel      TEXT NOT NULL,
  form         TEXT,                      -- plain|defanged|bare for text/js/comment
  first_seen   TIMESTAMP NOT NULL,
  last_seen    TIMESTAMP NOT NULL,
  PRIMARY KEY (src_page_id, dst_url, channel)
);

-- RAW: work queue and its history.
frontier (
  url             TEXT PRIMARY KEY,
  onion           TEXT NOT NULL,
  task_kind       TEXT NOT NULL DEFAULT 'crawl',   -- crawl | liveness (phase 2)
  depth           INTEGER NOT NULL,
  priority        REAL NOT NULL,          -- lower = sooner
  state           TEXT NOT NULL,          -- pending|in_flight|done|failed|skipped
  attempts        INTEGER NOT NULL DEFAULT 0,
  not_before      TIMESTAMP,              -- backoff / Retry-After / recheck
  discovered_from TEXT,
  updated_at      TIMESTAMP NOT NULL
);

-- RAW: status transitions, the feed for phase-2 alerts.
service_events (onion, at, old_status, new_status, error_class);

runs (id, started_at, finished_at, config_fingerprint, stats_json);
known_index (onion TEXT, source TEXT, imported_at TIMESTAMP, PRIMARY KEY (onion, source));
```

The crawler never writes titles, text, HTML or anchor text. Titles and anchor
text exist only in memory, long enough for the quarantine check (§8).

**Graph (Neo4j, optional, later)**

```
(:Service {onion, status, checksum_valid, first_seen, last_seen, in_known_index})
(:Service)-[:LINKS_TO {mention_count, channels, first_seen, last_seen}]->(:Service)
```

This graph comes straight from `services` and `service_links`, so it can be
rebuilt at any time.

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

## 7. Politeness defaults

The full, commented list is in
[`config/config.example.yaml`](../config/config.example.yaml). A test keeps that
file identical to the built-in defaults. The main values:

| Setting | Default | Hard bound |
|---|---|---|
| `crawl.global_concurrency` | 8 | 1–32 |
| `crawl.per_host_concurrency` | 1 | 1–2 |
| `crawl.per_host_delay_s` | 10 s ± 30% jitter; doubles on 429/503 | ≥ 2 s |
| `crawl.max_depth` (within a service) | 3 | 0–10 |
| `crawl.max_pages_per_service` | 50 | — |
| `crawl.max_total_pages` | 100,000 | — |
| `http.connect_timeout_s` / `total_timeout_s` | 45 / 90 s | ≤ 300 / 600 s |
| `http.max_body_bytes` (decompressed) | 2 MiB | 16 KiB–16 MiB |
| `http.max_redirects` (onion to onion only) | 5 | ≤ 10 |
| `http.allowed_content_types` | html, xhtml, plain, xml | textual types only |
| `tor.newnym_min_interval_s` | 60 s | ≥ 10 s |

Some behaviour has no switch at all. robots.txt is always respected, the scope
is always onion-only, and binary content types are rejected by the config
validator.

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
- **Metadata only.** Stored fields are addresses, discovery source, timestamps,
  checksum validity, status, HTTP status, byte counts, content hashes and links.
  HTML, body text, titles and anchor text are **never** stored, and there is no
  option to store them.
- **Denylist.** You maintain a list of onion addresses. Denylisted services are
  never fetched. Edges pointing at them are still recorded, so the graph stays
  truthful.
- **Keyword quarantine.** A configurable list of indicator terms is matched
  against URLs, plus titles and anchor text while they are still in memory. On a
  match, crawling of that service stops
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
| Leaving the intended scope | Scope is onion-only, with no switch to change it. Every redirect is re-checked. Clearnet links are ignored. |
| Malicious content aimed at parsers | `selectolax` does no I/O or script execution. `defusedxml` handles XML. Decompressed bytes, redirects and sitemap depth are capped. |
| Browser exploits (renderer) | Off by default, and limited to an explicit per-service allowlist when enabled. Runs in its own process or container with an ephemeral profile, WebRTC off, downloads off, service workers blocked and the Chromium sandbox **kept on**. Blocked resource types shrink the attack surface. |
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

1. ✅ `pyproject.toml`, `config.py`, example config and seeds
2. ✅ `onion.py` with unit tests (checksum, host parsing, plain, defanged and bare extraction)
3. `logging.py`, `models.py`, `urlnorm.py` and their unit tests
4. `tor/errors.py`, `tor/session.py`, `tor/controller.py`
5. `fetch/retry.py`, `fetch/robots.py`, `fetch/fetcher.py`
6. `extract/*` with fixture tests
7. `frontier/*` (scheduler, dedupe)
8. `storage/sqlite.py` and `schema.sql`, including retention purge
9. `crawler.py` and `cli.py`
10. Integration tests (fake SOCKS5 and mock onion site)
11. Exporters (JSONL, CSV, GraphML)
12. Dockerfiles and `docker-compose.yml`
13. Playwright fallback, restricted to the render allowlist
14. Docs: ETHICS, ROADMAP, TROUBLESHOOTING, example commands and output
15. Later, optional: PostgreSQL, Neo4j, Redis

## 13. Decisions

| Topic | Decision |
|---|---|
| Purpose | Authorized OSINT research: discover publicly reachable onion addresses that surface search engines don't show, and map how they link to one another. |
| Metadata | Address, discovery source, first and last seen, checksum validity, reachability, index presence. No page content. |
| Scale | One machine, about 100k pages, one Tor client (1–3 pages/s). Wide rather than deep: at most 50 pages and 3 levels per site. |
| Storage | SQLite as the main store, GraphML for analysis. PostgreSQL and Neo4j are optional and not needed for the MVP. |
| Content | Metadata only. No HTML, text snippets, titles, images or binaries. "Report, don't collect" for illegal content. |
| Jurisdiction | Jurisdiction-agnostic design. The operator handles legal compliance and ethics review. |
| Scope | Onion only. Seeds come from the seed file; Onion-Location headers and local index lists add more. No clearnet crawling in this phase. |
| JS rendering | Off by default. When enabled, it runs only for services on `render.allowed_services`, and only after static parsing finds no links. |
| Deployment | Docker Compose with a bundled Tor container. Non-root, read-only filesystem, all capabilities dropped, Tor ports internal only. |
| Mode | One-off discovery for the MVP. The data model and queue are ready for phase-2 monitoring (§15). |

## 14. Retention

| Data | Kept for | How it is enforced |
|---|---|---|
| `pages`, `edges`, finished `frontier` rows, `service_events`, `runs` | `retention.raw_metadata_days` (90) | A `purge` CLI command, which also runs at the start of each crawl, deletes rows older than the cutoff |
| Log files | `retention.log_days` (90) | Daily rotation that keeps N files. When logging to stdout under Docker, set a `max-file`/`max-size` log driver limit. |
| `services`, `service_links`, `known_index` | Until you purge them manually | `purge --aggregates` (asks for confirmation) |

Because the aggregate tables are updated incrementally as edges are written,
purging raw rows never changes the service-level graph.

## 15. Phase-2 extension points

These are already in the MVP design, so monitoring can be added without
restructuring:

- **Liveness checks.** `frontier.task_kind = 'liveness'` shares the scheduler,
  politeness rules and error classifier with crawl tasks.
  `services.next_check_at` drives how often each service is checked.
- **Mirror detection.** `pages.sha256` and `pages.simhash` are stored from day
  one. Clustering services by homepage simhash is a query, not a schema change.
- **Alerts.** Every status change is written to `service_events`. An alerting
  job reads that table; the crawler does not need to change.
- **Scale-out.** `Frontier` and `Repository` are protocols. Redis and PostgreSQL
  backends slot in behind them.
