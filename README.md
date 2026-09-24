# tor-scrape

A research-only crawler that reaches publicly accessible v3 `.onion` sites
through Tor, finds the onion addresses they link to or mention, and maps how
those services link to one another.

> **Status: under construction.** The config loader and onion validator are
> done. The crawler, storage, CLI and Docker setup are next. The design is in
> [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## What it does and does not do

- It stores **metadata only**: onion address, discovery source, first and last
  seen, checksum validity, reachability, and whether the address appears in
  your local index lists. It never stores page HTML, text, images or binaries.
- It is **onion-only**, sends only GET requests, always respects robots.txt,
  and rate-limits itself per site.
- It never logs in, submits forms, solves CAPTCHAs, uses onion client
  authorization or bypasses any other access control. When it meets one of
  these, it stops crawling that site.
- It does not attack Tor, harvest descriptors or try to deanonymize anyone.

You are responsible for complying with the laws that apply where you run it.
If you come across illegal content, **report it and do not collect it**
(for example NCMEC in the US, IWF in the UK, or an INHOPE member hotline).

## Development

Requires Python 3.11+.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check . && mypy src
```
