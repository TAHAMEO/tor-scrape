"""Configuration: a YAML file plus ``TORSCRAPE_*`` environment overrides.

Precedence, highest first: environment variables, the YAML file, built-in
defaults. Nested keys use a double underscore, e.g.
``TORSCRAPE_CRAWL__MAX_DEPTH=2`` or ``TORSCRAPE_TOR__SOCKS_HOST=tor``.

Some limits are hard bounds, not just defaults. They keep the crawler polite
and text-only even when misconfigured:

* concurrency is capped and per-host delays have a floor;
* only textual content types can be allowed, so images and binaries are
  never downloaded;
* robots.txt is always respected (there is no switch to turn it off);
* scope is onion-only (there is no clearnet option in this phase);
* JavaScript rendering needs an explicit per-service allowlist.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any, Literal, Self

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    FilePath,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

from torscrape.onion import check_label

CONFIG_ENV_VAR = "TORSCRAPE_CONFIG"

# The only content types the fetcher may ever read. Anything else is aborted
# before the body is downloaded, whatever the configuration says.
PERMITTED_CONTENT_TYPES = frozenset(
    {
        "text/html",
        "application/xhtml+xml",
        "text/plain",
        "application/xml",
        "text/xml",
        "application/rss+xml",
        "application/atom+xml",
        "text/javascript",
        "application/javascript",
        "application/json",
    }
)
DEFAULT_CONTENT_TYPES = (
    "text/html",
    "application/xhtml+xml",
    "text/plain",
    "application/xml",
    "text/xml",
)

_ROBOTS_TOKEN_RE = re.compile(r"^[A-Za-z_-]+$")  # RFC 9309 product token


class ConfigError(Exception):
    """The configuration file is missing or malformed."""


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TorSettings(_Section):
    socks_host: str = Field("127.0.0.1", min_length=1)
    socks_port: int = Field(9050, ge=1, le=65535)
    control_host: str = Field("127.0.0.1", min_length=1)
    control_port: int = Field(9051, ge=1, le=65535)
    control_password: SecretStr | None = None
    control_cookie_path: Path | None = None
    # A distinct SOCKS username per onion service, so Tor keeps each service's
    # streams on separate circuits (as Tor Browser does per first-party site).
    stream_isolation: bool = True
    # NEWNYM only after this many consecutive circuit-level failures across
    # different services. Never used in response to HTTP 403/429.
    newnym_after_failures: int = Field(20, ge=5)
    # Tor enforces >= 10 s between NEWNYM signals; stay well above that.
    newnym_min_interval_s: float = Field(60.0, ge=10.0)


class HttpSettings(_Section):
    user_agent: str = Field("tor-scrape-research/0.1", min_length=1, max_length=256)
    connect_timeout_s: float = Field(45.0, gt=0, le=300)
    total_timeout_s: float = Field(90.0, gt=0, le=600)
    max_body_bytes: int = Field(2 * 1024 * 1024, ge=16 * 1024, le=16 * 1024 * 1024)
    max_redirects: int = Field(5, ge=0, le=10)
    allowed_content_types: tuple[str, ...] = DEFAULT_CONTENT_TYPES

    @field_validator("user_agent")
    @classmethod
    def _no_header_injection(cls, value: str) -> str:
        if any(ch in value for ch in "\r\n\x00"):
            raise ValueError("user_agent must not contain CR, LF or NUL")
        return value

    @field_validator("allowed_content_types")
    @classmethod
    def _text_only(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(dict.fromkeys(ct.strip().lower() for ct in value))
        if not normalized:
            raise ValueError("at least one content type must be allowed")
        rejected = sorted(set(normalized) - PERMITTED_CONTENT_TYPES)
        if rejected:
            raise ValueError(
                f"content types {rejected} are not permitted; "
                f"allowed values: {sorted(PERMITTED_CONTENT_TYPES)}"
            )
        return normalized

    @model_validator(mode="after")
    def _timeouts_consistent(self) -> Self:
        if self.total_timeout_s < self.connect_timeout_s:
            raise ValueError("total_timeout_s must be >= connect_timeout_s")
        return self


class RetrySettings(_Section):
    max_attempts: int = Field(3, ge=1, le=5)
    backoff_base_s: float = Field(30.0, ge=1)
    backoff_max_s: float = Field(3600.0, ge=1)
    retry_after_cap_s: float = Field(3600.0, ge=0)
    # Rechecks for a service whose descriptor could not be found (SOCKS 0xF0/0xF1)
    # before it is marked offline.
    offline_recheck_h: tuple[float, ...] = (1.0, 6.0, 24.0)

    @field_validator("offline_recheck_h")
    @classmethod
    def _positive(cls, value: tuple[float, ...]) -> tuple[float, ...]:
        if any(h <= 0 for h in value):
            raise ValueError("offline_recheck_h entries must be > 0")
        return value

    @model_validator(mode="after")
    def _backoff_consistent(self) -> Self:
        if self.backoff_max_s < self.backoff_base_s:
            raise ValueError("backoff_max_s must be >= backoff_base_s")
        return self


class CrawlSettings(_Section):
    seeds_file: Path = Path("config/seeds.txt")
    global_concurrency: int = Field(8, ge=1, le=32)
    per_host_concurrency: int = Field(1, ge=1, le=2)
    per_host_delay_s: float = Field(10.0, ge=2.0, le=3600)
    delay_jitter: float = Field(0.3, ge=0.0, le=1.0)
    max_host_delay_s: float = Field(600.0, ge=2.0, le=86400)
    max_depth: int = Field(3, ge=0, le=10)
    max_pages_per_service: int = Field(50, ge=1, le=10_000)
    max_total_pages: int = Field(100_000, ge=1)
    # URL path or anchor terms that suggest a link hub; such pages are fetched sooner.
    hub_hints: tuple[str, ...] = (
        "links",
        "directory",
        "list",
        "wiki",
        "mirror",
        "onion",
        "sites",
        "catalog",
        "hub",
    )

    @field_validator("hub_hints")
    @classmethod
    def _lowercase_hints(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(h.strip().lower() for h in value if h.strip()))

    @model_validator(mode="after")
    def _delay_bounds(self) -> Self:
        if self.max_host_delay_s < self.per_host_delay_s:
            raise ValueError("max_host_delay_s must be >= per_host_delay_s")
        return self


class RobotsSettings(_Section):
    # robots.txt is always honoured; these only tune how.
    agent_token: str = "tor-scrape"  # noqa: S105 - robots product token, not a secret
    cache_ttl_h: float = Field(24.0, ge=1.0, le=168.0)

    @field_validator("agent_token")
    @classmethod
    def _rfc9309_token(cls, value: str) -> str:
        if not _ROBOTS_TOKEN_RE.fullmatch(value):
            raise ValueError("agent_token may only contain letters, '-' and '_' (RFC 9309)")
        return value


class RenderSettings(_Section):
    enabled: bool = False
    # Services (onion labels or hostnames) for which the Playwright fallback may
    # run when static parsing finds nothing. Required when enabled.
    allowed_services: tuple[str, ...] = ()
    timeout_s: float = Field(60.0, gt=0, le=300)
    max_concurrency: int = Field(1, ge=1, le=4)

    @field_validator("allowed_services")
    @classmethod
    def _valid_onions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        labels: list[str] = []
        for entry in value:
            check = check_label(entry)
            if not check.valid:
                raise ValueError(f"{entry!r} is not a valid v3 onion address ({check.reason})")
            labels.append(check.label)
        return tuple(dict.fromkeys(labels))

    @model_validator(mode="after")
    def _explicit_allowlist(self) -> Self:
        if self.enabled and not self.allowed_services:
            raise ValueError("render.enabled requires at least one entry in allowed_services")
        return self


class DiscoverySettings(_Section):
    # Local lists of already-indexed onions. Services missing from all of them
    # are flagged as not in a known index. Nothing is sent to third parties.
    known_index_files: tuple[FilePath, ...] = ()
    follow_onion_location: bool = True
    # Record checksum-invalid mentions as metadata. They are never fetched.
    record_invalid_mentions: bool = True


class SafetySettings(_Section):
    # One onion address per line; these services are never fetched.
    denylist_file: FilePath | None = None
    # One indicator term per line, matched against URLs and in-memory titles and
    # anchor text. A match quarantines the service. Ships empty on purpose.
    quarantine_terms_file: FilePath | None = None


class StorageSettings(_Section):
    backend: Literal["sqlite"] = "sqlite"
    sqlite_path: Path = Path("data/torscrape.db")


class RetentionSettings(_Section):
    # Page-level rows (pages, edges, frontier history) and log files older than
    # this are purged. Aggregated service-level graph rows are kept until
    # purged manually.
    raw_metadata_days: int = Field(90, ge=1)
    log_days: int = Field(90, ge=1)


class LoggingSettings(_Section):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    format: Literal["json", "console"] = "json"
    # When set, logs also go to this file, rotated daily and kept for
    # retention.log_days days.
    file: Path | None = None


class Settings(BaseSettings):
    """Validated, immutable crawler configuration."""

    model_config = SettingsConfigDict(
        env_prefix="TORSCRAPE_",
        env_nested_delimiter="__",
        extra="forbid",
        frozen=True,
    )

    tor: TorSettings = TorSettings()
    http: HttpSettings = HttpSettings()
    retry: RetrySettings = RetrySettings()
    crawl: CrawlSettings = CrawlSettings()
    robots: RobotsSettings = RobotsSettings()
    render: RenderSettings = RenderSettings()
    discovery: DiscoverySettings = DiscoverySettings()
    safety: SafetySettings = SafetySettings()
    storage: StorageSettings = StorageSettings()
    retention: RetentionSettings = RetentionSettings()
    logging: LoggingSettings = LoggingSettings()

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # load_settings() passes the YAML mapping as init kwargs, so putting the
        # environment first gives: environment > YAML > defaults.
        return (env_settings, init_settings)

    def fingerprint(self) -> str:
        """Stable hash of the effective configuration, recorded with each run.

        Secrets are masked by ``model_dump(mode="json")``, so they never
        influence (or leak through) the hash.
        """
        dumped = self.model_dump_json(exclude_none=False).encode("utf-8")
        return hashlib.sha256(dumped).hexdigest()[:16]


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a mapping at the top level")
    return data


def load_settings(path: str | Path | None = None) -> Settings:
    """Load settings from ``path`` (or ``$TORSCRAPE_CONFIG``) plus the environment.

    With neither, only defaults and environment overrides apply.
    """
    source = path if path is not None else os.environ.get(CONFIG_ENV_VAR)
    data = _read_yaml(Path(source)) if source else {}
    return Settings(**data)
