from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from tests.conftest import REPO_ROOT, fake_onion
from torscrape.config import (
    CONFIG_ENV_VAR,
    DEFAULT_CONTENT_TYPES,
    ConfigError,
    Settings,
    load_settings,
)


def _write(tmp_path: Path, text: str, name: str = "config.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


class TestDefaults:
    def test_documented_defaults(self) -> None:
        s = Settings()
        assert (s.tor.socks_host, s.tor.socks_port) == ("127.0.0.1", 9050)
        assert s.tor.stream_isolation is True
        assert s.crawl.global_concurrency == 8
        assert s.crawl.per_host_concurrency == 1
        assert s.crawl.per_host_delay_s == 10
        assert s.crawl.max_depth == 3
        assert s.crawl.max_pages_per_service == 50
        assert s.crawl.max_total_pages == 100_000
        assert s.http.allowed_content_types == DEFAULT_CONTENT_TYPES
        assert s.render.enabled is False
        assert s.render.allowed_services == ()
        assert s.discovery.follow_onion_location is True
        assert s.storage.backend == "sqlite"
        assert (s.retention.raw_metadata_days, s.retention.log_days) == (90, 90)

    def test_no_file_and_no_env_gives_defaults(self) -> None:
        assert load_settings() == Settings()

    def test_example_config_matches_defaults(self) -> None:
        # Keeps config/config.example.yaml honest: it documents the defaults.
        assert load_settings(REPO_ROOT / "config" / "config.example.yaml") == Settings()

    def test_settings_are_immutable(self) -> None:
        s = Settings()
        with pytest.raises(ValidationError):
            s.crawl.max_depth = 9  # type: ignore[misc]


class TestLoading:
    def test_yaml_values_apply(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "crawl:\n  max_depth: 1\n  max_pages_per_service: 10\n")
        s = load_settings(path)
        assert s.crawl.max_depth == 1
        assert s.crawl.max_pages_per_service == 10
        assert s.crawl.global_concurrency == 8  # untouched keys keep defaults

    def test_env_overrides_yaml_and_merges_nested(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _write(tmp_path, "crawl:\n  max_depth: 1\n  max_pages_per_service: 10\n")
        monkeypatch.setenv("TORSCRAPE_CRAWL__MAX_DEPTH", "2")
        monkeypatch.setenv("TORSCRAPE_TOR__SOCKS_HOST", "tor")
        s = load_settings(path)
        assert s.crawl.max_depth == 2
        assert s.crawl.max_pages_per_service == 10
        assert s.tor.socks_host == "tor"

    def test_config_path_from_environment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _write(tmp_path, "tor:\n  socks_port: 9150\n")
        monkeypatch.setenv(CONFIG_ENV_VAR, str(path))
        assert load_settings().tor.socks_port == 9150

    def test_explicit_path_beats_environment_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env_path = _write(tmp_path, "tor:\n  socks_port: 9150\n", "env.yaml")
        arg_path = _write(tmp_path, "tor:\n  socks_port: 9250\n", "arg.yaml")
        monkeypatch.setenv(CONFIG_ENV_VAR, str(env_path))
        assert load_settings(arg_path).tor.socks_port == 9250

    def test_empty_file_gives_defaults(self, tmp_path: Path) -> None:
        assert load_settings(_write(tmp_path, "# nothing\n")) == Settings()

    def test_list_values_from_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        onion = fake_onion("render")
        monkeypatch.setenv("TORSCRAPE_RENDER__ENABLED", "true")
        monkeypatch.setenv("TORSCRAPE_RENDER__ALLOWED_SERVICES", f'["{onion}.onion"]')
        assert load_settings().render.allowed_services == (onion,)

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="not found"):
            load_settings(tmp_path / "absent.yaml")

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="invalid YAML"):
            load_settings(_write(tmp_path, "crawl: [unclosed\n"))

    def test_top_level_must_be_mapping(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="mapping"):
            load_settings(_write(tmp_path, "- a\n- b\n"))

    @pytest.mark.parametrize(
        "text",
        [
            "crawl:\n  max_dpeth: 2\n",
            "crawler:\n  max_depth: 2\n",
            "http:\n  follow_clearnet: true\n",
        ],
        ids=["nested-typo", "section-typo", "unsupported-option"],
    )
    def test_unknown_keys_are_rejected(self, tmp_path: Path, text: str) -> None:
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            load_settings(_write(tmp_path, text))


class TestGuardrails:
    @pytest.mark.parametrize(
        "content_type", ["image/png", "video/mp4", "application/octet-stream", "application/zip"]
    )
    def test_binary_content_types_cannot_be_enabled(self, content_type: str) -> None:
        with pytest.raises(ValidationError, match="not permitted"):
            Settings(http={"allowed_content_types": ["text/html", content_type]})

    def test_content_types_are_normalized_and_deduplicated(self) -> None:
        s = Settings(http={"allowed_content_types": [" Text/HTML ", "text/html", "text/plain"]})
        assert s.http.allowed_content_types == ("text/html", "text/plain")

    def test_empty_content_types_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least one"):
            Settings(http={"allowed_content_types": []})

    @pytest.mark.parametrize(
        ("section", "values"),
        [
            ("crawl", {"global_concurrency": 33}),
            ("crawl", {"global_concurrency": 0}),
            ("crawl", {"per_host_concurrency": 3}),
            ("crawl", {"per_host_delay_s": 1}),
            ("crawl", {"per_host_delay_s": 30, "max_host_delay_s": 20}),
            ("crawl", {"delay_jitter": 1.5}),
            ("http", {"max_body_bytes": 64 * 1024 * 1024}),
            ("http", {"max_redirects": 50}),
            ("http", {"connect_timeout_s": 60, "total_timeout_s": 30}),
            ("tor", {"newnym_min_interval_s": 5}),
            ("tor", {"newnym_after_failures": 1}),
            ("tor", {"socks_port": 70000}),
            ("retry", {"max_attempts": 10}),
            ("retry", {"backoff_base_s": 100, "backoff_max_s": 10}),
            ("retry", {"offline_recheck_h": [1, -2]}),
        ],
    )
    def test_out_of_bounds_values_rejected(self, section: str, values: dict[str, object]) -> None:
        with pytest.raises(ValidationError):
            Settings.model_validate({section: values})

    @pytest.mark.parametrize("agent", ["tor-scrape/1.0", "tor scrape", "", "bot*"])
    def test_robots_token_must_follow_rfc9309(self, agent: str) -> None:
        with pytest.raises(ValidationError):
            Settings(robots={"agent_token": agent})

    @pytest.mark.parametrize("ua", ["ua\r\nX-Evil: 1", "ua\nx", "ua\x00"])
    def test_user_agent_header_injection(self, ua: str) -> None:
        with pytest.raises(ValidationError, match="CR, LF or NUL"):
            Settings(http={"user_agent": ua})

    def test_missing_safety_and_index_files_fail_fast(self, tmp_path: Path) -> None:
        missing = str(tmp_path / "absent.txt")
        with pytest.raises(ValidationError):
            Settings(safety={"denylist_file": missing})
        with pytest.raises(ValidationError):
            Settings(discovery={"known_index_files": [missing]})

    def test_existing_safety_files_accepted(self, tmp_path: Path) -> None:
        deny = _write(tmp_path, "", "deny.txt")
        index = _write(tmp_path, "", "index.txt")
        s = Settings(
            safety={"denylist_file": str(deny)},
            discovery={"known_index_files": [str(index)]},
        )
        assert s.safety.denylist_file == deny
        assert s.discovery.known_index_files == (index,)


class TestRenderAllowlist:
    def test_enabled_requires_allowlist(self) -> None:
        with pytest.raises(ValidationError, match="allowed_services"):
            Settings(render={"enabled": True})

    def test_entries_are_validated_and_normalized(self) -> None:
        a, b = fake_onion("a"), fake_onion("b")
        s = Settings(render={"enabled": True, "allowed_services": [f"{a.upper()}.onion", b, a]})
        assert s.render.allowed_services == (a, b)

    def test_invalid_entry_rejected(self) -> None:
        bad = fake_onion("a")[:-1] + "a"
        with pytest.raises(ValidationError, match="not a valid v3 onion"):
            Settings(render={"enabled": True, "allowed_services": [bad]})

    def test_allowlist_may_be_prepared_while_disabled(self) -> None:
        a = fake_onion("a")
        assert Settings(render={"allowed_services": [a]}).render.enabled is False


class TestSecretsAndFingerprint:
    def test_control_password_is_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TORSCRAPE_TOR__CONTROL_PASSWORD", "hunter2")
        s = load_settings()
        assert s.tor.control_password is not None
        assert s.tor.control_password.get_secret_value() == "hunter2"
        assert "hunter2" not in repr(s)
        assert "hunter2" not in s.model_dump_json()

    def test_fingerprint_is_stable(self) -> None:
        assert Settings().fingerprint() == Settings().fingerprint()
        assert len(Settings().fingerprint()) == 16

    def test_fingerprint_tracks_settings(self) -> None:
        assert Settings().fingerprint() != Settings(crawl={"max_depth": 2}).fingerprint()

    def test_fingerprint_ignores_secret_values(self) -> None:
        a = Settings(tor={"control_password": "one"})
        b = Settings(tor={"control_password": "two"})
        assert a.fingerprint() == b.fingerprint()
