from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from pathlib import Path

import pytest

from torscrape.onion import onion_address_from_pubkey

REPO_ROOT = Path(__file__).resolve().parents[1]


def fake_onion(seed: int | str) -> str:
    """A deterministic, checksum-valid v3 label that belongs to no real service."""
    return onion_address_from_pubkey(hashlib.sha256(f"tor-scrape-fixture:{seed}".encode()).digest())


@pytest.fixture
def make_onion() -> Callable[[int | str], str]:
    return fake_onion


@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the developer's TORSCRAPE_* variables out of every test."""
    for key in list(os.environ):
        if key.startswith("TORSCRAPE_"):
            monkeypatch.delenv(key)
