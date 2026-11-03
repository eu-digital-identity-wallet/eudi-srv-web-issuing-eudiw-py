"""Shared pytest fixtures."""

import os

# The .env.test environment, set before any app module is imported, so a plain
# `pytest` runs like CI (upstream #185). Values already set are kept.
os.environ.setdefault("MOCK_CONFIGURATION", "true")
os.environ.setdefault("EUDIW_TEST_ENV", "true")

import pytest  # noqa: E402

from config_helpers import set_configuration  # noqa: E402


@pytest.fixture(autouse=True)
def mock_configuration(monkeypatch):
    """Gives every test a minimal configuration in all app modules."""
    config = {"service_url": "https://service.test"}
    set_configuration(monkeypatch, config)
    yield config
