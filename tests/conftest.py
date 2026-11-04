###############################################################################
# Copyright (c) 2026 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
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
