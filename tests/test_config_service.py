# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
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
import os
import logging
import time
import pytest
from app.app_config.config_service import ConfService


@pytest.fixture(autouse=True)
def clear_env(monkeypatch):
    """Ensure environment variables do not interfere with defaults."""
    for key in [
        "SERVICE_URL",
        "WALLET_TEST_URL",
        "REVOCATION_SERVICE_URL",
        "REVOKE_SERVICE_URL",
        "EIDAS_NODE_URL",
        "TRUSTED_CAS_PATH",
        "PRIVKEY_PATH",
        "NOUNCE_KEY",
        "CREDENTIAL_KEY",
        "DYNAMIC_PRESENTATION_URL",
    ]:
        monkeypatch.delenv(key, raising=False)


def test_default_service_urls():
    """Test that default URLs are correctly set when env vars are not provided."""
    conf = ConfService()
    assert conf.service_url == "https://backend.issuer.eudiw.dev/"
    assert conf.wallet_test_url == "https://tester.issuer.eudiw.dev/"
    assert conf.revocation_service_url.endswith("/token_status_list/take")
    assert conf.revoke_service_url.endswith("/token_status_list/set")
    assert conf.dynamic_presentation_url.startswith("https://verifier-backend")


def test_env_override(monkeypatch):
    """Test environment variable overrides take precedence."""
    monkeypatch.setenv("SERVICE_URL", "https://example.com/")
    monkeypatch.setenv("WALLET_TEST_URL", "https://wallet.example.com/")
    monkeypatch.setenv("EIDAS_NODE_URL", "https://node.example.com/")

    # Reload class
    from importlib import reload
    import app.app_config.config_service as config_service

    reload(config_service)
    conf = config_service.ConfService()

    assert conf.service_url == "https://example.com/"
    assert conf.wallet_test_url == "https://wallet.example.com/"


def test_registered_claims_keys_exist():
    """Ensure important registered claims are correctly mapped."""
    claims = ConfService.Registered_claims
    assert "birth_date" in claims
    assert "resident_address" in claims
    assert claims["email_address"] == "email"


def test_error_list_contains_known_codes():
    """Check that known error codes are present and have correct descriptions."""
    errors = ConfService.error_list
    assert "-1" in errors
    assert errors["0"] == "No error."
    assert "101" in errors and "Missing mandatory" in errors["101"]
