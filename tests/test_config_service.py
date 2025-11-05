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
    assert conf.service_url == "https://dev.issuer.eudiw.dev/"
    assert conf.wallet_test_url == "https://dev.tester.issuer.eudiw.dev/"
    assert conf.revocation_service_url.endswith("/token_status_list/take")
    assert conf.revoke_service_url.endswith("/token_status_list/set")
    assert conf.eidasnode_url.startswith("https://preprod.")
    assert conf.dynamic_presentation_url.startswith("https://dev.verifier-backend")


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
    assert conf.eidasnode_url == "https://node.example.com/"


def test_registered_claims_keys_exist():
    """Ensure important registered claims are correctly mapped."""
    claims = ConfService.Registered_claims
    assert "birth_date" in claims
    assert "resident_address" in claims
    assert claims["email_address"] == "email"


def test_document_mappings_structure():
    """Verify that each document mapping contains expected keys."""
    mappings = ConfService.document_mappings
    for doc_type, doc_conf in mappings.items():
        assert isinstance(doc_conf, dict)
        assert "formatting_functions" in doc_conf
        assert isinstance(doc_conf["formatting_functions"], dict)


def test_config_doctype_consistency():
    """Ensure that each config_doctype entry has required fields."""
    for key, conf in ConfService.config_doctype.items():
        for required_field in [
            "issuing_authority",
            "organization_id",
            "validity",
            "organization_name",
            "namespace",
        ]:
            assert required_field in conf


from logging.handlers import TimedRotatingFileHandler


def test_error_list_contains_known_codes():
    """Check that known error codes are present and have correct descriptions."""
    errors = ConfService.error_list
    assert "-1" in errors
    assert errors["0"] == "No error."
    assert "101" in errors and "Missing mandatory" in errors["101"]


def test_dynamic_issuing_format():
    """Check structure of dynamic issuing configurations."""
    dynamic = ConfService.dynamic_issuing
    for cred, mapping in dynamic.items():
        assert isinstance(mapping, dict)
        for inner, inner_map in mapping.items():
            assert isinstance(inner_map, dict)
            for ns, claims in inner_map.items():
                assert isinstance(claims, list)
                assert "age_over_18" in claims
