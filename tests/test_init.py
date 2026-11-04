
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
import pytest
import json
from unittest.mock import MagicMock, Mock
from werkzeug.exceptions import NotFound
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

from config_helpers import set_configuration


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def mock_config_service(monkeypatch):
    configuration = {
        "service_url": "https://test-domain.com/",
        "trusted_CAs_path": "/fake/path/to/CAs",
        "frontend": {
            "default": "test_frontend",
            "frontends_config": {
                "test_frontend": { # Minimal mock frontend registry
                    "url": "https://frontend.test"
                }
            }
        },
        "keys":  {
            "credential_encryption_key": b"Key_Sample"
        },
        "logging": {
            "backend_path": "/tmp/log/fakepath.log",
            "log_level": "INFO"
        }
    }
    mock_cfgserv = Mock()
    mock_cfgserv.service_url = "https://test-domain.com/"
    mock_cfgserv.trusted_CAs_path = "/fake/path/to/CAs"
    mock_cfgserv.app_logger = Mock()
    mock_cfgserv.oidc = True
    mock_cfgserv.default_frontend = "test_frontend"
    
    mock_build_credential_encryption_metadata = MagicMock()
    mock_build_credential_encryption_metadata.return_value = 'Sample_Credential_Encryption_Metadata'

    set_configuration(monkeypatch, configuration)
    monkeypatch.setattr("app.services.metadata._build_credential_encryption_metadata", mock_build_credential_encryption_metadata)
    return configuration


@pytest.fixture(autouse=True)
def restore_shared_state():
    """Restores the in-place mutated shared registries after each test."""
    from app.core import state

    names = ("oidc_metadata", "oidc_metadata_clean", "trusted_CAs")
    saved = {name: dict(getattr(state, name)) for name in names}
    yield
    for name, contents in saved.items():
        state.replace_contents(getattr(state, name), contents)


@pytest.fixture
def temp_metadata_dir(tmp_path):
    """Create temporary metadata directory structure"""
    metadata_dir = tmp_path / "metadata_config"
    metadata_dir.mkdir()

    credentials_dir = metadata_dir / "credentials_supported"
    credentials_dir.mkdir()

    # Create sample credential
    credential = {
        "eu.europa.ec.eudi.pid.1": {
            "format": "mso_mdoc",
            "doctype": "eu.europa.ec.eudi.pid.1",
            "issuer_conditions": {"some": "condition"},
            "selective_disclosure": True,
        }
    }
    (credentials_dir / "credential1.json").write_text(json.dumps(credential))

    return metadata_dir


@pytest.fixture
def mock_cert_file(tmp_path):
    """Create a mock certificate file"""
    # Generate a self-signed certificate
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    cert_file = cert_dir / "test_ca.pem"

    from cryptography.hazmat.primitives import serialization

    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    return cert_dir


@pytest.fixture
def app(mock_config_service):
    """Create test Flask app"""
    from app.factory import create_app

    test_config = {"TESTING": True, "SECRET_KEY": "test-secret-key"}

    app = create_app(test_config=test_config)
    yield app


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


# ============================================================================
# UTILITY FUNCTION TESTS
# ============================================================================


class TestRemoveKeys:
    """Test remove_keys function"""

    def test_remove_keys_from_dict(self):
        from app.services.metadata import remove_keys

        obj = {"keep": "value", "remove": "gone", "nested": {"keep": 1, "remove": 2}}
        result = remove_keys(obj, {"remove"})

        assert result == {"keep": "value", "nested": {"keep": 1}}
        assert "remove" not in result

    def test_remove_keys_from_list(self):
        from app.services.metadata import remove_keys

        obj = [{"keep": 1, "remove": 2}, {"keep": 3, "remove": 4}]
        result = remove_keys(obj, {"remove"})

        assert result == [{"keep": 1}, {"keep": 3}]

    def test_remove_keys_empty_dict(self):
        from app.services.metadata import remove_keys

        obj = {"remove1": "value", "remove2": "value"}
        result = remove_keys(obj, {"remove1", "remove2"})

        assert result is None

    def test_remove_keys_nested_structure(self):
        from app.services.metadata import remove_keys

        obj = {"level1": {"level2": {"keep": "value", "remove": "gone"}}}
        result = remove_keys(obj, {"remove"})

        assert result == {"level1": {"level2": {"keep": "value"}}}

    def test_remove_keys_primitive_value(self):
        from app.services.metadata import remove_keys

        assert remove_keys("string", {"key"}) == "string"
        assert remove_keys(123, {"key"}) == 123
        assert remove_keys(None, {"key"}) is None


class TestReplaceDomain:
    """Test replace_domain function"""

    def test_replace_domain_in_string(self):
        from app.services.metadata import replace_domain

        result = replace_domain("https://old.com/path", "old.com", "new.com")
        assert result == "https://new.com/path"

    def test_replace_domain_in_dict(self):
        from app.services.metadata import replace_domain

        obj = {"url": "https://old.com", "endpoint": "https://old.com/api"}
        result = replace_domain(obj, "old.com", "new.com")

        assert result["url"] == "https://new.com"
        assert result["endpoint"] == "https://new.com/api"

    def test_replace_domain_in_list(self):
        from app.services.metadata import replace_domain

        obj = ["https://old.com/path1", "https://old.com/path2"]
        result = replace_domain(obj, "old.com", "new.com")

        assert result[0] == "https://new.com/path1"
        assert result[1] == "https://new.com/path2"

    def test_replace_domain_nested(self):
        from app.services.metadata import replace_domain

        obj = {"urls": ["https://old.com", {"nested": "https://old.com/api"}]}
        result = replace_domain(obj, "old.com", "new.com")

        assert result["urls"][0] == "https://new.com"
        assert result["urls"][1]["nested"] == "https://new.com/api"

    def test_replace_domain_no_match(self):
        from app.services.metadata import replace_domain

        obj = "https://other.com"
        result = replace_domain(obj, "old.com", "new.com")

        assert result == "https://other.com"

    def test_replace_domain_primitive_values(self):
        from app.services.metadata import replace_domain

        assert replace_domain(123, "old", "new") == 123
        assert replace_domain(None, "old", "new") is None


# ============================================================================
# METADATA SETUP TESTS
# ============================================================================


class TestSetupMetadata:
    """Test setup_metadata function"""

    def test_setup_metadata_success(self, temp_metadata_dir, mock_config_service):
        """Test successful metadata setup"""
        from app.core import state
        from app.services.metadata import setup_metadata

        setup_metadata(metadata_dir=temp_metadata_dir)

        # Verify metadata was loaded into the shared state (in place)
        assert list(state.oidc_metadata["credential_configurations_supported"]) == ["eu.europa.ec.eudi.pid.1"]
        assert (
            state.oidc_metadata_clean["credential_request_encryption"]
            == "Sample_Credential_Encryption_Metadata"
        )

    def test_setup_metadata_file_not_found(self, tmp_path, mock_config_service):
        """Test metadata setup with missing files"""
        from app.services.metadata import setup_metadata

        # Point to a non-existent directory
        with pytest.raises(FileNotFoundError):
            setup_metadata(metadata_dir=tmp_path / "metadata_config")

    def test_setup_metadata_invalid_json(self, tmp_path, mock_config_service):
        """Test metadata setup with invalid JSON"""
        from app.services.metadata import setup_metadata

        metadata_dir = tmp_path / "metadata_config"
        metadata_dir.mkdir()

        # Create invalid JSON file
        (metadata_dir / "credentials_supported").mkdir()
        (metadata_dir / "credentials_supported" / "broken.json").write_text("{invalid json")

        with pytest.raises(json.JSONDecodeError):
            setup_metadata(metadata_dir=metadata_dir)

    def test_setup_metadata_contents(self, temp_metadata_dir, mock_config_service):
        """Only credential configurations (+ request encryption) are loaded; templates are per frontend"""
        from app.core import state
        from app.services.metadata import setup_metadata

        setup_metadata(metadata_dir=temp_metadata_dir)

        assert set(state.oidc_metadata) == {"credential_configurations_supported"}
        assert set(state.oidc_metadata_clean) == {
            "credential_configurations_supported",
            "credential_request_encryption",
        }

    def test_setup_metadata_clean_removes_keys(self, temp_metadata_dir, mock_config_service):
        """Test that oidc_metadata_clean removes issuer only keys"""
        from app.core import state
        from app.services.metadata import setup_metadata

        setup_metadata(metadata_dir=temp_metadata_dir)

        # Check that issuer only keys are removed from clean version
        credentials = state.oidc_metadata_clean["credential_configurations_supported"]
        first_cred = list(credentials.values())[0]
        assert "issuer_conditions" not in first_cred
        assert "selective_disclosure" not in first_cred

        # ...but kept in the full (internal) version
        full_cred = state.oidc_metadata["credential_configurations_supported"][
            "eu.europa.ec.eudi.pid.1"
        ]
        assert "issuer_conditions" in full_cred


# ============================================================================
# TRUSTED CAs SETUP TESTS
# ============================================================================


class TestSetupTrustedCAs:
    """Test setup_trusted_cas function"""

    def test_setup_trusted_cas_success(self, mock_cert_file, mock_config_service):
        """Test successful CA setup (path from CONFIGURATION)"""
        from app.core import state
        from app.services.metadata import setup_trusted_cas

        mock_config_service["trusted_CAs_path"] = str(mock_cert_file)

        setup_trusted_cas()

        # Verify CAs were loaded
        assert len(state.trusted_CAs) == 1
        ca_info = list(state.trusted_CAs.values())[0]
        assert {"certificate", "public_key", "not_valid_before", "not_valid_after"} == set(ca_info)

    def test_setup_trusted_cas_explicit_path(self, mock_cert_file, mock_config_service):
        """Test CA setup with an explicit directory argument"""
        from app.core import state
        from app.services.metadata import setup_trusted_cas

        setup_trusted_cas(trusted_cas_path=str(mock_cert_file))

        assert len(state.trusted_CAs) == 1

    def test_setup_trusted_cas_file_not_found(self, mock_config_service):
        """Test CA setup with missing directory"""
        from app.services.metadata import setup_trusted_cas

        mock_config_service["trusted_CAs_path"] = "/nonexistent/path"

        with pytest.raises(FileNotFoundError):
            setup_trusted_cas()

    def test_setup_trusted_cas_invalid_cert(self, tmp_path, mock_config_service):
        """Test CA setup with invalid certificate"""
        from app.services.metadata import setup_trusted_cas

        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        (cert_dir / "invalid.pem").write_text("not a valid certificate")

        with pytest.raises(Exception):
            setup_trusted_cas(trusted_cas_path=str(cert_dir))


# ============================================================================
# ERROR HANDLER TESTS
# ============================================================================


class TestErrorHandlers:
    """Test error handler functions"""

    def test_handle_exception_with_http_exception(self, app, mock_config_service):
        """Test that HTTP exceptions are passed through"""
        from app.core.errors import handle_exception

        error = NotFound()
        with app.app_context():
            with app.test_request_context():
                result = handle_exception(error)

        assert isinstance(result, NotFound)

    def test_handle_exception_with_generic_exception(self, app, mock_config_service):
        """Test handling of generic exceptions"""
        from app.core.errors import handle_exception

        error = ValueError("Test error")
        with app.app_context():
            with app.test_request_context():
                result = handle_exception(error)

        assert isinstance(result, tuple)
        
        response = result[0]
        
        assert result[1] == 500
        assert b'error' in response.data
        
        parsed_response = json.loads(response.data.decode('utf-8'))
        
        assert parsed_response.get('error') == 'Internal Server Error'
        

    def test_page_not_found_handler(self, client, mock_config_service):
        """Test 404 error handler"""
        response = client.get("/nonexistent-route-12345")

        assert response.status_code == 404
        assert b"error" in response.data
        
        parsed_response = json.loads(response.data.decode('utf-8'))
        
        assert parsed_response.get('error') == 'Not Found'


# ============================================================================
# FLASK APP TESTS
# ============================================================================


class TestCreateApp:
    """Test Flask app creation"""

    def test_create_app_with_default_config(self, mock_config_service):
        """Test app creation with default config"""
        from app.factory import create_app

        app = create_app()

        assert app is not None
        # No key configured: tests get a random one, never a known default.
        assert app.config["SECRET_KEY"] != "dev" and len(app.config["SECRET_KEY"]) >= 32

    def test_create_app_with_test_config(self, mock_config_service):
        """Test app creation with test config"""
        from app.factory import create_app

        test_config = {"TESTING": True, "SECRET_KEY": "test-key"}
        app = create_app(test_config=test_config)

        assert app is not None
        assert app.config["TESTING"] is True
        assert app.config["SECRET_KEY"] == "test-key"

    def test_create_app_blueprints_registered(self, app):
        """Test that all blueprints are registered"""
        assert "formatter" not in app.blueprints
        assert "oidc" in app.blueprints
        assert "revocation" in app.blueprints
        assert "oid4vp" in app.blueprints
        assert "dynamic" in app.blueprints
        assert "preauth" in app.blueprints

    def test_create_app_error_handlers_registered(self, app):
        """Test that error handlers are registered"""
        assert 404 in app.error_handler_spec[None]
        assert None in app.error_handler_spec[None]

    def test_create_app_session_config(self, app):
        """Test session configuration"""
        assert app.config["SESSION_TYPE"] == "filesystem"
        assert app.config["SESSION_PERMANENT"] is False
        assert app.config["SESSION_COOKIE_SAMESITE"] == "None"
        assert app.config["SESSION_COOKIE_SECURE"] is True

    def test_session_cookie_samesite_configurable(self, mock_config_service):
        """session_cookie_samesite overrides the default (None) when frontends share the site"""
        from app.factory import create_app

        mock_config_service["session_cookie_samesite"] = "Lax"
        app = create_app(test_config={"TESTING": True, "SECRET_KEY": "k"})

        assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"

    def test_nosniff_header_on_every_response(self, client):
        """X-Content-Type-Options: nosniff is added to all responses, errors included"""
        assert client.get("/").headers["X-Content-Type-Options"] == "nosniff"
        assert client.get("/does-not-exist").headers["X-Content-Type-Options"] == "nosniff"


# ============================================================================
# ROUTE TESTS
# ============================================================================


class TestRoutes:
    """Test basic routes"""

    def test_initial_page_route(self, client, mock_config_service):
        """Test initial page route"""
        response = client.get("/")

        assert response.status_code == 200

# ============================================================================
# SESSION MANAGER TESTS
# ============================================================================


class TestSessionManager:
    """Test session manager initialization"""

    def test_session_manager_exists(self):
        """Test that session manager is initialized"""
        from app.core.state import session_manager
        from app.repositories.session_store import SessionManager

        assert isinstance(session_manager, SessionManager)

    def test_session_manager_has_expiry(self):
        """Test that session manager has default expiry"""
        from app.core.state import session_manager

        assert hasattr(session_manager, "default_expiry_minutes")


# ============================================================================
# GLOBAL VARIABLES TESTS
# ============================================================================


class TestGlobalVariables:
    """Test global (shared state) variables initialization"""

    def test_metadata_globals_exist(self):
        """Test that metadata globals exist"""
        from app.core import state

        for name in ("oidc_metadata", "oidc_metadata_clean"):
            assert isinstance(getattr(state, name), dict)
        # The backend no longer serves its own OpenID / OAuth metadata.
        assert not hasattr(state, "openid_metadata")
        assert not hasattr(state, "oauth_metadata")

    def test_trusted_cas_global_exists(self):
        """Test that trusted_CAs global exists"""
        from app.core import state

        assert isinstance(state.trusted_CAs, dict)

    def test_is_test_env_detection(self):
        """IS_TEST_ENV is on: .env.test sets EUDIW_TEST_ENV=true"""
        from app.core import config

        assert config._detect_test_env() is True
        assert config.IS_TEST_ENV is True

    def test_app_package_reexports_create_app(self):
        """app/__init__ only re-exports the factory"""
        import app
        from app.factory import create_app

        assert app.create_app is create_app


# ============================================================================
# INTEGRATION TESTS
# ============================================================================


class TestIntegration:
    """Integration tests"""

    def test_full_app_startup(self, mock_config_service):
        """Test complete app startup sequence"""
        from app.factory import create_app

        app = create_app(test_config={"TESTING": True})

        # Verify app is fully configured
        assert app is not None
        assert len(app.blueprints) > 0
        # Background services / trusted CAs are disabled under pytest
        assert app.config["INIT_BACKGROUND_SERVICES"] is False
        assert app.config["LOAD_TRUSTED_CAS"] is False

    def test_metadata_and_app_integration(self, temp_metadata_dir, mock_config_service):
        """Test that metadata is visible through modules that imported state"""
        from app.core import state
        from app.core.state import oidc_metadata
        from app.services.metadata import setup_metadata

        setup_metadata(metadata_dir=temp_metadata_dir)

        # Verify metadata is accessible (same dict object, mutated in place)
        assert oidc_metadata is state.oidc_metadata
        assert "eu.europa.ec.eudi.pid.1" in oidc_metadata["credential_configurations_supported"]


# ============================================================================
# CORS
# ============================================================================


class TestCors:
    """Cross-origin access is limited to the configured frontends."""

    def test_frontend_origin_allowed_with_credentials(self, client):
        response = client.get("/", headers={"Origin": "https://frontend.test"})

        assert response.headers["Access-Control-Allow-Origin"] == "https://frontend.test"
        assert response.headers["Access-Control-Allow-Credentials"] == "true"

    def test_preflight_from_frontend(self, client):
        response = client.options(
            "/pid_authorization",
            headers={"Origin": "https://frontend.test", "Access-Control-Request-Method": "GET"},
        )

        assert response.headers["Access-Control-Allow-Origin"] == "https://frontend.test"

    def test_unknown_origin_gets_no_cors_headers(self, client):
        response = client.get("/", headers={"Origin": "https://evil.example"})

        assert "Access-Control-Allow-Origin" not in response.headers
        assert "Access-Control-Allow-Credentials" not in response.headers

    def test_extra_configured_origin(self, mock_config_service):
        from app.factory import create_app

        mock_config_service["cors_allowed_origins"] = ["https://tester.example/some/path"]
        client = create_app(test_config={"TESTING": True}).test_client()

        response = client.get("/", headers={"Origin": "https://tester.example"})
        assert response.headers["Access-Control-Allow-Origin"] == "https://tester.example"

    def test_allowed_origins_derived_from_config(self, mock_config_service):
        from app.utils.frontend import allowed_cors_origins

        mock_config_service["frontend"]["frontends_config"]["second"] = {"url": "https://second.test:8443/issuer"}
        mock_config_service["cors_allowed_origins"] = ["https://frontend.test", "not-a-url"]

        assert allowed_cors_origins() == ["https://frontend.test", "https://second.test:8443"]


class TestTrustedCaKeyTypes:
    """CA certificates of any key type load (only EC was accepted before)."""

    def test_rsa_and_ec_cas_load(self, tmp_path, mock_config_service):
        from cryptography.hazmat.primitives.asymmetric import rsa

        from app.core import state
        from app.services.metadata import setup_trusted_cas
        from pki_helpers import make_cert

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ec_key = ec.generate_private_key(ec.SECP256R1())
        for name, key in (("RSA Root", rsa_key), ("EC Root", ec_key)):
            cert = make_cert(name, name, key.public_key(), key, ca=True)
            (tmp_path / f"{name.replace(' ', '_')}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        setup_trusted_cas(trusted_cas_path=str(tmp_path))

        assert {subject.rfc4514_string() for subject in state.trusted_CAs} == {"CN=RSA Root", "CN=EC Root"}
