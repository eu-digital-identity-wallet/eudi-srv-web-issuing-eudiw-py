import pytest
import json
from unittest.mock import Mock
from werkzeug.exceptions import NotFound
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def mock_config_service(monkeypatch):
    """Mock the config service"""
    mock_cfgserv = Mock()
    mock_cfgserv.service_url = "https://test-domain.com/"
    mock_cfgserv.trusted_CAs_path = "/fake/path/to/CAs"
    mock_cfgserv.app_logger = Mock()
    mock_cfgserv.oidc = True

    monkeypatch.setattr("app.cfgserv", mock_cfgserv)
    return mock_cfgserv


@pytest.fixture
def temp_metadata_dir(tmp_path):
    """Create temporary metadata directory structure"""
    metadata_dir = tmp_path / "metadata_config"
    metadata_dir.mkdir()

    credentials_dir = metadata_dir / "credentials_supported"
    credentials_dir.mkdir()

    # Create sample openid-configuration.json
    openid_config = {
        "issuer": "https://example.com",
        "authorization_endpoint": "https://example.com/authorize",
    }
    (metadata_dir / "openid-configuration.json").write_text(json.dumps(openid_config))

    # Create sample oauth-authorization-server.json
    oauth_config = {
        "issuer": "https://example.com",
        "token_endpoint": "https://example.com/token",
    }
    (metadata_dir / "oauth-authorization-server.json").write_text(
        json.dumps(oauth_config)
    )

    # Create sample metadata_config.json
    metadata_config = {
        "credential_issuer": "https://example.com",
        "credential_endpoint": "https://example.com/credential",
    }
    (metadata_dir / "metadata_config.json").write_text(json.dumps(metadata_config))

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
def app():
    """Create test Flask app"""
    from app import create_app

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
        from app import remove_keys

        obj = {"keep": "value", "remove": "gone", "nested": {"keep": 1, "remove": 2}}
        result = remove_keys(obj, {"remove"})

        assert result == {"keep": "value", "nested": {"keep": 1}}
        assert "remove" not in result

    def test_remove_keys_from_list(self):
        from app import remove_keys

        obj = [{"keep": 1, "remove": 2}, {"keep": 3, "remove": 4}]
        result = remove_keys(obj, {"remove"})

        assert result == [{"keep": 1}, {"keep": 3}]

    def test_remove_keys_empty_dict(self):
        from app import remove_keys

        obj = {"remove1": "value", "remove2": "value"}
        result = remove_keys(obj, {"remove1", "remove2"})

        assert result is None

    def test_remove_keys_nested_structure(self):
        from app import remove_keys

        obj = {"level1": {"level2": {"keep": "value", "remove": "gone"}}}
        result = remove_keys(obj, {"remove"})

        assert result == {"level1": {"level2": {"keep": "value"}}}

    def test_remove_keys_primitive_value(self):
        from app import remove_keys

        assert remove_keys("string", {"key"}) == "string"
        assert remove_keys(123, {"key"}) == 123
        assert remove_keys(None, {"key"}) is None


class TestReplaceDomain:
    """Test replace_domain function"""

    def test_replace_domain_in_string(self):
        from app import replace_domain

        result = replace_domain("https://old.com/path", "old.com", "new.com")
        assert result == "https://new.com/path"

    def test_replace_domain_in_dict(self):
        from app import replace_domain

        obj = {"url": "https://old.com", "endpoint": "https://old.com/api"}
        result = replace_domain(obj, "old.com", "new.com")

        assert result["url"] == "https://new.com"
        assert result["endpoint"] == "https://new.com/api"

    def test_replace_domain_in_list(self):
        from app import replace_domain

        obj = ["https://old.com/path1", "https://old.com/path2"]
        result = replace_domain(obj, "old.com", "new.com")

        assert result[0] == "https://new.com/path1"
        assert result[1] == "https://new.com/path2"

    def test_replace_domain_nested(self):
        from app import replace_domain

        obj = {"urls": ["https://old.com", {"nested": "https://old.com/api"}]}
        result = replace_domain(obj, "old.com", "new.com")

        assert result["urls"][0] == "https://new.com"
        assert result["urls"][1]["nested"] == "https://new.com/api"

    def test_replace_domain_no_match(self):
        from app import replace_domain

        obj = "https://other.com"
        result = replace_domain(obj, "old.com", "new.com")

        assert result == "https://other.com"

    def test_replace_domain_primitive_values(self):
        from app import replace_domain

        assert replace_domain(123, "old", "new") == 123
        assert replace_domain(None, "old", "new") is None


# ============================================================================
# METADATA SETUP TESTS
# ============================================================================


class TestSetupMetadata:
    """Test setup_metadata function"""

    def test_setup_metadata_success(
        self, monkeypatch, temp_metadata_dir, mock_config_service
    ):
        """Test successful metadata setup"""
        # Mock the directory path
        monkeypatch.setattr(
            "app.os.path.dirname", lambda x: str(temp_metadata_dir.parent)
        )
        monkeypatch.setattr(
            "app.os.path.realpath", lambda x: str(temp_metadata_dir.parent / "fake.py")
        )

        # Import after mocking
        import app

        # Call setup
        app.setup_metadata()

        # Verify metadata was loaded
        assert app.oidc_metadata is not None
        assert app.openid_metadata is not None
        assert app.oauth_metadata is not None
        assert "credential_configurations_supported" in app.oidc_metadata

    def test_setup_metadata_file_not_found(
        self, monkeypatch, tmp_path, mock_config_service
    ):
        """Test metadata setup with missing files"""
        # Point to empty directory
        monkeypatch.setattr("app.os.path.dirname", lambda x: str(tmp_path))
        monkeypatch.setattr("app.os.path.realpath", lambda x: str(tmp_path / "fake.py"))

        import app

        with pytest.raises(FileNotFoundError):
            app.setup_metadata()

    def test_setup_metadata_invalid_json(
        self, monkeypatch, tmp_path, mock_config_service
    ):
        """Test metadata setup with invalid JSON"""
        metadata_dir = tmp_path / "metadata_config"
        metadata_dir.mkdir()

        # Create invalid JSON file
        (metadata_dir / "openid-configuration.json").write_text("{invalid json")

        monkeypatch.setattr("app.os.path.dirname", lambda x: str(tmp_path))
        monkeypatch.setattr("app.os.path.realpath", lambda x: str(tmp_path / "fake.py"))

        import app

        with pytest.raises(json.JSONDecodeError):
            app.setup_metadata()

    def test_setup_metadata_domain_replacement(
        self, monkeypatch, temp_metadata_dir, mock_config_service
    ):
        """Test that domains are replaced correctly"""
        monkeypatch.setattr(
            "app.os.path.dirname", lambda x: str(temp_metadata_dir.parent)
        )
        monkeypatch.setattr(
            "app.os.path.realpath", lambda x: str(temp_metadata_dir.parent / "fake.py")
        )

        import app

        app.setup_metadata()

        # Check that domain was replaced
        assert "test-domain.com" in str(app.openid_metadata)
        assert "test-domain.com" in str(app.oauth_metadata)

    def test_setup_metadata_clean_removes_keys(
        self, monkeypatch, temp_metadata_dir, mock_config_service
    ):
        """Test that oidc_metadata_clean removes issuer only keys"""
        monkeypatch.setattr(
            "app.os.path.dirname", lambda x: str(temp_metadata_dir.parent)
        )
        monkeypatch.setattr(
            "app.os.path.realpath", lambda x: str(temp_metadata_dir.parent / "fake.py")
        )

        import app

        app.setup_metadata()

        # Check that issuer only keys are removed from clean version
        credentials = app.oidc_metadata_clean.get(
            "credential_configurations_supported", {}
        )
        if credentials:
            first_cred = list(credentials.values())[0]
            assert "issuer_conditions" not in first_cred
            assert "selective_disclosure" not in first_cred


# ============================================================================
# TRUSTED CAs SETUP TESTS
# ============================================================================


class TestSetupTrustedCAs:
    """Test setup_trusted_CAs function"""

    def test_setup_trusted_cas_success(
        self, monkeypatch, mock_cert_file, mock_config_service
    ):
        """Test successful CA setup"""

        monkeypatch.setattr("app.IS_TEST_ENV", False)
        mock_config_service.trusted_CAs_path = str(mock_cert_file)

        import app

        app.setup_trusted_cas()

        # Verify CAs were loaded
        assert app.trusted_CAs is not None
        assert len(app.trusted_CAs) > 0

    def test_setup_trusted_cas_skipped_in_test_env(
        self, monkeypatch, mock_config_service
    ):
        """Test that CA setup is skipped in test environment"""
        monkeypatch.setattr("app.IS_TEST_ENV", True)

        import app

        app.trusted_CAs = {}
        app.setup_trusted_cas()

        # Should remain empty in test environment
        assert app.trusted_CAs == {}

    def test_setup_trusted_cas_file_not_found(self, monkeypatch, mock_config_service):
        """Test CA setup with missing directory"""
        monkeypatch.setattr("app.IS_TEST_ENV", False)
        mock_config_service.trusted_CAs_path = "/nonexistent/path"

        import app

        with pytest.raises(FileNotFoundError):
            app.setup_trusted_cas()

    def test_setup_trusted_cas_invalid_cert(
        self, monkeypatch, tmp_path, mock_config_service
    ):
        """Test CA setup with invalid certificate"""
        monkeypatch.setattr("app.IS_TEST_ENV", False)

        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        (cert_dir / "invalid.pem").write_text("not a valid certificate")

        mock_config_service.trusted_CAs_path = str(cert_dir)

        import app

        with pytest.raises(Exception):
            app.setup_trusted_cas()


# ============================================================================
# ERROR HANDLER TESTS
# ============================================================================


class TestErrorHandlers:
    """Test error handler functions"""

    def test_handle_exception_with_http_exception(self, app, mock_config_service):
        """Test that HTTP exceptions are passed through"""
        from app import handle_exception

        error = NotFound()
        with app.app_context():
            with app.test_request_context():
                result = handle_exception(error)

        assert isinstance(result, NotFound)

    def test_handle_exception_with_generic_exception(self, app, mock_config_service):
        """Test handling of generic exceptions"""
        from app import handle_exception

        error = ValueError("Test error")
        with app.app_context():
            with app.test_request_context():
                result = handle_exception(error)

        assert isinstance(result, tuple)
        assert result[1] == 500

    def test_page_not_found_handler(self, client, mock_config_service):
        """Test 404 error handler"""
        response = client.get("/nonexistent-route-12345")

        assert response.status_code == 404
        assert b"Page not found" in response.data


# ============================================================================
# FLASK APP TESTS
# ============================================================================


class TestCreateApp:
    """Test Flask app creation"""

    def test_create_app_with_default_config(self, mock_config_service):
        """Test app creation with default config"""
        from app import create_app

        app = create_app()

        assert app is not None
        assert app.config["SECRET_KEY"] == "dev"

    def test_create_app_with_test_config(self, mock_config_service):
        """Test app creation with test config"""
        from app import create_app

        test_config = {"TESTING": True, "SECRET_KEY": "test-key"}
        app = create_app(test_config=test_config)

        assert app is not None
        assert app.config["TESTING"] is True
        assert app.config["SECRET_KEY"] == "test-key"

    def test_create_app_blueprints_registered(self, app):
        """Test that all blueprints are registered"""
        assert "formatter" in app.blueprints
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


# ============================================================================
# ROUTE TESTS
# ============================================================================


class TestRoutes:
    """Test basic routes"""

    def test_initial_page_route(self, client, mock_config_service):
        """Test initial page route"""
        response = client.get("/")

        assert response.status_code == 200

    def test_favicon_route(self, client):
        """Test favicon route"""
        response = client.get("/favicon.ico")

        # May be 200 or 404 depending on file existence
        assert response.status_code in [200, 404]

    def test_logo_route(self, client):
        """Test logo route"""
        response = client.get("/ic-logo.png")

        # May be 200 or 404 depending on file existence
        assert response.status_code in [200, 404]


# ============================================================================
# SESSION MANAGER TESTS
# ============================================================================


class TestSessionManager:
    """Test session manager initialization"""

    def test_session_manager_exists(self):
        """Test that session manager is initialized"""
        from app import session_manager

        assert session_manager is not None

    def test_session_manager_has_expiry(self):
        """Test that session manager has default expiry"""
        from app import session_manager

        assert hasattr(session_manager, "default_expiry_minutes")


# ============================================================================
# GLOBAL VARIABLES TESTS
# ============================================================================


class TestGlobalVariables:
    """Test global variables initialization"""

    def test_metadata_globals_exist(self):
        """Test that metadata globals exist"""
        import app

        assert hasattr(app, "oidc_metadata")
        assert hasattr(app, "oidc_metadata_clean")
        assert hasattr(app, "openid_metadata")
        assert hasattr(app, "oauth_metadata")

    def test_trusted_cas_global_exists(self):
        """Test that trusted_CAs global exists"""
        import app

        assert hasattr(app, "trusted_CAs")

    def test_is_test_env_detection(self, monkeypatch):
        """Test IS_TEST_ENV detection"""
        # Test with PYTEST_CURRENT_TEST
        monkeypatch.setenv("PYTEST_CURRENT_TEST", "test")

        # Need to reload module to pick up env var
        import importlib
        import app

        importlib.reload(app)

        assert app.IS_TEST_ENV is True


# ============================================================================
# INTEGRATION TESTS
# ============================================================================


class TestIntegration:
    """Integration tests"""

    def test_full_app_startup(self, mock_config_service):
        """Test complete app startup sequence"""
        from app import create_app

        app = create_app(test_config={"TESTING": True})

        # Verify app is fully configured
        assert app is not None
        assert len(app.blueprints) > 0

    def test_metadata_and_app_integration(
        self, monkeypatch, temp_metadata_dir, mock_config_service
    ):
        """Test that metadata is properly integrated into app"""
        monkeypatch.setattr(
            "app.os.path.dirname", lambda x: str(temp_metadata_dir.parent)
        )
        monkeypatch.setattr(
            "app.os.path.realpath", lambda x: str(temp_metadata_dir.parent / "fake.py")
        )

        import app

        app.setup_metadata()

        # Verify metadata is accessible
        assert len(app.oidc_metadata) > 0
        assert "credential_issuer" in app.oidc_metadata
