# coding: utf-8
"""
Pytest test suite for route_oidc.py

Tests cover:
- Well-known endpoints
- Credential issuance flow
- Authentication and authorization
- Token introspection
- Encryption/decryption
- Error handling
"""

import pytest
import json
import base64
import uuid
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from io import BytesIO

from flask import Flask, session
from jwcrypto import jwk, jwe
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


@pytest.fixture
def app():
    """Create Flask app for testing"""
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key"

    # Import and register blueprint
    with patch("app.route_oidc.cfgservice"), patch(
        "app.route_oidc.ConfFrontend"
    ), patch("app.route_oidc.session_manager"):
        from app.route_oidc import oidc

        app.register_blueprint(oidc)

    return app


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


@pytest.fixture
def mock_session_manager():
    """Mock session manager"""
    with patch("app.route_oidc.session_manager") as mock:
        mock_session = Mock()
        mock_session.transaction_id = {}
        mock_session.session_id = "test-session-id"
        mock.get_session.return_value = mock_session
        mock.add_session.return_value = None
        mock.update_is_batch_credential.return_value = None
        mock.store_notification_id.return_value = None
        yield mock


@pytest.fixture
def mock_cfgservice():
    """Mock configuration service"""
    with patch("app.route_oidc.cfgservice") as mock:
        mock.service_url = "https://test.issuer.dev/"
        mock.wallet_test_url = "https://test.wallet.dev/"
        mock.form_expiry = 10
        mock.nonce_key = "test-key.pem"
        mock.credential_request_priv_key = "test-priv-key.pem"
        mock.dynamic_presentation_url = "https://test.presentation.dev/"
        mock.auth_method_supported_credencials = {
            "PID_login": ["eu.europa.ec.eudi.pid_mdoc"],
            "country_selection": ["eu.europa.ec.eudi.mdl"],
        }
        mock.default_frontend = "test_frontend"
        mock.app_logger = Mock()
        yield mock


@pytest.fixture(autouse=True)
def mock_conf_frontend(monkeypatch):
    """Mock ConfFrontend registry"""
    mock_conf = type(
        "MockConfFrontend",
        (),
        {
            "registered_frontends": {
                "test_frontend": {"url": "https://frontend.example.com"}
            }
        },
    )()
    monkeypatch.setattr("app.route_oidc.ConfFrontend", mock_conf)


class TestWellKnownEndpoints:
    """Test well-known configuration endpoints"""

    def test_well_known_openid_credential_issuer(self, client):
        """Test /.well-known/openid-credential-issuer endpoint"""
        with patch("app.route_oidc.oidc_metadata_clean", {"issuer": "test"}):
            response = client.get("/.well-known/openid-credential-issuer")

            assert response.status_code == 200
            assert response.headers["Content-Type"] == "application/json"
            assert response.headers["Cache-Control"] == "no-store"
            assert response.json == {"issuer": "test"}

    def test_well_known_oauth_authorization_server(self, client):
        """Test /.well-known/oauth-authorization-server endpoint"""
        with patch(
            "app.route_oidc.openid_metadata", {"authorization_endpoint": "test"}
        ):
            response = client.get("/.well-known/oauth-authorization-server")

            assert response.status_code == 200
            assert response.json == {"authorization_endpoint": "test"}

    def test_well_known_openid_configuration(self, client):
        """Test /.well-known/openid-configuration endpoint"""
        with patch("app.route_oidc.openid_metadata", {"issuer": "test"}):
            response = client.get("/.well-known/openid-configuration")

            assert response.status_code == 200
            assert response.json == {"issuer": "test"}

    def test_well_known_unsupported_service(self, client):
        """Test unsupported well-known service"""
        response = client.get("/.well-known/unsupported-service")

        assert response.status_code == 400
        assert b"Not supported" in response.data


class TestAuthChoice:
    """Test authentication choice endpoint"""

    def test_auth_choice_with_scope(
        self, client, mock_session_manager, mock_cfgservice
    ):
        """Test auth_choice with scope parameter"""
        with patch("app.route_oidc.ConfFrontend") as mock_frontend:
            mock_frontend.registered_frontends = {
                "5d725b3c-6d42-448e-8bfd-1eff1fcf152d": {
                    "url": "https://test.frontend.dev"
                }
            }

            response = client.get(
                "/auth_choice",
                query_string={
                    "token": "test-token",
                    "session_id": "test-session",
                    "scope": "openid eu.europa.ec.eudi.pid_mdoc",
                },
            )

            # Should redirect to auth method display
            assert response.status_code in [200, 302]

    def test_auth_choice_with_authorization_details(
        self, client, mock_session_manager, mock_cfgservice
    ):
        """Test auth_choice with authorization_details"""
        auth_details = json.dumps(
            [{"credential_configuration_id": "eu.europa.ec.eudi.pid_mdoc"}]
        )

        with patch("app.route_oidc.ConfFrontend") as mock_frontend:
            mock_frontend.registered_frontends = {
                "5d725b3c-6d42-448e-8bfd-1eff1fcf152d": {
                    "url": "https://test.frontend.dev"
                }
            }

            response = client.get(
                "/auth_choice",
                query_string={
                    "token": "test-token",
                    "session_id": "test-session",
                    "authorization_details": json.dumps(auth_details),
                },
            )

            assert response.status_code in [200, 302]


class TestCredentialEndpoint:
    """Test credential issuance endpoint"""

    def test_credential_missing_authorization(self, client):
        """Test credential endpoint without authorization header"""
        response = client.post(
            "/credential", json={"credential_configuration_id": "test-cred"}
        )

        assert response.status_code == 401
        assert response.json["error"] == "invalid_request"

    def test_credential_invalid_bearer_format(self, client):
        """Test credential endpoint with invalid bearer format"""
        response = client.post(
            "/credential",
            headers={"Authorization": "InvalidFormat token"},
            json={"credential_configuration_id": "test-cred"},
        )

        assert response.status_code == 401
        assert response.json["error"] == "invalid_token"

    @patch("app.route_oidc.verify_introspection")
    def test_credential_invalid_token(self, mock_introspect, client):
        """Test credential endpoint with invalid token"""
        mock_introspect.return_value = ({"error": "invalid_token"}, 401)

        response = client.post(
            "/credential",
            headers={"Authorization": "Bearer invalid-token"},
            json={"credential_configuration_id": "test-cred"},
        )

        assert response.status_code == 401

    @patch("app.route_oidc.verify_introspection")
    @patch("app.route_oidc.generate_credentials")
    def test_credential_success(
        self, mock_generate, mock_introspect, client, mock_cfgservice
    ):
        """Test successful credential issuance"""
        mock_introspect.return_value = "test-session-id"
        mock_generate.return_value = {"credential": "test-credential-data"}

        with patch("app.route_oidc.session_manager") as mock_sm:
            mock_session = Mock()
            mock_sm.get_session.return_value = mock_session

            response = client.post(
                "/credential",
                headers={"Authorization": "Bearer valid-token"},
                json={
                    "credential_configuration_id": "test-cred",
                    "proof": {"proof_type": "jwt", "jwt": "test-jwt"},
                },
            )

            assert response.status_code == 200
            assert "notification_id" in response.json

    @patch("app.route_oidc.verify_introspection")
    @patch("app.route_oidc.generate_credentials")
    def test_credential_deferred(
        self, mock_generate, mock_introspect, client, mock_cfgservice
    ):
        """Test deferred credential response"""
        mock_introspect.return_value = "test-session-id"
        mock_generate.return_value = {"error": "Pending"}

        with patch("app.route_oidc.session_manager") as mock_sm:
            mock_session = Mock()
            mock_sm.get_session.return_value = mock_session

            response = client.post(
                "/credential",
                headers={"Authorization": "Bearer valid-token"},
                json={
                    "credential_configuration_id": "test-cred",
                    "proof": {"proof_type": "jwt", "jwt": "test-jwt"},
                },
            )

            assert response.status_code == 202
            assert "transaction_id" in response.json


class TestVerifyIntrospection:
    """Test token introspection verification"""

    @patch("requests.request")
    def test_verify_introspection_success(self, mock_request, app):
        """Test successful token introspection"""
        from app.route_oidc import verify_introspection

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"active": True, "username": "test-user"}
        mock_request.return_value = mock_response

        with app.app_context():
            result = verify_introspection("valid-token")

        assert result == "test-user"

    @patch("requests.request")
    def test_verify_introspection_inactive_token(self, mock_request, app):
        """Test introspection with inactive token"""
        from app.route_oidc import verify_introspection

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"active": False}
        mock_request.return_value = mock_response

        with app.app_context():
            result = verify_introspection("inactive-token")

        assert isinstance(result, tuple)
        assert result[1] == 401

    @patch("requests.request")
    def test_verify_introspection_network_error(self, mock_request, app):
        """Test introspection with network error"""
        from app.route_oidc import verify_introspection
        import requests

        # Use requests.exceptions.RequestException which the code catches
        mock_request.side_effect = requests.exceptions.RequestException("Network error")

        with app.app_context():
            result = verify_introspection("token")

        assert isinstance(result, tuple)
        assert result[1] == 502


class TestVerifyCredentialRequest:
    """Test credential request verification"""

    def test_verify_credential_request_valid(self, app):
        """Test valid credential request"""
        from app.route_oidc import verify_credential_request

        request = {
            "credential_configuration_id": "test-cred",
            "proof": {"proof_type": "jwt", "jwt": "test-jwt"},
        }

        with app.app_context():
            result = verify_credential_request(request)

        assert result == request

    def test_verify_credential_request_missing_id(self, app):
        """Test request missing credential identifier"""
        from app.route_oidc import verify_credential_request

        request = {"proof": {"proof_type": "jwt", "jwt": "test-jwt"}}

        with app.app_context():
            result = verify_credential_request(request)

        assert isinstance(result, tuple)
        assert result[1] == 400

    def test_verify_credential_request_missing_proof(self, app):
        """Test request missing proof"""
        from app.route_oidc import verify_credential_request

        request = {"credential_configuration_id": "test-cred"}

        with app.app_context():
            result = verify_credential_request(request)

        assert isinstance(result, tuple)
        assert result[1] == 400


class TestDeferredCredential:
    """Test deferred credential endpoint"""

    def test_deferred_missing_transaction_id(self, client):
        """Test deferred request without transaction_id"""
        response = client.post(
            "/deferred_credential", headers={"Authorization": "Bearer token"}, json={}
        )

        assert response.status_code == 401
        assert response.json["error"] == "invalid_transaction_id"

    def test_deferred_invalid_transaction_id_format(self, client):
        """Test deferred request with invalid UUID format"""
        response = client.post(
            "/deferred_credential",
            headers={"Authorization": "Bearer token"},
            json={"transaction_id": "not-a-valid-uuid"},
        )

        assert response.status_code == 401
        assert response.json["error"] == "invalid_transaction_id_format"

    @patch("app.route_oidc.verify_introspection")
    @patch("app.route_oidc.generate_credentials")
    def test_deferred_success(
        self, mock_generate, mock_introspect, client, mock_cfgservice
    ):
        """Test successful deferred credential"""
        transaction_id = str(uuid.uuid4())
        mock_introspect.return_value = "test-session-id"
        mock_generate.return_value = {"credential": "test-credential"}

        with patch("app.route_oidc.session_manager") as mock_sm:
            mock_session = Mock()
            mock_session.transaction_id = {
                transaction_id: {
                    "credential_configuration_id": "test-cred",
                    "proof": {"proof_type": "jwt", "jwt": "test"},
                }
            }
            mock_sm.get_session.return_value = mock_session

            response = client.post(
                "/deferred_credential",
                headers={"Authorization": "Bearer token"},
                json={"transaction_id": transaction_id},
            )

            assert response.status_code == 200
            assert "notification_id" in response.json


class TestNotification:
    """Test notification endpoint"""

    @patch("app.route_oidc.verify_introspection")
    def test_notification_success(self, mock_introspect, client, mock_cfgservice):
        """Test successful notification"""
        mock_introspect.return_value = "test-session-id"

        response = client.post(
            "/notification",
            headers={"Authorization": "Bearer token"},
            json={"notification_id": "test-notification"},
        )

        assert response.status_code == 204

    def test_notification_missing_auth(self, client):
        """Test notification without authorization"""
        response = client.post("/notification", json={"notification_id": "test"})

        assert response.status_code == 401


class TestNonce:
    """Test nonce endpoint"""

    @patch("app.route_oidc.JsonWebEncryption")
    @patch("builtins.open")
    def test_nonce_generation(self, mock_open, mock_jwe_class, client, mock_cfgservice):
        """Test nonce generation"""
        # Mock file reading
        mock_file = MagicMock()
        mock_file.read.return_value = b"test-key-data"
        mock_open.return_value.__enter__.return_value = mock_file

        # Mock JWE
        mock_jwe = MagicMock()
        mock_jwe.serialize_compact.return_value = b"encrypted-jwt-token"
        mock_jwe.deserialize_compact.return_value = {
            "payload": b'{"iss":"test","iat":123,"exp":456}'
        }
        mock_jwe_class.return_value = mock_jwe

        response = client.post("/nonce")

        assert response.status_code == 200
        assert "c_nonce" in response.json
        assert "DPoP-Nonce" in response.headers
        assert response.headers["Cache-Control"] == "no-store"


class TestCredentialOffer:
    """Test credential offer endpoints"""

    @patch("app.route_oidc.render_template")
    def test_credential_offer_choice(self, mock_render, client, mock_cfgservice):
        """Test credential offer choice page"""
        mock_render.return_value = "rendered_template"

        with patch(
            "app.route_oidc.oidc_metadata",
            {
                "credential_configurations_supported": {
                    "eu.europa.ec.eudi.pid_mdoc": {
                        "format": "mso_mdoc",
                        "credential_metadata": {"display": [{"name": "PID"}]},
                    }
                }
            },
        ):
            response = client.get("/credential_offer_choice")

            assert response.status_code == 200

    @patch("app.route_oidc.generate_unique_id")
    def test_credential_offer2_qr_generation(self, mock_uuid, client, mock_cfgservice):
        """Test QR code generation for credential offer"""
        mock_uuid.return_value = "test-session-id"

        response = client.get("/credential_offer2")

        assert response.status_code == 200
        assert "base64_img" in response.json
        assert "session_id" in response.json


class TestHelperFunctions:
    """Test helper functions"""

    def test_pKfromJWK(self):
        """Test public key extraction from JWK"""
        from app.route_oidc import pKfromJWK

        # Create a test P-256 key
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        # Get coordinates
        public_numbers = public_key.public_numbers()
        x = public_numbers.x.to_bytes(32, "big")
        y = public_numbers.y.to_bytes(32, "big")

        jwk_data = {
            "kty": "EC",
            "crv": "P-256",
            "x": base64.urlsafe_b64encode(x).decode("utf-8").rstrip("="),
            "y": base64.urlsafe_b64encode(y).decode("utf-8").rstrip("="),
        }

        result = pKfromJWK(jwk_data)

        assert isinstance(result, str)
        assert len(result) > 0

    def test_pKfromJWK_unsupported_curve(self):
        """Test public key extraction with unsupported curve"""
        from app.route_oidc import pKfromJWK

        jwk_data = {"kty": "EC", "crv": "P-384", "x": "test", "y": "test"}

        result = pKfromJWK(jwk_data)

        assert "error" in result
        assert result["error"] == "invalid_proof"


class TestLogs:
    """Test logs endpoint"""

    @patch("builtins.open", create=True)
    def test_get_logs_by_session(self, mock_open, client):
        """Test retrieving logs by session ID"""
        mock_file = MagicMock()
        mock_file.__enter__.return_value.__iter__.return_value = [
            "INFO - Session ID: test-session, Started Request\n",
            "INFO - Session ID: test-session, Credential Issuance Succesfull\n",
        ]
        mock_open.return_value = mock_file

        response = client.get("/logs", query_string={"session_id": "test-session"})

        assert response.status_code == 200
        assert response.json["count"] >= 0
        assert response.json["session_id"] == "test-session"

    def test_get_logs_missing_session_id(self, client):
        """Test logs endpoint without session_id"""
        response = client.get("/logs")

        assert response.status_code == 400
        assert "error" in response.json


# Additional test cases to improve coverage


class TestEncryptResponse:
    """Test encrypt_response function"""

    @patch("app.route_oidc.JsonWebKey")
    @patch("app.route_oidc.JsonWebEncryption")
    def test_encrypt_response_success(self, mock_jwe_class, mock_jwk, app):
        """Test successful response encryption"""
        from app.route_oidc import encrypt_response

        credential_request = {
            "credential_response_encryption": {
                "jwk": {"kty": "RSA", "n": "test", "e": "AQAB", "alg": "RSA-OAEP"},
                "enc": "A256GCM",
            }
        }
        credential_response = {"credential": "test-data"}

        mock_key = Mock()
        mock_jwk.import_key.return_value = mock_key

        mock_jwe = Mock()
        mock_jwe.serialize_compact.return_value = b"encrypted-token"
        mock_jwe_class.return_value = mock_jwe

        with app.app_context():
            result = encrypt_response(credential_request, credential_response)

        assert result.status_code == 200
        assert result.headers["Content-Type"] == "application/jwt"

    def test_encrypt_response_missing_fields(self, app):
        """Test encryption with missing required fields"""
        from app.route_oidc import encrypt_response

        credential_request = {"credential_response_encryption": {}}
        credential_response = {"credential": "test"}

        with app.app_context():
            result = encrypt_response(credential_request, credential_response)

        assert result.status_code == 400


class TestGenerateCredentials:
    """Test generate_credentials function"""

    @patch("app.route_oidc.requests.post")
    @patch("app.route_oidc.pKfromJWT")
    def test_generate_credentials_jwt_proof(self, mock_pk, mock_post, mock_cfgservice):
        """Test credential generation with JWT proof"""
        from app.route_oidc import generate_credentials

        mock_pk.return_value = "test-public-key"
        mock_post.return_value.json.return_value = {"credential": "test"}

        credential_request = {
            "credential_configuration_id": "test-cred",
            "proof": {"proof_type": "jwt", "jwt": "test-jwt-token"},
        }

        result = generate_credentials(credential_request, "test-session-id")

        assert "credential" in result

    @patch("app.route_oidc.requests.post")
    @patch("app.route_oidc.pKfromJWT")
    def test_generate_credentials_batch_proofs(
        self, mock_pk, mock_post, mock_session_manager, mock_cfgservice
    ):
        """Test batch credential generation"""
        from app.route_oidc import generate_credentials

        mock_pk.return_value = "test-public-key"
        mock_post.return_value.json.return_value = {"credentials": []}

        credential_request = {
            "credential_configuration_id": "test-cred",
            "proofs": {"jwt": ["jwt1", "jwt2", "jwt3"]},
        }

        result = generate_credentials(credential_request, "test-session-id")

        mock_session_manager.update_is_batch_credential.assert_called_once()

    @patch("app.route_oidc.decode_verify_attestation")
    @patch("app.route_oidc.pKfromJWK")
    @patch("app.route_oidc.requests.post")
    def test_generate_credentials_attestation(
        self, mock_post, mock_pk_jwk, mock_decode, mock_cfgservice
    ):
        """Test credential generation with attestation proof"""
        from app.route_oidc import generate_credentials

        mock_decode.return_value = {
            "attested_keys": [{"kty": "EC", "crv": "P-256", "x": "test", "y": "test"}]
        }
        mock_pk_jwk.return_value = "test-public-key"
        mock_post.return_value.json.return_value = {"credential": "test"}

        credential_request = {
            "credential_configuration_id": "test-cred",
            "proof": {
                "proof_type": "attestation",
                "attestation": "test-attestation-jwt",
            },
        }

        result = generate_credentials(credential_request, "test-session-id")

        assert "credential" in result


class TestDecryptJWE:
    """Test JWE decryption"""

    @patch("builtins.open")
    @patch("app.route_oidc.jwk.JWK")
    @patch("app.route_oidc.jwe.JWE")
    def test_decrypt_jwe_success(
        self, mock_jwe_class, mock_jwk_class, mock_open, mock_cfgservice
    ):
        """Test successful JWE decryption"""
        from app.route_oidc import decrypt_jwe_credential_request

        # Mock file reading
        mock_file = Mock()
        mock_file.read.return_value = (
            "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
        )
        mock_open.return_value.__enter__.return_value = mock_file

        # Mock JWK
        mock_key = Mock()
        mock_jwk_class.from_pem.return_value = mock_key

        # Mock JWE
        mock_jwe = Mock()
        mock_jwe.payload = b'{"credential_configuration_id": "test"}'
        mock_jwe_class.return_value = mock_jwe

        jwt_token = "header.payload.signature.tag.iv"
        result = decrypt_jwe_credential_request(jwt_token)

        assert "credential_configuration_id" in result

    def test_decrypt_jwe_invalid_format(self, mock_cfgservice):
        """Test JWE decryption with invalid format"""
        from app.route_oidc import decrypt_jwe_credential_request

        with pytest.raises(ValueError, match="Invalid JWE format"):
            decrypt_jwe_credential_request("invalid.token")


class TestAuthChoiceFlow:
    """Test auth_choice endpoint flows"""

    def test_auth_choice_redirect_to_oid4vp(
        self, client, mock_session_manager, mock_cfgservice
    ):
        """Test redirect to OID4VP"""
        with patch("app.route_oidc.ConfFrontend"):
            response = client.get(
                "/auth_choice",
                query_string={
                    "token": "test",
                    "session_id": "test-session",
                    "scope": "openid eu.europa.ec.eudi.pid_mdoc",
                    "frontend_id": "test-frontend",
                },
            )

            # Should handle the request
            assert response.status_code in [200, 302, 307]


class TestPidAuthorization:
    """Test PID authorization endpoint"""

    @patch("requests.request")
    def test_pid_authorization_success(self, mock_request, client, mock_cfgservice):
        """Test successful PID authorization"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        response = client.get(
            "/pid_authorization",
            query_string={"presentation_id": "test-presentation-123"},
        )

        assert response.status_code == 200
        assert "message" in response.json

    def test_pid_authorization_missing_id(self, client):
        """Test PID authorization without presentation_id"""
        with pytest.raises(ValueError, match="Presentation id is required"):
            client.get("/pid_authorization")

    def test_pid_authorization_invalid_id(self, client):
        """Test PID authorization with invalid ID format"""
        with pytest.raises(ValueError, match="Invalid Presentation id format"):
            client.get(
                "/pid_authorization", query_string={"presentation_id": "invalid@id!"}
            )


class TestOfferReference:
    """Test offer reference endpoint"""

    def test_offer_reference_success(self, client):
        """Test retrieving credential offer by reference"""
        from app.route_oidc import credential_offer_references

        reference_id = "test-ref-123"
        test_offer = {
            "credential_issuer": "test",
            "credential_configuration_ids": ["test-cred"],
        }

        credential_offer_references[reference_id] = {
            "credential_offer": test_offer,
            "expires": datetime.now() + timedelta(minutes=10),
        }

        response = client.get(f"/credential-offer-reference/{reference_id}")

        assert response.status_code == 200
        assert response.json == test_offer


class TestBranchCoverage:
    """Additional tests for branch coverage"""

    @patch("app.route_oidc.verify_introspection")
    def test_credential_with_dpop_header(
        self, mock_introspect, client, mock_cfgservice
    ):
        """Test credential endpoint with DPoP authorization"""
        mock_introspect.return_value = "test-session"

        with patch("app.route_oidc.session_manager") as mock_sm, patch(
            "app.route_oidc.generate_credentials"
        ) as mock_gen:
            mock_session = Mock()
            mock_sm.get_session.return_value = mock_session
            mock_gen.return_value = {"credential": "test"}

            response = client.post(
                "/credential",
                headers={"Authorization": "DPoP test-token"},
                json={
                    "credential_configuration_id": "test",
                    "proof": {"proof_type": "jwt", "jwt": "test"},
                },
            )

            assert response.status_code == 200

    def test_verify_credential_request_typo_identifier(self, app):
        """Test request with typo in identifier field"""
        from app.route_oidc import verify_credential_request

        request = {
            "credential_indentifier": "test",  # typo
            "proof": {"proof_type": "jwt", "jwt": "test"},
        }

        with app.app_context():
            result = verify_credential_request(request)

        assert isinstance(result, tuple)
        assert result[1] == 400

    def test_verify_credential_request_invalid_proof_type(self, app):
        """Test request with invalid proof type"""
        from app.route_oidc import verify_credential_request

        request = {
            "credential_configuration_id": "test",
            "proof": {
                "proof_type": "jwt"
                # missing 'jwt' field
            },
        }

        with app.app_context():
            result = verify_credential_request(request)

        assert isinstance(result, tuple)
        assert result[1] == 400


class TestErrorHandling:
    """Test error handling"""

    def test_bad_request_error_handler(self, client):
        """Test bad request error handler"""
        # This would typically be triggered by werkzeug
        # You might need to create a route that deliberately triggers it
        pass
