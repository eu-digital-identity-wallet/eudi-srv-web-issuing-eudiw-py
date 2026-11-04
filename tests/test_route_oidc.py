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

import jwt
from flask import Flask, session
from jwcrypto import jwk, jwe
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from config_helpers import patch_configuration
from proof_helpers import nonce_key_pem, p256_jwk, proof_jwt


API_KEY_HEADERS = {"X-Api-Key": "test-api-key"}


@pytest.fixture(autouse=True)
def _credential_types_authorized():
    """These tests cover other parts of /credential; the authorization check
    of the requested credential type is tested in test_security_regressions."""
    with patch("app.routes.oidc.require_authorized_configuration"):
        yield

@pytest.fixture
def app():
    """Create Flask app for testing"""
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key"

    # Import and register blueprint
    with patch("app.routes.oidc.CONFIGURATION"), patch(
        "app.routes.oidc.session_manager"
    ):
        from app.routes.oidc import oidc

        app.register_blueprint(oidc)

    return app


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


@pytest.fixture
def mock_session_manager():
    """Mock session manager"""
    # generate_credentials (services.credential_issuance) uses its own
    # session_manager binding; share one mock between both modules.
    with patch("app.routes.oidc.session_manager") as mock, patch(
        "app.services.credential_issuance.session_manager", mock
    ):
        mock_session = Mock()
        mock_session.client_status = None
        mock_session.transaction_id = {}
        mock_session.session_id = "test-session-id"
        mock.get_session.return_value = mock_session
        mock.add_session.return_value = None
        mock.update_is_batch_credential.return_value = None
        mock.store_notification_id.return_value = None
        yield mock


@pytest.fixture
def mock_cfgservice():
    """Mock configuration in every app module (routes, services, utils)"""
    with patch_configuration({
        "service_url": "https://test.issuer.dev/",
        "wallet_test_url": "https://test.wallet.dev/",
        "expiry": {
            "form": 10,
        },
        "keys": {
            "nonce_path": "test-key.pem",
            "nonce_key": "test-key.pem", # This has been added because of errors on test_nonce_generation, which expects a 'nonce_key' field in the configuration for loading the private key. The 'nonce_path' field is still included as it may be used elsewhere in the code.
            "credential_request_path": "test-priv-key.pem",
            "credential_encryption_key": "credential_encryption_key.pem",
        },
        "dynamic_presentation_url": "https://test.presentation.dev/",
        "credential_auth_methods": {
            "PID_login": ["eu.europa.ec.eudi.pid_mdoc"],
            "country_selection": ["eu.europa.ec.eudi.mdl"],
        },
        "frontend": {
            "default": "test_frontend",
            "frontends_config": {
                "test_frontend": {"url": "https://frontend.example.com"}
            }
        },
        "credential_offer_scheme": "haip-vci://",
        "authorization_server": {
            "base_url": "https://backend.issuer.eudiw.dev/oidc",
            "user_verify_endpoint": "https://issuer.eudiw.dev/oidc/verify/user"
        },
        "logging": {
            "backend_path": "/tmp/log_prod/logs.log",
            "level": "INFO"
        },
        "status_validator": {"enabled": False, "url": "https://status.test"},
        "backend_api_key": "test-api-key",
        "admin_api_key": "test-api-key",
    }) as mock:
        yield mock


class TestWellKnownEndpoints:
    """The backend no longer publishes metadata; frontends get it via /metadata/<frontend_id>."""

    @pytest.mark.parametrize(
        "service",
        [
            "openid-credential-issuer",
            "openid-credential-issuer2",
            "oauth-authorization-server",
            "openid-configuration",
        ],
    )
    def test_well_known_removed(self, client, service):
        response = client.get(f"/.well-known/{service}")

        assert response.status_code == 404

class TestAuthChoice:
    """Test authentication choice endpoint"""

    def test_auth_choice_with_scope(
        self, client, mock_session_manager, mock_cfgservice
    ):
        mock_session_manager.get_session.return_value = None  # new session
        mock_oidc_metadata = {
            "credential_configurations_supported": {
                "eu.europa.ec.eudi.pid_mdoc": {
                    "format": "mso_mdoc",
                    "credential_metadata": {"display": [{"name": "PID"}]},
                    "scope": "eu.europa.ec.eudi.pid_mdoc",
                }
            }
        }
        
        """Test auth_choice with scope parameter"""
        with patch.dict("app.routes.oidc.CONFIGURATION", {
            "frontend": {
                "default": "5d725b3c-6d42-448e-8bfd-1eff1fcf152d",
                "frontends_config": {
                    "5d725b3c-6d42-448e-8bfd-1eff1fcf152d": {"url": "https://test.frontend.dev"}
                }
            }
        }), patch.dict(
            "app.routes.oidc.oidc_metadata",
            mock_oidc_metadata,
            clear=True
        ), patch.dict(
            "app.services.attributes.oidc_metadata",
            mock_oidc_metadata,
            clear=True
        ):
            query = {
                    "token": "test-token",
                    "session_id": "test-session",
                    "frontend_id": "5d725b3c-6d42-448e-8bfd-1eff1fcf152d",
                    "scope": "openid eu.europa.ec.eudi.pid_mdoc",
                }
            with patch("app.routes.oidc.verify_session_token", return_value={k: v for k, v in query.items() if k != "token"}):
                response = client.get("/auth_choice", query_string={"token": query["token"], "session_token": "signed"})

            # Should redirect to auth method display
            assert response.status_code in [200, 302]

    def test_auth_choice_with_authorization_details(
        self, client, mock_session_manager, mock_cfgservice
    ):
        mock_session_manager.get_session.return_value = None  # new session
        """Test auth_choice with authorization_details"""
        auth_details = json.dumps(
            [{"credential_configuration_id": "eu.europa.ec.eudi.pid_mdoc"}]
        )

        with patch.dict("app.routes.oidc.CONFIGURATION", {
            "frontend": {
                "default": "5d725b3c-6d42-448e-8bfd-1eff1fcf152d",
                "frontends_config": {
                    "5d725b3c-6d42-448e-8bfd-1eff1fcf152d": {"url": "https://test.frontend.dev"}
                }
            }
        }):

            query = {
                    "token": "test-token",
                    "session_id": "test-session",
                    "frontend_id": "5d725b3c-6d42-448e-8bfd-1eff1fcf152d",
                    "authorization_details": json.dumps(auth_details),
                }
            with patch("app.routes.oidc.verify_session_token", return_value={k: v for k, v in query.items() if k != "token"}):
                response = client.get("/auth_choice", query_string={"token": query["token"], "session_token": "signed"})

            assert response.status_code in [200, 302]


class TestCredentialEndpoint:
    """Test credential issuance endpoint"""

    def test_credential_missing_authorization(self, client):
        """Test credential endpoint without authorization header"""
        response = client.post(
            "/credential", json={"credential_configuration_id": "test-cred"}
        )

        # RFC 6750 section 3.1: no credentials -> 401 challenge without an error code.
        assert response.status_code == 401
        assert "error" not in response.json
        assert "WWW-Authenticate" in response.headers

    def test_credential_invalid_bearer_format(self, client):
        """Test credential endpoint with invalid bearer format"""
        response = client.post(
            "/credential",
            headers={"Authorization": "InvalidFormat token"},
            json={"credential_configuration_id": "test-cred"},
        )

        # RFC 6750 section 3.1: an unsupported scheme is treated like no credentials.
        assert response.status_code == 401
        assert "error" not in response.json
        assert "WWW-Authenticate" in response.headers

    @patch("app.routes.oidc.verify_introspection")
    def test_credential_invalid_token(self, mock_introspect, client):
        """Test credential endpoint with invalid token"""
        mock_introspect.return_value = ({"error": "invalid_token"}, 401)

        response = client.post(
            "/credential",
            headers={"Authorization": "Bearer invalid-token"},
            json={"credential_configuration_id": "test-cred"},
        )

        assert response.status_code == 401

    @patch("app.routes.oidc.verify_introspection")
    @patch("app.routes.oidc.generate_credentials")
    def test_credential_success(
        self, mock_generate, mock_introspect, client, mock_cfgservice
    ):
        """Test successful credential issuance"""
        mock_introspect.return_value = ("test-session-id", None)
        mock_generate.return_value = {"credential": "test-credential-data"}

        with patch("app.routes.oidc.session_manager") as mock_sm:
            mock_session = Mock()
            mock_session.client_status = None
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

    @patch("app.routes.oidc.verify_introspection")
    @patch("app.routes.oidc.generate_credentials")
    def test_credential_deferred(
        self, mock_generate, mock_introspect, client, mock_cfgservice
    ):
        """Test deferred credential response"""
        mock_introspect.return_value = ("test-session-id", None)
        mock_generate.return_value = {"error": "Pending"}

        with patch("app.routes.oidc.session_manager") as mock_sm:
            mock_session = Mock()
            mock_session.client_status = None
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

    @patch("app.routes.oidc.verify_introspection")
    @patch("app.routes.oidc.generate_credentials")
    def test_credential_undecodable_proof(
        self, mock_generate, mock_introspect, client, mock_cfgservice
    ):
        """Fixed behaviour: non-dict generate_credentials result -> 400 invalid_proof"""
        mock_introspect.return_value = ("test-session-id", None)
        mock_generate.return_value = ""

        with patch("app.routes.oidc.session_manager"):
            response = client.post(
                "/credential",
                headers={"Authorization": "Bearer valid-token"},
                json={
                    "credential_configuration_id": "test-cred",
                    "proof": {"proof_type": "jwt", "jwt": "test-jwt"},
                },
            )

        assert response.status_code == 400
        assert response.json["error"] == "invalid_proof"
            
@pytest.mark.usefixtures("mock_cfgservice")
class TestVerifyIntrospection:
    """Test token introspection verification"""

    @patch("app.services.auth_server.requests.request")
    def test_verify_introspection_success(self, mock_request, app):
        """Test successful token introspection"""
        from app.routes.oidc import verify_introspection

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"active": True, "username": "test-user"}
        mock_request.return_value = mock_response

        with app.app_context():
            result = verify_introspection("valid-token")

        # verify_introspection now returns (username, client_status)
        assert result == ("test-user", None)

    @patch("app.services.auth_server.requests.request")
    def test_verify_introspection_inactive_token(self, mock_request, app):
        """Test introspection with inactive token"""
        from app.routes.oidc import verify_introspection

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"active": False}
        mock_request.return_value = mock_response

        with app.app_context():
            result = verify_introspection("inactive-token")

        assert isinstance(result, tuple)
        assert result[1] == 401

    @patch("app.services.auth_server.requests.request")
    def test_verify_introspection_network_error(self, mock_request, app):
        """Test introspection with network error"""
        from app.routes.oidc import verify_introspection
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
        from app.routes.oidc import verify_credential_request

        request = {
            "credential_configuration_id": "test-cred",
            "proof": {"proof_type": "jwt", "jwt": "test-jwt"},
        }

        with app.app_context():
            result = verify_credential_request(request)

        assert result == request

    def test_verify_credential_request_missing_id(self, app):
        """Test request missing credential identifier"""
        from app.routes.oidc import verify_credential_request

        request = {"proof": {"proof_type": "jwt", "jwt": "test-jwt"}}

        from app.core.errors import OAuthEndpointError

        with app.app_context(), pytest.raises(OAuthEndpointError) as raised:
            verify_credential_request(request)

        assert (raised.value.error, raised.value.status) == ("invalid_credential_request", 400)

    def test_verify_credential_request_missing_proof(self, app):
        """Test request missing proof"""
        from app.routes.oidc import verify_credential_request

        request = {"credential_configuration_id": "test-cred"}

        from app.core.errors import OAuthEndpointError

        with app.app_context(), pytest.raises(OAuthEndpointError) as raised:
            verify_credential_request(request)

        assert (raised.value.error, raised.value.status) == ("invalid_proof", 400)


class TestDeferredCredential:
    """Test deferred credential endpoint"""

    def test_deferred_missing_transaction_id(self, client):
        """Test deferred request without transaction_id"""
        response = client.post(
            "/deferred_credential", headers={"Authorization": "Bearer token"}, json={}
        )

        # OpenID4VCI 1.0 section 9.3 / 8.3.1.2: missing parameter.
        assert response.status_code == 400
        assert response.json["error"] == "invalid_credential_request"

    def test_deferred_invalid_transaction_id_format(self, client):
        """Test deferred request with invalid UUID format"""
        response = client.post(
            "/deferred_credential",
            headers={"Authorization": "Bearer token"},
            json={"transaction_id": "not-a-valid-uuid"},
        )

        assert response.status_code == 400
        assert response.json["error"] == "invalid_transaction_id"

    @patch("app.routes.oidc.verify_introspection")
    @patch("app.routes.oidc.generate_credentials")
    def test_deferred_success(
        self, mock_generate, mock_introspect, client, mock_cfgservice
    ):
        """Test successful deferred credential"""
        transaction_id = str(uuid.uuid4())
        mock_introspect.return_value = ("test-session-id", None)
        mock_generate.return_value = {"credential": "test-credential"}

        with patch("app.routes.oidc.session_manager") as mock_sm:
            mock_session = Mock()
            mock_session.client_status = None
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

    @patch("app.routes.oidc.verify_introspection")
    @patch("app.routes.oidc.generate_credentials")
    def test_deferred_still_pending(
        self, mock_generate, mock_introspect, client, mock_cfgservice
    ):
        """Fixed behaviour: a still-pending deferred request returns 202 with the
        same transaction_id and no notification_id (was 400)"""
        transaction_id = str(uuid.uuid4())
        mock_introspect.return_value = ("test-session-id", None)
        mock_generate.return_value = {"error": "Pending"}

        with patch("app.routes.oidc.session_manager") as mock_sm:
            mock_session = Mock()
            mock_session.client_status = None
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

            assert response.status_code == 202
            assert response.json == {"transaction_id": transaction_id, "interval": 30}
            mock_sm.store_notification_id.assert_not_called()

    @patch("app.routes.oidc.encrypt_response")
    @patch("app.routes.oidc.verify_introspection")
    @patch("app.routes.oidc.generate_credentials")
    def test_deferred_encryption_uses_deferred_request_params(
        self, mock_generate, mock_introspect, mock_encrypt, client, app, mock_cfgservice
    ):
        """Fixed behaviour: response encryption uses the deferred request's
        credential_response_encryption"""
        transaction_id = str(uuid.uuid4())
        public_jwk = json.loads(jwk.JWK.generate(kty="RSA", size=2048).export_public())
        encryption = {"jwk": public_jwk, "alg": "RSA-OAEP", "enc": "A256GCM"}
        mock_introspect.return_value = ("test-session-id", None)
        mock_generate.return_value = {"credential": "test-credential"}
        with app.app_context():
            from flask import make_response

            mock_encrypt.return_value = make_response(
                "eyJencrypted", 200, {"Content-Type": "application/jwt"}
            )

        with patch("app.routes.oidc.session_manager") as mock_sm:
            mock_session = Mock()
            mock_session.client_status = None
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
                json={
                    "transaction_id": transaction_id,
                    "credential_response_encryption": encryption,
                },
            )

            assert response.status_code == 200
            assert response.content_type == "application/jwt"
            kwargs = mock_encrypt.call_args.kwargs
            assert kwargs["credential_request"]["credential_response_encryption"] == encryption
            assert "notification_id" in kwargs["credential_response"]


class TestNotification:
    """Test notification endpoint"""

    @patch("app.routes.oidc.verify_introspection")
    def test_notification_success(self, mock_introspect, client, mock_cfgservice):
        """Test successful notification"""
        mock_introspect.return_value = ("test-session-id", None)

        with patch("app.routes.oidc.session_manager.get_session_by_notification_id") as owner:
            owner.return_value.session_id = "test-session-id"
            response = client.post(
            "/notification",
                headers={"Authorization": "Bearer token"},
                json={"notification_id": "test-notification", "event": "credential_accepted"},
            )

        assert response.status_code == 204

    def test_notification_missing_auth(self, client):
        """Test notification without authorization"""
        response = client.post("/notification", json={"notification_id": "test"})

        assert response.status_code == 401


@pytest.mark.usefixtures("mock_cfgservice")
class TestNonce:
    """Test nonce endpoint"""

    def test_nonce_generation(self, client, mock_cfgservice):
        """The c_nonce is a JWE only the issuer's nonce_key can decrypt"""
        nonce_key = jwk.JWK.generate(kty="RSA", size=2048)
        mock_cfgservice["keys"]["nonce_key"] = nonce_key.export_to_pem(private_key=True, password=None)

        response = client.post("/nonce")

        assert response.status_code == 200
        c_nonce = response.json["c_nonce"]
        assert response.headers["DPoP-Nonce"] == c_nonce
        assert response.headers["Cache-Control"] == "no-store"

        token = jwe.JWE()
        token.deserialize(c_nonce, key=nonce_key)
        header = json.loads(token.objects["protected"])
        assert header == {"alg": "RSA-OAEP", "enc": "A256GCM", "typ": "cnonce+jwt"}
        claims = json.loads(token.payload)
        service_url = mock_cfgservice["service_url"]
        assert claims["iss"] == service_url
        assert claims["aud"] == [f"{service_url}/credential"]
        assert claims["exp"] - claims["iat"] == 3600

    def test_nonce_does_not_purge_expired_entries(self, client, mock_cfgservice):
        """Purging is the scheduler's job, not the nonce endpoint's"""
        from app.repositories import offer_store

        mock_cfgservice["keys"]["nonce_key"] = nonce_key_pem()
        expired = {"old": {"expires": datetime.now() - timedelta(seconds=1)}}

        with patch.dict(offer_store.credential_offer_references, expired, clear=True):
            response = client.post("/nonce")
            assert response.status_code == 200
            assert list(offer_store.credential_offer_references) == ["old"]


class TestCredentialOffer:
    """Test credential offer endpoints"""

    @patch("app.routes.oidc.post_redirect_with_payload")
    def test_credential_offer_choice(self, mock_render, client, mock_cfgservice):
        """Test credential offer choice page"""
        mock_render.return_value = "rendered_template"
        
        mock_oidc_metadata = {
            "credential_configurations_supported": {
                "eu.europa.ec.eudi.pid_mdoc": {
                    "format": "mso_mdoc",
                    "credential_metadata": {"display": [{"name": "PID"}]},
                }
            }
        }

        with patch.dict(
            "app.routes.oidc.oidc_metadata",
            mock_oidc_metadata,
            clear=True
        ), patch.dict(
            "app.services.attributes.oidc_metadata",
            mock_oidc_metadata,
            clear=True
        ):
            response = client.get("/credential_offer_choice")

            assert response.status_code == 200
            payload = mock_render.call_args.kwargs["data_payload"]
            assert payload["cred"]["mdoc format"] == {"eu.europa.ec.eudi.pid_mdoc": "PID"}

    @patch("app.routes.oidc.generate_unique_id")
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
        from app.services.credential_issuance import pKfromJWK

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
        from app.services.credential_issuance import pKfromJWK

        jwk_data = {"kty": "EC", "crv": "secp256k1", "x": "test", "y": "test"}

        result = pKfromJWK(jwk_data)

        assert "error" in result
        assert result["error"] == "invalid_proof"


class TestLogs:
    """Test logs endpoint"""

    @patch("builtins.open", create=True)
    def test_get_logs_by_session(self, mock_open, client, mock_cfgservice):
        """Test retrieving logs by session ID"""
        mock_file = MagicMock()
        mock_file.__enter__.return_value.__iter__.return_value = [
            "INFO - Session ID: 0c6f8a52-1b2c-4d3e-8f90-123456789abc, Started Request\n",
            "INFO - Session ID: 0c6f8a52-1b2c-4d3e-8f90-123456789abc, Credential Issuance Succesfull\n",
        ]
        mock_open.return_value = mock_file

        response = client.get(
            "/logs", query_string={"session_id": "0c6f8a52-1b2c-4d3e-8f90-123456789abc"}, headers=API_KEY_HEADERS
        )

        assert response.status_code == 200
        assert response.json["count"] == 2
        assert response.json["session_id"] == "0c6f8a52-1b2c-4d3e-8f90-123456789abc"

    def test_get_logs_missing_session_id(self, client, mock_cfgservice):
        """Test logs endpoint without session_id"""
        response = client.get("/logs", headers=API_KEY_HEADERS)

        assert response.status_code == 400
        assert "error" in response.json


class TestInternalApiKey:
    """/logs and /admin/sessions/client_status require the admin API key."""

    @pytest.mark.parametrize("path", ["/logs?session_id=s1", "/admin/sessions/client_status"])
    def test_missing_key_rejected(self, client, mock_cfgservice, path):
        response = client.get(path)

        assert response.status_code == 401
        assert response.json["error"] == "unauthorized"

    @pytest.mark.parametrize("path", ["/logs?session_id=s1", "/admin/sessions/client_status"])
    def test_wrong_key_rejected(self, client, mock_cfgservice, path):
        response = client.get(path, headers={"X-Api-Key": "wrong"})

        assert response.status_code == 401

    @pytest.mark.parametrize("path", ["/logs?session_id=s1", "/admin/sessions/client_status"])
    def test_unconfigured_key_fails_closed(self, client, path):
        """Without admin_api_key in the configuration the endpoints are unavailable."""
        response = client.get(path, headers={"X-Api-Key": "anything"})

        assert response.status_code == 503

    def test_client_status_with_valid_key(self, client, mock_cfgservice):
        with patch("app.routes.oidc.session_manager") as manager:
            manager.get_all_client_statuses.return_value = {"s1": {"exp": 1}}
            response = client.get("/admin/sessions/client_status", headers=API_KEY_HEADERS)

        assert response.status_code == 200
        assert response.json == {"s1": {"exp": 1}}


# Additional test cases to improve coverage


class TestEncryptResponse:
    """Test encrypt_response function"""

    @pytest.mark.parametrize(
        "kty, alg, enc",
        [
            ("EC", "ECDH-ES", "A256GCM"),
            ("EC", "ECDH-ES", "A128CBC-HS256"),
            ("RSA", "RSA-OAEP-256", "A256GCM"),
            ("RSA", "RSA-OAEP", "A192GCM"),
        ],
    )
    def test_encrypt_response_round_trip(self, app, kty, alg, enc):
        """The wallet can decrypt the response with its private key; kid is echoed"""
        from app.routes.oidc import encrypt_response

        wallet_key = jwk.JWK.generate(kty=kty, crv="P-256") if kty == "EC" else jwk.JWK.generate(kty="RSA", size=2048)
        public_jwk = {**wallet_key.export_public(as_dict=True), "kid": "wallet-key-1"}
        credential_request = {"credential_response_encryption": {"jwk": public_jwk, "alg": alg, "enc": enc}}
        credential_response = {"credentials": [{"credential": "test-data"}], "notification_id": "n1"}

        with app.app_context():
            result = encrypt_response(credential_request, credential_response)

        assert result.status_code == 200
        assert result.headers["Content-Type"] == "application/jwt"
        token = jwe.JWE()
        token.deserialize(result.get_data(as_text=True), key=wallet_key)
        assert json.loads(token.payload) == credential_response
        header = json.loads(token.objects["protected"])
        assert (header["alg"], header["enc"], header["kid"]) == (alg, enc, "wallet-key-1")

    def test_encrypt_response_alg_from_jwk(self, app):
        """alg may come from the JWK instead of the encryption parameters"""
        from app.routes.oidc import encrypt_response

        wallet_key = jwk.JWK.generate(kty="EC", crv="P-256")
        public_jwk = {**wallet_key.export_public(as_dict=True), "alg": "ECDH-ES"}
        credential_request = {"credential_response_encryption": {"jwk": public_jwk, "enc": "A256GCM"}}

        with app.app_context():
            result = encrypt_response(credential_request, {"credential": "x"})

        token = jwe.JWE()
        token.deserialize(result.get_data(as_text=True), key=wallet_key)
        assert json.loads(token.payload) == {"credential": "x"}
        assert "kid" not in json.loads(token.objects["protected"])

    def test_encrypt_response_invalid_jwk(self, app):
        """An unusable wallet key yields invalid_encryption_parameters"""
        from app.routes.oidc import encrypt_response

        credential_request = {
            "credential_response_encryption": {"jwk": {"kty": "EC", "crv": "P-256"}, "alg": "ECDH-ES", "enc": "A256GCM"}
        }
        with app.app_context():
            result = encrypt_response(credential_request, {"credential": "x"})

        assert result.status_code == 400
        assert result.get_json()["error_description"] == "Failed to encrypt with the provided key."

    def test_encrypt_response_missing_fields(self, app):
        """Test encryption with missing required fields"""
        from app.routes.oidc import encrypt_response

        credential_request = {"credential_response_encryption": {}}
        credential_response = {"credential": "test"}

        with app.app_context():
            result = encrypt_response(credential_request, credential_response)

        assert result.status_code == 400

@pytest.mark.usefixtures("mock_session_manager")
class TestGenerateCredentials:
    """Test generate_credentials function (real proofs, verified end to end)"""

    @pytest.fixture(autouse=True)
    def _credential_metadata(self):
        """generate_credentials reads batch_size / validity from the issuer metadata"""
        with patch.dict(
            "app.services.credential_issuance.oidc_metadata",
            {"credential_configurations_supported": {"test-cred": {}}},
            clear=True,
        ):
            yield

    @pytest.fixture(autouse=True)
    def _nonce_key(self, mock_cfgservice):
        """Proofs carry a real c_nonce, encrypted to the configured nonce_key"""
        mock_cfgservice["keys"]["nonce_key"] = nonce_key_pem()

    def _proof(self):
        return proof_jwt(aud="https://frontend.example.com")

    @patch("app.services.credential_issuance.issue_credentials_for_session")
    def test_generate_credentials_jwt_proof(self, mock_issue, mock_cfgservice):
        """A single JWT proof is passed to credential creation directly (no HTTP self-call)"""
        from app.routes.oidc import generate_credentials
        from app.services.credential_issuance import pKfromJWK

        token, key = self._proof()
        mock_issue.return_value = {"credentials": [{"credential": "test"}]}

        result = generate_credentials(
            {"credential_configuration_id": "test-cred", "proof": {"proof_type": "jwt", "jwt": token}},
            "test-session-id",
        )

        assert result == {"credentials": [{"credential": "test"}]}
        holder_key = pKfromJWK(json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key())))
        mock_issue.assert_called_once_with(
            "test-session-id",
            {"credential_configuration_id": "test-cred", "proofs": [{"jwt": holder_key}]},
        )

    @patch("app.services.credential_issuance.issue_credentials_for_session", return_value={"credentials": []})
    def test_generate_credentials_batch_proofs(self, mock_issue, mock_session_manager, mock_cfgservice):
        """Test batch credential generation"""
        from app.routes.oidc import generate_credentials

        proofs = [self._proof()[0] for _ in range(3)]
        generate_credentials({"credential_configuration_id": "test-cred", "proofs": {"jwt": proofs}}, "test-session-id")

        mock_session_manager.update_is_batch_credential.assert_called_once()
        assert len(mock_issue.call_args[0][1]["proofs"]) == 3

    @patch("app.services.credential_issuance.issue_credentials_for_session")
    def test_generate_credentials_unverified_proof(self, mock_issue, mock_cfgservice):
        """An unsigned / foreign proof is rejected before anything is issued"""
        from app.routes.oidc import generate_credentials

        result = generate_credentials(
            {"credential_configuration_id": "test-cred", "proof": {"proof_type": "jwt", "jwt": "test-jwt-token"}},
            "test-session-id",
        )

        assert result["error"] == "invalid_proof"
        mock_issue.assert_not_called()

    @patch("app.services.credential_issuance.decode_verify_attestation")
    @patch("app.services.credential_issuance.issue_credentials_for_session")
    def test_generate_credentials_attestation(self, mock_issue, mock_decode, mock_cfgservice):
        """Test credential generation with attestation proof"""
        from app.routes.oidc import generate_credentials
        from app.services.credential_issuance import create_c_nonce, pKfromJWK

        _, attested_jwk = p256_jwk()
        mock_decode.return_value = {"attested_keys": [attested_jwk], "nonce": create_c_nonce()}
        mock_issue.return_value = {"credentials": [{"credential": "test"}]}

        result = generate_credentials(
            {
                "credential_configuration_id": "test-cred",
                "proof": {"proof_type": "attestation", "attestation": "test-attestation-jwt"},
            },
            "test-session-id",
        )

        assert result == {"credentials": [{"credential": "test"}]}
        assert mock_issue.call_args[0][1]["proofs"] == [{"attestation": pKfromJWK(attested_jwk)}]

    @patch("app.services.credential_issuance.issue_credentials_for_session", side_effect=RuntimeError("signing failed"))
    def test_generate_credentials_signing_failure(self, mock_issue, mock_cfgservice):
        """An exception during credential creation becomes credential_request_denied"""
        from app.routes.oidc import generate_credentials

        result = generate_credentials(
            {"credential_configuration_id": "test-cred", "proof": {"proof_type": "jwt", "jwt": self._proof()[0]}},
            "test-session-id",
        )

        assert result == {
            "error": "credential_request_denied",
            "error_description": "The credential could not be issued",
        }


class TestDecryptJWE:
    """Test JWE decryption"""

    @patch("builtins.open")
    @patch("app.services.credential_issuance.jwk.JWK")
    @patch("app.services.credential_issuance.jwe.JWE")
    def test_decrypt_jwe_success(
        self, mock_jwe_class, mock_jwk_class, mock_open, mock_cfgservice
    ):
        """Test successful JWE decryption"""
        from app.routes.oidc import decrypt_jwe_credential_request

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
        from app.routes.oidc import decrypt_jwe_credential_request

        with pytest.raises(ValueError, match="Invalid JWE format"):
            decrypt_jwe_credential_request("invalid.token")


class TestAuthChoiceFlow:
    """Test auth_choice endpoint flows"""

    def test_auth_choice_redirect_to_oid4vp(
        self, client, mock_session_manager, mock_cfgservice
    ):
        mock_session_manager.get_session.return_value = None  # new session
        mock_oidc_metadata = {
            "credential_configurations_supported": {
                "eu.europa.ec.eudi.pid_mdoc": {
                    "format": "mso_mdoc",
                    "credential_metadata": {"display": [{"name": "PID"}]},
                    "scope": "eu.europa.ec.eudi.pid_mdoc",
                }
            }
        }
        with patch.dict(
            "app.routes.oidc.oidc_metadata",
            mock_oidc_metadata,
            clear=True
        ), patch.dict(
            "app.services.attributes.oidc_metadata",
            mock_oidc_metadata,
            clear=True
        ):
            """Test redirect to OID4VP"""
            query = {
                    "token": "test",
                    "session_id": "test-session",
                    "scope": "openid eu.europa.ec.eudi.pid_mdoc",
                    "frontend_id": "test_frontend",
                }
            with patch("app.routes.oidc.verify_session_token", return_value={k: v for k, v in query.items() if k != "token"}):
                response = client.get("/auth_choice", query_string={"token": query["token"], "session_token": "signed"})

            # Should handle the request
            assert response.status_code in [200, 302, 307]

    def test_auth_choice_unknown_frontend_is_refused(self, client, mock_session_manager, mock_cfgservice):
        """The authorization server always names the frontend; an unknown one is not replaced by the default."""
        mock_session_manager.get_session.return_value = None
        claims = {"session_id": "test-session", "scope": "eu.europa.ec.eudi.pid_mdoc", "frontend_id": "unknown"}
        with patch("app.routes.oidc.verify_session_token", return_value=claims):
            response = client.get("/auth_choice", query_string={"token": "t", "session_token": "signed"})
        assert response.status_code == 400
        assert response.get_json()["error_description"] == "Unknown frontend"
        mock_session_manager.add_session.assert_not_called()

    def test_auth_method_choice_shows_the_choice_again(self, client, mock_session_manager):
        """The PID login page's Back reopens the choice from the browser session."""
        mock_session_manager.get_session.return_value = Mock(
            credentials_requested=["pid"], frontend_id="test-frontend"
        )
        with client.session_transaction() as sess:
            sess["session_id"] = "test-session"
        with patch("app.routes.oidc._show_auth_methods", return_value="page") as show:
            response = client.get("/auth_method_choice")
        assert response.status_code == 200
        show.assert_called_once_with("test-session", ["pid"], "test-frontend")

    def test_auth_method_choice_without_session(self, client, mock_session_manager):
        """Without an issuance session there is no choice to show."""
        mock_session_manager.get_session.return_value = None
        assert client.get("/auth_method_choice").status_code == 400
        with client.session_transaction() as sess:
            sess["session_id"] = "expired-session"
        assert client.get("/auth_method_choice").status_code == 400


class TestPidAuthorization:
    """Test PID authorization endpoint"""

    @patch("app.services.oid4vp.requests.request")
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
        # Fixed behaviour: "/" between dynamic_presentation_url and the id
        url = mock_request.call_args.args[1]
        assert url.endswith("/test-presentation-123")

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
        from app.routes.oidc import credential_offer_references

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
        assert response.headers["Cache-Control"] == "no-store"

    def test_offer_reference_expired(self, client):
        from app.routes.oidc import credential_offer_references

        credential_offer_references["expired-ref"] = {
            "credential_offer": {"credential_issuer": "test"},
            "expires": datetime.now() - timedelta(seconds=1),
        }

        assert client.get("/credential-offer-reference/expired-ref").status_code == 404
        assert "expired-ref" not in credential_offer_references

    def test_offer_reference_unknown(self, client):
        assert client.get("/credential-offer-reference/unknown").status_code == 404


class TestBranchCoverage:
    """Additional tests for branch coverage"""

    @patch("app.routes.oidc.verify_introspection")
    def test_credential_with_dpop_header(
        self, mock_introspect, client, mock_cfgservice
    ):
        """Test credential endpoint with DPoP authorization"""
        mock_introspect.return_value = ("test-session", None)

        with patch("app.routes.oidc.session_manager") as mock_sm, patch(
            "app.routes.oidc.generate_credentials"
        ) as mock_gen:
            mock_session = Mock()
            mock_session.client_status = None
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
        from app.routes.oidc import verify_credential_request

        request = {
            "credential_indentifier": "test",  # typo
            "proof": {"proof_type": "jwt", "jwt": "test"},
        }

        from app.core.errors import OAuthEndpointError

        with app.app_context(), pytest.raises(OAuthEndpointError) as raised:
            verify_credential_request(request)

        assert (raised.value.error, raised.value.status) == ("invalid_credential_request", 400)

    def test_verify_credential_request_invalid_proof_type(self, app):
        """Test request with invalid proof type"""
        from app.routes.oidc import verify_credential_request

        request = {
            "credential_configuration_id": "test",
            "proof": {
                "proof_type": "jwt"
                # missing 'jwt' field
            },
        }

        from app.core.errors import OAuthEndpointError

        with app.app_context(), pytest.raises(OAuthEndpointError) as raised:
            verify_credential_request(request)

        assert (raised.value.error, raised.value.status) == ("invalid_proof", 400)


class TestErrorHandling:
    """Test error handling"""

    def test_bad_request_error_handler(self, client):
        """Test bad request error handler"""
        # This would typically be triggered by werkzeug
        # You might need to create a route that deliberately triggers it
        pass
