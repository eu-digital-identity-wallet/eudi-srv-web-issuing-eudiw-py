import pytest
import json
import uuid
from unittest.mock import Mock, patch, MagicMock
from flask import Flask, jsonify, make_response
from app.route_oidc import oidc


@pytest.fixture
def app():
    """Create a Flask app for testing"""
    app = Flask(__name__)
    app.config["TESTING"] = True

    app.register_blueprint(oidc)
    return app


@pytest.fixture
def client(app):
    """Create a test client"""
    return app.test_client()


@pytest.fixture
def mock_dependencies():
    """Mock all external dependencies"""
    with patch("app.route_oidc.cfgservice") as mock_cfg, patch(
        "app.route_oidc.decrypt_jwe_credential_request"
    ) as mock_decrypt, patch(
        "app.route_oidc.verify_introspection"
    ) as mock_introspection, patch(
        "app.route_oidc.verify_credential_request"
    ) as mock_verify_request, patch(
        "app.route_oidc.session_manager"
    ) as mock_session, patch(
        "app.route_oidc.generate_credentials"
    ) as mock_generate, patch(
        "app.route_oidc.encrypt_response"
    ) as mock_encrypt:

        # Setup default mock behaviors
        mock_cfg.app_logger = Mock()

        yield {
            "cfgservice": mock_cfg,
            "decrypt_jwe": mock_decrypt,
            "introspection": mock_introspection,
            "verify_request": mock_verify_request,
            "session_manager": mock_session,
            "generate_credentials": mock_generate,
            "encrypt_response": mock_encrypt,
        }


class TestCredentialEndpoint:

    def test_json_credential_request_success(self, client, mock_dependencies):
        """Test successful credential request with JSON content type"""
        # Setup

        print("\nRegistered routes:")
        for rule in client.application.url_map.iter_rules():
            print(rule)

        session_id = "test-session-123"
        credential_request = {
            "credential_configuration_id": "eu.europa.ec.eudi.pid_mdoc",
            "proof": {
                "proof_type": "jwt",
                "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoid1V1UDJPbHdIZWZlRS1ZMTZXajdQSEF6WjBKQVF5ZXZxV01mZDUtS21LWSIsInkiOiJZVy1iOE8zVWszTlVyazlvWnBBVDFsYVBlQWdpTlF3RGNvdFdpd0JGUTZFIn19.eyJhdWQiOiJodHRwczovL3ByZXByb2QuaXNzdWVyLmV1ZGl3LmRldi9vaWRjIiwibm9uY2UiOiJTcUdTMzc0eUFheFpIc254aUs5NWVnIiwiaWF0IjoxNzA0ODg2ODU1fQ.IdmxwbfJIKwcaqvADp6bzV2u-o0UwKIVmo_kQkc1rZHQ9MtBDNbO21NoVr99ZEgumTX8UYNFJcr_R95xfO1NiA",
            },
        }

        mock_dependencies["introspection"].return_value = session_id
        mock_dependencies["verify_request"].return_value = credential_request
        mock_dependencies["generate_credentials"].return_value = {
            "credentials": [{"credential": "test_credential"}]
        }

        mock_dependencies["session_manager"].get_session.return_value = {}

        # Execute
        response = client.post(
            "/credential",
            json=credential_request,
            headers={"Authorization": "Bearer valid_token"},
        )

        # Assert
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "credentials" in data
        assert isinstance(data["credentials"], list)
        assert data["credentials"][0]["credential"] == "test_credential"

        assert "notification_id" in data
        mock_dependencies["session_manager"].store_notification_id.assert_called_once()

    def test_encrypted_credential_request_success(self, client, mock_dependencies, app):
        """Test successful credential request with encrypted JWT content type"""
        # Setup

        session_id = "test-session-123"
        jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGc..."
        decrypted_request = {
            "credential_configuration_id": "eu.europa.ec.eudi.pid_jwt_vc_json",
            "proof": {
                "proof_type": "jwt",
                "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoid1V1UDJPbHdIZWZlRS1ZMTZXajdQSEF6WjBKQVF5ZXZxV01mZDUtS21LWSIsInkiOiJZVy1iOE8zVWszTlVyazlvWnBBVDFsYVBlQWdpTlF3RGNvdFdpd0JGUTZFIn19.eyJhdWQiOiJodHRwczovL3ByZXByb2QuaXNzdWVyLmV1ZGl3LmRldi9vaWRjIiwibm9uY2UiOiJTcUdTMzc0eUFheFpIc254aUs5NWVnIiwiaWF0IjoxNzA0ODg2ODU1fQ.IdmxwbfJIKwcaqvADp6bzV2u-o0UwKIVmo_kQkc1rZHQ9MtBDNbO21NoVr99ZEgumTX8UYNFJcr_R95xfO1NiA",
            },
            "credential_response_encryption": {
                "jwk": {
                    "kty": "RSA",
                    "e": "AQAB",
                    "use": "enc",
                    "kid": "TnZdnKa6J2CNWVqiXfeA0cTncNEUpW1aUz7sjLGT3KM",
                    "alg": "RSA1_5",
                    "n": "vb0jIdYbhIWgUguleNnycccu1O3of20BghIllQ9jjaa8QQNQaVN3KkRk6-YoeOz6PUfEtlZPBSQ3qmXndX3f1JPQ3m1hRor6oWs7oBzAndKbKAPtgnLl5iOMcQDW0K6OmIJJnrtrx6zTZCjcoJhdN063ZeUhmeQ5-K5kF0Ka9ZSdmqvTwpYmSTTbxrVtIJvq-LxqxPEb1a_cMVcZ4VahO5GCh8bGBcw0Rity9JGGxUo2m2c1e5cyqn5nN5tnHh0A17qinxlWg65CeOv9LTrEp4inf4ymlneyoNzhugdRqf5aS_3lLL-R4aQOxsm1nhB0JMpHKf23YRuNDT945GWP0w",
                },
                "alg": "RSA1_5",
                "enc": "A256GCM",
            },
        }

        mock_dependencies["decrypt_jwe"].return_value = decrypted_request
        mock_dependencies["introspection"].return_value = session_id
        mock_dependencies["verify_request"].return_value = decrypted_request
        mock_dependencies["generate_credentials"].return_value = {
            "credentials": [{"credential": "test_credential"}]
        }
        fake_jwe = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."

        """ mock_dependencies["encrypt_response"].return_value = make_response(
            fake_jwe, 200, {"Content-Type": "application/jwt"}
        ) """

        mock_dependencies["session_manager"].get_session.return_value = {}

        # Execute
        """ response = client.post(
            "/credential",
            data=jwt_token,
            content_type="application/jwt",
            headers={"Authorization": "Bearer valid_token"},
        ) """

        with app.app_context():
            mock_dependencies["encrypt_response"].return_value = make_response(
                fake_jwe, 200, {"Content-Type": "application/jwt"}
            )

            # Execute request
            response = client.post(
                "/credential",
                data=jwt_token,
                content_type="application/jwt",
                headers={"Authorization": "Bearer valid_token"},
            )

        print("response: ", response)

        # Assert
        assert response.status_code == 200
        assert response.content_type == "application/jwt"
        encrypted_jwe = response.data.decode("utf-8")
        assert encrypted_jwe.startswith("eyJ")

        mock_dependencies["decrypt_jwe"].assert_called_once_with(jwt_token)

    def test_missing_authorization_header(self, client, mock_dependencies):
        """Test request without Authorization header"""

        response = client.post(
            "/credential",
            json={
                "credential_configuration_id": "eu.europa.ec.eudi.pid_mdoc",
                "proof": {
                    "proof_type": "jwt",
                    "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoid1V1UDJPbHdIZWZlRS1ZMTZXajdQSEF6WjBKQVF5ZXZxV01mZDUtS21LWSIsInkiOiJZVy1iOE8zVWszTlVyazlvWnBBVDFsYVBlQWdpTlF3RGNvdFdpd0JGUTZFIn19.eyJhdWQiOiJodHRwczovL3ByZXByb2QuaXNzdWVyLmV1ZGl3LmRldi9vaWRjIiwibm9uY2UiOiJTcUdTMzc0eUFheFpIc254aUs5NWVnIiwiaWF0IjoxNzA0ODg2ODU1fQ.IdmxwbfJIKwcaqvADp6bzV2u-o0UwKIVmo_kQkc1rZHQ9MtBDNbO21NoVr99ZEgumTX8UYNFJcr_R95xfO1NiA",
                },
            },
        )

        assert response.status_code == 401
        data = json.loads(response.data)
        assert data["error"] == "invalid_request"

    def test_invalid_authorization_header_format(self, client, mock_dependencies):
        """Test request with invalid Authorization header format"""
        response = client.post(
            "/credential",
            json={"format": "jwt_vc_json"},
            headers={"Authorization": "Basic invalid"},
        )

        assert response.status_code == 401
        data = json.loads(response.data)
        assert "invalid_token" in data["error"]

    def test_authorization_header_without_token(self, client, mock_dependencies):
        """Test request with Authorization header but no token"""
        response = client.post(
            "/credential",
            json={"format": "jwt_vc_json"},
            headers={"Authorization": "Bearer"},
        )

        assert response.status_code == 401
        data = json.loads(response.data)
        assert "invalid_token" in data["error"]

    def test_dpop_authorization_success(self, client, mock_dependencies):
        """Test successful request with DPoP token"""
        session_id = "test-session-123"
        credential_request = {"format": "jwt_vc_json"}

        mock_dependencies["introspection"].return_value = session_id
        mock_dependencies["verify_request"].return_value = credential_request
        mock_dependencies["generate_credentials"].return_value = {
            "credentials": [{"credential": "test_credential"}]
        }
        mock_dependencies["session_manager"].get_session.return_value = {}

        response = client.post(
            "/credential",
            json=credential_request,
            headers={"Authorization": "DPoP valid_dpop_token"},
        )

        assert response.status_code == 200

    def test_introspection_verification_failure(self, client, mock_dependencies):
        """Test when token introspection fails"""
        error_response = ({"error": "invalid_token"}, 401)
        mock_dependencies["introspection"].return_value = error_response

        response = client.post(
            "/credential",
            json={"format": "jwt_vc_json"},
            headers={"Authorization": "Bearer invalid_token"},
        )

        assert response.status_code == 401
        data = json.loads(response.data)
        assert "invalid_token" in data["error"]

    def test_credential_request_verification_failure(self, client, mock_dependencies):
        """Test when credential request verification fails"""
        session_id = "test-session-123"
        error_response = ({"error": "invalid_credential_request"}, 400)

        mock_dependencies["introspection"].return_value = session_id
        mock_dependencies["verify_request"].return_value = error_response

        response = client.post(
            "/credential",
            json={"format": "invalid_format"},
            headers={"Authorization": "Bearer valid_token"},
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert "invalid_credential_request" in data["error"]

    def test_deferred_credential_with_pending_error(self, client, mock_dependencies):
        """Test deferred credential issuance with Pending error"""
        session_id = "test-session-123"
        credential_request = {"format": "mso_mdoc"}

        mock_dependencies["introspection"].return_value = session_id
        mock_dependencies["verify_request"].return_value = credential_request
        mock_dependencies["generate_credentials"].return_value = {"error": "Pending"}
        mock_dependencies["session_manager"].get_session.return_value = {}

        response = client.post(
            "/credential",
            json=credential_request,
            headers={"Authorization": "Bearer valid_token"},
        )

        assert response.status_code == 202
        data = json.loads(response.data)
        assert "transaction_id" in data
        assert data["interval"] == 30
        mock_dependencies["session_manager"].add_transaction_id.assert_called_once()

    def test_deferred_credential_with_config_id(self, client, mock_dependencies):
        """Test deferred credential with specific configuration ID"""
        session_id = "test-session-123"
        credential_request = {
            "credential_configuration_id": "eu.europa.ec.eudi.pid_mdoc_deferred"
        }

        mock_dependencies["introspection"].return_value = session_id
        mock_dependencies["verify_request"].return_value = credential_request
        mock_dependencies["generate_credentials"].return_value = {"credential": "test"}
        mock_dependencies["session_manager"].get_session.return_value = {}

        response = client.post(
            "/credential",
            json=credential_request,
            headers={"Authorization": "Bearer valid_token"},
        )

        assert response.status_code == 202
        data = json.loads(response.data)
        assert "transaction_id" in data

    def test_encrypted_response_success(self, client, mock_dependencies, app):
        """Test successful encrypted credential response"""
        session_id = "test-session-123"
        credential_request = {
            "credential_configuration_id": "eu.europa.ec.eudi.pid_jwt_vc_json",
            "proof": {
                "proof_type": "jwt",
                "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoid1V1UDJPbHdIZWZlRS1ZMTZXajdQSEF6WjBKQVF5ZXZxV01mZDUtS21LWSIsInkiOiJZVy1iOE8zVWszTlVyazlvWnBBVDFsYVBlQWdpTlF3RGNvdFdpd0JGUTZFIn19.eyJhdWQiOiJodHRwczovL3ByZXByb2QuaXNzdWVyLmV1ZGl3LmRldi9vaWRjIiwibm9uY2UiOiJTcUdTMzc0eUFheFpIc254aUs5NWVnIiwiaWF0IjoxNzA0ODg2ODU1fQ.IdmxwbfJIKwcaqvADp6bzV2u-o0UwKIVmo_kQkc1rZHQ9MtBDNbO21NoVr99ZEgumTX8UYNFJcr_R95xfO1NiA",
            },
            "credential_response_encryption": {
                "jwk": {
                    "kty": "RSA",
                    "e": "AQAB",
                    "use": "enc",
                    "kid": "TnZdnKa6J2CNWVqiXfeA0cTncNEUpW1aUz7sjLGT3KM",
                    "alg": "RSA1_5",
                    "n": "vb0jIdYbhIWgUguleNnycccu1O3of20BghIllQ9jjaa8QQNQaVN3KkRk6-YoeOz6PUfEtlZPBSQ3qmXndX3f1JPQ3m1hRor6oWs7oBzAndKbKAPtgnLl5iOMcQDW0K6OmIJJnrtrx6zTZCjcoJhdN063ZeUhmeQ5-K5kF0Ka9ZSdmqvTwpYmSTTbxrVtIJvq-LxqxPEb1a_cMVcZ4VahO5GCh8bGBcw0Rity9JGGxUo2m2c1e5cyqn5nN5tnHh0A17qinxlWg65CeOv9LTrEp4inf4ymlneyoNzhugdRqf5aS_3lLL-R4aQOxsm1nhB0JMpHKf23YRuNDT945GWP0w",
                },
                "alg": "RSA1_5",
                "enc": "A256GCM",
            },
        }

        with app.app_context():
            mock_response = make_response(
                b"encrypted_response", 200, {"Content-Type": "application/jwt"}
            )

        mock_dependencies["introspection"].return_value = session_id
        mock_dependencies["verify_request"].return_value = credential_request
        mock_dependencies["generate_credentials"].return_value = {
            "credentials": [{"credential": "test_credential"}]
        }
        mock_dependencies["encrypt_response"].return_value = mock_response
        mock_dependencies["session_manager"].get_session.return_value = {}

        response = client.post(
            "/credential",
            json=credential_request,
            headers={"Authorization": "Bearer valid_token"},
        )

        assert response.status_code == 200
        mock_dependencies["encrypt_response"].assert_called_once()

    def test_encrypted_response_deferred(self, client, mock_dependencies, app):
        """Test encrypted deferred credential response"""
        session_id = "test-session-123"
        credential_request = {
            "credential_configuration_id": "eu.europa.ec.eudi.pid_jwt_vc_json",
            "proof": {
                "proof_type": "jwt",
                "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoid1V1UDJPbHdIZWZlRS1ZMTZXajdQSEF6WjBKQVF5ZXZxV01mZDUtS21LWSIsInkiOiJZVy1iOE8zVWszTlVyazlvWnBBVDFsYVBlQWdpTlF3RGNvdFdpd0JGUTZFIn19.eyJhdWQiOiJodHRwczovL3ByZXByb2QuaXNzdWVyLmV1ZGl3LmRldi9vaWRjIiwibm9uY2UiOiJTcUdTMzc0eUFheFpIc254aUs5NWVnIiwiaWF0IjoxNzA0ODg2ODU1fQ.IdmxwbfJIKwcaqvADp6bzV2u-o0UwKIVmo_kQkc1rZHQ9MtBDNbO21NoVr99ZEgumTX8UYNFJcr_R95xfO1NiA",
            },
            "credential_response_encryption": {
                "jwk": {
                    "kty": "RSA",
                    "e": "AQAB",
                    "use": "enc",
                    "kid": "TnZdnKa6J2CNWVqiXfeA0cTncNEUpW1aUz7sjLGT3KM",
                    "alg": "RSA1_5",
                    "n": "vb0jIdYbhIWgUguleNnycccu1O3of20BghIllQ9jjaa8QQNQaVN3KkRk6-YoeOz6PUfEtlZPBSQ3qmXndX3f1JPQ3m1hRor6oWs7oBzAndKbKAPtgnLl5iOMcQDW0K6OmIJJnrtrx6zTZCjcoJhdN063ZeUhmeQ5-K5kF0Ka9ZSdmqvTwpYmSTTbxrVtIJvq-LxqxPEb1a_cMVcZ4VahO5GCh8bGBcw0Rity9JGGxUo2m2c1e5cyqn5nN5tnHh0A17qinxlWg65CeOv9LTrEp4inf4ymlneyoNzhugdRqf5aS_3lLL-R4aQOxsm1nhB0JMpHKf23YRuNDT945GWP0w",
                },
                "alg": "RSA1_5",
                "enc": "A256GCM",
            },
        }

        with app.app_context():
            mock_response = make_response(
                b"encrypted_response", 200, {"Content-Type": "application/jwt"}
            )

        mock_dependencies["introspection"].return_value = session_id
        mock_dependencies["verify_request"].return_value = credential_request
        mock_dependencies["generate_credentials"].return_value = {"error": "Pending"}
        mock_dependencies["encrypt_response"].return_value = mock_response
        mock_dependencies["session_manager"].get_session.return_value = {}

        response = client.post(
            "/credential",
            json=credential_request,
            headers={"Authorization": "Bearer valid_token"},
        )

        assert response.status_code == 202

    def test_encrypted_response_error(self, client, mock_dependencies, app):
        """Test when encryption fails"""
        session_id = "test-session-123"
        credential_request = {
            "format": "jwt_vc_json",
            "credential_response_encryption": {"jwk": {"kty": "RSA"}},
        }

        with app.app_context():
            mock_response = make_response(
                jsonify(
                    {
                        "error": "invalid_credential_response_encryption",
                        "error_description": "Missing alg field in credential_response_encryption.",
                    }
                ),
                400,
            )

        mock_dependencies["introspection"].return_value = session_id
        mock_dependencies["verify_request"].return_value = credential_request
        mock_dependencies["generate_credentials"].return_value = {
            "credentials": [{"credential": "test_credential"}]
        }
        mock_dependencies["encrypt_response"].return_value = mock_response
        mock_dependencies["session_manager"].get_session.return_value = {}

        response = client.post(
            "/credential",
            json=credential_request,
            headers={"Authorization": "Bearer valid_token"},
        )

        assert response.status_code == 400

    def test_invalid_jwt_request_token(self, client, mock_dependencies):
        """Test with invalid JWT token"""
        from jwt import InvalidTokenError

        mock_dependencies["decrypt_jwe"].side_effect = InvalidTokenError(
            "Invalid token"
        )

        response = client.post(
            "/credential",
            data="invalid_jwt_token",
            content_type="application/jwt",
            headers={"Authorization": "Bearer valid_token"},
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert "invalid_credential_request" in data["error"]

    def test_notification_id_stored(self, client, mock_dependencies):
        """Test that notification_id is generated and stored"""
        session_id = "test-session-123"
        credential_request = {"format": "jwt_vc_json"}

        mock_dependencies["introspection"].return_value = session_id
        mock_dependencies["verify_request"].return_value = credential_request
        mock_dependencies["generate_credentials"].return_value = {
            "credentials": [{"credential": "test_credential"}]
        }
        mock_dependencies["session_manager"].get_session.return_value = {}

        with patch("app.route_oidc.uuid.uuid4") as mock_uuid:
            mock_uuid.return_value = uuid.UUID("12345678-1234-5678-1234-567812345678")

            response = client.post(
                "/credential",
                json=credential_request,
                headers={"Authorization": "Bearer valid_token"},
            )

            data = json.loads(response.data)
            assert data["notification_id"] == "12345678-1234-5678-1234-567812345678"
            mock_dependencies[
                "session_manager"
            ].store_notification_id.assert_called_with(
                session_id=session_id,
                notification_id="12345678-1234-5678-1234-567812345678",
            )


class TestIntegrationScenarios:
    """Integration-style tests for complete flows"""

    def test_complete_credential_issuance_flow(self, client, mock_dependencies):
        """Test complete flow from request to credential issuance"""
        session_id = "integration-test-session"
        credential_request = {
            "credential_configuration_id": "eu.europa.ec.eudi.pid_jwt_vc_json",
            "proof": {
                "proof_type": "jwt",
                "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoid1V1UDJPbHdIZWZlRS1ZMTZXajdQSEF6WjBKQVF5ZXZxV01mZDUtS21LWSIsInkiOiJZVy1iOE8zVWszTlVyazlvWnBBVDFsYVBlQWdpTlF3RGNvdFdpd0JGUTZFIn19.eyJhdWQiOiJodHRwczovL3ByZXByb2QuaXNzdWVyLmV1ZGl3LmRldi9vaWRjIiwibm9uY2UiOiJTcUdTMzc0eUFheFpIc254aUs5NWVnIiwiaWF0IjoxNzA0ODg2ODU1fQ.IdmxwbfJIKwcaqvADp6bzV2u-o0UwKIVmo_kQkc1rZHQ9MtBDNbO21NoVr99ZEgumTX8UYNFJcr_R95xfO1NiA",
            },
        }

        mock_dependencies["introspection"].return_value = session_id
        mock_dependencies["verify_request"].return_value = credential_request
        mock_dependencies["generate_credentials"].return_value = {
            "credentials": [{"credential": "test_credential"}]
        }
        mock_dependencies["session_manager"].get_session.return_value = {
            "user_id": "user123"
        }

        response = client.post(
            "/credential",
            json=credential_request,
            headers={"Authorization": "Bearer valid_access_token"},
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert "credentials" in data
        for cred in data["credentials"]:
            assert "credential" in cred
        assert "notification_id" in data
