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
from pki_helpers import ca_entry, make_cert, x5c
from cryptography.hazmat.primitives.asymmetric import ec
import jwt
import json
import time
import base64
import io
from unittest.mock import Mock, patch, MagicMock, call
from datetime import datetime, timezone
from flask import Flask, session

from app.routes.preauth import preauth, preauthRed, preauth_form, form_authorize_generate, generate_offer, credentialOfferReq2, request_preauth_token


@pytest.fixture
def app():
    """Create and configure a Flask app for testing."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key"
    app.register_blueprint(preauth)
    return app


@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()


@pytest.fixture
def mock_session_manager():
    """Mock the session_manager module."""
    with patch("app.routes.preauth.session_manager") as mock:
        mock_session = Mock()
        mock_session.frontend_id = "5d725b3c-6d42-448e-8bfd-1eff1fcf152d"
        mock_session.credentials_requested = ["credential_1", "credential_2"]
        mock_session.user_data = {"name": "Test User", "email": "test@example.com"}
        mock_session.pre_authorized_code = "test_preauth_code_123"
        mock_session.tx_code = "12345"

        mock.get_session.return_value = mock_session
        mock.add_session.return_value = None
        mock.update_authorization_details.return_value = None
        mock.update_frontend_id.return_value = None
        mock.update_credentials_requested.return_value = None
        mock.update_user_data.return_value = None

        yield mock


@pytest.fixture(autouse=True)
def supported_credentials():
    """Credential ids the /preauth tests request (credentials_id is validated)."""
    ids = ["credential_1", "credential_2", "single_credential", "c1", "c2", "cred_1"]
    with patch.dict("app.core.state.oidc_metadata", {"credential_configurations_supported": {i: {} for i in ids}}):
        yield


@pytest.fixture
def mock_configuration():
    """Mock configuration services."""
        
    mock_cfg = {
        "service_url": "http://test-service.com/",
        "expiry": {
            "form": 30
        },
        "wallet_tester_url": "http://test-wallet.com/",
        "frontend": {
            "default": "default",
            "frontends_config": {
                "5d725b3c-6d42-448e-8bfd-1eff1fcf152d": {"url": "http://test-frontend.com"},
                "default": {"url": "http://default-frontend.com"},
            }
        },
        "authorization_server": {
            "base_url": "http://127.0.0.1:6005"
        },
        "credential_offer_scheme": "haip-vci://",
        "test_features": {"form_countries": True, "tx_code_in_offer": True, "credential_offer_request": True},
    }
    
    with patch.dict("app.routes.preauth.CONFIGURATION", mock_cfg):
        yield mock_cfg


class TestPreauthRed:
    """Test the /preauth route."""

    @patch("app.routes.preauth.request_preauth_token")
    @patch("app.routes.preauth.getAttributesForm")
    @patch("app.routes.preauth.getAttributesForm2")
    @patch("app.routes.preauth.post_redirect_with_payload")
    def test_preauth_red_success(
        self,
        mock_post_redirect,
        mock_getattr2,
        mock_getattr1,
        mock_request_token,
        client,
        mock_session_manager,
        mock_configuration,
    ):
        """Test successful preauth request."""
        # Setup
        mock_request_token.return_value = "test_session_id"
        mock_getattr1.return_value = {"name": "required", "email": "required"}
        mock_getattr2.return_value = {
            "name": "optional",
            "email": "optional",
            "phone": "optional",
        }

        # Create a proper Flask response
        from flask import Response

        mock_post_redirect.return_value = Response("redirect", status=302)

        # Execute
        with client.session_transaction() as sess:
            sess["credential_offer_URI"] = "openid-credential-offer://"

        response = client.post('/preauth?credentials_id=["credential_1","credential_2"]')

        # Assert
        assert response.status_code == 302
        # No frontend in the browser session: request_preauth_token uses the default.
        mock_request_token.assert_called_once_with(scope="credential_1 credential_2", frontend_id=None)
        mock_session_manager.update_authorization_details.assert_called_once()
        mock_session_manager.update_credentials_requested.assert_called_once()
        mock_post_redirect.assert_called_once()

        # Verify authorization_details structure
        call_args = mock_session_manager.update_authorization_details.call_args
        auth_details = call_args[1]["authorization_details"]
        assert len(auth_details) == 2
        assert auth_details[0]["type"] == "openid_credential"
        assert auth_details[0]["credential_configuration_id"] == "credential_1"

    @patch("app.routes.preauth.request_preauth_token")
    @patch("app.routes.preauth.getAttributesForm")
    @patch("app.routes.preauth.getAttributesForm2")
    @patch("app.routes.preauth.post_redirect_with_payload")
    def test_preauth_red_empty_credentials(
        self,
        mock_post_redirect,
        mock_getattr2,
        mock_getattr1,
        mock_request_token,
        client,
        mock_session_manager,
        mock_configuration,
    ):
        """An empty credentials list is invalid input: no pre-authorized code is requested."""
        from flask import Response

        mock_request_token.return_value = "test_session_id"
        mock_getattr1.return_value = {}
        mock_getattr2.return_value = {}
        mock_post_redirect.return_value = Response("redirect", status=302)

        with client.session_transaction() as sess:
            sess["credential_offer_URI"] = "openid-credential-offer://"

        response = client.post("/preauth?credentials_id=[]")

        mock_request_token.assert_not_called()
        assert response.status_code == 400

    @patch("app.routes.preauth.request_preauth_token")
    @patch("app.routes.preauth.getAttributesForm")
    @patch("app.routes.preauth.getAttributesForm2")
    @patch("app.routes.preauth.post_redirect_with_payload")
    def test_preauth_red_filters_optional_attributes(
        self,
        mock_post_redirect,
        mock_getattr2,
        mock_getattr1,
        mock_request_token,
        client,
        mock_session_manager,
        mock_configuration,
    ):
        """Test that optional attributes are filtered correctly."""
        from flask import Response

        mock_request_token.return_value = "test_session_id"
        mock_getattr1.return_value = {"name": "required", "email": "required"}
        mock_getattr2.return_value = {
            "name": "optional",
            "email": "optional",
            "phone": "optional",
        }
        mock_post_redirect.return_value = Response("redirect", status=302)

        with client.session_transaction() as sess:
            sess["credential_offer_URI"] = "openid-credential-offer://"

        response = client.post('/preauth?credentials_id=["credential_1"]')

        # Check that optional attributes don't include mandatory ones
        call_args = mock_post_redirect.call_args[1]["data_payload"]
        optional_attrs = call_args["optional_attributes"]
        assert "phone" in optional_attrs
        assert "name" not in optional_attrs
        assert "email" not in optional_attrs


class TestPreauthForm:
    """Test the /preauth_form route."""

    @patch("app.routes.preauth.form_formatter")
    @patch("app.routes.preauth.presentation_formatter")
    @patch("app.routes.preauth.post_redirect_with_payload")
    def test_preauth_form_success(
        self,
        mock_post_redirect,
        mock_pres_formatter,
        mock_form_formatter,
        client,
        mock_session_manager,
        mock_configuration,
    ):
        """Test successful form submission."""
        from flask import Response

        # Setup
        mock_form_formatter.return_value = {
            "name": "John Doe",
            "email": "john@example.com",
        }
        mock_pres_formatter.return_value = {"formatted": "data"}
        mock_post_redirect.return_value = Response("redirect", status=302)

        # Execute
        with client.session_transaction() as sess:
            sess["session_id"] = "test_session_id"

        response = client.post(
            "/preauth_form",
            data={"name": "John Doe", "email": "john@example.com", "proceed": "true"},
        )

        # Assert
        assert response.status_code == 302
        mock_form_formatter.assert_called_once()
        mock_pres_formatter.assert_called_once()
        mock_session_manager.update_user_data.assert_called_once()
        mock_post_redirect.assert_called_once()

        # Verify proceed was removed from form data
        call_args = mock_form_formatter.call_args[0][0]
        assert "proceed" not in call_args

    @patch("app.routes.preauth.presentation_formatter")
    @patch("app.routes.preauth.post_redirect_with_payload")
    def test_preauth_form_with_date(
        self,
        mock_post_redirect,
        mock_pres_formatter,
        client,
        mock_session_manager,
        mock_configuration,
    ):
        """Test form submission with date conversion.

        The RFC 3339 conversion now happens inside the (real) form_formatter,
        so the converted value is checked in the stored user data.
        """
        from flask import Response

        mock_pres_formatter.return_value = {"formatted": "data"}
        mock_post_redirect.return_value = Response("redirect", status=302)
        mock_session_manager.get_session.return_value.country = "FC"

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session_id"

        response = client.post(
            "/preauth_form",
            data={
                "name": "John Doe",
                "effective_from_date": "2024-01-01",
                "proceed": "true",
            },
        )

        assert response.status_code == 302
        user_data = mock_session_manager.update_user_data.call_args.kwargs["user_data"]
        assert "effective_from_date" in user_data
        assert user_data["effective_from_date"].endswith("Z")
        assert user_data["effective_from_date"] == "2024-01-01T00:00:00Z"
        assert user_data["name"] == "John Doe"
        assert user_data["issuing_country"] == "FC"

    @pytest.mark.parametrize(
        "form",
        [
            {"effective_from_date": "garbage"},
            {"a": "x", "a[0]": "y"},
            {"a[0]": "x", "a[0][b]": "y"},
        ],
    )
    def test_preauth_form_malformed(self, client, mock_session_manager, mock_configuration, form):
        """Malformed client input gives 400, not 500 (upstream #178)."""
        mock_session_manager.get_session.return_value.country = "FC"

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session_id"

        response = client.post("/preauth_form", data=form)

        assert response.status_code == 400
        mock_session_manager.update_user_data.assert_not_called()


class TestFormAuthorizeGenerate:
    """Test the /form_authorize_generate route."""

    @patch("app.routes.preauth.generate_offer")
    def test_form_authorize_generate_success(
        self, mock_generate_offer, client, mock_session_manager, mock_configuration
    ):
        """Test successful authorization generation."""
        from flask import Response

        mock_generate_offer.return_value = Response("offer", status=200)

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session_id"

        response = client.post(
            "/form_authorize_generate", data={"user_id": "test_session_id"}
        )

        assert response.status_code == 200
        mock_generate_offer.assert_called_once()

        # Verify the correct data was passed
        call_args = mock_generate_offer.call_args[0][0]
        assert call_args == mock_session_manager.get_session.return_value.user_data



@pytest.fixture
def trusted_request_signer():
    """Treats any request JWT as signed by a trusted certificate.

    Used by tests about payload handling; trust itself is covered by
    TestCredentialOfferReq2Trust and tests/test_trust.py.
    """
    def decode(token, **kwargs):
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        # A verified request always carries exp and iat (required_claims).
        claims.setdefault("iat", int(time.time()))
        claims.setdefault("exp", claims["iat"] + 300)
        return claims

    with patch("app.routes.preauth.verify_jwt_with_x5c", side_effect=decode) as verify:
        yield verify

class TestCredentialOfferReq2:
    """Test the /credentialOfferReq2 route."""

    @pytest.mark.usefixtures("trusted_request_signer")
    @patch("app.routes.preauth.request_preauth_token")
    def test_credential_offer_req2_success(
        self, mock_request_token, client, mock_session_manager, mock_configuration
    ):
        """Test successful credential offer request."""
        # Setup - Create a valid JWT-like token
        header = (
            base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode("utf-8").rstrip("=")
        )
        payload_data = {
            "credentials": [
                {
                    "credential_configuration_id": "credential_1",
                    "data": {"name": "Test User"},
                }
            ]
        }
        payload = (
            base64.urlsafe_b64encode(json.dumps(payload_data).encode("utf-8"))
            .decode("utf-8")
            .rstrip("=")
        )
        signature = base64.urlsafe_b64encode(b"signature").decode("utf-8").rstrip("=")

        jwt_token = f"{header}.{payload}.{signature}"

        mock_request_token.return_value = "test_session_id"

        # Execute
        response = client.post("/credentialOfferReq2", data={"request": jwt_token})

        # Assert
        assert response.status_code == 200
        response_data = response.get_json()
        assert "credential_issuer" in response_data
        assert "credential_configuration_ids" in response_data
        assert "grants" in response_data
        assert response_data["credential_configuration_ids"] == ["credential_1"]

        mock_session_manager.update_authorization_details.assert_called_once()
        mock_session_manager.update_user_data.assert_called_once()

    @pytest.mark.usefixtures("trusted_request_signer")
    @patch("app.routes.preauth.request_preauth_token")
    def test_credential_offer_req2_multiple_credentials(
        self, mock_request_token, client, mock_session_manager, mock_configuration
    ):
        """Test credential offer request with multiple credentials."""
        header = (
            base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode("utf-8").rstrip("=")
        )
        payload_data = {
            "credentials": [
                {
                    "credential_configuration_id": "credential_1",
                    "data": {"name": "Test User"},
                },
                {
                    "credential_configuration_id": "credential_2",
                    "data": {"email": "test@example.com"},
                },
                {
                    "credential_configuration_id": "credential_1",  # Duplicate
                    "data": {"name": "Test User 2"},
                },
            ]
        }
        payload = (
            base64.urlsafe_b64encode(json.dumps(payload_data).encode("utf-8"))
            .decode("utf-8")
            .rstrip("=")
        )
        signature = base64.urlsafe_b64encode(b"signature").decode("utf-8").rstrip("=")

        jwt_token = f"{header}.{payload}.{signature}"
        mock_request_token.return_value = "test_session_id"

        response = client.post("/credentialOfferReq2", data={"request": jwt_token})

        response_data = response.get_json()
        # Should only have unique credential IDs
        assert len(response_data["credential_configuration_ids"]) == 2
        assert "credential_1" in response_data["credential_configuration_ids"]
        assert "credential_2" in response_data["credential_configuration_ids"]

    @pytest.mark.usefixtures("trusted_request_signer")
    @patch("app.routes.preauth.request_preauth_token")
    def test_credential_offer_req2_with_padding(
        self, mock_request_token, client, mock_session_manager, mock_configuration
    ):
        """Test JWT token with different padding scenarios."""
        header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode(
            "utf-8"
        )  # Keep padding
        payload_data = {
            "credentials": [{"credential_configuration_id": "cred", "data": {"x": "y"}}]
        }
        payload = base64.urlsafe_b64encode(
            json.dumps(payload_data).encode("utf-8")
        ).decode(
            "utf-8"
        )  # Keep padding
        signature = base64.urlsafe_b64encode(b"sig").decode("utf-8")

        jwt_token = f"{header}.{payload}.{signature}"
        mock_request_token.return_value = "test_session_id"

        response = client.post("/credentialOfferReq2", data={"request": jwt_token})

        assert response.status_code == 200


class TestRequestPreauthToken:
    """Test the request_preauth_token function."""

    @patch("app.services.auth_server.requests.request")
    def test_request_preauth_token_success(
        self, mock_requests, mock_session_manager, mock_configuration
    ):
        """Test successful preauth token request."""
        # Setup

        mock_cfg = mock_configuration

        mock_response = Mock()
        mock_response.json.return_value = {
            "preauth_code": "test_code_123",
            "session_id": "test_session_id",
            "tx_code": "12345",
        }
        mock_requests.return_value = mock_response

        # Execute
        result = request_preauth_token("credential_1 credential_2")

        # Assert
        assert result == "test_session_id"

        expected_url = f"{mock_cfg['authorization_server']['base_url']}/preauth_generate"

        mock_requests.assert_called_once_with(
            "POST",
            expected_url,
            headers={"Content-Type": "application/x-www-form-urlencoded", "X-Api-Key": ""},
            data={"scope": "credential_1 credential_2", "frontend_id": mock_cfg["frontend"]["default"]},
            timeout=30,
        )
        mock_session_manager.add_session.assert_called_once_with(
            session_id="test_session_id",
            pre_authorized_code="test_code_123",
            scope="credential_1 credential_2",
            tx_code="12345",
            country="FC",
            frontend_id=mock_cfg["frontend"]["default"],
        )

    @patch("app.services.auth_server.requests.request")
    def test_request_preauth_token_empty_scope(
        self, mock_requests, mock_session_manager, mock_configuration
    ):
        """Test preauth token request with empty scope."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "preauth_code": "test_code",
            "session_id": "test_id",
            "tx_code": "54321",
        }
        mock_requests.return_value = mock_response

        result = request_preauth_token("")

        assert result == "test_id"
        call_args = mock_requests.call_args
        assert call_args[1]["data"] == {"scope": "", "frontend_id": "default"}

    @patch("app.services.auth_server.requests.request")
    def test_request_preauth_token_with_special_chars(
        self, mock_requests, mock_session_manager, mock_configuration
    ):
        """Test preauth token request with special characters in scope."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "preauth_code": "code",
            "session_id": "sid",
            "tx_code": "99999",
        }
        mock_requests.return_value = mock_response

        result = request_preauth_token("credential-1 credential_2")

        assert result == "sid"
        assert mock_session_manager.add_session.called


class TestIntegration:
    """Integration tests for the preauth flow."""

    @patch("app.routes.preauth.form_formatter")
    @patch("app.routes.preauth.presentation_formatter")
    @patch("app.routes.preauth.post_redirect_with_payload")
    @patch("app.routes.preauth.generate_offer")
    def test_form_to_offer_flow(
        self,
        mock_generate_offer,
        mock_post_redirect,
        mock_pres_formatter,
        mock_form_formatter,
        client,
        mock_session_manager,
        mock_configuration,
    ):
        """Test flow from form submission to offer generation."""
        from flask import Response

        mock_form_formatter.return_value = {"name": "John", "email": "john@test.com"}
        mock_pres_formatter.return_value = {"display": "data"}
        mock_post_redirect.return_value = Response("redirect", status=302)
        mock_generate_offer.return_value = Response("offer", status=200)

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session_id"

        # Submit form
        response1 = client.post(
            "/preauth_form",
            data={"name": "John", "email": "john@test.com", "proceed": "yes"},
        )

        assert response1.status_code == 302
        assert mock_session_manager.update_user_data.called

        # Generate offer
        response2 = client.post(
            "/form_authorize_generate", data={"user_id": "test_session_id"}
        )

        assert response2.status_code == 200
        assert mock_generate_offer.called


class TestEdgeCases:
    """Test edge cases and error scenarios."""

    @patch("app.routes.preauth.request_preauth_token")
    @patch("app.routes.preauth.getAttributesForm")
    @patch("app.routes.preauth.getAttributesForm2")
    @patch("app.routes.preauth.post_redirect_with_payload")
    def test_preauth_with_vct_credentials(
        self,
        mock_post_redirect,
        mock_getattr2,
        mock_getattr1,
        mock_request_token,
        client,
        mock_session_manager,
        mock_configuration,
    ):
        """Test preauth handles credentials with 'vct' field instead of 'credential_configuration_id'."""
        from flask import Response

        mock_request_token.return_value = "test_session_id"
        mock_getattr1.return_value = {}
        mock_getattr2.return_value = {}
        mock_post_redirect.return_value = Response("redirect", status=302)

        # Mock authorization_details with vct
        mock_session = mock_session_manager.get_session.return_value

        with client.session_transaction() as sess:
            sess["credential_offer_URI"] = "openid-credential-offer://"

        # Simulate authorization_details being set with vct
        def mock_update_auth_details(session_id, authorization_details):
            # Modify authorization_details to include vct type
            for detail in authorization_details:
                if "credential_configuration_id" in detail:
                    detail["vct"] = detail["credential_configuration_id"]

        mock_session_manager.update_authorization_details.side_effect = (
            mock_update_auth_details
        )

        response = client.post('/preauth?credentials_id=["credential_1"]')
        assert response.status_code == 302

    @patch("app.routes.preauth.form_formatter")
    @patch("app.routes.preauth.presentation_formatter")
    @patch("app.routes.preauth.post_redirect_with_payload")
    def test_preauth_form_without_date_field(
        self,
        mock_post_redirect,
        mock_pres_formatter,
        mock_form_formatter,
        client,
        mock_session_manager,
        mock_configuration,
    ):
        """Test form submission without effective_from_date."""
        from flask import Response

        mock_form_formatter.return_value = {"name": "Test"}
        mock_pres_formatter.return_value = {"data": "test"}
        mock_post_redirect.return_value = Response("redirect", status=302)

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session_id"

        response = client.post(
            "/preauth_form",
            data={"name": "Test", "other_field": "value", "proceed": "yes"},
        )

        assert response.status_code == 302
        call_args = mock_form_formatter.call_args[0][0]
        assert "effective_from_date" not in call_args

    @pytest.mark.usefixtures("trusted_request_signer")
    @patch("app.routes.preauth.request_preauth_token")
    def test_credential_offer_req2_includes_tx_code_value(
        self, mock_request_token, client, mock_session_manager, mock_configuration
    ):
        """Test that credentialOfferReq2 includes tx_code value in response."""
        header = (
            base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode("utf-8").rstrip("=")
        )
        payload_data = {
            "credentials": [
                {"credential_configuration_id": "test_cred", "data": {"field": "value"}}
            ]
        }
        payload = (
            base64.urlsafe_b64encode(json.dumps(payload_data).encode("utf-8"))
            .decode("utf-8")
            .rstrip("=")
        )
        signature = base64.urlsafe_b64encode(b"sig").decode("utf-8").rstrip("=")

        jwt_token = f"{header}.{payload}.{signature}"
        mock_request_token.return_value = "test_session_id"

        response = client.post("/credentialOfferReq2", data={"request": jwt_token})

        response_data = response.get_json()
        grants = response_data["grants"][
            "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        ]

        assert "tx_code" in grants
        assert "value" in grants["tx_code"]
        assert grants["tx_code"]["value"] == "12345"
        assert grants["tx_code"]["length"] == 5
        assert grants["tx_code"]["input_mode"] == "numeric"

    @patch("app.routes.preauth.request_preauth_token")
    @patch("app.routes.preauth.getAttributesForm")
    @patch("app.routes.preauth.getAttributesForm2")
    @patch("app.routes.preauth.post_redirect_with_payload")
    def test_preauth_with_single_credential(
        self,
        mock_post_redirect,
        mock_getattr2,
        mock_getattr1,
        mock_request_token,
        client,
        mock_session_manager,
        mock_configuration,
    ):
        """Test preauth with a single credential."""
        from flask import Response

        mock_request_token.return_value = "test_session_id"
        mock_getattr1.return_value = {"field1": "req"}
        mock_getattr2.return_value = {"field1": "opt", "field2": "opt"}
        mock_post_redirect.return_value = Response("redirect", status=302)

        with client.session_transaction() as sess:
            sess["credential_offer_URI"] = "openid-credential-offer://"

        response = client.post('/preauth?credentials_id=["single_credential"]')

        assert response.status_code == 302

        # Verify credentials_requested has single credential
        call_args = mock_session_manager.update_credentials_requested.call_args
        creds = call_args[1]["credentials_requested"]
        assert len(creds) == 1
        assert "single_credential" in creds

    @patch("app.routes.preauth.form_formatter")
    @patch("app.routes.preauth.presentation_formatter")
    @patch("app.routes.preauth.post_redirect_with_payload")
    @patch("app.routes.preauth.logger")
    def test_preauth_form_logs_data(
        self,
        mock_logger,
        mock_post_redirect,
        mock_pres_formatter,
        mock_form_formatter,
        client,
        mock_session_manager,
        mock_configuration,
    ):
        """preauth_form logs a milestone at INFO and only field names at DEBUG, never values."""
        from flask import Response

        mock_form_formatter.return_value = {"data": "test"}
        mock_pres_formatter.return_value = {"display": "test"}
        mock_post_redirect.return_value = Response("redirect", status=302)

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session_id"

        client.post("/preauth_form", data={"family_name": "Secret-Name", "proceed": "yes"})

        info_lines = [str(c.args[0]) for c in mock_logger.info.call_args_list]
        debug_lines = [str(c.args[0]) for c in mock_logger.debug.call_args_list]
        assert any("Pre-authorized attribute form submitted" in line for line in info_lines)
        assert any("family_name" in line for line in debug_lines)
        assert not any("Secret-Name" in line for line in info_lines + debug_lines)

    @patch("app.services.auth_server.requests.request")
    def test_request_preauth_token_returns_all_values(
        self, mock_requests, mock_session_manager, mock_configuration
    ):
        """Test that request_preauth_token extracts all values from response."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "preauth_code": "abc123",
            "session_id": "session_456",
            "tx_code": "99999",
        }
        mock_requests.return_value = mock_response

        result = request_preauth_token("test_scope")

        # Verify all values were passed to add_session
        call_args = mock_session_manager.add_session.call_args[1]
        assert call_args["pre_authorized_code"] == "abc123"
        assert call_args["session_id"] == "session_456"
        assert call_args["tx_code"] == "99999"
        assert call_args["scope"] == "test_scope"
        assert call_args["country"] == "FC"


class TestCompleteCodeCoverage:
    """Additional tests to ensure 100% code coverage."""

    @patch("app.routes.preauth.request_preauth_token")
    @patch("app.routes.preauth.getAttributesForm")
    @patch("app.routes.preauth.getAttributesForm2")
    @patch("app.routes.preauth.post_redirect_with_payload")
    def test_preauth_updates_all_session_fields(
        self,
        mock_post_redirect,
        mock_getattr2,
        mock_getattr1,
        mock_request_token,
        client,
        mock_session_manager,
        mock_configuration,
    ):
        """Test that preauth updates all required session fields."""
        from flask import Response

        mock_request_token.return_value = "new_session"
        mock_getattr1.return_value = {"a": "b"}
        mock_getattr2.return_value = {"c": "d"}
        mock_post_redirect.return_value = Response("redirect", status=302)

        with client.session_transaction() as sess:
            sess["credential_offer_URI"] = "openid-credential-offer://"

        response = client.post('/preauth?credentials_id=["c1","c2"]')

        # Verify all update methods were called
        assert mock_session_manager.update_authorization_details.called
        assert mock_session_manager.update_credentials_requested.called

    @patch("app.routes.preauth.form_formatter")
    @patch("app.routes.preauth.presentation_formatter")
    @patch("app.routes.preauth.post_redirect_with_payload")
    def test_preauth_form_removes_proceed_before_formatting(
        self,
        mock_post_redirect,
        mock_pres_formatter,
        mock_form_formatter,
        client,
        mock_session_manager,
        mock_configuration,
    ):
        """Test that 'proceed' is removed from form_data before formatting."""
        from flask import Response

        mock_form_formatter.return_value = {"clean": "data"}
        mock_pres_formatter.return_value = {"pres": "data"}
        mock_post_redirect.return_value = Response("redirect", status=302)

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session_id"

        response = client.post(
            "/preauth_form",
            data={"field1": "value1", "field2": "value2", "proceed": "Submit"},
        )

        # Verify proceed was removed
        call_args = mock_form_formatter.call_args[0][0]
        assert "proceed" not in call_args
        assert "field1" in call_args
        assert "field2" in call_args

    @pytest.mark.usefixtures("trusted_request_signer")
    @patch("app.routes.preauth.request_preauth_token")
    def test_credential_offer_req2_constructs_authorization_details(
        self, mock_request_token, client, mock_session_manager, mock_configuration
    ):
        """Test that credentialOfferReq2 constructs proper authorization_details."""
        header = base64.urlsafe_b64encode(b"{}").decode("utf-8").rstrip("=")
        payload_data = {
            "credentials": [
                {"credential_configuration_id": "id1", "data": {"d": "1"}},
                {"credential_configuration_id": "id2", "data": {"d": "2"}},
            ]
        }
        payload = (
            base64.urlsafe_b64encode(json.dumps(payload_data).encode("utf-8"))
            .decode("utf-8")
            .rstrip("=")
        )
        signature = base64.urlsafe_b64encode(b"s").decode("utf-8").rstrip("=")

        jwt_token = f"{header}.{payload}.{signature}"
        mock_request_token.return_value = "sid"

        response = client.post("/credentialOfferReq2", data={"request": jwt_token})

        # Verify authorization_details was updated correctly
        call_args = mock_session_manager.update_authorization_details.call_args
        auth_details = call_args[1]["authorization_details"]

        assert len(auth_details) == 2
        assert all(d["type"] == "openid_credential" for d in auth_details)
        assert auth_details[0]["credential_configuration_id"] == "id1"
        assert auth_details[1]["credential_configuration_id"] == "id2"

    @pytest.mark.usefixtures("trusted_request_signer")
    @patch("app.routes.preauth.request_preauth_token")
    def test_credential_offer_req2_extracts_data_from_first_credential(
        self, mock_request_token, client, mock_session_manager, mock_configuration
    ):
        """Test that credentialOfferReq2 extracts data from first credential only."""
        header = base64.urlsafe_b64encode(b"{}").decode("utf-8").rstrip("=")
        payload_data = {
            "credentials": [
                {"credential_configuration_id": "id1", "data": {"name": "Alice"}},
                {"credential_configuration_id": "id2", "data": {"name": "Bob"}},
            ]
        }
        payload = (
            base64.urlsafe_b64encode(json.dumps(payload_data).encode("utf-8"))
            .decode("utf-8")
            .rstrip("=")
        )
        signature = base64.urlsafe_b64encode(b"s").decode("utf-8").rstrip("=")

        jwt_token = f"{header}.{payload}.{signature}"
        mock_request_token.return_value = "sid"

        response = client.post("/credentialOfferReq2", data={"request": jwt_token})

        # Verify user_data was updated with first credential's data
        call_args = mock_session_manager.update_user_data.call_args
        user_data = call_args[1]["user_data"]

        assert user_data == {"name": "Alice"}


class TestCredentialOfferReq2Trust:
    """credentialOfferReq2 only accepts requests signed by a trusted certificate."""

    PAYLOAD = {
        "credentials": [{"credential_configuration_id": "cred_1", "data": {"name": "Test"}}],
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
    }

    @pytest.fixture
    def pki(self):
        root_key = ec.generate_private_key(ec.SECP256R1())
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        other_key = ec.generate_private_key(ec.SECP256R1())
        root = make_cert("Root CA", "Root CA", root_key.public_key(), root_key, ca=True)
        return {
            "root": root,
            "leaf": make_cert("Requester", "Root CA", leaf_key.public_key(), root_key, ca=False),
            "untrusted": make_cert("Requester", "Other CA", leaf_key.public_key(), other_key, ca=False),
            "leaf_key": leaf_key,
            "other_key": other_key,
        }

    @pytest.fixture(autouse=True)
    def trusted_store(self, pki):
        with patch.dict("app.core.state.trusted_CAs", {pki["root"].subject: ca_entry(pki["root"])}, clear=True):
            yield

    @pytest.fixture
    def preauth_token(self):
        with patch("app.routes.preauth.request_preauth_token", return_value="test_session_id") as mock:
            yield mock

    def _post(self, client, token):
        return client.post("/credentialOfferReq2", data={"request": token})

    def test_trusted_signer_accepted(self, client, mock_session_manager, mock_configuration, pki, preauth_token):
        token = jwt.encode(self.PAYLOAD, pki["leaf_key"], algorithm="ES256", headers={"x5c": x5c(pki["leaf"])})

        response = self._post(client, token)

        assert response.status_code == 200
        assert response.get_json()["credential_configuration_ids"] == ["cred_1"]
        preauth_token.assert_called_once_with(scope="cred_1")

    def test_untrusted_signer_rejected(self, client, mock_session_manager, mock_configuration, pki, preauth_token):
        token = jwt.encode(self.PAYLOAD, pki["leaf_key"], algorithm="ES256", headers={"x5c": x5c(pki["untrusted"])})

        response = self._post(client, token)

        assert response.status_code == 401
        assert response.get_json()["error_description"] == "Untrusted request signer"
        preauth_token.assert_not_called()

    def test_signature_not_matching_certificate_rejected(
        self, client, mock_session_manager, mock_configuration, pki, preauth_token
    ):
        token = jwt.encode(self.PAYLOAD, pki["other_key"], algorithm="ES256", headers={"x5c": x5c(pki["leaf"])})

        response = self._post(client, token)

        assert response.status_code == 401
        assert response.get_json()["error_description"] == "Invalid request JWT signature"
        preauth_token.assert_not_called()

    def test_unsigned_token_without_x5c_rejected(
        self, client, mock_session_manager, mock_configuration, pki, preauth_token
    ):
        token = jwt.encode(self.PAYLOAD, "shared-secret", algorithm="HS256")

        response = self._post(client, token)

        assert response.status_code == 400
        preauth_token.assert_not_called()

    def test_missing_request_rejected(self, client, mock_session_manager, mock_configuration, preauth_token):
        response = client.post("/credentialOfferReq2", data={})

        assert response.status_code == 400
        assert response.get_json()["error_description"] == "Missing request JWT"

    def test_trust_validator_context(self, client, mock_session_manager, mock_configuration, pki, preauth_token):
        token = jwt.encode(self.PAYLOAD, pki["leaf_key"], algorithm="ES256", headers={"x5c": x5c(pki["leaf"])})
        with patch("app.routes.preauth.verify_jwt_with_x5c", return_value=self.PAYLOAD) as verify:
            self._post(client, token)

        assert verify.call_args.kwargs["verification_context"] == "WalletRelyingPartyAccessCertificate"


class TestGenerateOfferMode:
    """Pre-authorized offers honour the offer form's credential_offer_mode (#70)."""

    @pytest.mark.parametrize("mode", [None, "by_value", "unknown"])
    def test_by_value(self, app, mock_session_manager, mock_configuration, mode):
        from app.repositories import offer_store

        with app.test_request_context(), patch.dict(offer_store.credential_offer_references, {}, clear=True), patch(
            "app.routes.preauth.post_redirect_with_payload", return_value="page"
        ) as page:
            session.update(session_id="s1", credential_offer_URI="openid-credential-offer://", credential_offer_mode=mode)
            generate_offer({})
            assert offer_store.credential_offer_references == {}

        assert "credential_offer=" in page.call_args.kwargs["data_payload"]["url_data"]

    def test_by_reference(self, app, mock_session_manager, mock_configuration):
        from urllib.parse import parse_qs, urlsplit

        from app.repositories import offer_store

        with app.test_request_context(), patch.dict(offer_store.credential_offer_references, {}, clear=True), patch(
            "app.routes.preauth.post_redirect_with_payload", return_value="page"
        ) as page:
            session.update(session_id="s1", credential_offer_URI="openid-credential-offer://", credential_offer_mode="by_reference")
            generate_offer({})
            (reference_id, entry), = offer_store.credential_offer_references.items()

        payload = page.call_args.kwargs["data_payload"]
        [reference_url] = parse_qs(urlsplit(payload["url_data"]).query)["credential_offer_uri"]
        assert reference_url.endswith(f"/credential-offer-reference/{reference_id}")
        assert entry["credential_offer"] == payload["credential_offer"]
        assert entry["credential_offer"]["grants"]
