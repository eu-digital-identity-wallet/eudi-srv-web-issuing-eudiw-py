import pytest
import json
import base64
import io
from unittest.mock import Mock, patch, MagicMock, call
from datetime import datetime, timezone
from flask import Flask, session

from app.preauthorization import (
    preauth,
    preauthRed,
    preauth_form,
    form_authorize_generate,
    generate_offer,
    credentialOfferReq2,
    request_preauth_token,
)


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
    with patch("app.preauthorization.session_manager") as mock:
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


@pytest.fixture
def mock_config():
    """Mock configuration services."""
    with patch("app.preauthorization.cfgservice") as mock_cfg, patch(
        "app.preauthorization.ConfFrontend"
    ) as mock_frontend:

        mock_cfg.service_url = "http://test-service.com/"
        mock_cfg.form_expiry = 30
        mock_cfg.wallet_test_url = "http://test-wallet.com/"
        mock_cfg.default_frontend = "default"
        mock_cfg.authorization_server_internal_url = "http://127.0.0.1:6005"
        mock_cfg.app_logger = Mock()

        mock_frontend.registered_frontends = {
            "5d725b3c-6d42-448e-8bfd-1eff1fcf152d": {"url": "http://test-frontend.com"},
            "default": {"url": "http://default-frontend.com"},
        }

        yield mock_cfg, mock_frontend


class TestPreauthRed:
    """Test the /preauth route."""

    @patch("app.preauthorization.request_preauth_token")
    @patch("app.preauthorization.getAttributesForm")
    @patch("app.preauthorization.getAttributesForm2")
    @patch("app.preauthorization.post_redirect_with_payload")
    def test_preauth_red_success(
        self,
        mock_post_redirect,
        mock_getattr2,
        mock_getattr1,
        mock_request_token,
        client,
        mock_session_manager,
        mock_config,
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

        response = client.get('/preauth?credentials_id=["credential_1","credential_2"]')

        # Assert
        assert response.status_code == 302
        mock_request_token.assert_called_once_with(scope="credential_1 credential_2")
        mock_session_manager.update_authorization_details.assert_called_once()
        mock_session_manager.update_frontend_id.assert_called_once()
        mock_session_manager.update_credentials_requested.assert_called_once()
        mock_post_redirect.assert_called_once()

        # Verify authorization_details structure
        call_args = mock_session_manager.update_authorization_details.call_args
        auth_details = call_args[1]["authorization_details"]
        assert len(auth_details) == 2
        assert auth_details[0]["type"] == "openid_credential"
        assert auth_details[0]["credential_configuration_id"] == "credential_1"

    @patch("app.preauthorization.request_preauth_token")
    @patch("app.preauthorization.getAttributesForm")
    @patch("app.preauthorization.getAttributesForm2")
    @patch("app.preauthorization.post_redirect_with_payload")
    def test_preauth_red_empty_credentials(
        self,
        mock_post_redirect,
        mock_getattr2,
        mock_getattr1,
        mock_request_token,
        client,
        mock_session_manager,
        mock_config,
    ):
        """Test preauth with empty credentials list."""
        from flask import Response

        mock_request_token.return_value = "test_session_id"
        mock_getattr1.return_value = {}
        mock_getattr2.return_value = {}
        mock_post_redirect.return_value = Response("redirect", status=302)

        with client.session_transaction() as sess:
            sess["credential_offer_URI"] = "openid-credential-offer://"

        response = client.get("/preauth?credentials_id=[]")

        mock_request_token.assert_called_once_with(scope="")
        assert response.status_code == 302

    @patch("app.preauthorization.request_preauth_token")
    @patch("app.preauthorization.getAttributesForm")
    @patch("app.preauthorization.getAttributesForm2")
    @patch("app.preauthorization.post_redirect_with_payload")
    def test_preauth_red_filters_optional_attributes(
        self,
        mock_post_redirect,
        mock_getattr2,
        mock_getattr1,
        mock_request_token,
        client,
        mock_session_manager,
        mock_config,
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

        response = client.get('/preauth?credentials_id=["credential_1"]')

        # Check that optional attributes don't include mandatory ones
        call_args = mock_post_redirect.call_args[1]["data_payload"]
        optional_attrs = call_args["optional_attributes"]
        assert "phone" in optional_attrs
        assert "name" not in optional_attrs
        assert "email" not in optional_attrs


class TestPreauthForm:
    """Test the /preauth_form route."""

    @patch("app.preauthorization.form_formatter")
    @patch("app.preauthorization.presentation_formatter")
    @patch("app.preauthorization.post_redirect_with_payload")
    def test_preauth_form_success(
        self,
        mock_post_redirect,
        mock_pres_formatter,
        mock_form_formatter,
        client,
        mock_session_manager,
        mock_config,
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

    @patch("app.preauthorization.form_formatter")
    @patch("app.preauthorization.presentation_formatter")
    @patch("app.preauthorization.post_redirect_with_payload")
    def test_preauth_form_with_date(
        self,
        mock_post_redirect,
        mock_pres_formatter,
        mock_form_formatter,
        client,
        mock_session_manager,
        mock_config,
    ):
        """Test form submission with date conversion."""
        from flask import Response

        mock_form_formatter.return_value = {
            "name": "John Doe",
            "effective_from_date": "2024-01-01T00:00:00Z",
        }
        mock_pres_formatter.return_value = {"formatted": "data"}
        mock_post_redirect.return_value = Response("redirect", status=302)

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

        # Verify form_formatter was called with converted date
        call_args = mock_form_formatter.call_args[0][0]
        assert "effective_from_date" in call_args
        assert call_args["effective_from_date"].endswith("Z")
        assert "T00:00:00Z" in call_args["effective_from_date"]


class TestFormAuthorizeGenerate:
    """Test the /form_authorize_generate route."""

    @patch("app.preauthorization.generate_offer")
    def test_form_authorize_generate_success(
        self, mock_generate_offer, client, mock_session_manager, mock_config
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


class TestCredentialOfferReq2:
    """Test the /credentialOfferReq2 route."""

    @patch("app.preauthorization.request_preauth_token")
    def test_credential_offer_req2_success(
        self, mock_request_token, client, mock_session_manager, mock_config
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

    @patch("app.preauthorization.request_preauth_token")
    def test_credential_offer_req2_multiple_credentials(
        self, mock_request_token, client, mock_session_manager, mock_config
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

    @patch("app.preauthorization.request_preauth_token")
    def test_credential_offer_req2_with_padding(
        self, mock_request_token, client, mock_session_manager, mock_config
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

    @patch("app.preauthorization.requests.request")
    def test_request_preauth_token_success(
        self, mock_requests, mock_session_manager, mock_config
    ):
        """Test successful preauth token request."""
        # Setup

        mock_cfg, mock_frontend = mock_config

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

        expected_url = f"{mock_cfg.authorization_server_internal_url}/preauth_generate"

        mock_requests.assert_called_once_with(
            "POST",
            expected_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data="scope=credential_1 credential_2",
        )
        mock_session_manager.add_session.assert_called_once_with(
            session_id="test_session_id",
            pre_authorized_code="test_code_123",
            scope="credential_1 credential_2",
            tx_code="12345",
            country="FC",
        )

    @patch("app.preauthorization.requests.request")
    def test_request_preauth_token_empty_scope(
        self, mock_requests, mock_session_manager, mock_config
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
        assert "scope=" in call_args[1]["data"]

    @patch("app.preauthorization.requests.request")
    def test_request_preauth_token_with_special_chars(
        self, mock_requests, mock_session_manager, mock_config
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

    @patch("app.preauthorization.form_formatter")
    @patch("app.preauthorization.presentation_formatter")
    @patch("app.preauthorization.post_redirect_with_payload")
    @patch("app.preauthorization.generate_offer")
    def test_form_to_offer_flow(
        self,
        mock_generate_offer,
        mock_post_redirect,
        mock_pres_formatter,
        mock_form_formatter,
        client,
        mock_session_manager,
        mock_config,
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

    @patch("app.preauthorization.request_preauth_token")
    @patch("app.preauthorization.getAttributesForm")
    @patch("app.preauthorization.getAttributesForm2")
    @patch("app.preauthorization.post_redirect_with_payload")
    def test_preauth_with_vct_credentials(
        self,
        mock_post_redirect,
        mock_getattr2,
        mock_getattr1,
        mock_request_token,
        client,
        mock_session_manager,
        mock_config,
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

        response = client.get('/preauth?credentials_id=["credential_1"]')
        assert response.status_code == 302

    @patch("app.preauthorization.form_formatter")
    @patch("app.preauthorization.presentation_formatter")
    @patch("app.preauthorization.post_redirect_with_payload")
    def test_preauth_form_without_date_field(
        self,
        mock_post_redirect,
        mock_pres_formatter,
        mock_form_formatter,
        client,
        mock_session_manager,
        mock_config,
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

    @patch("app.preauthorization.request_preauth_token")
    def test_credential_offer_req2_includes_tx_code_value(
        self, mock_request_token, client, mock_session_manager, mock_config
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

    @patch("app.preauthorization.request_preauth_token")
    @patch("app.preauthorization.getAttributesForm")
    @patch("app.preauthorization.getAttributesForm2")
    @patch("app.preauthorization.post_redirect_with_payload")
    def test_preauth_with_single_credential(
        self,
        mock_post_redirect,
        mock_getattr2,
        mock_getattr1,
        mock_request_token,
        client,
        mock_session_manager,
        mock_config,
    ):
        """Test preauth with a single credential."""
        from flask import Response

        mock_request_token.return_value = "test_session_id"
        mock_getattr1.return_value = {"field1": "req"}
        mock_getattr2.return_value = {"field1": "opt", "field2": "opt"}
        mock_post_redirect.return_value = Response("redirect", status=302)

        with client.session_transaction() as sess:
            sess["credential_offer_URI"] = "openid-credential-offer://"

        response = client.get('/preauth?credentials_id=["single_credential"]')

        assert response.status_code == 302

        # Verify credentials_requested has single credential
        call_args = mock_session_manager.update_credentials_requested.call_args
        creds = call_args[1]["credentials_requested"]
        assert len(creds) == 1
        assert "single_credential" in creds

    @patch("app.preauthorization.form_formatter")
    @patch("app.preauthorization.presentation_formatter")
    @patch("app.preauthorization.post_redirect_with_payload")
    def test_preauth_form_logs_data(
        self,
        mock_post_redirect,
        mock_pres_formatter,
        mock_form_formatter,
        client,
        mock_session_manager,
        mock_config,
    ):
        """Test that preauth_form logs form data."""
        from flask import Response

        mock_form_formatter.return_value = {"data": "test"}
        mock_pres_formatter.return_value = {"display": "test"}
        mock_post_redirect.return_value = Response("redirect", status=302)

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session_id"

        response = client.post(
            "/preauth_form", data={"field": "value", "proceed": "yes"}
        )

        # Verify logger was called
        mock_cfg, _ = mock_config
        assert mock_cfg.app_logger.info.called
        assert mock_cfg.app_logger.info.call_count >= 2

    @patch("app.preauthorization.requests.request")
    def test_request_preauth_token_returns_all_values(
        self, mock_requests, mock_session_manager, mock_config
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

    @patch("app.preauthorization.request_preauth_token")
    @patch("app.preauthorization.getAttributesForm")
    @patch("app.preauthorization.getAttributesForm2")
    @patch("app.preauthorization.post_redirect_with_payload")
    def test_preauth_updates_all_session_fields(
        self,
        mock_post_redirect,
        mock_getattr2,
        mock_getattr1,
        mock_request_token,
        client,
        mock_session_manager,
        mock_config,
    ):
        """Test that preauth updates all required session fields."""
        from flask import Response

        mock_request_token.return_value = "new_session"
        mock_getattr1.return_value = {"a": "b"}
        mock_getattr2.return_value = {"c": "d"}
        mock_post_redirect.return_value = Response("redirect", status=302)

        with client.session_transaction() as sess:
            sess["credential_offer_URI"] = "openid-credential-offer://"

        response = client.get('/preauth?credentials_id=["c1","c2"]')

        # Verify all update methods were called
        assert mock_session_manager.update_authorization_details.called
        assert mock_session_manager.update_frontend_id.called
        assert mock_session_manager.update_credentials_requested.called

        # Verify frontend_id is set correctly
        frontend_call = mock_session_manager.update_frontend_id.call_args
        assert frontend_call[1]["frontend_id"] == "5d725b3c-6d42-448e-8bfd-1eff1fcf152d"

    @patch("app.preauthorization.form_formatter")
    @patch("app.preauthorization.presentation_formatter")
    @patch("app.preauthorization.post_redirect_with_payload")
    def test_preauth_form_removes_proceed_before_formatting(
        self,
        mock_post_redirect,
        mock_pres_formatter,
        mock_form_formatter,
        client,
        mock_session_manager,
        mock_config,
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

    @patch("app.preauthorization.request_preauth_token")
    def test_credential_offer_req2_constructs_authorization_details(
        self, mock_request_token, client, mock_session_manager, mock_config
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

    @patch("app.preauthorization.request_preauth_token")
    def test_credential_offer_req2_extracts_data_from_first_credential(
        self, mock_request_token, client, mock_session_manager, mock_config
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
