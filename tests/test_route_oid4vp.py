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
import io
import json
import base64
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask, session
from app.route_oid4vp import oid4vp


# --- Fixtures ---
@pytest.fixture
def app():
    app = Flask(__name__)
    app.secret_key = "test_secret"
    app.register_blueprint(oid4vp)
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def mock_session_data():
    # Minimal mock session
    mock = MagicMock()
    mock.frontend_id = "test_frontend"
    mock.oid4vp_transaction_id = "tx123"
    mock.credentials_requested = ["eu.europa.ec.eudi.pid_mdoc"]
    mock.authorization_details = (
        [{"credential_configuration_id": "eu.europa.ec.eudi.pid_mdoc"}],
    )
    mock.scope = []
    return mock


# --- Test Classes ---
class TestOid4vpRouteSuccess:
    @patch("app.route_oid4vp.session_manager.get_session")
    @patch("app.route_oid4vp.session_manager.update_oid4vp_transaction_id")
    @patch("app.route_oid4vp.requests.request")
    @patch("app.route_oid4vp.cfgservice")
    @patch("app.route_oid4vp.ConfFrontend")
    @patch("app.route_oid4vp.post_redirect_with_payload")
    @patch("app.route_oid4vp.segno.make")
    @patch("app.route_oid4vp.oidc_metadata")
    def test_openid4vp_success(
        self,
        mock_oidc_metadata,
        mock_segno,
        mock_post_redirect,
        mock_conf_frontend,
        mock_cfgservice,
        mock_requests,
        mock_update_tx,
        mock_get_session,
        client,
        mock_session_data,
    ):
        # Setup session
        with client.session_transaction() as sess:
            sess["session_id"] = "123"

        # Mock session manager
        mock_get_session.return_value = mock_session_data

        # Mock oidc_metadata
        mock_oidc_metadata.__getitem__ = MagicMock(
            return_value={
                "eu.europa.ec.eudi.pid_mdoc": {
                    "format": "mso_mdoc",
                    "doctype": "eu.europa.ec.eudi.pid.1",
                    "credential_metadata": {
                        "claims": [{"path": ["family_name"]}, {"path": ["given_name"]}]
                    },
                }
            }
        )

        # Mock config
        mock_cfgservice.dynamic_presentation_url = "https://example.com/"
        mock_cfgservice.service_url = "https://service.com/"

        mock_conf_frontend.registered_frontends = {
            "test_frontend": {"url": "https://frontend.com"}
        }

        # Mock requests
        mock_response_cross = {
            "client_id": "clientX",
            "request_uri": "reqX",
            "transaction_id": "txX",
        }
        mock_response_same = {
            "client_id": "clientY",
            "request_uri": "reqY",
            "transaction_id": "txY",
        }
        mock_requests.side_effect = [
            MagicMock(json=MagicMock(return_value=mock_response_cross)),
            MagicMock(json=MagicMock(return_value=mock_response_same)),
        ]

        # Mock QR code
        mock_qr_instance = MagicMock()
        mock_qr_instance.save = MagicMock()
        mock_segno.return_value = mock_qr_instance

        # Mock redirect
        mock_post_redirect.return_value = "REDIRECT_CALLED"

        resp = client.get("/oid4vp")
        assert resp.data == b"REDIRECT_CALLED"
        mock_update_tx.assert_called_once_with(
            session_id="123", oid4vp_transaction_id="txY"
        )
        mock_segno.assert_called_once()


class TestOid4vpRouteSessionError:
    def test_missing_session(self, client):
        resp = client.get("/oid4vp")
        # Flask will raise a KeyError when session_id is missing
        assert (
            resp.status_code == 500
        )  # You can handle KeyError differently in production


class TestOid4vpRouteRequestError:
    @patch("app.route_oid4vp.requests.request")
    @patch("app.route_oid4vp.session_manager.get_session")
    @patch("app.route_oid4vp.cfgservice")
    @patch("app.route_oid4vp.oidc_metadata")
    def test_requests_fail(
        self,
        mock_oidc_metadata,
        mock_cfgservice,
        mock_get_session,
        mock_requests,
        client,
        mock_session_data,
    ):
        with client.session_transaction() as sess:
            sess["session_id"] = "123"

        mock_get_session.return_value = mock_session_data
        mock_cfgservice.dynamic_presentation_url = "https://example.com/"

        # Mock oidc_metadata
        mock_oidc_metadata.__getitem__ = MagicMock(
            return_value={
                "eu.europa.ec.eudi.pid_mdoc": {
                    "format": "mso_mdoc",
                    "doctype": "eu.europa.ec.eudi.pid.1",
                    "credential_metadata": {"claims": []},
                }
            }
        )

        mock_requests.side_effect = Exception("Request failed")

        resp = client.get("/oid4vp")
        assert resp.status_code == 500


class TestGetPidOid4vp:
    @patch("app.route_oid4vp.session_manager.get_session")
    @patch("app.route_oid4vp.session_manager.update_country")
    @patch("app.route_oid4vp.requests.request")
    @patch("app.route_oid4vp.validate_vp_token")
    @patch("app.route_oid4vp.cbor2elems")
    @patch("app.route_oid4vp.post_redirect_with_payload")
    @patch("app.route_oid4vp.cfgservice")
    @patch("app.route_oid4vp.ConfFrontend")
    @patch("app.route_oid4vp.getAttributesForm")
    @patch("app.route_oid4vp.getAttributesForm2")
    def test_same_device_flow(
        self,
        mock_getAttributesForm2,
        mock_getAttributesForm,
        mock_conf_frontend,
        mock_cfgservice,
        mock_post_redirect,
        mock_cbor2elems,
        mock_validate_vp_token,
        mock_requests,
        mock_update_country,
        mock_get_session,
        client,
        mock_session_data,
    ):
        # Setup session
        with client.session_transaction() as sess:
            sess["session_id"] = "123"

        mock_session_data.authorization_details = [
            {"credential_configuration_id": "dummy"}
        ]
        mock_get_session.return_value = mock_session_data

        # Configs
        mock_cfgservice.dynamic_presentation_url = "https://example.com/"
        mock_cfgservice.service_url = "https://service.com/"
        mock_cfgservice.config_doctype = {
            "eu.europa.ec.eudi.pseudonym.age_over_18.1": {
                "issuing_authority": "FC Authority",
                "validity": 365,
                "credential_type": "over18",
            }
        }

        mock_conf_frontend.registered_frontends = {
            "test_frontend": {"url": "https://frontend.com"}
        }

        # Requests mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vp_token": {"query_0": ["mocked_base64"]}}
        mock_requests.return_value = mock_response

        # Validate VP token returns no error
        mock_validate_vp_token.return_value = (False, "")

        # cbor2elems returns fake decoded data
        mock_cbor2elems.return_value = {
            "eu.europa.ec.eudi.pseudonym.age_over_18.1": [("age_over_18", True)]
        }

        # Mock getAttributesForm functions - these WILL be called since authorization_details is empty
        mock_getAttributesForm.return_value = {"age_over_18": {"type": "boolean"}}
        mock_getAttributesForm2.return_value = {"optional1": {"type": "string"}}

        mock_post_redirect.return_value = "REDIRECT_CALLED"

        resp = client.get("/getpidoid4vp?response_code=resp123&session_id=123")
        assert resp.data == b"REDIRECT_CALLED"
        mock_get_session.assert_called()
        mock_requests.assert_called()
        mock_post_redirect.assert_called_once()

    def test_missing_params(self, client):
        # If neither presentation_id nor response_code is present
        with client.session_transaction() as sess:
            sess["session_id"] = "123"
        resp = client.get("/getpidoid4vp")
        # Will likely raise KeyError or ValueError; depending on production error handling
        assert resp.status_code == 500

    @patch("app.route_oid4vp.session_manager.get_session")
    @patch("app.route_oid4vp.requests.request")
    def test_invalid_presentation_id(
        self, mock_requests, mock_get_session, client, mock_session_data
    ):
        with client.session_transaction() as sess:
            sess["session_id"] = "123"

        mock_get_session.return_value = mock_session_data

        resp = client.get("/getpidoid4vp?presentation_id=invalid*id")
        # Invalid format
        assert resp.status_code == 500


class TestGetPidOid4vpAdditional:
    @patch("app.route_oid4vp.session_manager.get_session")
    @patch("app.route_oid4vp.session_manager.update_country")
    @patch("app.route_oid4vp.requests.request")
    @patch("app.route_oid4vp.validate_vp_token")
    @patch("app.route_oid4vp.cbor2elems")
    @patch("app.route_oid4vp.post_redirect_with_payload")
    @patch("app.route_oid4vp.cfgservice")
    @patch("app.route_oid4vp.ConfFrontend")
    @patch("app.route_oid4vp.getAttributesForm")
    @patch("app.route_oid4vp.getAttributesForm2")
    def test_cross_device_flow(
        self,
        mock_getAttributesForm2,
        mock_getAttributesForm,
        mock_conf_frontend,
        mock_cfgservice,
        mock_post_redirect,
        mock_cbor2elems,
        mock_validate_vp_token,
        mock_requests,
        mock_update_country,
        mock_get_session,
        client,
        mock_session_data,
    ):
        """Cross-device flow using presentation_id"""
        with client.session_transaction() as sess:
            sess["session_id"] = "123"

        mock_session_data.authorization_details = [
            {"credential_configuration_id": "dummy"}
        ]
        mock_get_session.return_value = mock_session_data

        mock_cfgservice.dynamic_presentation_url = "https://example.com/"
        mock_cfgservice.service_url = "https://service.com/"
        mock_conf_frontend.registered_frontends = {
            "test_frontend": {"url": "https://frontend.com"}
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vp_token": {"query_0": ["mocked_base64"]}}
        mock_requests.return_value = mock_response

        mock_validate_vp_token.return_value = (False, "")
        mock_cbor2elems.return_value = {"doctype1": [("attr1", "val1")]}

        # Mock getAttributesForm functions
        mock_getAttributesForm.return_value = {"attr1": {"type": "string"}}
        mock_getAttributesForm2.return_value = {"optional1": {"type": "string"}}

        mock_post_redirect.return_value = "REDIRECT_CALLED"

        resp = client.get("/getpidoid4vp?presentation_id=validID123")
        assert resp.data == b"REDIRECT_CALLED"
        mock_requests.assert_called()
        mock_post_redirect.assert_called_once()

    @patch("app.route_oid4vp.session_manager.get_session")
    @patch("app.route_oid4vp.session_manager.update_country")
    @patch("app.route_oid4vp.requests.request")
    @patch("app.route_oid4vp.validate_vp_token")
    @patch("app.route_oid4vp.cbor2elems")
    @patch("app.route_oid4vp.post_redirect_with_payload")
    @patch("app.route_oid4vp.cfgservice")
    @patch("app.route_oid4vp.ConfFrontend")
    @patch("app.route_oid4vp.getAttributesForm")
    @patch("app.route_oid4vp.getAttributesForm2")
    def test_non_age_over18_flow(
        self,
        mock_getAttributesForm2,
        mock_getAttributesForm,
        mock_conf_frontend,
        mock_cfgservice,
        mock_post_redirect,
        mock_cbor2elems,
        mock_validate_vp_token,
        mock_requests,
        mock_update_country,
        mock_get_session,
        client,
        mock_session_data,
    ):
        """Non-age-over-18 normal form-filling"""
        with client.session_transaction() as sess:
            sess["session_id"] = "123"

        mock_session_data.authorization_details = [
            {"credential_configuration_id": "dummy"}
        ]
        mock_get_session.return_value = mock_session_data
        mock_cfgservice.dynamic_presentation_url = "https://example.com/"
        mock_cfgservice.service_url = "https://service.com/"
        mock_conf_frontend.registered_frontends = {
            "test_frontend": {"url": "https://frontend.com"}
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vp_token": {"query_0": ["mocked_base64"]}}
        mock_requests.return_value = mock_response
        mock_validate_vp_token.return_value = (False, "")
        mock_cbor2elems.return_value = {"doctype1": [("attr1", "val1")]}

        mock_getAttributesForm.return_value = {"attr1": {"type": "string"}}
        mock_getAttributesForm2.return_value = {"optional1": {"type": "string"}}
        mock_post_redirect.return_value = "REDIRECT_CALLED"

        resp = client.get("/getpidoid4vp?response_code=resp123&session_id=123")
        assert resp.data == b"REDIRECT_CALLED"
        mock_post_redirect.assert_called_once()

    @patch("app.route_oid4vp.session_manager.get_session")
    @patch("app.route_oid4vp.requests.request")
    @patch("app.route_oid4vp.validate_vp_token")
    def test_vp_token_invalid(
        self,
        mock_validate_vp_token,
        mock_requests,
        mock_get_session,
        client,
        mock_session_data,
    ):
        """VP token validation fails and raises ValueError"""
        with client.session_transaction() as sess:
            sess["session_id"] = "123"
        mock_get_session.return_value = mock_session_data

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vp_token": {"query_0": ["mocked_base64"]}}
        mock_requests.return_value = mock_response

        mock_validate_vp_token.return_value = (True, "error_message")

        client.application.config["PROPAGATE_EXCEPTIONS"] = True
        import pytest

        with pytest.raises(ValueError):
            client.get("/getpidoid4vp?response_code=resp123&session_id=123")

    @patch("app.route_oid4vp.session_manager.get_session")
    @patch("app.route_oid4vp.requests.request")
    def test_requests_non_200(
        self, mock_requests, mock_get_session, client, mock_session_data
    ):
        """Requests returns non-200 → 400 response"""
        with client.session_transaction() as sess:
            sess["session_id"] = "123"
        mock_get_session.return_value = mock_session_data

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_requests.return_value = mock_response

        resp = client.get("/getpidoid4vp?presentation_id=validID123")
        assert resp.status_code == 400
        assert b"500" in resp.data

    @patch("app.route_oid4vp.session_manager.get_session")
    @patch("app.route_oid4vp.session_manager.update_country")
    @patch("app.route_oid4vp.requests.request")
    @patch("app.route_oid4vp.validate_vp_token")
    @patch("app.route_oid4vp.cbor2elems")
    @patch("app.route_oid4vp.post_redirect_with_payload")
    @patch("app.route_oid4vp.cfgservice")
    @patch("app.route_oid4vp.ConfFrontend")
    @patch("app.route_oid4vp.getAttributesForm")
    @patch("app.route_oid4vp.getAttributesForm2")
    def test_authorization_details_age_over18(
        self,
        mock_getAttributesForm2,
        mock_getAttributesForm,
        mock_conf_frontend,
        mock_cfgservice,
        mock_post_redirect,
        mock_cbor2elems,
        mock_validate_vp_token,
        mock_requests,
        mock_update_country,
        mock_get_session,
        client,
    ):
        """authorization_details triggers age-over-18 logic"""
        mock_session_data = MagicMock()
        mock_session_data.frontend_id = "test_frontend"
        mock_session_data.oid4vp_transaction_id = "tx123"
        mock_session_data.credentials_requested = [
            "eu.europa.ec.eudi.pseudonym_over18_mdoc"
        ]
        mock_session_data.authorization_details = [
            {"credential_configuration_id": "eu.europa.ec.eudi.pseudonym_over18_mdoc"}
        ]
        mock_session_data.scope = []

        with client.session_transaction() as sess:
            sess["session_id"] = "123"

        mock_get_session.return_value = mock_session_data
        mock_cfgservice.dynamic_presentation_url = "https://example.com/"
        mock_cfgservice.service_url = "https://service.com/"
        mock_cfgservice.config_doctype = {
            "eu.europa.ec.eudi.pseudonym.age_over_18.1": {
                "issuing_authority": "FC Authority",
                "validity": 365,
                "credential_type": "over18",
            }
        }

        mock_conf_frontend.registered_frontends = {
            "test_frontend": {"url": "https://frontend.com"}
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vp_token": {"query_0": ["mocked_base64"]}}
        mock_requests.return_value = mock_response
        mock_validate_vp_token.return_value = (False, "")
        mock_cbor2elems.return_value = {
            "eu.europa.ec.eudi.pseudonym.age_over_18.1": [("age_over_18", True)]
        }

        # Even though authorization_details has age_over_18, the code STILL calls getAttributesForm
        # So we need to mock it to return something valid
        mock_getAttributesForm.return_value = {"age_over_18": {"type": "boolean"}}
        mock_getAttributesForm2.return_value = {}

        mock_post_redirect.return_value = "REDIRECT_CALLED"

        resp = client.get("/getpidoid4vp?response_code=resp123&session_id=123")
        assert resp.data == b"REDIRECT_CALLED"
        mock_post_redirect.assert_called_once()
