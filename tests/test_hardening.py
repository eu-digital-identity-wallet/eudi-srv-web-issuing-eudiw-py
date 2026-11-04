###############################################################################
# Copyright (c) 2026 European Commission
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
"""Tests for the security hardening helpers: log sanitizing, CSRF origin check, OAuth errors."""

import logging
from unittest.mock import Mock, patch

import pytest
from flask import Flask

from app.core.errors import OAuthEndpointError, oauth_error_response
from app.core.log_utils import safe, summarize_credential_request
from app.core.security import require_frontend_origin, trusted_browser_origins
from config_helpers import patch_configuration


class TestSafe:
    def test_line_breaks_cannot_forge_log_lines(self):
        assert safe("id\r\nINFO fake entry\tx") == "id\\r\\nINFO fake entry\\tx"

    def test_other_control_characters_replaced(self):
        assert safe("a\x00b\x1bc\x7f") == "a?b?c?"

    def test_truncated_with_omitted_count(self):
        assert safe("x" * 15, limit=10) == "xxxxxxxxxx...(+5 chars)"

    def test_non_strings(self):
        assert safe(None) == "None" and safe(ValueError("bad\nvalue")) == "bad\\nvalue"


class TestSummarizeCredentialRequest:
    def test_batch_request(self):
        summary = summarize_credential_request(
            {"credential_configuration_id": "pid", "proofs": {"jwt": ["secret-1", "secret-2"]}, "credential_response_encryption": {}}
        )
        assert summary == "config=pid proofs=jwt:2 encrypted_response=True"

    def test_single_proof_never_logs_the_proof(self):
        summary = summarize_credential_request({"credential_identifier": "id", "proof": {"proof_type": "jwt", "jwt": "eyJsecret"}})
        assert summary == "config=id proofs=jwt:1 encrypted_response=False"
        assert "eyJ" not in summary

    def test_no_proof_and_non_mapping(self):
        assert summarize_credential_request({"credential_configuration_id": "pid"}).startswith("config=pid proofs=none")
        assert summarize_credential_request(["x"]) == "<list>"


@pytest.fixture
def origin_app():
    config = {
        "service_url": "https://backend.test/",
        "frontend": {"frontends_config": {"fe1": {"url": "https://frontend.test/app"}}},
        "cors_allowed_origins": ["https://extra.test"],
    }
    app = Flask(__name__)

    @app.route("/form", methods=["GET", "POST"])
    @require_frontend_origin
    def form():
        return "ok"

    with patch_configuration(config):
        yield app.test_client()


class TestRequireFrontendOrigin:
    def test_trusted_origins(self, origin_app):
        assert trusted_browser_origins() == {"https://frontend.test", "https://extra.test", "https://backend.test"}

    @pytest.mark.parametrize("origin", ["https://frontend.test", "https://extra.test", "https://backend.test"])
    def test_trusted_origin_allowed(self, origin_app, origin):
        assert origin_app.post("/form", headers={"Origin": origin}).status_code == 200

    def test_cross_site_post_rejected(self, origin_app, caplog):
        with caplog.at_level(logging.WARNING):
            response = origin_app.post("/form", headers={"Origin": "https://evil.test\x1b[2Jforged"})
        assert response.status_code == 403
        assert response.get_json() == {"error": "forbidden", "error_description": "Untrusted request origin"}
        assert "\x1b" not in caplog.text and "evil.test?[2Jforged" in caplog.text

    def test_referer_used_without_origin(self, origin_app):
        assert origin_app.post("/form", headers={"Referer": "https://frontend.test/app/page?x=1"}).status_code == 200
        assert origin_app.post("/form", headers={"Referer": "https://evil.test/page"}).status_code == 403

    def test_non_browser_client_allowed(self, origin_app):
        assert origin_app.post("/form").status_code == 200

    def test_safe_methods_not_checked(self, origin_app):
        assert origin_app.get("/form", headers={"Origin": "https://evil.test"}).status_code == 200


class TestOAuthEndpointError:
    def _app(self, error):
        app = Flask(__name__)
        app.register_error_handler(OAuthEndpointError, oauth_error_response)

        @app.route("/fail")
        def fail():
            raise error

        return app.test_client()

    def test_error_only(self):
        response = self._app(OAuthEndpointError("invalid_proof")).get("/fail")
        assert (response.status_code, response.get_json()) == (400, {"error": "invalid_proof"})

    def test_status_and_description(self):
        response = self._app(OAuthEndpointError("invalid_transaction_id", 401, "Unknown")).get("/fail")
        assert response.status_code == 401
        assert response.get_json() == {"error": "invalid_transaction_id", "error_description": "Unknown"}


class TestRevocationRejectsForeignCredentials:
    @pytest.fixture
    def client(self):
        from app.routes import revocation

        app = Flask(__name__)
        app.config.update(SECRET_KEY="k", TESTING=True)
        app.register_blueprint(revocation.revocation)
        config = {"service_url": "https://backend.test", "dynamic_presentation_url": "https://verifier.test/",
                  "frontend": {"default": "fe1", "frontends_config": {"fe1": {"url": "https://frontend.test"}}},
                  "expiry": {"revocation_code": 10}, "countries": {}}
        with patch_configuration(config):
            yield app.test_client()

    @pytest.mark.parametrize("fmt, credential", [("dc+sd-jwt", "not-an-sd-jwt~"), ("mso_mdoc", "@@not-base64@@")])
    def test_untrusted_presentation_is_400(self, client, fmt, credential):
        with client.session_transaction() as sess:
            sess["session_id"] = "s1"
            sess["oid4vp_transaction_id"] = "tx"
            sess["oid4vp_cross_device_id"] = "tx"
            sess["q0"] = fmt
        verifier = Mock(status_code=200)
        verifier.json.return_value = {"vp_token": {"q0": [credential]}}
        with patch("app.routes.revocation.fetch_presentation_result", return_value=verifier), patch(
            "app.routes.revocation.post_redirect_with_payload"
        ) as redirect:
            response = client.get("/revocation/getoid4vp?presentation_id=tx")

        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_presentation"
        redirect.assert_not_called()
