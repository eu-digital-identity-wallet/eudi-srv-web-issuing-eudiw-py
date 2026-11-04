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
"""Branch coverage for the OIDC / metadata routes (error and edge paths)."""

import json
import urllib.parse
import uuid
from unittest.mock import MagicMock, patch

import jwt
import pytest
from urllib.parse import parse_qs, urlsplit
import requests
from flask import Flask

from app.repositories import offer_store
from app.routes import oidc as oidc_routes
from app.routes.metadata import metadata as metadata_blueprint
from app.routes.oidc import oidc
from config_helpers import patch_configuration

API_KEY = {"X-Api-Key": "k"}


@pytest.fixture
def config(tmp_path):
    cfg = {
        "service_url": "https://backend.test",
        "backend_api_key": "k",
        "admin_api_key": "k",
        "wallet_tester_url": "https://tester.test",
        "credential_offer_scheme": "openid-credential-offer://",
        "expiry": {"form": 5},
        "status_validator": {"enabled": False},
        "authorization_server": {"base_url": "https://as.test"},
        "credential_auth_methods": {"PID_login": ["pid"], "country_selection": ["pid", "mdl"]},
        "frontend": {"default": "fe", "frontends_config": {"fe": {"url": "https://fe.test"}, "fe2": {"url": "https://fe2.test"}}},
        "logging": {"backend_path": str(tmp_path / "backend.log")},
    }
    with patch_configuration(cfg):
        yield cfg


@pytest.fixture
def app(config):
    application = Flask(__name__)
    application.config.update(TESTING=True, SECRET_KEY="test")
    application.register_blueprint(oidc)
    application.register_blueprint(metadata_blueprint)
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def _introspection_response(body=None, error=None):
    response = MagicMock()
    if error:
        response.raise_for_status.side_effect = error
    response.json.return_value = body if body is not None else {}
    return response


class TestVerifyIntrospection:
    @pytest.mark.parametrize(
        "response, status, message",
        [
            (_introspection_response(error=requests.ConnectionError("down")), 502, "Failed to validate token"),
            (_introspection_response(body={"active": False}), 401, "invalid_token"),
            (_introspection_response(body={"active": True}), 401, "invalid_token"),
        ],
    )
    def test_rejections(self, app, config, response, status, message):
        with app.app_context(), patch.object(oidc_routes, "introspect", return_value=response):
            body, code = oidc_routes.verify_introspection("token")
        assert code == status and message in json.dumps(body.get_json())

    def test_invalid_json(self, app, config):
        response = _introspection_response()
        response.json.side_effect = json.JSONDecodeError("bad", "", 0)
        with app.app_context(), patch.object(oidc_routes, "introspect", return_value=response):
            body, code = oidc_routes.verify_introspection("token")
        assert code == 502 and "Invalid response" in body.get_json()["error"]

    def test_opaque_token_has_no_client_status(self, app, config):
        response = _introspection_response(body={"active": True, "username": "s1"})
        with app.app_context(), patch.object(oidc_routes, "introspect", return_value=response):
            assert oidc_routes.verify_introspection("opaque-token") == ("s1", None)

    @pytest.fixture
    def as_key(self, config, tmp_path):
        """Signing key of the authorization server, published via jwks_path."""
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
        (tmp_path / "as_jwks.json").write_text(json.dumps({"keys": [{**jwk, "kid": "as", "use": "sig"}]}))
        config.setdefault("authorization_server", {})["jwks_path"] = str(tmp_path / "as_jwks.json")
        return key

    def test_jwt_token_client_status_without_validator(self, app, config, as_key):
        token = jwt.encode({"client_status": {"exp": 1}}, as_key, algorithm="ES256")
        response = _introspection_response(body={"active": True, "username": "s1"})
        with app.app_context(), patch.object(oidc_routes, "introspect", return_value=response):
            assert oidc_routes.verify_introspection(token) == ("s1", {"exp": 1})

    @pytest.mark.parametrize("signer", ["unsigned", "other_key"])
    def test_unverified_access_token_claims_are_not_trusted(self, app, config, as_key, signer):
        """client_status was read from the access token without checking its signature."""
        from cryptography.hazmat.primitives.asymmetric import ec

        claims = {"client_status": {"exp": 1}}
        if signer == "unsigned":
            token = jwt.encode(claims, "secret-secret-secret-secret-secret", algorithm="HS256")
        else:
            token = jwt.encode(claims, ec.generate_private_key(ec.SECP256R1()), algorithm="ES256")
        response = _introspection_response(body={"active": True, "username": "s1"})
        with app.app_context(), patch.object(oidc_routes, "introspect", return_value=response):
            body, status = oidc_routes.verify_introspection(token)
        assert status == 401 and body.get_json() == {"error": "invalid_token"}


class TestVerifyCredentialRequest:
    @pytest.mark.parametrize(
        "request_body, error",
        [
            ({"credential_indentifier": "typo", "proof": {}}, "invalid_credential_request"),
            ({"proof": {"proof_type": "jwt", "jwt": "x"}}, "invalid_credential_request"),
            ({"credential_configuration_id": "pid"}, "invalid_proof"),
            ({"credential_configuration_id": "pid", "proof": {}}, "invalid_proof"),
            ({"credential_configuration_id": "pid", "proof": {"proof_type": "jwt"}}, "invalid_proof"),
            ({"credential_configuration_id": "pid", "proof": {"proof_type": "attestation"}}, "invalid_proof"),
        ],
    )
    def test_invalid(self, app, request_body, error):
        from app.core.errors import OAuthEndpointError

        with app.app_context(), pytest.raises(OAuthEndpointError) as raised:
            oidc_routes.verify_credential_request(request_body)
        assert (raised.value.error, raised.value.status) == (error, 400)

    @pytest.mark.parametrize(
        "request_body",
        [
            {"credential_identifier": "pid", "proofs": {"jwt": ["x"]}},
            {"credential_configuration_id": "pid", "proof": {"proof_type": "jwt", "jwt": "x"}},
            {"credential_configuration_id": "pid", "proof": {"proof_type": "cwt"}},
        ],
    )
    def test_valid(self, app, request_body):
        with app.app_context():
            assert oidc_routes.verify_credential_request(request_body) is request_body


class TestCredentialEndpointAuth:
    @pytest.mark.parametrize(
        "headers, body",
        [
            ({}, {}),
            ({"Authorization": "Basic abc"}, {}),
            ({"Authorization": "Bearer"}, {"error": "invalid_token", "error_description": "Missing access token"}),
        ],
    )
    def test_authorization_header(self, client, config, headers, body):
        response = client.post("/credential", json={}, headers=headers)
        assert response.status_code == 401 and response.get_json() == body
        assert "WWW-Authenticate" in response.headers

    def test_undecryptable_jwe_body(self, client, config):
        with patch.object(oidc_routes, "decrypt_jwe_credential_request", side_effect=ValueError("bad")):
            response = client.post(
                "/credential", data="a.b.c.d.e", content_type="application/jwt", headers={"Authorization": "Bearer t"}
            )
        assert response.status_code == 400 and response.get_json() == {"error": "invalid_credential_request"}

    def test_introspection_error_is_returned(self, client, config):
        with patch.object(oidc_routes, "verify_introspection", return_value=({"error": "x"}, 401)):
            response = client.post("/credential", json={}, headers={"Authorization": "DPoP t"})
        assert response.status_code == 401


class TestDeferredAndNotification:
    def test_deferred_missing_transaction(self, client, config):
        response = client.post("/deferred_credential", json={}, headers={"Authorization": "Bearer t"})
        assert response.status_code == 400 and response.get_json()["error"] == "invalid_credential_request"

    def test_deferred_bad_transaction_format(self, client, config):
        response = client.post("/deferred_credential", json={"transaction_id": "not-a-uuid"}, headers={"Authorization": "Bearer t"})
        assert response.status_code == 400 and response.get_json() == {"error": "invalid_transaction_id"}

    @pytest.mark.parametrize("headers, body", [({}, {}), ({"Authorization": "Bearer"}, {"error": "invalid_token", "error_description": "Missing access token"})])
    def test_deferred_auth(self, client, config, headers, body):
        response = client.post("/deferred_credential", json={"transaction_id": str(uuid.uuid4())}, headers=headers)
        assert response.status_code == 401 and response.get_json() == body
        assert "WWW-Authenticate" in response.headers

    def test_deferred_unknown_transaction(self, client, config):
        session = MagicMock(transaction_id={})
        tx = str(uuid.uuid4())
        with patch.object(oidc_routes, "verify_introspection", return_value=("s1", None)), patch.object(
            oidc_routes.session_manager, "get_session", return_value=session
        ):
            response = client.post("/deferred_credential", json={"transaction_id": tx}, headers={"Authorization": "Bearer t"})
        body = response.get_json()
        assert response.status_code == 400 and body["error"] == "invalid_transaction_id"
        assert tx not in str(body)  # request input is not reflected

    def test_deferred_invalid_stored_request(self, client, config):
        tx = str(uuid.uuid4())
        session = MagicMock(transaction_id={tx: {"credential_configuration_id": "pid"}})
        with patch.object(oidc_routes, "verify_introspection", return_value=("s1", None)), patch.object(
            oidc_routes.session_manager, "get_session", return_value=session
        ):
            response = client.post("/deferred_credential", json={"transaction_id": tx}, headers={"Authorization": "Bearer t"})
        assert response.status_code == 400 and response.get_json() == {"error": "invalid_proof"}

    def test_deferred_issuance_error(self, client, config):
        tx = str(uuid.uuid4())
        stored = {"credential_configuration_id": "pid", "proof": {"proof_type": "jwt", "jwt": "x"}}
        session = MagicMock(transaction_id={tx: stored})
        with patch.object(oidc_routes, "verify_introspection", return_value=("s1", None)), patch.object(
            oidc_routes.session_manager, "get_session", return_value=session
        ), patch.object(oidc_routes, "generate_credentials", return_value={"error": "invalid_proof"}):
            response = client.post("/deferred_credential", json={"transaction_id": tx}, headers={"Authorization": "Bearer t"})
        assert response.status_code == 400 and response.get_json() == {"error": "invalid_proof"}

    @pytest.mark.parametrize(
        "headers, body",
        [
            ({}, {}),
            ({"Authorization": "Basic t"}, {}),
            ({"Authorization": "Bearer "}, {"error": "invalid_token", "error_description": "Missing access token"}),
        ],
    )
    def test_notification_auth(self, client, config, headers, body):
        with patch.object(oidc_routes, "verify_introspection", return_value=({"error": "invalid_token"}, 401)):
            response = client.post("/notification", json={}, headers=headers)
        assert response.status_code == 401 and response.get_json() == body
        assert "WWW-Authenticate" in response.headers


class TestAuthChoice:
    def _get(self, client, **params):
        """Calls /auth_choice; the session claims stand in for a verified session_token."""
        claims = {"session_id": "s1", "frontend_id": "fe", **params}
        with patch.object(oidc_routes, "verify_session_token", return_value=claims):
            return client.get("/auth_choice?" + urllib.parse.urlencode({"token": "t", "session_token": "signed"}))

    def test_invalid_authorization_details(self, client, config):
        response = self._get(client, authorization_details="{not json")
        assert response.status_code == 400

    def test_no_credentials_requested(self, app, config):
        app.config["TESTING"] = True
        with pytest.raises(ValueError, match="invalid authentication"):
            self._get(app.test_client())

    @pytest.mark.parametrize(
        "requested, location",
        [(["pid"], None), (["mdl"], "https://backend.test/dynamic/")],
    )
    def test_method_selection(self, client, config, requested, location):
        details = json.dumps(json.dumps([{"credential_configuration_id": c} for c in requested]))
        with patch.object(oidc_routes, "post_redirect_with_payload", return_value="page") as page, patch.object(
            oidc_routes.session_manager, "add_session"
        ):
            response = self._get(client, authorization_details=details)
        if location:
            assert response.status_code == 302 and response.headers["Location"] == location
        else:
            # pid supports both methods -> the user chooses
            payload = page.call_args.kwargs["data_payload"]
            assert (payload["pid_auth"], payload["country_selection"]) == (True, True)

    def test_unknown_credential_offers_no_method(self, client, config):
        details = json.dumps(json.dumps([{"credential_configuration_id": "other"}]))
        with patch.object(oidc_routes, "post_redirect_with_payload", return_value="page") as page, patch.object(
            oidc_routes.session_manager, "add_session"
        ):
            self._get(client, authorization_details=details, frontend_id="fe2")
        assert page.call_args.kwargs["target_url"] == "https://fe2.test/display_auth_method"
        assert (page.call_args.kwargs["data_payload"]["pid_auth"], page.call_args.kwargs["data_payload"]["country_selection"]) == (False, False)

    def test_scope_only(self, client, config):
        with patch.object(oidc_routes, "scope2details", return_value=["openid", {"credential_configuration_id": "pid"}]), patch.object(
            oidc_routes.session_manager, "add_session"
        ) as add, patch.object(oidc_routes, "post_redirect_with_payload", return_value="page"):
            self._get(client, scope="openid pid")
        assert add.call_args.kwargs["scope"] == "pid"
        assert add.call_args.kwargs["credentials_requested"] == ["pid"]


class TestLogs:
    def test_collects_dedupes_and_strips(self, client, config, tmp_path):
        (tmp_path / "backend.log").write_text(
            "\x1b[32mINFO 0c6f8a52-1b2c-4d3e-8f90-123456789abc started\x1b[0m\nINFO 0c6f8a52-1b2c-4d3e-8f90-123456789abc started\nINFO 9d1e2f30-4a5b-4c6d-8e7f-abcdefabcdef other\nINFO 0c6f8a52-1b2c-4d3e-8f90-123456789abc Credential Issuance Successful\n"
        )
        (tmp_path / "as.log").write_text("AS 0c6f8a52-1b2c-4d3e-8f90-123456789abc token issued\n")
        config["logging"]["authorization_server_path"] = str(tmp_path / "as.log")

        issued = MagicMock(credential_issued=True)
        with patch.object(oidc_routes.session_manager, "get_session", return_value=issued):
            body = client.get("/logs?session_id=0c6f8a52-1b2c-4d3e-8f90-123456789abc", headers=API_KEY).get_json()

        assert body["logs"] == ["INFO 0c6f8a52-1b2c-4d3e-8f90-123456789abc started", "INFO 0c6f8a52-1b2c-4d3e-8f90-123456789abc Credential Issuance Successful", "AS 0c6f8a52-1b2c-4d3e-8f90-123456789abc token issued"]
        assert body["count"] == 3 and body["successful"] is True

    def test_missing_log_files(self, client, config):
        body = client.get("/logs?session_id=0c6f8a52-1b2c-4d3e-8f90-123456789abc", headers=API_KEY).get_json()
        assert body == {"session_id": "0c6f8a52-1b2c-4d3e-8f90-123456789abc", "count": 0, "successful": False, "logs": []}


class TestCredentialOffers:
    def test_offer2_returns_qr_and_session(self, client, config):
        body = client.get("/credential_offer2?credential_configuration_id=pid").get_json()
        assert body["base64_img"] and uuid.UUID(body["session_id"])

    def test_offer_create(self, client, config):
        assert client.get("/credential_offer_create").status_code == 400
        offer = client.get("/credential_offer_create?credential_configuration_id=pid").get_json()
        assert offer["credential_issuer"] == "https://fe.test"
        assert offer["credential_configuration_ids"] == ["pid"]

    @pytest.mark.parametrize("frontend_id, query", [(None, ""), ("fe2", "?frontend_id=fe2")])
    def test_offer_without_proceed_redirects_to_choice(self, client, config, frontend_id, query):
        if frontend_id:
            with client.session_transaction() as s:
                s["frontend_id"] = frontend_id
        with patch.dict("app.core.state.oidc_metadata", {"credential_configurations_supported": {}}, clear=True):
            response = client.get("/credential_offer")
        assert response.headers["Location"] == f"https://backend.test/credential_offer_choice{query}"

    def _form(self, **extra):
        return {"proceed": "1", "credential_offer_URI": "openid-credential-offer://", "Authorization Code Grant": "auth_code", "pid": "on", **extra}

    def test_unsupported_credential(self, client, config):
        with patch.dict("app.core.state.oidc_metadata", {"credential_configurations_supported": {"pid": {}}}, clear=True):
            response = client.post("/credential_offer", data=self._form(unknown="on"))
        assert response.status_code == 400

    @staticmethod
    def _display(name):
        return {"format": "mso_mdoc", "credential_metadata": {"display": [{"name": name}]}}

    def test_choice_lists_only_credentials_the_frontend_publishes(self, client, config):
        config["frontend"]["frontends_config"]["fe2"]["credentials_supported"] = ["pid"]
        configs = {"pid": self._display("PID"), "mdl": self._display("mDL")}
        with patch.dict("app.core.state.oidc_metadata", {"credential_configurations_supported": configs}, clear=True), patch.object(
            oidc_routes, "post_redirect_with_payload", return_value="page"
        ) as page:
            client.get("/credential_offer_choice?frontend_id=fe2")
            restricted = page.call_args.kwargs["data_payload"]["cred"]["mdoc format"]
            client.get("/credential_offer_choice")
            default = page.call_args.kwargs["data_payload"]["cred"]["mdoc format"]

        assert restricted == {"pid": "PID"}
        assert default == {"pid": "PID", "mdl": "mDL"}

    @pytest.mark.parametrize("selected, status", [("mdl", 400), ("pid", 200)])
    def test_offer_rejects_credentials_the_frontend_does_not_publish(self, client, config, selected, status):
        config["frontend"]["frontends_config"]["fe2"]["credentials_supported"] = ["pid"]
        with client.session_transaction() as s:
            s["frontend_id"] = "fe2"
        form = {k: v for k, v in self._form(**{selected: "on"}).items() if k != "pid" or selected == "pid"}
        with patch.dict("app.core.state.oidc_metadata", {"credential_configurations_supported": {"pid": {}, "mdl": {}}}, clear=True), patch.object(
            oidc_routes, "post_redirect_with_payload", return_value="page"
        ):
            response = client.post("/credential_offer", data=form)
        assert response.status_code == status

    def test_offer_create_rejects_credentials_the_default_frontend_does_not_publish(self, client, config):
        config["frontend"]["frontends_config"]["fe"]["credentials_supported"] = ["pid"]
        assert client.get("/credential_offer_create?credential_configuration_id=mdl").status_code == 400
        assert client.get("/credential_offer_create?credential_configuration_id=pid").status_code == 200

    def test_pre_authorized_redirect(self, client, config):
        with patch.dict("app.core.state.oidc_metadata", {"credential_configurations_supported": {"pid": {}}}, clear=True):
            app_ctx = client.application
            app_ctx.add_url_rule("/preauth", "preauth.preauthRed", lambda: "ok")
            response = client.post("/credential_offer", data=self._form(**{"Authorization Code Grant": "pre_auth_code"}))
        assert response.status_code == 307 and "/preauth?credentials_id=" in response.headers["Location"]

    def test_authorization_code_offer_by_value(self, client, config):
        with patch.dict("app.core.state.oidc_metadata", {"credential_configurations_supported": {"pid": {}}}, clear=True), patch.dict(
            offer_store.credential_offer_references, {}, clear=True
        ), patch.object(oidc_routes, "post_redirect_with_payload", return_value="page") as page:
            client.post("/credential_offer", data=self._form())
            assert offer_store.credential_offer_references == {}

        payload = page.call_args.kwargs["data_payload"]
        assert payload["url_data"].startswith("openid-credential-offer://credential_offer?credential_offer=")
        assert payload["qrcode"].startswith("data:image/png;base64,")
        assert payload["wallet_dev"] == "https://tester.test/credential_offer"

    def test_authorization_code_offer_by_reference(self, client, config):
        with patch.dict("app.core.state.oidc_metadata", {"credential_configurations_supported": {"pid": {}}}, clear=True), patch.dict(
            offer_store.credential_offer_references, {}, clear=True
        ), patch.object(oidc_routes, "post_redirect_with_payload", return_value="page") as page:
            client.post("/credential_offer", data=self._form(credential_offer_mode="by_reference"))
            payload = page.call_args.kwargs["data_payload"]
            query = parse_qs(urlsplit(payload["url_data"]).query)
            reference_url = query["credential_offer_uri"][0]
            assert "credential_offer" not in query
            assert reference_url.startswith("https://backend.test/credential-offer-reference/")

            served = client.get(urlsplit(reference_url).path)
            again = client.get(urlsplit(reference_url).path)

        assert served.status_code == 200 and served.get_json() == payload["credential_offer"]
        assert served.headers["Cache-Control"] == "no-store"
        assert again.status_code == 404  # single use
        # credential_offer_mode is a form control, not a credential id
        assert payload["credential_offer"]["credential_configuration_ids"] == ["pid"]


class TestMetadataSignerValidation:
    @pytest.mark.parametrize(
        "body, error",
        [
            ({"issuer_frontend_id": "fe"}, "metadata is required"),
            ({"metadata": {"a": 1}}, "issuer_frontend_id is required"),
            ({"metadata": ["not", "an", "object"], "issuer_frontend_id": "fe"}, "metadata must be a JSON object"),
        ],
    )
    def test_validation(self, client, config, body, error):
        response = client.post("/metadata/metadata_signer", json=body, headers=API_KEY)
        assert response.status_code == 400 and response.get_json()["error"] == error

    def test_no_json(self, client, config):
        response = client.post("/metadata/metadata_signer", json={}, headers=API_KEY)
        assert response.status_code == 400 and response.get_json()["error"] == "No JSON data provided"

    def test_unknown_frontend_is_not_found(self, client, config):
        response = client.post("/metadata/metadata_signer", json={"metadata": {"a": 1}, "issuer_frontend_id": "nope"}, headers=API_KEY)
        assert response.status_code == 404 and response.get_json() == {"error": "unknown_frontend"}

    def test_jwt_error(self, client, config):
        with patch("app.routes.metadata.sign_issuer_metadata", side_effect=jwt.PyJWTError("boom")):
            response = client.post("/metadata/metadata_signer", json={"metadata": {"a": 1}, "issuer_frontend_id": "fe"}, headers=API_KEY)
        # Internal details are logged, never returned.
        assert response.status_code == 500 and response.get_json() == {"error": "JWT encoding failed"}
