"""User-flow tests for the /dynamic and OID4VP routes and the app factory start-up."""

from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from app.routes import dynamic as dynamic_routes
from app.routes import oid4vp as oid4vp_routes
from app.routes.dynamic import dynamic
from app.routes.oid4vp import oid4vp
from config_helpers import patch_configuration

CONFIG = {
    "service_url": "https://backend.test",
    "dynamic_presentation_url": "https://verifier.test/presentations",
    "authorization_server": {"user_verify_endpoint": "https://as.test/verify"},
    "frontend": {"default": "fe", "frontends_config": {"fe": {"url": "https://fe.test"}}},
    "countries": {
        "ZZ": {"name": "Zed", "connection_type": "saml", "supported_credential_ids": ["pid"]},
        "OO": {"name": "Oh", "connection_type": "openid", "auth": {}, "supported_credential_ids": ["pid"]},
    },
    "test_features": {"form_countries": True, "passport_age_verification": True},
}


@pytest.fixture
def client():
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="test")
    app.register_blueprint(dynamic)
    app.register_blueprint(oid4vp)
    with patch_configuration(CONFIG):
        test_client = app.test_client()
        with test_client.session_transaction() as s:
            s["session_id"] = "s1"
        yield test_client


def _session(**overrides):
    values = {
        "session_id": "s1",
        "country": "FC",
        "frontend_id": "fe",
        "jws_token": "jws",
        "credentials_requested": ["pid"],
        "authorization_details": [{"credential_configuration_id": "pid"}],
        "oid4vp_transaction_id": "tx",
        "oid4vp_cross_device_id": "abc",
        "verified_attributes": None,
    }
    values.update(overrides)
    return MagicMock(**values)


class TestDynamicFlows:
    def test_passport_age_verification_skips_country_choice(self, client):
        session = _session(credentials_requested=["eu.europa.ec.eudi.age_verification_mdoc_passport"])
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=session), patch.object(
            dynamic_routes.session_manager, "update_user_data"
        ) as user_data, patch.object(dynamic_routes.session_manager, "update_country") as country:
            response = client.get("/dynamic/")

        assert response.status_code == 302
        assert response.headers["Location"] == "https://as.test/verify?token=jws&username=s1"
        user_data.assert_called_once_with(session_id="s1", user_data={"age_over_18": True})
        country.assert_called_once_with(session_id="s1", country="AV")

    def test_openid_country_redirects_to_idp(self, client):
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=_session()), patch.object(
            dynamic_routes.session_manager, "update_country"
        ), patch.object(dynamic_routes, "openid_authorization_url", return_value="https://idp.test/authorize") as url:
            response = client.post("/dynamic/country_selected", data={"country": "OO"})

        assert response.headers["Location"] == "https://idp.test/authorize"
        # A random state (not the session id), kept for the redirect check.
        state = url.call_args.kwargs["state"]
        assert state != "s1" and len(state) >= 43
        with client.session_transaction() as s:
            assert s["oauth_state"] == state

    def test_unsupported_connection_type(self, client):
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=_session()), patch.object(
            dynamic_routes.session_manager, "update_country"
        ):
            response = client.post("/dynamic/country_selected", data={"country": "ZZ"})
        assert response.status_code == 400 and b"saml" in response.data

    def test_form_get_is_rejected(self, client):
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=_session()):
            response = client.get("/dynamic/form")
        assert response.status_code == 400 and response.data.startswith(b"Error 101")

    def test_form_submission_stores_normalised_data_and_shows_consent(self, client):
        form = {
            "proceed": "Submit",
            "family_name": "Doe",
            "birth_date": "1990-01-01",
            "nationalities[0][country_code]": "PT",
            "effective_from_date": "2025-01-20",
            "empty": "",
        }
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=_session()), patch.object(
            dynamic_routes.session_manager, "update_user_data"
        ) as store, patch.object(dynamic_routes, "presentation_formatter", return_value={"PID": {"family_name": "Doe"}}) as present, patch.object(
            dynamic_routes, "post_redirect_with_payload", return_value="consent page"
        ) as page:
            response = client.post("/dynamic/form", data=form)

        assert response.data == b"consent page"
        stored = store.call_args.kwargs["user_data"]
        assert stored["family_name"] == "Doe" and stored["birthdate"] == "1990-01-01"
        assert stored["nationality"] == stored["nationalities"] == ["PT"]
        assert stored["effective_from_date"] == "2025-01-20T00:00:00Z"
        assert stored["issuing_country"] == "FC" and "empty" not in stored and "proceed" not in stored
        assert present.call_args.kwargs == {"cleaned_data": stored, "credentials_requested": ["pid"], "country": "FC"}
        assert page.call_args.kwargs["target_url"] == "https://fe.test/display_authorization"
        assert page.call_args.kwargs["data_payload"]["redirect_url"] == "https://backend.test/dynamic/redirect_wallet"
        assert "signature_usual_mark" in page.call_args.kwargs["data_payload"]["image_attributes"]

    def test_form_submission_without_proceed(self, client):
        # "proceed" is the submit button, so a client can leave it out (upstream #178).
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=_session()), patch.object(
            dynamic_routes.session_manager, "update_user_data"
        ), patch.object(dynamic_routes, "presentation_formatter", return_value={}), patch.object(
            dynamic_routes, "post_redirect_with_payload", return_value="consent page"
        ):
            response = client.post("/dynamic/form", data={"family_name": "Doe"})

        assert response.status_code == 200 and response.data == b"consent page"


class TestGetPidOid4vp:
    def _get(self, client, session, query="?presentation_id=abc", verifier_status=200, vp_error=(False, "")):
        verifier = MagicMock(status_code=verifier_status)
        verifier.json.return_value = {"vp_token": {"query_0": ["mdoc"]}}
        with patch.object(oid4vp_routes.session_manager, "get_session", return_value=session), patch.object(
            oid4vp_routes.session_manager, "update_country"
        ), patch.object(oid4vp_routes, "fetch_presentation_result", return_value=verifier), patch.object(
            oid4vp_routes, "validate_vp_token", return_value=vp_error
        ), patch.object(
            oid4vp_routes, "cbor2elems", return_value={"ns": [("family_name", "Doe"), ("nickname", "JD"), ("other", "x")]}
        ), patch.object(
            oid4vp_routes, "getAttributesForm", return_value={"family_name": {"filled_value": None}, "user_pseudonym": {}}
        ), patch.object(
            oid4vp_routes, "getAttributesForm2", return_value={"nickname": {"filled_value": None}}
        ), patch.object(oid4vp_routes, "post_redirect_with_payload", return_value="form page") as page:
            return client.get(f"/getpidoid4vp{query}"), page

    def test_prefills_forms_from_presented_pid(self, client):
        response, page = self._get(client, _session())

        assert response.data == b"form page"
        payload = page.call_args.kwargs["data_payload"]
        assert payload["mandatory_attributes"]["family_name"]["filled_value"] == "Doe"
        assert payload["optional_attributes"]["nickname"]["filled_value"] == "JD"
        pseudonym = payload["mandatory_attributes"]["user_pseudonym"]
        assert pseudonym["type"] == "string" and len(pseudonym["filled_value"]) == 36

    def test_missing_parameters(self, client):
        response, _ = self._get(client, _session(), query="")
        assert response.status_code == 400 and response.get_json() == {"error": "Missing required parameters"}

    def test_verifier_error(self, client):
        response, _ = self._get(client, _session(), verifier_status=404)
        assert response.status_code == 400 and response.get_json() == {"error": "404"}

    def test_invalid_presentation(self, client):
        client.application.config["PROPAGATE_EXCEPTIONS"] = True
        with pytest.raises(ValueError, match="invalid_request"):
            self._get(client, _session(), vp_error=(True, "Signature not valid"))

    def test_no_authorization_details(self, client):
        response, _ = self._get(client, _session(authorization_details=[]))
        assert response.status_code == 400 and response.get_json() == {"error": "No authorization details in session"}


class TestFactoryStartup:
    def test_production_startup_initialises_services(self, tmp_path):
        from app import factory

        config = {
            "logging": {"backend_path": str(tmp_path / "backend.log")},
            "postgres": {"host": "db"},
            "frontend": {"frontends_config": {}},
        }
        with patch_configuration(config), patch("app.services.metadata.setup_metadata") as metadata, patch(
            "app.services.metadata.setup_trusted_cas"
        ) as trusted_cas, patch("app.repositories.status_store.init_db_status") as init_db, patch(
            "app.services.scheduler.start_scheduler"
        ) as scheduler:
            app = factory.create_app({"INIT_BACKGROUND_SERVICES": True, "LOAD_TRUSTED_CAS": True})

        metadata.assert_called_once()
        trusted_cas.assert_called_once()
        init_db.assert_called_once_with({"host": "db"})
        scheduler.assert_called_once()
        assert app.static_folder is None
