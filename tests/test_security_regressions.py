"""Regression tests for the findings of the 2026-07 security assessments.

Each test replays the attack request from the report against the routes and
asserts it is now rejected (or that the protected behaviour holds).
"""

import base64
import json
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from app.routes import dynamic as dynamic_routes
from app.routes import preauth as preauth_routes
from app.routes.dynamic import dynamic
from app.routes.preauth import preauth
from config_helpers import patch_configuration

CONFIG = {
    "service_url": "https://backend.test",
    "wallet_tester_url": "https://tester.test",
    "credential_offer_scheme": "openid-credential-offer://",
    "authorization_server": {"user_verify_endpoint": "https://as.test/verify"},
    "frontend": {"default": "fe", "frontends_config": {"fe": {"url": "https://fe.test"}}},
    "countries": {
        "FC": {"name": "FormEU", "supported_credential_ids": ["pid"]},
        "AV": {"name": "Age", "supported_credential_ids": ["pid"]},
        "OO": {"name": "Oh", "connection_type": "openid", "auth": {}, "supported_credential_ids": ["pid"]},
    },
}


def _session(**overrides):
    values = {
        "session_id": "s1",
        "country": "FC",
        "frontend_id": "fe",
        "jws_token": "jws",
        "credentials_requested": ["pid"],
        "authorization_details": [{"credential_configuration_id": "pid"}],
        "verified_attributes": None,
        "user_data": {"family_name": "Doe"},
        "tx_code": 12345,
        "pre_authorized_code": "code",
    }
    values.update(overrides)
    return MagicMock(**values)


@pytest.fixture
def config():
    return json.loads(json.dumps(CONFIG))


@pytest.fixture
def client(config):
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="test")
    app.register_blueprint(dynamic)
    app.register_blueprint(preauth)
    with patch_configuration(config):
        test_client = app.test_client()
        with test_client.session_transaction() as s:
            s["session_id"] = "s1"
        yield test_client


def _jwt(payload):
    def b64(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    return f"{b64({'alg': 'ES256'})}.{b64(payload)}.sig"


class TestFormatterSigningOracle:
    """AUTH-VULN-10 / AUTHZ-VULN-07: /formatter/* signed caller-supplied claims."""

    def test_formatter_routes_are_gone(self, monkeypatch):
        from app.factory import create_app

        monkeypatch.setattr("app.services.metadata._build_credential_encryption_metadata", MagicMock(return_value="enc"))
        config = {
            "service_url": "https://backend.test/",
            "frontend": {"default": "fe", "frontends_config": {"fe": {"url": "https://fe.test"}}},
            "keys": {"credential_encryption_key": b"Key_Sample"},
            "logging": {"backend_path": "/tmp/log/fakepath.log", "log_level": "INFO"},
        }
        with patch_configuration(config):
            app = create_app(test_config={"TESTING": True, "SECRET_KEY": "k"})
            client = app.test_client()
            for path in ("/formatter/sd-jwt", "/formatter/cbor"):
                assert client.post(path, json={"country": "FC", "data": {}}).status_code == 404
        assert "formatter" not in app.blueprints


class TestSelfAssertedIdentity:
    """AUTHZ-VULN-13: identity data typed into the form became a signed PID."""

    def test_form_countries_not_offered_by_default(self, client):
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=_session()), patch.object(
            dynamic_routes, "post_redirect_with_payload", return_value="page"
        ) as page, patch.object(dynamic_routes, "openid_authorization_url", return_value="https://idp.test/a"):
            response = client.get("/dynamic/")
        # Only the connector country is left, so it is selected directly.
        assert response.status_code == 302 and response.headers["Location"] == "https://idp.test/a"
        page.assert_not_called()

    @pytest.mark.parametrize("country", ["FC", "AV", "AV2", "sample", "XX"])
    def test_form_country_selection_rejected(self, client, country):
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=_session()), patch.object(
            dynamic_routes.session_manager, "update_country"
        ) as update_country:
            response = client.post("/dynamic/country_selected", data={"country": country})
        assert response.status_code == 400
        update_country.assert_not_called()

    def test_attribute_form_rejected_without_verified_pid(self, client):
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=_session()), patch.object(
            dynamic_routes.session_manager, "update_user_data"
        ) as store:
            response = client.post("/dynamic/form", data={"proceed": "1", "family_name": "ATTACKER"})
        assert response.status_code == 403
        store.assert_not_called()

    def test_attribute_form_rejected_for_connector_country(self, client, config):
        config["test_features"] = {"form_countries": True}
        with patch.object(
            dynamic_routes.session_manager, "get_session", return_value=_session(country="OO")
        ), patch.object(dynamic_routes.session_manager, "update_user_data") as store:
            response = client.post("/dynamic/form", data={"proceed": "1", "family_name": "ATTACKER"})
        assert response.status_code == 403
        store.assert_not_called()

    def test_verified_pid_values_cannot_be_changed(self, client):
        verified = {"family_name": "Real", "birth_date": "1980-02-03", "nationality": ["PT"]}
        with patch.object(
            dynamic_routes.session_manager, "get_session", return_value=_session(verified_attributes=verified)
        ), patch.object(
            dynamic_routes, "_form_attribute_names", return_value={"family_name", "given_name", "birth_date"}
        ), patch.object(dynamic_routes.session_manager, "update_user_data") as store, patch.object(
            dynamic_routes, "presentation_formatter", return_value={}
        ), patch.object(dynamic_routes, "post_redirect_with_payload", return_value="consent"):
            response = client.post(
                "/dynamic/form",
                data={"proceed": "1", "family_name": "ATTACKER", "birth_date": "1990-01-01", "given_name": "Extra"},
            )
        assert response.status_code == 200
        stored = store.call_args.kwargs["user_data"]
        assert stored["family_name"] == "Real" and stored["birthdate"] == "1980-02-03"
        assert stored["given_name"] == "Extra"

    def test_passport_age_verification_needs_feature(self, client):
        session = _session(credentials_requested=["eu.europa.ec.eudi.age_verification_mdoc_passport"])
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=session), patch.object(
            dynamic_routes.session_manager, "update_user_data"
        ) as store, patch.object(dynamic_routes, "post_redirect_with_payload", return_value="page"):
            client.get("/dynamic/")
        store.assert_not_called()

    @pytest.mark.parametrize(
        "method, path",
        [
            ("post", '/preauth?credentials_id=["pid"]'),
            ("post", "/preauth_form"),
            ("post", "/form_authorize_generate"),
        ],
    )
    def test_preauth_form_flow_disabled_by_default(self, client, method, path):
        with patch.object(preauth_routes, "request_preauth_token") as token:
            response = getattr(client, method)(path, data={"proceed": "1", "family_name": "ATTACKER"})
        assert response.status_code == 403
        token.assert_not_called()

    def test_form_authorize_generate_ignores_client_user_id(self, client, config):
        """The offer is built for the browser's session, never a posted user_id."""
        config["test_features"] = {"form_countries": True}
        sessions = {"s1": _session(), "victim": _session(session_id="victim")}
        with patch.object(
            preauth_routes.session_manager, "get_session", side_effect=lambda session_id: sessions.get(session_id)
        ) as get_session, patch.object(preauth_routes, "generate_offer", return_value="offer") as offer:
            client.post("/form_authorize_generate", data={"user_id": "victim"})
        assert "victim" not in [c.args[0] if c.args else c.kwargs.get("session_id") for c in get_session.call_args_list]
        offer.assert_called_once_with(sessions["s1"].user_data)


class TestVerifiedPidOverride:
    """Verified PID values were only rebound for exact-name scalar form fields."""

    VERIFIED = {
        "family_name": "Real",
        "birth_date": "1980-02-03",
        "age_over_18": True,
        "nationality": ["PT"],
        "place_of_birth": {"country": "PT", "locality": "Lisboa"},
        "portrait": "UmVhbA",
        "expiry_date": "2030-01-01",
    }
    #: Form of a PID request that has both the mdoc and SD-JWT names.
    MANDATORY = {
        name: {"type": "string", "filled_value": None, "mandatory": True}
        for name in ("family_name", "given_name", "birth_date", "age_over_18", "nationality", "place_of_birth")
    }
    OPTIONAL = {
        "birthdate": {"type": "string"},
        "nationalities": {"type": "list"},
        "birth_place": {"type": "list"},
        "portrait": {"type": "jpeg"},
    }

    def _submit(self, client, data):
        with patch.object(
            dynamic_routes.session_manager, "get_session", return_value=_session(verified_attributes=self.VERIFIED)
        ), patch.object(dynamic_routes, "getAttributesForm", return_value=dict(self.MANDATORY)), patch.object(
            dynamic_routes, "getAttributesForm2", return_value=dict(self.OPTIONAL)
        ), patch.object(dynamic_routes.session_manager, "update_user_data") as store, patch.object(
            dynamic_routes, "presentation_formatter", return_value={}
        ), patch.object(dynamic_routes, "post_redirect_with_payload", return_value="consent"):
            response = client.post("/dynamic/form", data={"proceed": "1", **data})
        assert response.status_code == 200
        return store.call_args.kwargs["user_data"]

    def _assert_verified(self, stored):
        assert stored["family_name"] == "Real"
        assert stored["birth_date"] == stored["birthdate"] == "1980-02-03"
        assert stored["age_over_18"] is True
        assert stored["nationality"] == stored["nationalities"] == ["PT"]
        assert stored["place_of_birth"] == stored["birth_place"] == {"country": "PT", "locality": "Lisboa"}
        assert stored["portrait"] == stored["picture"] == "UmVhbA"

    @pytest.mark.parametrize("key", ["[family_name]", "family_name][x", "[family_name][]"])
    def test_bracketed_name_cannot_override(self, client, key):
        stored = self._submit(client, {key: "ATTACKER", "given_name": "Extra"})
        self._assert_verified(stored)
        assert stored["given_name"] == "Extra"

    def test_non_scalar_values_cannot_be_overridden(self, client):
        stored = self._submit(
            client,
            {
                "age_over_18": "false",
                "nationality[]": ["XX", "YY"],
                "place_of_birth[0][country]": "XX",
                "place_of_birth[0][locality]": "Nowhere",
            },
        )
        self._assert_verified(stored)

    def test_aliases_cannot_override(self, client):
        stored = self._submit(
            client,
            {
                "birthdate": "1999-09-09",
                "birth_place[0][country]": "XX",
                "nationalities[0][country_code]": "XX",
                "portrait": "Port1",
                "picture": "QXR0YWNrZXI",
            },
        )
        self._assert_verified(stored)

    def test_attributes_outside_the_form_ignored(self, client):
        stored = self._submit(client, {"issuing_authority": "Forged", "family_name ": "ATTACKER", "[]": "x"})
        assert {"issuing_authority", "family_name "}.isdisjoint(stored)
        # PID metadata is not copied into the new credential either.
        assert "expiry_date" not in stored and stored["issuing_country"] == "FC"
        self._assert_verified(stored)


class TestCredentialOfferRequestDisabled:
    """credentialOfferReq2: any trusted signer chose the credential type and data, PID included."""

    def _token(self):
        import time

        now = int(time.time())
        return _jwt({"credentials": [{"credential_configuration_id": "pid", "data": {"family_name": "X"}}], "iat": now, "exp": now + 300})

    def test_disabled_by_default(self, client):
        with patch.object(preauth_routes, "verify_jwt_with_x5c") as verify, patch.object(
            preauth_routes, "request_preauth_token"
        ) as start, patch.object(preauth_routes, "session_manager") as sessions:
            response = client.post("/credentialOfferReq2", data={"request": self._token()})
        assert response.status_code == 403
        assert response.get_json()["error"] == "access_denied"
        verify.assert_not_called()
        start.assert_not_called()
        sessions.update_user_data.assert_not_called()

    @pytest.mark.parametrize("value", [False, "true", 1])
    def test_only_explicit_true_enables(self, client, config, value):
        config["test_features"] = {"credential_offer_request": value, "form_countries": True, "tx_code_in_offer": True}
        with patch.object(preauth_routes, "request_preauth_token") as start:
            response = client.post("/credentialOfferReq2", data={"request": self._token()})
        assert response.status_code == 403
        start.assert_not_called()


class TestTxCodeInOffer:
    """The tx_code (second factor) travelled inside the credential offer."""

    def test_tx_code_returned_beside_the_offer(self, client, config):
        import time

        config["test_features"] = {"credential_offer_request": True}

        now = int(time.time())
        token = _jwt({"credentials": [{"credential_configuration_id": "pid", "data": {"family_name": "Doe"}}], "iat": now, "exp": now + 300})
        with patch.object(preauth_routes, "verify_jwt_with_x5c", side_effect=lambda t, **_: json.loads(
            base64.urlsafe_b64decode(t.split(".")[1] + "==")
        )), patch.object(preauth_routes, "request_preauth_token", return_value="s1"), patch.object(
            preauth_routes, "session_manager"
        ) as sessions:
            sessions.get_session.return_value = _session()
            response = client.post("/credentialOfferReq2", data={"request": token})
        body = response.get_json()
        assert body["tx_code"] == 12345
        grant = body["credential_offer"]["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        assert "value" not in grant["tx_code"]
        assert "12345" not in json.dumps(body["credential_offer"])


class TestReflectedOfferUri:
    """INJ-VULN-02 / XSS-VULN-05: credential_offer_URI was reflected into the page."""

    @pytest.mark.parametrize(
        "prefix",
        ["openid-credential-offer://", "haip-vci://", "eudi-openid4ci://", "https://wallet.example/offer/"],
    )
    def test_wallet_prefixes_accepted(self, prefix):
        from app.services.credential_offer import is_valid_offer_prefix

        assert is_valid_offer_prefix(prefix)

    @pytest.mark.parametrize(
        "prefix",
        [
            "'><script>alert(document.cookie)</script>",
            "javascript://%0aalert(1)",
            "data://text/html,x",
            'openid-credential-offer://"onmouseover=x',
            "openid-credential-offer:// x",
            "no-scheme",
            "",
            None,
        ],
    )
    def test_dangerous_prefixes_rejected(self, prefix):
        from app.services.credential_offer import is_valid_offer_prefix

        assert not is_valid_offer_prefix(prefix)

    def test_route_rejects_script_prefix(self):
        from app.routes import oidc as oidc_routes
        from app.routes.oidc import oidc

        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(oidc)
        with patch_configuration(json.loads(json.dumps(CONFIG))), patch.dict(
            oidc_routes.oidc_metadata, {"credential_configurations_supported": {"pid": {}}}
        ), patch.object(oidc_routes, "post_redirect_with_payload") as page:
            response = app.test_client().post(
                "/credential_offer",
                data={
                    "proceed": "1",
                    "credential_offer_URI": "'><script>alert(document.domain)</script><x x='",
                    "Authorization Code Grant": "auth_code",
                    "pid": "on",
                },
            )
        assert response.status_code == 400
        page.assert_not_called()


class TestSecurityHeaders:
    """No CSP was set on the backend origin."""

    def test_csp_and_referrer_policy(self, monkeypatch):
        from app.factory import create_app

        monkeypatch.setattr(
            "app.services.metadata._build_credential_encryption_metadata", MagicMock(return_value="enc")
        )
        config = {
            "service_url": "https://backend.test/",
            "frontend": {"default": "fe", "frontends_config": {"fe": {"url": "https://fe.test/app"}}},
            "keys": {"credential_encryption_key": b"Key_Sample"},
            "logging": {"backend_path": "/tmp/log/fakepath.log", "log_level": "INFO"},
        }
        with patch_configuration(config):
            app = create_app(test_config={"TESTING": True, "SECRET_KEY": "k"})
            headers = app.test_client().get("/").headers
        csp = headers["Content-Security-Policy"]
        assert "default-src 'none'" in csp and "form-action https://fe.test;" in csp
        assert "script-src 'sha256-" in csp and "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]
        assert headers["Referrer-Policy"] == "no-referrer"


class TestSessionSigningKey:
    """SECRET_KEY='dev' let anyone forge session cookies."""

    @pytest.fixture
    def factory_config(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.metadata._build_credential_encryption_metadata", MagicMock(return_value="enc")
        )
        return {
            "service_url": "https://backend.test/",
            "frontend": {"default": "fe", "frontends_config": {"fe": {"url": "https://fe.test"}}},
            "keys": {"credential_encryption_key": b"Key_Sample"},
            "logging": {"backend_path": "/tmp/log/fakepath.log", "log_level": "INFO"},
        }

    @pytest.mark.parametrize("key", [None, "dev", "change-me", "short"])
    def test_production_refuses_weak_or_missing_key(self, factory_config, monkeypatch, key):
        from app.factory import create_app

        monkeypatch.setattr("app.core.config.IS_TEST_ENV", False)
        monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)
        if key:
            factory_config["secret_key"] = key
        with patch_configuration(factory_config), patch("app.factory._start_background_services"), patch(
            "app.services.metadata.setup_trusted_cas"
        ), pytest.raises(RuntimeError, match="secret_key"):
            create_app()

    def test_production_uses_configured_key(self, factory_config, monkeypatch):
        from app.factory import create_app

        monkeypatch.setattr("app.core.config.IS_TEST_ENV", False)
        factory_config["secret_key"] = "k" * 40
        with patch_configuration(factory_config), patch("app.factory._start_background_services"), patch(
            "app.services.metadata.setup_trusted_cas"
        ):
            app = create_app()
        assert app.config["SECRET_KEY"] == "k" * 40


class TestPlaceholderApiKey:
    """The example configuration shipped backend_api_key: "change-me"."""

    @pytest.mark.parametrize("key", ["change-me", "secret", ""])
    def test_placeholder_key_is_treated_as_unset(self, key):
        from app.core.security import configured_api_key, is_valid_api_key

        with patch_configuration({"backend_api_key": key}):
            assert configured_api_key() is None
            assert not is_valid_api_key(key)


class TestPresentationReplayAndIdor:
    """AUTH-VULN-06 (static OID4VP nonce) and the cross-device presentation_id IDOR."""

    VERIFIER_CONFIG = {
        "dynamic_presentation_url": "https://verifier.test/ui/presentations",
        "oid4vp_scheme": "eudi-openid4vp://",
        "intended_use_id": "use",
    }

    def test_each_presentation_gets_a_fresh_nonce(self):
        from app.services import oid4vp as oid4vp_service

        responses = [{"transaction_id": f"t{i}", "client_id": "c", "request_uri": "r"} for i in range(4)]
        with patch_configuration(self.VERIFIER_CONFIG), patch.object(oid4vp_service.requests, "request") as http:
            http.return_value.json.side_effect = responses
            first = oid4vp_service.start_presentation({"credentials": []}, "https://b.test/cb")
            second = oid4vp_service.start_presentation({"credentials": []}, "https://b.test/cb")
        sent = [json.loads(call.kwargs["data"])["nonce"] for call in http.call_args_list]
        assert sent == [first.nonce, first.nonce, second.nonce, second.nonce]
        assert first.nonce != second.nonce and len(first.nonce) >= 43
        assert "hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc=" not in sent

    def test_foreign_presentation_id_is_not_fetched_by_pid_login(self):
        from app.routes import oid4vp as oid4vp_routes
        from app.routes.oid4vp import oid4vp

        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(oid4vp)
        session = _session(oid4vp_transaction_id="mine-same", oid4vp_cross_device_id="mine-cross")
        with patch_configuration({**CONFIG, **self.VERIFIER_CONFIG}), patch.object(
            oid4vp_routes.session_manager, "get_session", return_value=session
        ), patch.object(oid4vp_routes, "fetch_presentation_result") as fetch:
            client = app.test_client()
            with client.session_transaction() as s:
                s["session_id"] = "s1"
            response = client.get("/getpidoid4vp?presentation_id=victim-transaction")
        assert response.status_code == 400
        fetch.assert_not_called()

    def test_foreign_presentation_id_is_not_fetched_by_revocation(self):
        from app.routes import revocation as revocation_routes

        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(revocation_routes.revocation)
        with patch_configuration({**CONFIG, **self.VERIFIER_CONFIG}), patch.object(
            revocation_routes, "fetch_presentation_result"
        ) as fetch:
            client = app.test_client()
            with client.session_transaction() as s:
                s["session_id"] = "s1"
                s["oid4vp_cross_device_id"] = "mine-cross"
            response = client.get("/revocation/getoid4vp?presentation_id=victim-transaction")
            no_request = client.get("/revocation/getoid4vp?response_code=x&session_id=s1")
        assert response.status_code == 400 and no_request.status_code == 400
        fetch.assert_not_called()

    def test_own_cross_device_transaction_is_fetched(self):
        from app.services.oid4vp import result_url_from_request

        with patch_configuration(self.VERIFIER_CONFIG):
            url = result_url_from_request({"presentation_id": "mine-cross"}, "mine-same", "mine-cross")
            same = result_url_from_request({"response_code": "rc&x", "session_id": "s1"}, "mine-same", "mine-cross")
        assert url == "https://verifier.test/ui/presentations/mine-cross"
        assert same == "https://verifier.test/ui/presentations/mine-same?response_code=rc%26x"


class TestPidPresentationChecks:
    """The PID login accepted any document type and expired document signers."""

    def _token(self, documents):
        import cbor2

        return {"vp_token": {"query_0": [base64.urlsafe_b64encode(cbor2.dumps({"status": 0, "documents": documents})).decode()]}}

    @pytest.mark.parametrize(
        "documents",
        [[], [{"docType": "org.iso.18013.5.1.mDL"}], [{"docType": "eu.europa.ec.eudi.pid.1"}, {"docType": "eu.europa.ec.eudi.pid.1"}]],
    )
    def test_only_a_single_pid_document_is_accepted(self, documents):
        from app.services import vp_validation

        with patch.object(vp_validation, "validate_certificate", return_value=(True, "")) as check:
            is_error, _ = vp_validation.validate_vp_token(self._token(documents), [])
        assert is_error
        check.assert_not_called()


class TestSessionFixation:
    """AUTH-VULN-01 / AUTHZ-VULN-01: /auth_choice took session_id from the query string."""

    @pytest.fixture
    def as_key(self, tmp_path):
        import jwt
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
        jwk.update({"kid": "as-1", "use": "sig", "alg": "ES256"})
        path = tmp_path / "as_jwks.json"
        path.write_text(json.dumps({"keys": [jwk]}))
        return key, str(path)

    @pytest.fixture
    def oidc_client(self, as_key):
        from app.routes import oidc as oidc_routes
        from app.routes.oidc import oidc

        config = json.loads(json.dumps(CONFIG))
        config["authorization_server"]["jwks_path"] = as_key[1]
        config["credential_auth_methods"] = {"PID_login": [], "country_selection": ["pid"]}
        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(oidc)
        with patch_configuration(config), patch.object(oidc_routes, "session_manager") as sessions:
            sessions.get_session.return_value = None
            yield app.test_client(), sessions

    def _token(self, key, **overrides):
        import time

        import jwt

        claims = {
            "session_id": "as-session",
            "authorization_details": [{"type": "openid_credential", "credential_configuration_id": "pid"}],
            "frontend_id": CONFIG["frontend"]["default"],
            "aud": ["eudiw-issuer-backend"],
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            **overrides,
        }
        return jwt.encode(claims, key, algorithm="ES256", headers={"kid": "as-1"})

    def test_session_comes_from_the_signed_token(self, oidc_client, as_key):
        client, sessions = oidc_client
        response = client.get(
            "/auth_choice",
            query_string={"token": "jws", "session_token": self._token(as_key[0]), "session_id": "attacker-chosen"},
        )
        assert response.status_code == 302
        assert sessions.add_session.call_args.kwargs["session_id"] == "as-session"
        with client.session_transaction() as s:
            assert s["session_id"] == "as-session"

    @pytest.mark.parametrize(
        "case",
        ["missing", "other_key", "expired", "wrong_audience", "no_session_id", "query_params_only"],
    )
    def test_untrusted_session_rejected(self, oidc_client, as_key, case):
        import time

        from cryptography.hazmat.primitives.asymmetric import ec

        client, sessions = oidc_client
        key = as_key[0]
        tokens = {
            "missing": None,
            "other_key": lambda: self._token(ec.generate_private_key(ec.SECP256R1())),
            "expired": lambda: self._token(key, iat=int(time.time()) - 900, exp=int(time.time()) - 600),
            "wrong_audience": lambda: self._token(key, aud=["someone-else"]),
            "no_session_id": lambda: self._token(key, session_id=""),
            "query_params_only": None,
        }
        token = tokens[case]() if tokens[case] else None
        query = {"token": "jws", "session_id": "victim", "authorization_details": json.dumps(json.dumps([{"credential_configuration_id": "pid"}]))}
        if token:
            query["session_token"] = token
        response = client.get("/auth_choice", query_string=query)
        assert response.status_code == 400
        sessions.add_session.assert_not_called()

    def test_existing_session_of_another_browser_rejected(self, oidc_client, as_key):
        client, sessions = oidc_client
        sessions.get_session.return_value = _session(session_id="as-session")
        response = client.get("/auth_choice", query_string={"token": "jws", "session_token": self._token(as_key[0])})
        assert response.status_code == 400
        sessions.add_session.assert_not_called()

    def test_same_browser_may_reload(self, oidc_client, as_key):
        client, sessions = oidc_client
        sessions.get_session.return_value = _session(session_id="as-session")
        with client.session_transaction() as s:
            s["session_id"] = "as-session"
        response = client.get("/auth_choice", query_string={"token": "jws", "session_token": self._token(as_key[0])})
        assert response.status_code == 302

    def test_preauth_code_request_sends_api_key(self):
        from app.services import auth_server

        config = {"authorization_server": {"base_url": "https://as.test", "api_key": "as-key"}}
        with patch_configuration(config), patch.object(auth_server.requests, "request") as http:
            http.return_value.json.return_value = {"session_id": "s"}
            auth_server.generate_preauth_code("pid", "fe")
        assert http.call_args.kwargs["headers"]["X-Api-Key"] == "as-key"
        assert http.call_args.kwargs["data"] == {"scope": "pid", "frontend_id": "fe"}
        http.return_value.raise_for_status.assert_called_once()


class TestCredentialTypeAuthorization:
    """A token authorized for credential A could obtain credential B."""

    @pytest.fixture
    def credential_client(self):
        from app.routes import oidc as oidc_routes
        from app.routes.oidc import oidc

        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(oidc)
        session = _session(
            credentials_requested=["pid"],
            scope=None,
            authorization_details=[{"type": "openid_credential", "credential_configuration_id": "pid"}],
        )
        with patch_configuration(json.loads(json.dumps(CONFIG))), patch.object(
            oidc_routes, "verify_introspection", return_value=("s1", None)
        ), patch.object(oidc_routes, "session_manager") as sessions, patch.object(
            oidc_routes, "generate_credentials", return_value={"credentials": [{"credential": "c"}]}
        ) as generate, patch.object(oidc_routes, "vct2id", return_value=None), patch.object(
            oidc_routes, "_finish", side_effect=lambda session_id, response, *a: (response, 200)
        ):
            sessions.get_session.return_value = session
            yield app.test_client(), generate

    def _request(self, client, configuration_id):
        return client.post(
            "/credential",
            headers={"Authorization": "Bearer tok"},
            json={"credential_configuration_id": configuration_id, "proof": {"proof_type": "jwt", "jwt": "x"}},
        )

    def test_other_credential_rejected(self, credential_client):
        from app.routes import oidc as oidc_routes

        client, generate = credential_client
        # OpenID4VCI 1.0 section 8.3.1.1 / RFC 6750 section 3.1: a supported configuration
        # the token does not cover is insufficient_scope; an unsupported one is unknown.
        with patch.dict(oidc_routes.oidc_metadata, {"credential_configurations_supported": {"eu.europa.ec.eudi.mdl_mdoc": {}}}):
            response = self._request(client, "eu.europa.ec.eudi.mdl_mdoc")
        assert response.status_code == 403
        assert response.get_json()["error"] == "insufficient_scope"
        assert response.headers["WWW-Authenticate"].startswith('Bearer error="insufficient_scope"')
        with patch.dict(oidc_routes.oidc_metadata, {"credential_configurations_supported": {}}):
            response = self._request(client, "eu.europa.ec.eudi.mdl_mdoc")
        assert response.status_code == 400
        assert response.get_json()["error"] == "unknown_credential_configuration"
        generate.assert_not_called()

    def test_authorized_credential_issued(self, credential_client):
        client, generate = credential_client
        response = self._request(client, "pid")
        assert response.status_code == 200
        generate.assert_called_once()

    def test_credential_identifier_only_request_is_handled(self, credential_client):
        client, generate = credential_client
        response = client.post(
            "/credential",
            headers={"Authorization": "Bearer tok"},
            json={"credential_identifier": "pid", "proof": {"proof_type": "jwt", "jwt": "x"}},
        )
        assert response.status_code == 200
        assert generate.call_args.kwargs["credential_request"]["credential_configuration_id"] == "pid"


class TestIdpRedirectState:
    """AUTH-VULN-05: /dynamic/redirect accepted any code without checking state."""

    @pytest.fixture
    def redirect_client(self, client):
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=_session(country="OO")), patch.object(
            dynamic_routes, "exchange_authorization_code", return_value="at"
        ) as exchange, patch.object(dynamic_routes, "collect_user_data", return_value={}), patch.object(
            dynamic_routes, "presentation_formatter", return_value={}
        ), patch.object(dynamic_routes, "post_redirect_with_payload", return_value="consent"), patch.object(
            dynamic_routes.session_manager, "update_user_data"
        ):
            yield client, exchange

    @pytest.mark.parametrize("stored, sent", [(None, "x"), ("expected", None), ("expected", "attacker"), ("expected", "")])
    def test_wrong_or_missing_state_rejected(self, redirect_client, stored, sent):
        client, exchange = redirect_client
        with client.session_transaction() as s:
            if stored:
                s["oauth_state"] = stored
        query = {"code": "attacker-code"}
        if sent is not None:
            query["state"] = sent
        response = client.get("/dynamic/redirect", query_string=query)
        assert response.status_code == 400
        exchange.assert_not_called()

    def test_matching_state_accepted_once(self, redirect_client):
        client, exchange = redirect_client
        with client.session_transaction() as s:
            s["oauth_state"] = "expected"
        assert client.get("/dynamic/redirect", query_string={"code": "c", "state": "expected"}).status_code == 200
        assert client.get("/dynamic/redirect", query_string={"code": "c", "state": "expected"}).status_code == 400
        exchange.assert_called_once()


class TestLogsExactMatch:
    """AUTH-VULN-03: /logs?session_id=<any substring> returned every user's log lines."""

    SESSION = "0c6f8a52-1b2c-4d3e-8f90-123456789abc"
    OTHER = "9d1e2f30-4a5b-4c6d-8e7f-abcdefabcdef"

    @pytest.fixture
    def logs_client(self, tmp_path):
        from app.routes.oidc import oidc

        log = tmp_path / "backend.log"
        log.write_text(
            f"INFO | , Session ID: {self.SESSION}, Authorization selection\n"
            f"INFO | , Session ID: {self.OTHER}, form_data: given_name Doris\n"
            f"INFO | , Session ID: {self.SESSION}x, lookalike\n"
        )
        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(oidc)
        config = {"admin_api_key": "k" * 40, "logging": {"backend_path": str(log)}}
        with patch_configuration(config):
            yield app.test_client()

    @pytest.mark.parametrize("probe", ["Session ID:", " ", "INFO", "given_name", "form_data", "a", SESSION[:8]])
    def test_substrings_rejected(self, logs_client, probe):
        response = logs_client.get("/logs", query_string={"session_id": probe}, headers={"X-Api-Key": "k" * 40})
        assert response.status_code == 400

    def test_only_the_exact_session_is_returned(self, logs_client):
        body = logs_client.get(
            "/logs", query_string={"session_id": self.SESSION}, headers={"X-Api-Key": "k" * 40}
        ).get_json()
        assert body["count"] == 1 and "Doris" not in json.dumps(body) and "lookalike" not in json.dumps(body)


class TestMetadataSigner:
    """AUTHZ-VULN-08 residue: caller metadata overrode sub/iat; errors leaked details."""

    def test_metadata_cannot_override_registered_claims(self, monkeypatch):
        import jwt
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        import datetime

        from app.services import metadata as metadata_service

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fe")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        frontend = {
            "url": "https://fe.test",
            "metadata_signing_key": key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ),
            "metadata_signing_key_password": None,
            "metadata_access_certificate": cert.public_bytes(serialization.Encoding.PEM),
        }
        monkeypatch.setattr(metadata_service, "frontend_config", lambda _id: frontend)
        token = metadata_service.sign_issuer_metadata(
            {"sub": "https://attacker.example", "iat": 1, "exp": 1, "credential_issuer": "https://fe.test"}, "fe"
        )
        claims = jwt.decode(token, options={"verify_signature": False})
        assert claims["sub"] == "https://fe.test" and claims["iat"] > 1 and "exp" not in claims
        assert claims["credential_issuer"] == "https://fe.test"

    def test_errors_do_not_leak_details(self):
        from app.routes import metadata as metadata_routes
        from app.routes.metadata import metadata
        from app.services.metadata import MetadataSigningError

        app = Flask(__name__)
        app.config.update(TESTING=True)
        app.register_blueprint(metadata)
        config = {"admin_api_key": "k" * 40, "frontend": {"frontends_config": {"fe": {}}}}
        with patch_configuration(config), patch.object(
            metadata_routes, "sign_issuer_metadata",
            side_effect=MetadataSigningError("Failed to load private key", "/etc/eudiw/keys/fe.key: bad password"),
        ):
            response = app.test_client().post(
                "/metadata/metadata_signer",
                json={"metadata": {"a": 1}, "issuer_frontend_id": "fe"},
                headers={"X-Api-Key": "k" * 40},
            )
        assert response.status_code == 500 and "/etc/eudiw" not in response.get_data(as_text=True)


class TestFormIndexDos:
    """x[9999999999]=1 made the form parser append billions of list items."""

    def test_huge_index_rejected_quickly(self):
        import time

        from app.services.presentation import InvalidFormError, _set_nested

        start = time.monotonic()
        with pytest.raises(InvalidFormError):
            _set_nested({}, "x[9999999999]", "1")
        with pytest.raises(InvalidFormError):
            _set_nested({}, "x[9999999999][y]", "1")
        assert time.monotonic() - start < 1

    def test_normal_indices_still_work(self):
        from app.services.presentation import _set_nested

        target = {}
        _set_nested(target, "capacities[1][code]", "A")
        assert target == {"capacities": [{}, {"code": "A"}]}

    def test_route_returns_400(self, client, config):
        config["test_features"] = {"form_countries": True}
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=_session()), patch.object(
            dynamic_routes.session_manager, "update_user_data"
        ) as store:
            response = client.post("/dynamic/form", data={"proceed": "1", "x[9999999999]": "1"})
        assert response.status_code == 400
        store.assert_not_called()

    def test_key_without_name_returns_400(self, client, config):
        """``[]=x`` raised IndexError in the parser (500)."""
        config["test_features"] = {"form_countries": True}
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=_session()), patch.object(
            dynamic_routes.session_manager, "update_user_data"
        ) as store:
            response = client.post("/dynamic/form", data={"proceed": "1", "[]": "x"})
        assert response.status_code == 400
        store.assert_not_called()


class TestRevocationBinding:
    """AUTH-VULN-13: anyone holding a revocation_identifier could revoke."""

    @pytest.fixture
    def revoke_client(self):
        import datetime as dt

        from app.routes import revocation as revocation_routes

        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(revocation_routes.revocation)
        pending = {
            "victim-revocation": {
                "status_lists": {"dc+sd-jwt": [{"status_list": {"idx": 1, "uri": "https://sl.test/1"}}], "mso_mdoc": []},
                "expires": dt.datetime.now() + dt.timedelta(minutes=5),
            },
            "expired": {"status_lists": {}, "expires": dt.datetime.now() - dt.timedelta(seconds=1)},
        }
        with patch_configuration(json.loads(json.dumps(CONFIG))), patch.object(
            revocation_routes, "revocation_requests", pending
        ), patch.object(revocation_routes, "set_token_status", return_value=1) as set_status, patch.object(
            revocation_routes, "post_redirect_with_payload", return_value="done"
        ):
            yield app.test_client(), set_status, pending

    def test_identifier_of_another_session_rejected(self, revoke_client):
        client, set_status, pending = revoke_client
        response = client.post("/revocation/revoke", data={"revocation_identifier": "victim-revocation"})
        assert response.status_code == 403
        set_status.assert_not_called()
        assert "victim-revocation" in pending

    def test_expired_request_rejected(self, revoke_client):
        client, set_status, _ = revoke_client
        with client.session_transaction() as s:
            s["revocation_id"] = "expired"
        assert client.post("/revocation/revoke", data={"revocation_identifier": "expired"}).status_code == 404
        set_status.assert_not_called()

    def test_own_request_revoked_once(self, revoke_client):
        client, set_status, _ = revoke_client
        with client.session_transaction() as s:
            s["revocation_id"] = "victim-revocation"
        assert client.post("/revocation/revoke", data={"revocation_identifier": "victim-revocation"}).status_code == 200
        assert client.post("/revocation/revoke", data={"revocation_identifier": "victim-revocation"}).status_code == 403
        set_status.assert_called_once()


class TestX5cTrust:
    """Key-attestation / offer-request chains: any alg was accepted; a leaf could act as a CA."""

    @pytest.fixture
    def pki(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        from app.core import state
        from pki_helpers import ca_entry, make_cert

        root_key, mid_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
        root = make_cert("Root CA", "Root CA", root_key.public_key(), root_key, ca=True)
        leaf_as_ca = make_cert("Not a CA", "Root CA", mid_key.public_key(), root_key, ca=False)
        leaf = make_cert("Signer", "Not a CA", leaf_key.public_key(), mid_key, ca=False)
        with patch.dict(state.trusted_CAs, {root.subject: ca_entry(root)}, clear=True):
            yield {"root": root, "leaf_as_ca": leaf_as_ca, "leaf": leaf, "root_key": root_key, "leaf_key": leaf_key}

    def test_leaf_certificate_cannot_issue(self, pki):
        from app.core.errors import CertificateVerificationError
        from app.services.trust import verify_chain_against_trusted_CAs
        from cryptography.hazmat.primitives import serialization

        der = [c.public_bytes(serialization.Encoding.DER) for c in (pki["leaf"], pki["leaf_as_ca"])]
        with pytest.raises(CertificateVerificationError, match="not a CA"):
            verify_chain_against_trusted_CAs(der)

    @pytest.mark.parametrize("alg", ["none", "HS256"])
    def test_symmetric_or_none_alg_rejected_by_default(self, alg):
        from app.services.trust import _x5c_header

        header = base64.urlsafe_b64encode(json.dumps({"alg": alg, "x5c": ["AA=="]}).encode()).rstrip(b"=").decode()
        with pytest.raises(ValueError, match="not allowed"):
            _x5c_header(f"{header}.e30.", None)

    @pytest.mark.parametrize(
        "claims",
        [{}, {"iat": 1}, {"exp": 4102444800}, {"iat": 1700000000, "exp": 1700000000 + 86400}],
    )
    def test_offer_request_needs_short_lived_exp_and_iat(self, client, config, pki, claims):
        import time

        config["test_features"] = {"credential_offer_request": True}

        import jwt as pyjwt
        from cryptography.hazmat.primitives.asymmetric import ec

        from pki_helpers import make_cert, x5c

        if "exp" in claims and claims["exp"] < time.time():
            claims = {"iat": int(time.time()), "exp": int(time.time()) + 86400}
        signer = make_cert("Requester", "Root CA", pki["leaf_key"].public_key(), pki["root_key"], ca=False)
        token = pyjwt.encode(
            {"credentials": [{"credential_configuration_id": "pid", "data": {}}], **claims},
            pki["leaf_key"],
            algorithm="ES256",
            headers={"x5c": x5c(signer)},
        )
        with patch.object(preauth_routes, "request_preauth_token") as start:
            response = client.post("/credentialOfferReq2", data={"request": token})
        assert response.status_code == 401
        start.assert_not_called()


class TestBrowserSessionEnds:
    """AUTH-VULN-11: the browser session stayed usable after the flow."""

    def test_session_cleared_on_hand_off_to_the_wallet(self, client, config):
        config["test_features"] = {"form_countries": True}
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=_session()):
            response = client.post("/dynamic/redirect_wallet")
            assert response.status_code == 302
            with client.session_transaction() as s:
                assert "session_id" not in s
            # The same cookie cannot submit the form again (400, not a 500).
            assert client.post("/dynamic/form", data={"proceed": "1", "family_name": "x"}).status_code == 400
            assert client.post("/dynamic/redirect_wallet").status_code == 400


class TestRateLimits:
    """AUTH-VULN-04: no endpoint was rate limited."""

    def _app(self, monkeypatch, **settings):
        from app.factory import create_app

        monkeypatch.setattr(
            "app.services.metadata._build_credential_encryption_metadata", MagicMock(return_value="enc")
        )
        config = {
            "service_url": "https://backend.test/",
            "admin_api_key": "k" * 40,
            "frontend": {"default": "fe", "frontends_config": {"fe": {"url": "https://fe.test"}}},
            "keys": {"credential_encryption_key": b"Key_Sample"},
            "logging": {"backend_path": "/tmp/log/fakepath.log", "log_level": "INFO"},
            "rate_limiting": settings,
        }
        with patch_configuration(config):
            return create_app(test_config={"TESTING": True, "SECRET_KEY": "k" * 40}), config

    def test_logs_endpoint_throttled(self, monkeypatch):
        app, config = self._app(monkeypatch, limits={"oidc.get_logs_by_session": "3 per minute"})
        client = app.test_client()
        with patch_configuration(config):
            codes = [client.get("/logs?session_id=x", headers={"X-Api-Key": "k" * 40}).status_code for _ in range(5)]
        assert codes[:3] == [400, 400, 400] and codes[3:] == [429, 429]

    def test_limits_are_per_client_behind_a_proxy(self, monkeypatch):
        app, config = self._app(monkeypatch, trusted_proxies=1, limits={"oidc.get_logs_by_session": "1 per minute"})
        client = app.test_client()
        headers = {"X-Api-Key": "k" * 40}
        with patch_configuration(config):
            first = client.get("/logs?session_id=x", headers={**headers, "X-Forwarded-For": "198.51.100.1"})
            again = client.get("/logs?session_id=x", headers={**headers, "X-Forwarded-For": "198.51.100.1"})
            other = client.get("/logs?session_id=x", headers={**headers, "X-Forwarded-For": "198.51.100.2"})
        assert (first.status_code, again.status_code, other.status_code) == (400, 429, 400)

    def test_can_be_disabled(self, monkeypatch):
        app, config = self._app(monkeypatch, enabled=False, limits={"oidc.get_logs_by_session": "1 per minute"})
        client = app.test_client()
        with patch_configuration(config):
            codes = {client.get("/logs?session_id=x", headers={"X-Api-Key": "k" * 40}).status_code for _ in range(3)}
        assert codes == {400}


class TestDpopAtResourceEndpoints:
    """AUTH-VULN-07: a DPoP-bound token replayed as a Bearer token was accepted."""

    TOKEN = "access-token-value"

    @pytest.fixture
    def wallet_key(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        return ec.generate_private_key(ec.SECP256R1())

    def _jkt(self, key):
        import jwt as pyjwt

        from app.services.dpop import jwk_thumbprint

        return jwk_thumbprint(json.loads(pyjwt.algorithms.ECAlgorithm.to_jwk(key.public_key())))

    def _proof(self, key, htu="https://backend.test/credential", htm="POST", token=None, **extra):
        import hashlib
        import time
        import uuid

        import jwt as pyjwt

        claims = {
            "jti": str(uuid.uuid4()),
            "htm": htm,
            "htu": htu,
            "iat": int(time.time()),
            "ath": base64.urlsafe_b64encode(hashlib.sha256((token or self.TOKEN).encode()).digest()).rstrip(b"=").decode(),
            **extra,
        }
        public = json.loads(pyjwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
        return pyjwt.encode(claims, key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": public})

    @pytest.fixture
    def credential_client(self, wallet_key):
        from app.routes import oidc as oidc_routes
        from app.routes.oidc import oidc

        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(oidc)
        config = json.loads(json.dumps(CONFIG))
        config["status_validator"] = {"enabled": False}
        introspection = MagicMock()
        introspection.json.return_value = {"active": True, "username": "s1", "cnf": {"jkt": self._jkt(wallet_key)}}
        with patch_configuration(config), patch.object(oidc_routes, "introspect", return_value=introspection), patch.object(
            oidc_routes, "session_manager"
        ) as sessions, patch.object(
            oidc_routes, "generate_credentials", return_value={"credentials": [{"credential": "c"}]}
        ) as generate, patch.object(oidc_routes, "vct2id", return_value=None), patch.object(
            oidc_routes, "_finish", side_effect=lambda session_id, response, *a: (response, 200)
        ):
            sessions.get_session.return_value = _session(credentials_requested=["pid"], scope=None)
            yield app.test_client(), generate

    def _post(self, client, headers):
        return client.post("/credential", headers=headers, json={"credential_configuration_id": "pid", "proof": {"proof_type": "jwt", "jwt": "x"}})

    def test_bearer_replay_rejected(self, credential_client):
        client, generate = credential_client
        response = self._post(client, {"Authorization": f"Bearer {self.TOKEN}"})
        # RFC 9449 section 7.2: rejected per RFC 6750 (invalid_token), with a DPoP challenge.
        assert response.status_code == 401 and response.get_json()["error"] == "invalid_token"
        assert response.headers["WWW-Authenticate"].startswith('DPoP error="invalid_token"')
        generate.assert_not_called()

    def test_valid_proof_accepted(self, credential_client, wallet_key):
        client, generate = credential_client
        response = self._post(client, {"Authorization": f"DPoP {self.TOKEN}", "DPoP": self._proof(wallet_key)})
        assert response.status_code == 200
        generate.assert_called_once()

    @pytest.mark.parametrize("variant", ["other_key", "wrong_htu", "wrong_htm", "wrong_ath", "missing", "replayed"])
    def test_invalid_proofs_rejected(self, credential_client, wallet_key, variant):
        from cryptography.hazmat.primitives.asymmetric import ec

        client, generate = credential_client
        proofs = {
            "other_key": lambda: self._proof(ec.generate_private_key(ec.SECP256R1())),
            "wrong_htu": lambda: self._proof(wallet_key, htu="https://backend.test/notification"),
            "wrong_htm": lambda: self._proof(wallet_key, htm="GET"),
            "wrong_ath": lambda: self._proof(wallet_key, token="another-token"),
            "missing": lambda: None,
            "replayed": lambda: self._proof(wallet_key, jti="same-jti"),
        }
        proof = proofs[variant]()
        headers = {"Authorization": f"DPoP {self.TOKEN}"}
        if proof:
            headers["DPoP"] = proof
        if variant == "replayed":
            assert self._post(client, headers).status_code == 200
            generate.reset_mock()
        response = self._post(client, headers)
        assert response.status_code == 401
        generate.assert_not_called()

    @pytest.mark.parametrize("offset, status", [(30, 200), (-200, 200), (120, 401), (-400, 401)])
    def test_iat_window(self, credential_client, wallet_key, offset, status):
        """A wallet clock slightly ahead was rejected: PyJWT allowed no skew on iat."""
        import time

        client, _ = credential_client
        proof = self._proof(wallet_key, iat=int(time.time()) + offset)
        assert self._post(client, {"Authorization": f"DPoP {self.TOKEN}", "DPoP": proof}).status_code == status

    def test_introspection_sends_api_key(self):
        from app.services import auth_server

        with patch_configuration({"authorization_server": {"base_url": "https://as.test", "api_key": "as-key"}}), patch.object(
            auth_server.requests, "request"
        ) as http:
            auth_server.introspect("tok")
        assert http.call_args.kwargs["headers"]["X-Api-Key"] == "as-key"
        assert http.call_args.kwargs["data"] == {"token": "tok"}



class TestSessionRepr:
    """Pre-authorized codes and tx_codes could end up in logs via repr()."""

    def test_secrets_are_masked(self):
        import datetime as dt

        from app.repositories.session_store import Session

        session = Session(
            session_id="s1",
            expiry_time=dt.datetime.now(dt.timezone.utc),
            pre_authorized_code="secret-code",
            tx_code=12345,
            user_data={"family_name": "Doe"},
            country="FC",
        )
        text = repr(session)
        assert "secret-code" not in text and "12345" not in text and "Doe" not in text
        assert "tx_code=<set>" in text and "country='FC'" in text


# ---------------------------------------------------------------------------
# Final review (2026-10-07)
# ---------------------------------------------------------------------------


class TestTrustAnchorsPerPurpose:
    """One CA store anchored key attestations, offer requests and PID signers alike;
    a trust validator "trusted: false" fell back to it; any certificate profile passed."""

    @pytest.fixture
    def pki(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        from pki_helpers import make_cert

        keys = {name: ec.generate_private_key(ec.SECP256R1()) for name in ("ka", "offer", "mid", "leaf")}
        ka_root = make_cert("KA Root", "KA Root", keys["ka"].public_key(), keys["ka"], ca=True)
        offer_root = make_cert("Offer Root", "Offer Root", keys["offer"].public_key(), keys["offer"], ca=True)
        return {"keys": keys, "ka_root": ka_root, "offer_root": offer_root}

    def _leaf(self, pki, **kwargs):
        from pki_helpers import make_cert

        keys = pki["keys"]
        return make_cert("Signer", "Offer Root", keys["leaf"].public_key(), keys["offer"], **{"ca": False, **kwargs})

    @pytest.fixture
    def stores(self, pki):
        from app.core import state
        from pki_helpers import ca_entry

        shared = {pki["offer_root"].subject: ca_entry(pki["offer_root"])}
        own = {"key_attestation": {pki["ka_root"].subject: ca_entry(pki["ka_root"])}}
        with patch.dict(state.trusted_CAs, shared, clear=True), patch.dict(state.trusted_CAs_by_purpose, own, clear=True):
            yield

    def test_offer_request_ca_does_not_anchor_key_attestations(self, pki, stores):
        from app.core.errors import CertificateVerificationError
        from app.services import trust
        from pki_helpers import x5c

        chain = x5c(self._leaf(pki))
        with patch_configuration({"trust_validator": {"enabled": False}}):
            # offer_request has no folder of its own: the shared store anchors it.
            assert trust.verify_x5c_chain(chain, "ctx", purpose="offer_request").subject.rfc4514_string() == "CN=Signer"
            with pytest.raises(CertificateVerificationError, match="not issued by a trusted CA"):
                trust.verify_x5c_chain(chain, "ctx", purpose="key_attestation")

    def test_setup_loads_per_purpose_folders_with_fallback(self, pki, tmp_path):
        from cryptography.hazmat.primitives import serialization

        from app.core import state
        from app.services import metadata, trust

        for folder, cert in (("shared", pki["offer_root"]), ("pid", pki["ka_root"])):
            (tmp_path / folder).mkdir()
            (tmp_path / folder / "ca.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        config = {"trusted_CAs_path": str(tmp_path / "shared"), "trusted_CAs_paths": {"pid_signer": str(tmp_path / "pid")}}
        with patch.dict(state.trusted_CAs, {}, clear=True), patch.dict(state.trusted_CAs_by_purpose, {}, clear=True):
            with patch_configuration(config):
                metadata.setup_trusted_cas()
            assert list(trust.trust_store("pid_signer")) == [pki["ka_root"].subject]
            assert list(trust.trust_store("key_attestation")) == [pki["offer_root"].subject]
            assert list(trust.trust_store("offer_request")) == [pki["offer_root"].subject]

    def test_validator_rejection_is_not_overridden_locally(self, pki, stores):
        from app.core.errors import CertificateVerificationError
        from app.services import trust
        from pki_helpers import x5c

        config = {"trust_validator": {"enabled": True, "url": "https://tv.test/trust"}}
        with patch_configuration(config), patch.object(trust, "call_trust_validator", return_value=False):
            with pytest.raises(CertificateVerificationError, match="rejected by the trust validator"):
                trust.verify_x5c_chain(x5c(self._leaf(pki)), "ctx", purpose="offer_request")
        # An unreachable validator still falls back to the local store.
        with patch_configuration(config), patch.object(trust, "call_trust_validator", side_effect=ConnectionError):
            assert trust.verify_x5c_chain(x5c(self._leaf(pki)), "ctx", purpose="offer_request")

    @pytest.mark.parametrize("profile", ["ca_leaf", "no_digital_signature", "validator_ca_leaf"])
    def test_leaf_must_be_a_signing_certificate(self, pki, stores, profile):
        from app.core.errors import CertificateVerificationError
        from app.services import trust
        from pki_helpers import key_usage, x5c

        if profile == "no_digital_signature":
            leaf = self._leaf(pki, usage=key_usage(ca=True))
        else:
            leaf = self._leaf(pki, ca=True)
        config = {"trust_validator": {"enabled": profile == "validator_ca_leaf", "url": "https://tv.test/trust"}}
        with patch_configuration(config), patch.object(trust, "call_trust_validator", return_value=True):
            with pytest.raises(CertificateVerificationError, match="must not be a CA|digitalSignature"):
                trust.verify_x5c_chain(x5c(leaf), "ctx", purpose="offer_request")

    def test_intermediate_needs_key_cert_sign(self, pki, stores):
        from app.core.errors import CertificateVerificationError
        from app.services import trust
        from pki_helpers import make_cert, x5c

        keys = pki["keys"]
        mid = make_cert("Mid", "Offer Root", keys["mid"].public_key(), keys["offer"], ca=True, usage=None)
        leaf = make_cert("Signer", "Mid", keys["leaf"].public_key(), keys["mid"], ca=False)
        with patch_configuration({}):
            with pytest.raises(CertificateVerificationError, match="keyCertSign"):
                trust.verify_x5c_chain(x5c(leaf, mid), "ctx", purpose="offer_request")

    @pytest.mark.parametrize("eku, accepted", [(None, True), ("1.0.18013.5.1.2", True), ("1.3.6.1.5.5.7.3.2", False)])
    def test_pid_signer_extended_key_usage(self, pki, eku, accepted):
        from cryptography import x509

        from app.core.errors import CertificateVerificationError
        from app.services import trust

        extensions = [(x509.ExtendedKeyUsage([x509.ObjectIdentifier(eku)]), False)] if eku else []
        leaf = self._leaf(pki, extensions=extensions)
        if accepted:
            trust.check_leaf_certificate(leaf, "pid_signer")
        else:
            with pytest.raises(CertificateVerificationError, match="mdoc DS"):
                trust.check_leaf_certificate(leaf, "pid_signer")
        trust.check_leaf_certificate(leaf, "offer_request")  # the EKU only binds PID signers

    def test_pid_presentation_uses_the_pid_signer_anchors(self, pki):
        from cryptography.hazmat.primitives import serialization

        from app.core import state
        from app.services import vp_validation
        from pki_helpers import ca_entry

        leaf = self._leaf(pki)
        message = MagicMock(uhdr={vp_validation.X5chain: leaf.public_bytes(serialization.Encoding.DER)})
        shared = {pki["offer_root"].subject: ca_entry(pki["offer_root"])}
        own = {"pid_signer": {pki["ka_root"].subject: ca_entry(pki["ka_root"])}}
        with patch.dict(state.trusted_CAs, shared, clear=True), patch.dict(
            state.trusted_CAs_by_purpose, own, clear=True
        ), patch.object(vp_validation.Sign1Message, "decode", return_value=message):
            result = vp_validation.validate_certificate({"issuerSigned": {"issuerAuth": []}})
        assert result == (False, vp_validation._UNTRUSTED_CA)


class TestSeparateAdminApiKey:
    """One backend_api_key, held by every frontend, also opened /logs,
    /admin/sessions/client_status and the metadata signer."""

    FRONTEND_KEY = "f" * 40
    ADMIN_KEY = "a" * 40

    @pytest.fixture
    def admin_client(self, tmp_path):
        from app.routes import oidc as oidc_routes
        from app.routes.metadata import metadata
        from app.routes.oidc import oidc

        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(oidc)
        app.register_blueprint(metadata)
        config = {
            "backend_api_key": self.FRONTEND_KEY,
            "admin_api_key": self.ADMIN_KEY,
            "logging": {"backend_path": str(tmp_path / "none.log")},
            "frontend": {"default": "fe", "frontends_config": {"fe": {"url": "https://fe.test"}}},
        }
        with patch_configuration(config) as cfg, patch.object(oidc_routes, "session_manager") as sessions:
            sessions.get_all_client_statuses.return_value = {}
            yield app.test_client(), cfg

    ADMIN_REQUESTS = [
        ("get", "/logs?session_id=0c6f8a52-1b2c-4d3e-8f90-123456789abc"),
        ("get", "/admin/sessions/client_status"),
        ("post", "/metadata/metadata_signer"),
    ]

    @pytest.mark.parametrize("method, path", ADMIN_REQUESTS)
    def test_frontend_key_does_not_open_admin_endpoints(self, admin_client, method, path):
        client, _ = admin_client
        response = getattr(client, method)(path, json={}, headers={"X-Api-Key": self.FRONTEND_KEY})
        assert response.status_code == 401

    @pytest.mark.parametrize("method, path", ADMIN_REQUESTS)
    def test_admin_key_opens_admin_endpoints(self, admin_client, method, path):
        client, _ = admin_client
        response = getattr(client, method)(path, json={}, headers={"X-Api-Key": self.ADMIN_KEY})
        assert response.status_code not in (401, 503)

    @pytest.mark.parametrize("method, path", ADMIN_REQUESTS)
    def test_unset_admin_key_fails_closed(self, admin_client, method, path):
        client, config = admin_client
        del config["admin_api_key"]
        response = getattr(client, method)(path, json={}, headers={"X-Api-Key": self.FRONTEND_KEY})
        assert response.status_code == 503

    def test_admin_key_does_not_read_frontend_metadata(self, admin_client):
        client, _ = admin_client
        assert client.get("/metadata/fe", headers={"X-Api-Key": self.ADMIN_KEY}).status_code == 401


class TestSignedDisplayPayloads:
    """The frontend could not tell a display payload posted by the backend from a forged one."""

    KEY_A = "A" * 32
    KEY_B = "B" * 48

    @pytest.fixture
    def frontends(self):
        from app.utils import http

        config = {
            "service_url": "https://backend.test",
            "credential_offer_scheme": "openid-credential-offer://",
            "frontend": {
                "default": "fa",
                "frontends_config": {
                    "fa": {"url": "https://fe.test", "payload_key": self.KEY_A},
                    "fb": {"url": "https://fe.test/b", "payload_key": self.KEY_B},
                    "fc": {"url": "https://other.test"},
                },
            },
        }
        app = Flask(__name__)
        with patch_configuration(config), patch.object(http, "_unsigned_frontends_warned", set()), app.app_context():
            yield config

    @staticmethod
    def _fields(page):
        import html
        import re

        return {name: html.unescape(value) for name, value in re.findall(r'name="(payload(?:_jwt)?)" value="([^"]*)"', page)}

    def test_payload_jwt_matches_the_spec(self, frontends):
        import jwt as pyjwt

        from app.utils.http import post_redirect_with_payload

        fields = self._fields(post_redirect_with_payload("https://fe.test/display_form", {"session_id": "s1", "n": [1]}))
        token = fields["payload_jwt"]
        assert pyjwt.get_unverified_header(token) == {"alg": "HS256", "typ": "JWT"}
        claims = pyjwt.decode(token, self.KEY_A.encode(), algorithms=["HS256"], audience="fa")
        assert claims["payload"] == json.loads(fields["payload"]) == {"session_id": "s1", "n": [1]}
        assert claims["exp"] - claims["iat"] == 300

    def test_each_frontend_gets_its_own_key_and_audience(self, frontends):
        import jwt as pyjwt

        from app.utils.http import post_redirect_with_payload

        token = self._fields(post_redirect_with_payload("https://fe.test/b/display_form", {}))["payload_jwt"]
        assert pyjwt.decode(token, self.KEY_B.encode(), algorithms=["HS256"], audience="fb")["aud"] == "fb"
        with pytest.raises(pyjwt.InvalidSignatureError):
            pyjwt.decode(token, self.KEY_A.encode(), algorithms=["HS256"], audience="fb")

    def test_frontend_without_key_gets_no_jwt_and_one_warning(self, frontends, caplog):
        from app.utils.http import post_redirect_with_payload

        for _ in range(3):
            fields = self._fields(post_redirect_with_payload("https://other.test/display_form", {"a": 1}))
            assert set(fields) == {"payload"}
        assert sum("has no payload_key" in r.getMessage() for r in caplog.records) == 1

    @pytest.mark.parametrize("key", ["short", "x" * 31, 12345678901234567890123456789012345])
    def test_weak_payload_key_rejected(self, frontends, key):
        from app.utils.http import post_redirect_with_payload

        frontends["frontend"]["frontends_config"]["fa"]["payload_key"] = key
        with pytest.raises(ValueError, match="payload_key"):
            post_redirect_with_payload("https://fe.test/display_form", {})

    def test_route_pages_carry_the_signature(self, frontends):
        from app.routes import oidc as oidc_routes
        from app.routes.oidc import oidc

        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(oidc)
        with patch.object(oidc_routes, "credential_display_names", return_value={}):
            page = app.test_client().get("/credential_offer_choice?frontend_id=fa").get_data(as_text=True)
        assert "payload_jwt" in self._fields(page)


PID_CONFIG = "eu.europa.ec.eudi.pid_mdoc"
DEFERRED_CONFIG = "eu.europa.ec.eudi.pid_mdoc_deferred"


@pytest.fixture
def issuance():
    """Real proofs and c_nonces; batch size 2; issuance and sessions mocked."""
    from app.services import credential_issuance as ci
    from proof_helpers import proof_config

    policy = {"credential_metadata": {"credential_reuse_policy": {"options": [{"details": ["once_only"], "batch_size": 2}]}}}
    configs = {PID_CONFIG: policy, DEFERRED_CONFIG: policy}
    sessions = MagicMock()
    sessions.get_session.return_value = MagicMock(frontend_id="fe1")
    with patch_configuration({"status_validator": {"enabled": False}, **proof_config()}), patch.dict(
        ci.oidc_metadata, {"credential_configurations_supported": configs}, clear=True
    ), patch.object(ci, "session_manager", sessions), patch.object(
        ci, "issue_credentials_for_session", return_value={"credentials": [{"credential": "c"}]}
    ) as issue:
        yield issue


def _proofs_request(*tokens, configuration_id=PID_CONFIG):
    return {"credential_configuration_id": configuration_id, "proofs": {"jwt": list(tokens)}}


class TestSingleUseCNonce:
    """A c_nonce stayed valid for its whole hour, so a captured proof could be replayed."""

    def test_replayed_proof_rejected(self, issuance):
        from app.services import credential_issuance as ci
        from proof_helpers import proof_jwt

        token, _ = proof_jwt()
        assert "credentials" in ci.generate_credentials(_proofs_request(token), "s1")
        replay = ci.generate_credentials(_proofs_request(token), "s1")
        assert replay["error"] == "invalid_nonce" and "already been used" in replay["error_description"]
        assert issuance.call_count == 1

    def test_new_proof_with_spent_nonce_rejected(self, issuance):
        from app.services import credential_issuance as ci
        from proof_helpers import c_nonce, proof_jwt

        nonce = c_nonce()
        assert "credentials" in ci.generate_credentials(_proofs_request(proof_jwt(nonce=nonce)[0]), "s1")
        assert ci.generate_credentials(_proofs_request(proof_jwt(nonce=nonce)[0]), "s1")["error"] == "invalid_nonce"

    def test_batch_proofs_may_share_the_request_nonce(self, issuance):
        from app.services import credential_issuance as ci
        from proof_helpers import c_nonce, proof_jwt

        nonce = c_nonce()
        result = ci.generate_credentials(_proofs_request(proof_jwt(nonce=nonce)[0], proof_jwt(nonce=nonce)[0]), "s1")
        assert "credentials" in result

    def test_rejected_request_does_not_spend_the_nonce(self, issuance):
        from app.services import credential_issuance as ci
        from proof_helpers import c_nonce, proof_jwt

        nonce = c_nonce()
        good, bad = proof_jwt(nonce=nonce)[0], proof_jwt(nonce=nonce, aud="https://evil.test")[0]
        assert ci.generate_credentials(_proofs_request(good, bad), "s1")["error"] == "invalid_proof"
        assert "credentials" in ci.generate_credentials(_proofs_request(good), "s1")

    def test_nonce_without_identifier_rejected(self, issuance):
        import time

        from jwcrypto import jwk

        from app.services import credential_issuance as ci
        from proof_helpers import nonce_key_pem, proof_jwt

        now = int(time.time())
        legacy = ci.encrypt_jwe(
            {"iss": "https://backend.test", "iat": now, "exp": now + 60, "aud": ["https://backend.test/credential"]},
            jwk.JWK.from_pem(nonce_key_pem()),
            alg="RSA-OAEP",
            enc="A256GCM",
        )
        result = ci.generate_credentials(_proofs_request(proof_jwt(nonce=legacy)[0]), "s1")
        assert result["error"] == "invalid_nonce" and not issuance.called

    def test_deferred_retrieval_reuses_the_proven_keys(self, issuance):
        from app.services import credential_issuance as ci
        from proof_helpers import proof_jwt

        request = _proofs_request(proof_jwt()[0], configuration_id=DEFERRED_CONFIG)
        proven = ci.ProvenKeys()
        assert "credentials" in ci.generate_credentials(request, "s1", holder_keys=proven)
        assert proven.verified and len(proven.keys) == 1
        with patch.object(ci, "verify_proof_jwt") as verify:
            # Same stored request: its nonce is spent, so it must not be checked again.
            assert "credentials" in ci.generate_credentials(request, "s1", holder_keys=proven)
        verify.assert_not_called()
        assert issuance.call_args_list[0].args == issuance.call_args_list[1].args


def _encrypted_nonce(**claims):
    """Encrypts a c_nonce payload to the test nonce key (defaults: valid for a minute)."""
    import time

    from jwcrypto import jwk

    from app.services import credential_issuance as ci
    from proof_helpers import nonce_key_pem

    now = int(time.time())
    payload = {"iss": "https://backend.test", "jti": "j1", "iat": now, "exp": now + 60, "aud": ["https://backend.test/credential"]}
    payload.update(claims)
    return ci.encrypt_jwe(payload, jwk.JWK.from_pem(nonce_key_pem()), alg="RSA-OAEP", enc="A256GCM")


class TestCNonceConformance:
    """OpenID4VCI 1.0: nonce reuse is the issuer's choice (§13.8); a missing nonce is invalid_proof (§8.3.1.2)."""

    def test_single_use_is_the_default(self, issuance):
        from app.services import credential_issuance as ci
        from proof_helpers import c_nonce, proof_jwt

        assert "proof_validation" not in ci.CONFIGURATION and ci._nonce_single_use() is True
        nonce = c_nonce()
        assert "credentials" in ci.generate_credentials(_proofs_request(proof_jwt(nonce=nonce)[0]), "s1")
        replay = ci.generate_credentials(_proofs_request(proof_jwt(nonce=nonce)[0]), "s1")
        assert replay["error"] == "invalid_nonce" and "already been used" in replay["error_description"]

    def test_reuse_allowed_when_switched_off(self, issuance):
        from app.services import credential_issuance as ci
        from proof_helpers import c_nonce, proof_jwt

        nonce = c_nonce()
        with patch.dict(ci.CONFIGURATION, {"proof_validation": {"single_use_nonce": False}}), patch.object(
            ci.used_nonces, "consume_all"
        ) as store:
            for _ in range(3):
                assert "credentials" in ci.generate_credentials(_proofs_request(proof_jwt(nonce=nonce)[0]), "s1")
        store.assert_not_called()
        assert issuance.call_count == 3

    @pytest.mark.parametrize("single_use", [True, False])
    def test_missing_nonce_is_invalid_proof(self, issuance, single_use):
        from app.services import credential_issuance as ci
        from proof_helpers import proof_jwt

        with patch.dict(ci.CONFIGURATION, {"proof_validation": {"single_use_nonce": single_use}}):
            result = ci.generate_credentials(_proofs_request(proof_jwt(nonce=None)[0]), "s1")
        assert result == {"error": "invalid_proof", "error_description": "Proof has no c_nonce"}
        assert not issuance.called

    def test_missing_nonce_accepted_when_not_required(self, issuance):
        from app.services import credential_issuance as ci
        from proof_helpers import proof_jwt

        with patch.dict(ci.CONFIGURATION, {"proof_validation": {"require_nonce": False}}):
            assert "credentials" in ci.generate_credentials(_proofs_request(proof_jwt(nonce=None)[0]), "s1")

    @pytest.mark.parametrize("single_use", [True, False])
    @pytest.mark.parametrize(
        "make_nonce",
        [
            lambda: "not-a-jwe",
            lambda: 42,
            lambda: _encrypted_nonce(exp=1),
            lambda: _encrypted_nonce(aud=["https://other.test/credential"]),
            lambda: _encrypted_nonce(jti=None),
        ],
        ids=["undecryptable", "not-a-string", "expired", "unknown-audience", "no-identifier"],
    )
    def test_bad_or_expired_nonce_is_invalid_nonce(self, issuance, make_nonce, single_use):
        from app.services import credential_issuance as ci
        from proof_helpers import proof_jwt

        with patch.dict(ci.CONFIGURATION, {"proof_validation": {"single_use_nonce": single_use}}):
            result = ci.generate_credentials(_proofs_request(proof_jwt(nonce=make_nonce())[0]), "s1")
        assert result["error"] == "invalid_nonce" and not issuance.called

    def test_nonce_from_another_issuer_key_is_invalid_nonce(self, issuance):
        from jwcrypto import jwk

        from app.services import credential_issuance as ci
        from proof_helpers import proof_jwt

        foreign = ci.encrypt_jwe({"iss": "https://backend.test"}, jwk.JWK.generate(kty="RSA", size=2048), alg="RSA-OAEP", enc="A256GCM")
        assert ci.generate_credentials(_proofs_request(proof_jwt(nonce=foreign)[0]), "s1")["error"] == "invalid_nonce"


class TestDeferredCredentialRoute:
    """/deferred_credential re-verified the stored proofs (it would fail once nonces are single-use)."""

    def test_deferred_flow_with_single_use_nonce(self, issuance):
        from app.repositories.session_store import SessionManager
        from app.routes import oidc as oidc_routes
        from app.routes.oidc import oidc
        from app.services import credential_issuance as ci
        from proof_helpers import proof_jwt

        manager = SessionManager()
        manager.add_session("s1", frontend_id="fe1", credentials_requested=[DEFERRED_CONFIG])
        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(oidc)
        with patch.object(oidc_routes, "session_manager", manager), patch.object(ci, "session_manager", manager), patch.object(
            oidc_routes, "verify_introspection", return_value=("s1", None)
        ), patch.object(oidc_routes, "vct2id", return_value=None):
            client = app.test_client()
            headers = {"Authorization": "Bearer t"}
            first = client.post("/credential", headers=headers, json=_proofs_request(proof_jwt()[0], configuration_id=DEFERRED_CONFIG))
            assert first.status_code == 202
            transaction_id = first.get_json()["transaction_id"]
            deferred = client.post("/deferred_credential", headers=headers, json={"transaction_id": transaction_id})
        assert deferred.status_code == 200 and deferred.get_json()["credentials"] == [{"credential": "c"}]
        assert manager.get_session("s1").credential_issued is True


class TestProofCountLimit:
    """Any number of proofs was verified (trust / status calls each) before the batch size was applied."""

    def test_too_many_proofs_rejected_before_any_work(self, issuance):
        from app.services import credential_issuance as ci

        with patch.object(ci, "verify_proof_jwt") as verify, patch.object(ci, "decode_verify_attestation") as attest:
            result = ci.generate_credentials(
                {"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": ["a", "b"], "attestation": ["c"]}}, "s1"
            )
        assert result["error"] == "invalid_credential_request"
        verify.assert_not_called()
        attest.assert_not_called()
        assert not issuance.called

    def test_issuer_batch_size_applies_without_a_reuse_policy(self, issuance):
        from app.services import credential_issuance as ci

        ci.oidc_metadata["credential_configurations_supported"]["other"] = {}
        assert ci.max_proofs("other") == ci.issuer_metadata_template()["batch_credential_issuance"]["batch_size"]
        with patch.object(ci, "verify_proof_jwt") as verify:
            result = ci.generate_credentials(_proofs_request(*["x"] * (ci.max_proofs("other") + 1), configuration_id="other"), "s1")
        assert result["error"] == "invalid_credential_request"
        verify.assert_not_called()


class TestKeyAttestationFreshness:
    """Key attestations without iat / exp, of any age or with any typ were accepted."""

    @pytest.fixture
    def attestation(self, issuance):
        import json as _json
        import time

        import jwt as pyjwt
        from cryptography.hazmat.primitives.asymmetric import ec

        from app.core import state
        from pki_helpers import ca_entry, make_cert, x5c

        ca_key, signer_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
        root = make_cert("WP Root", "WP Root", ca_key.public_key(), ca_key, ca=True)
        signer = make_cert("Wallet Provider", "WP Root", signer_key.public_key(), ca_key, ca=False)
        attested = ec.generate_private_key(ec.SECP256R1())
        attested_jwk = _json.loads(pyjwt.algorithms.ECAlgorithm.to_jwk(attested.public_key()))

        def build(typ="key-attestation+jwt", drop=(), age=0):
            from proof_helpers import c_nonce

            now = int(time.time())
            claims = {
                "attested_keys": [attested_jwk],
                "iat": now - age,
                "exp": now + 3600,
                "nonce": c_nonce(),
                "key_storage_status": {"exp": now + 3600, "status": {"status_list": {"idx": 1, "uri": "u"}}},
            }
            for name in drop:
                claims.pop(name)
            # typ None: PyJWT then leaves the header out (it adds "JWT" otherwise).
            headers = {"x5c": x5c(signer), "typ": typ}
            return pyjwt.encode(claims, signer_key, algorithm="ES256", headers=headers)

        with patch.dict(state.trusted_CAs, {root.subject: ca_entry(root)}, clear=True), patch.dict(
            state.trusted_CAs_by_purpose, {}, clear=True
        ):
            yield build

    def _request(self, token):
        return {"credential_configuration_id": PID_CONFIG, "proofs": {"attestation": [token]}}

    @pytest.mark.parametrize("variant", ["fresh", "no_typ"])
    def test_valid_attestation_accepted(self, attestation, issuance, variant):
        from app.services import credential_issuance as ci

        token = attestation(typ=None) if variant == "no_typ" else attestation()
        assert "credentials" in ci.generate_credentials(self._request(token), "s1")

    @pytest.mark.parametrize(
        "kwargs",
        [{"drop": ("iat",)}, {"drop": ("exp",)}, {"age": 25 * 3600}, {"typ": "JWT"}, {"typ": "openid4vci-proof+jwt"}],
    )
    def test_invalid_attestation_rejected(self, attestation, issuance, kwargs):
        from app.services import credential_issuance as ci

        result = ci.generate_credentials(self._request(attestation(**kwargs)), "s1")
        assert result["error"] == "invalid_proof" and not issuance.called

    def test_max_age_is_configurable(self, attestation, issuance):
        from app.services import credential_issuance as ci

        ci.CONFIGURATION["proof_validation"] = {"key_attestation_max_age_seconds": 3600}
        result = ci.generate_credentials(self._request(attestation(age=2 * 3600)), "s1")
        assert result["error"] == "invalid_proof"


class TestLogInjection:
    """Messages without safe() could forge log lines; /logs trusted forged lines;
    /notification logged any caller-chosen notification_id."""

    SESSION = "0c6f8a52-1b2c-4d3e-8f90-123456789abc"

    @pytest.fixture
    def configured_logging(self, tmp_path):
        import logging

        from app.core.logging_setup import configure_logging

        names = ["", "werkzeug", "gunicorn.error", "gunicorn.access"]
        app = Flask(__name__)
        loggers = [logging.getLogger(n) for n in names] + [app.logger]
        saved = [(lg, list(lg.handlers), lg.level, lg.propagate, list(lg.filters)) for lg in loggers]
        log_file = tmp_path / "backend.log"
        try:
            configure_logging(app, {"backend_path": str(log_file), "log_level": "INFO"})
            yield log_file
        finally:
            for lg, handlers, level, propagate, filters in saved:
                for handler in lg.handlers:
                    if handler not in handlers:
                        handler.close()
                lg.handlers[:] = handlers
                lg.setLevel(level)
                lg.propagate = propagate
                lg.filters[:] = filters

    def test_every_record_is_one_line(self, configured_logging):
        import logging

        forged = "x\nINFO | app.routes.oidc | INFO | , Session ID: victim, Credential Issuance Successful\r"
        logging.getLogger("app.anything").warning("Unsanitized %s", forged)
        logging.getLogger("app.anything").warning(forged)
        for handler in logging.getLogger().handlers:
            handler.flush()
        lines = configured_logging.read_text().splitlines()
        assert not any(line.startswith("INFO | app.routes.oidc") for line in lines)
        assert sum("Credential Issuance Successful" in line for line in lines) == 2
        assert all("\\n" in line for line in lines if "Credential Issuance Successful" in line)

    def test_404_path_is_escaped(self, caplog):
        from app.core.errors import page_not_found

        app = Flask(__name__)
        app.register_error_handler(404, page_not_found)
        with caplog.at_level("WARNING"):
            app.test_client().get("/nope%0aINFO%20forged")
        [message] = [r.getMessage() for r in caplog.records if "404" in r.getMessage()]
        assert "\n" not in message and "\\n" in message

    @pytest.fixture
    def oidc_client(self, tmp_path):
        from app.repositories.session_store import SessionManager
        from app.routes import oidc as oidc_routes
        from app.routes.oidc import oidc

        manager = SessionManager()
        manager.add_session(self.SESSION)
        manager.add_session("other")
        manager.store_notification_id("other", "foreign-id")
        manager.store_notification_id(self.SESSION, "own-id")
        log = tmp_path / "backend.log"
        log.write_text(f"WARNING | Rejected ... , Session ID: {self.SESSION}, Credential Issuance Successful\n")
        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(oidc)
        config = {"admin_api_key": "k" * 40, "logging": {"backend_path": str(log)}}
        with patch_configuration(config), patch.object(oidc_routes, "session_manager", manager), patch.object(
            oidc_routes, "verify_introspection", return_value=(self.SESSION, None)
        ):
            yield app.test_client(), manager

    def test_logs_success_comes_from_the_session(self, oidc_client):
        client, manager = oidc_client
        query = {"session_id": self.SESSION}
        headers = {"X-Api-Key": "k" * 40}
        assert client.get("/logs", query_string=query, headers=headers).get_json()["successful"] is False
        manager.mark_credential_issued(self.SESSION)
        assert client.get("/logs", query_string=query, headers=headers).get_json()["successful"] is True

    @pytest.mark.parametrize(
        "notification_id, error",
        [
            ("foreign-id", "invalid_notification_id"),
            ("unknown\nINFO forged", "invalid_notification_id"),
            # OpenID4VCI 1.0 section 11.3: a missing / non-string id is a malformed request.
            (None, "invalid_notification_request"),
            (["own-id"], "invalid_notification_request"),
        ],
    )
    def test_foreign_notification_id_rejected_unlogged(self, oidc_client, caplog, notification_id, error):
        client, _ = oidc_client
        with caplog.at_level("DEBUG"):
            response = client.post(
                "/notification",
                headers={"Authorization": "Bearer t"},
                json={"notification_id": notification_id, "event": "credential_accepted"},
            )
        assert response.status_code == 400 and response.get_json()["error"] == error
        assert not any("foreign-id" in r.getMessage() or "forged" in r.getMessage() for r in caplog.records)

    def test_own_notification_accepted(self, oidc_client):
        client, _ = oidc_client
        response = client.post(
            "/notification", headers={"Authorization": "Bearer t"}, json={"notification_id": "own-id", "event": "credential_accepted"}
        )
        assert response.status_code == 204


class TestSessionStoreAndSizeLimits:
    """Anonymous GETs created server-side sessions for any frontend_id; the session file
    threshold was fixed at 50; request bodies were unbounded."""

    @pytest.fixture
    def factory_config(self, monkeypatch):
        monkeypatch.setattr("app.services.metadata._build_credential_encryption_metadata", MagicMock(return_value="enc"))
        return {
            "service_url": "https://backend.test/",
            "frontend": {"default": "fe", "frontends_config": {"fe": {"url": "https://fe.test"}}},
            "keys": {"credential_encryption_key": b"Key_Sample"},
            "logging": {"backend_path": "/tmp/log/fakepath.log", "log_level": "INFO"},
            "rate_limiting": {"enabled": False},
        }

    def _create(self, config):
        from app.factory import create_app

        with patch_configuration(config):
            return create_app(test_config={"TESTING": True, "SECRET_KEY": "k" * 40})

    def test_defaults(self, factory_config):
        app = self._create(factory_config)
        assert app.config["SESSION_FILE_THRESHOLD"] == 10000
        assert app.config["MAX_CONTENT_LENGTH"] == 1024 * 1024

    def test_configurable(self, factory_config):
        factory_config.update(session_file_threshold=123, max_content_length=4096)
        app = self._create(factory_config)
        assert app.config["SESSION_FILE_THRESHOLD"] == 123 and app.config["MAX_CONTENT_LENGTH"] == 4096

    def test_oversized_body_rejected_before_the_view(self, factory_config):
        from app.routes import oidc as oidc_routes

        factory_config["max_content_length"] = 1024
        app = self._create(factory_config)
        with patch_configuration(factory_config), patch.object(oidc_routes, "verify_introspection") as introspect:
            response = app.test_client().post(
                "/credential", headers={"Authorization": "Bearer t"}, json={"proofs": {"jwt": ["x" * 4096]}}
            )
        assert response.status_code == 413
        introspect.assert_not_called()

    def test_short_payload_key_refused_at_start_up(self, factory_config):
        factory_config["frontend"]["frontends_config"]["fe"]["payload_key"] = "too-short"
        with pytest.raises(RuntimeError, match="payload_key"):
            self._create(factory_config)

    @pytest.fixture
    def offer_client(self):
        from app.routes import oidc as oidc_routes
        from app.routes.oidc import oidc

        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(oidc)
        with patch_configuration(json.loads(json.dumps(CONFIG))), patch.object(
            oidc_routes, "credential_display_names", return_value={}
        ):
            yield app.test_client()

    @pytest.mark.parametrize("frontend_id", ["unknown", "../fe", ""])
    def test_unknown_frontend_gets_404_without_a_session(self, offer_client, frontend_id):
        response = offer_client.get("/credential_offer_choice", query_string={"frontend_id": frontend_id})
        assert response.status_code == 404
        assert "Set-Cookie" not in response.headers

    def test_known_frontend_still_served(self, offer_client):
        response = offer_client.get("/credential_offer_choice", query_string={"frontend_id": "fe"})
        assert response.status_code == 200 and "Set-Cookie" in response.headers


class TestPreauthPostOnly:
    """GET /preauth created a pre-authorized code (CSRF by link); a missing or unknown
    credentials_id raised a 500 or reached the authorization server."""

    @pytest.fixture
    def preauth_client(self, client, config):
        from app.core import state

        config["test_features"] = {"form_countries": True}
        with patch.dict(state.oidc_metadata, {"credential_configurations_supported": {"pid": {}}}), patch.object(
            preauth_routes, "request_preauth_token"
        ) as token:
            yield client, token

    @pytest.mark.parametrize("path", ['/preauth?credentials_id=["pid"]', "/preauth_form"])
    def test_get_not_allowed(self, preauth_client, path):
        client, token = preauth_client
        assert client.get(path).status_code == 405
        token.assert_not_called()

    @pytest.mark.parametrize(
        "credentials_id", [None, "", "not json", "{}", "[]", '["unknown"]', '["pid", 3]', '"pid"', '[["pid"]]']
    )
    def test_invalid_credentials_id_rejected(self, preauth_client, credentials_id):
        client, token = preauth_client
        data = {} if credentials_id is None else {"credentials_id": credentials_id}
        response = client.post("/preauth", data=data)
        assert response.status_code == 400
        token.assert_not_called()

    def test_cross_site_post_rejected(self, preauth_client):
        client, token = preauth_client
        response = client.post("/preauth", data={"credentials_id": '["pid"]'}, headers={"Origin": "https://evil.test"})
        assert response.status_code == 403
        token.assert_not_called()

    def test_offer_form_reposts_to_preauth(self, preauth_client):
        from app.routes.oidc import oidc

        client, _ = preauth_client
        client.application.register_blueprint(oidc)
        form = {"proceed": "1", "credential_offer_URI": "openid-credential-offer://", "Authorization Code Grant": "pre_auth_code", "pid": "on"}
        response = client.post("/credential_offer", data=form)
        assert response.status_code == 307 and "/preauth?credentials_id=" in response.headers["Location"]


class TestResponseEncryptionParameters:
    """Bad credential_response_encryption was only detected after the credentials were signed."""

    @pytest.fixture
    def credential_client(self):
        from jwcrypto import jwk

        from app.routes import oidc as oidc_routes
        from app.routes.oidc import oidc

        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(oidc)
        session = _session(credentials_requested=["pid"], scope=None)
        with patch_configuration(json.loads(json.dumps(CONFIG))), patch.object(
            oidc_routes, "verify_introspection", return_value=("s1", None)
        ), patch.object(oidc_routes, "session_manager") as sessions, patch.object(
            oidc_routes, "generate_credentials", return_value={"credentials": [{"credential": "c"}]}
        ) as generate, patch.object(oidc_routes, "vct2id", return_value=None), patch.object(
            oidc_routes, "persist_client_status"
        ):
            sessions.get_session.return_value = session
            public = json.loads(jwk.JWK.generate(kty="EC", crv="P-256").export_public())
            yield app.test_client(), generate, public

    def _post(self, client, encryption):
        return client.post(
            "/credential",
            headers={"Authorization": "Bearer t"},
            json={
                "credential_configuration_id": "pid",
                "proof": {"proof_type": "jwt", "jwt": "x"},
                "credential_response_encryption": encryption,
            },
        )

    @pytest.mark.parametrize(
        "variant",
        ["not_object", "jwk_string", "private_jwk", "enc_number", "enc_unadvertised", "alg_missing", "alg_rsa1_5", "alg_list", "bad_jwk"],
    )
    def test_rejected_before_issuance(self, credential_client, variant):
        from jwcrypto import jwk

        client, generate, public = credential_client
        base = {"jwk": public, "alg": "ECDH-ES", "enc": "A256GCM"}
        encryption = {
            "not_object": "ECDH-ES",
            "jwk_string": {**base, "jwk": json.dumps(public)},
            "private_jwk": {**base, "jwk": json.loads(jwk.JWK.generate(kty="EC", crv="P-256").export_private())},
            "enc_number": {**base, "enc": 256},
            "enc_unadvertised": {**base, "enc": "A256KW"},
            "alg_missing": {"jwk": public, "enc": "A256GCM"},
            "alg_rsa1_5": {**base, "alg": "RSA1_5"},
            "alg_list": {**base, "alg": ["ECDH-ES"]},
            "bad_jwk": {**base, "jwk": {"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}},
        }[variant]
        response = self._post(client, encryption)
        assert response.status_code == 400 and response.get_json()["error"] == "invalid_encryption_parameters"
        generate.assert_not_called()

    def test_valid_parameters_encrypt_the_response(self, credential_client):
        client, generate, public = credential_client
        response = self._post(client, {"jwk": public, "alg": "ECDH-ES", "enc": "A256GCM"})
        assert response.status_code == 200 and response.headers["Content-Type"] == "application/jwt"
        generate.assert_called_once()


class TestExplicitTestEnvironment:
    """CI=true (set by many build platforms) switched on the relaxed test defaults."""

    @pytest.mark.parametrize("variable", ["CI", "SONARCLOUD", "GITHUB_ACTIONS"])
    def test_generic_ci_variables_do_not_enable_it(self, monkeypatch, variable):
        from app.core import config

        monkeypatch.delenv("EUDIW_TEST_ENV", raising=False)
        monkeypatch.setenv(variable, "true")
        assert config._detect_test_env() is False

    def test_explicit_variable_enables_it(self, monkeypatch):
        from app.core import config

        monkeypatch.setenv("EUDIW_TEST_ENV", "true")
        assert config._detect_test_env() is True
