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
"""Tests for per-frontend issuer metadata (unsigned + signed) and its endpoints."""

import base64
import copy
import hashlib
import json

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from flask import Flask

from app.routes.metadata import metadata as metadata_blueprint
from app.services import frontend_metadata
from app.services.frontend_metadata import (
    TEMPLATE_DIR,
    UnknownFrontendError,
    build_frontend_metadata,
    sign_frontend_metadata,
)
from app.services.metadata import replace_domain
from app.utils.encoding import urlsafe_b64encode_nopad
from config_helpers import patch_configuration
from pki_helpers import make_cert

API_KEY = "test-api-key"
HEADERS = {"X-Api-Key": API_KEY}
FRONTEND_ID = "fe-1"
FRONTEND_URL = "https://frontend.test"
BACKEND_URL = "https://backend.test"
AUTH_URL = "https://auth.test/oidc"

BACKEND_CLEAN_METADATA = {
    "credential_issuer": BACKEND_URL,
    "credential_configurations_supported": {
        "eu.europa.ec.eudi.pid_mdoc": {"format": "mso_mdoc", "doctype": "eu.europa.ec.eudi.pid.1"},
        "eu.europa.ec.eudi.pid_vc_sd_jwt": {"format": "dc+sd-jwt", "vct": "urn:eudi:pid:1"},
        "eu.europa.ec.eudi.mdl_mdoc": {"format": "mso_mdoc", "doctype": "org.iso.18013.5.1.mDL"},
    },
    "credential_request_encryption": {"jwks": {"keys": [{"kid": "backend-kid"}]}, "encryption_required": False},
}
REGISTRATION_CERT = "eyJ0eXAiOiJyYy13cnArand0In0.eyJuYW1lIjoiSXNzdWVyIn0.c2ln"


@pytest.fixture(scope="module")
def signing_material():
    key = ec.generate_private_key(ec.SECP256R1())
    cert = make_cert("Frontend Metadata", "Frontend Metadata", key.public_key(), key, ca=False)
    return {
        "key": key,
        "cert": cert,
        "key_pem": key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
        "cert_pem": cert.public_bytes(serialization.Encoding.PEM),
    }


def _config(signing_material, **frontend_overrides):
    frontend = {
        "url": FRONTEND_URL,
        "metadata_signing_key": signing_material["key_pem"],
        "metadata_access_certificate": signing_material["cert_pem"],
        "metadata_signing_key_password": None,
        **frontend_overrides,
    }
    return {
        "service_url": BACKEND_URL,
        "backend_api_key": API_KEY,
        "admin_api_key": API_KEY,
        "authorization_server": {"base_url": AUTH_URL},
        "frontend": {"default": FRONTEND_ID, "frontends_config": {FRONTEND_ID: frontend}},
    }


@pytest.fixture
def config(signing_material):
    with patch_configuration(_config(signing_material)) as cfg:
        yield cfg


@pytest.fixture(autouse=True)
def backend_metadata():
    from unittest.mock import patch

    with patch.dict("app.core.state.oidc_metadata_clean", copy.deepcopy(BACKEND_CLEAN_METADATA), clear=True):
        yield


@pytest.fixture
def client():
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.register_blueprint(metadata_blueprint)
    return app.test_client()


def _frontend_reference(service_url, backend_url, credentials_supported_cfg, backend_data):
    """Reference copy of the frontend's former ``setup_metadata`` (domain logic)."""
    with open(TEMPLATE_DIR / "metadata_config.json") as f:
        oidc_metadata = json.load(f)

    credentials_supported = backend_data.get("credential_configurations_supported", {})
    if credentials_supported_cfg and credentials_supported_cfg != ["*"] and credentials_supported_cfg != "*":
        allowed = set(credentials_supported_cfg)
        credentials_supported = {k: v for k, v in credentials_supported.items() if k in allowed}

    oidc_metadata["credential_configurations_supported"] = credentials_supported
    if backend_data.get("credential_request_encryption"):
        oidc_metadata["credential_request_encryption"] = backend_data["credential_request_encryption"]

    old_domain = oidc_metadata["credential_issuer"]
    oidc_metadata = replace_domain(oidc_metadata, old_domain, backend_url)
    oidc_metadata["credential_issuer"] = service_url
    oidc_metadata["display"][0]["logo"]["uri"] = f"{service_url}/ic-logo.png"
    return oidc_metadata


class TestBuildFrontendMetadata:
    @pytest.mark.parametrize("credentials_supported", [None, "*", ["*"], ["eu.europa.ec.eudi.pid_mdoc"]])
    def test_matches_former_frontend_logic(self, signing_material, credentials_supported):
        overrides = {} if credentials_supported is None else {"credentials_supported": credentials_supported}
        with patch_configuration(_config(signing_material, **overrides)):
            documents = build_frontend_metadata(FRONTEND_ID)

        oidc = _frontend_reference(FRONTEND_URL, BACKEND_URL, credentials_supported, copy.deepcopy(BACKEND_CLEAN_METADATA))
        oidc["authorization_servers"] = [f"{AUTH_URL}/{FRONTEND_ID}"]
        assert documents.openid_credential_issuer == oidc

    def test_authorization_servers_is_the_frontends_issuer(self, config):
        # One issuer per frontend at the authorization server (OpenID4VCI 1.0
        # section 12.2.4); its metadata comes from that server, not from here.
        documents = build_frontend_metadata(FRONTEND_ID)
        assert documents.openid_credential_issuer["authorization_servers"] == [f"{AUTH_URL}/{FRONTEND_ID}"]
        assert set(documents.to_dict()) == {"openid_credential_issuer", "jwt_vc_issuer"}

    def test_authorization_servers_without_trailing_slash(self, signing_material):
        config = _config(signing_material)
        config["authorization_server"]["base_url"] = AUTH_URL + "/"
        with patch_configuration(config):
            issuer = build_frontend_metadata(FRONTEND_ID).openid_credential_issuer
        assert issuer["authorization_servers"] == [f"{AUTH_URL}/{FRONTEND_ID}"]

    def test_no_public_client_method_anywhere(self, config):
        # Frontend #14: "public" is not an OAuth client authentication method.
        assert '"public"' not in json.dumps(build_frontend_metadata(FRONTEND_ID).to_dict())

    def test_key_fields(self, config):
        documents = build_frontend_metadata(FRONTEND_ID)
        issuer = documents.openid_credential_issuer

        assert issuer["credential_issuer"] == FRONTEND_URL
        assert issuer["credential_endpoint"] == f"{BACKEND_URL}/credential"
        assert issuer["display"][0]["logo"]["uri"] == f"{FRONTEND_URL}/ic-logo.png"
        assert issuer["credential_request_encryption"]["jwks"]["keys"][0]["kid"] == "backend-kid"
        # No registration certificate configured: no issuer_info.
        assert "issuer_info" not in issuer
        assert set(issuer["credential_configurations_supported"]) == set(
            BACKEND_CLEAN_METADATA["credential_configurations_supported"]
        )

    def test_credentials_filter(self, signing_material):
        with patch_configuration(_config(signing_material, credentials_supported=["eu.europa.ec.eudi.mdl_mdoc"])):
            issuer = build_frontend_metadata(FRONTEND_ID).openid_credential_issuer
        assert list(issuer["credential_configurations_supported"]) == ["eu.europa.ec.eudi.mdl_mdoc"]

    def test_templates_and_backend_state_not_mutated(self, config):
        first = build_frontend_metadata(FRONTEND_ID)
        first.openid_credential_issuer["credential_configurations_supported"].clear()
        first.openid_credential_issuer["display"][0]["name"] = "changed"

        second = build_frontend_metadata(FRONTEND_ID)
        assert second.openid_credential_issuer["credential_configurations_supported"]
        assert second.openid_credential_issuer["display"][0]["name"] != "changed"

    def test_unknown_frontend(self, config):
        with pytest.raises(UnknownFrontendError):
            build_frontend_metadata("nope")

    def test_signed_metadata(self, config, signing_material):
        token = sign_frontend_metadata(FRONTEND_ID)

        header = jwt.get_unverified_header(token)
        assert header["typ"] == "openidvci-issuer-metadata+jwt"
        assert header["alg"] == "ES256"
        payload = jwt.decode(token, signing_material["cert"].public_key(), algorithms=["ES256"])
        assert payload["iss"] == FRONTEND_URL
        assert payload["sub"] == FRONTEND_URL
        assert payload["credential_issuer"] == FRONTEND_URL
        assert payload["credential_configurations_supported"]


class TestRegistrationCertificate:
    ISSUER_INFO = [{"format": "registration_cert", "data": REGISTRATION_CERT}]

    def test_unsigned_metadata(self, signing_material):
        with patch_configuration(_config(signing_material, registration_certificate=REGISTRATION_CERT)):
            documents = build_frontend_metadata(FRONTEND_ID)

        assert documents.openid_credential_issuer["issuer_info"] == self.ISSUER_INFO
        assert "issuer_info" not in documents.jwt_vc_issuer

    def test_signed_metadata(self, signing_material):
        with patch_configuration(_config(signing_material, registration_certificate=REGISTRATION_CERT)):
            token = sign_frontend_metadata(FRONTEND_ID)

        payload = jwt.decode(token, signing_material["cert"].public_key(), algorithms=["ES256"])
        assert payload["issuer_info"] == self.ISSUER_INFO

    def test_each_frontend_has_its_own(self, signing_material):
        cfg = _config(signing_material, registration_certificate=REGISTRATION_CERT)
        cfg["frontend"]["frontends_config"]["fe-2"] = {
            **cfg["frontend"]["frontends_config"][FRONTEND_ID],
            "url": "https://other-frontend.test",
            "registration_certificate": "a.b.c",
        }
        cfg["frontend"]["frontends_config"]["fe-3"] = {
            k: v for k, v in cfg["frontend"]["frontends_config"][FRONTEND_ID].items() if k != "registration_certificate"
        }
        with patch_configuration(cfg):
            first = build_frontend_metadata(FRONTEND_ID).openid_credential_issuer
            second = build_frontend_metadata("fe-2").openid_credential_issuer
            third = build_frontend_metadata("fe-3").openid_credential_issuer

        assert first["issuer_info"][0]["data"] == REGISTRATION_CERT
        assert second["issuer_info"][0]["data"] == "a.b.c"
        assert "issuer_info" not in third

    def test_backend_issuer_info_is_not_published(self, config):
        from unittest.mock import patch

        with patch.dict("app.core.state.oidc_metadata_clean", {"issuer_info": [{"data": "global"}]}):
            issuer = build_frontend_metadata(FRONTEND_ID).openid_credential_issuer
        assert "issuer_info" not in issuer


def _country_cert_der(name):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = make_cert(name, name, key.public_key(), key, ca=False)
    return cert.public_bytes(serialization.Encoding.DER)


class TestJwtVcIssuer:
    @pytest.fixture(scope="class")
    def certs(self):
        return {"EU": _country_cert_der("EU DS"), "LU": _country_cert_der("LU DS"), "fe": _country_cert_der("FE DS")}

    def _config(self, signing_material, certs):
        cfg = _config(signing_material)
        cfg["frontend"]["frontends_config"]["fe-2"] = {
            **cfg["frontend"]["frontends_config"][FRONTEND_ID],
            "url": "https://other-frontend.test",
        }
        cfg["countries"] = {
            "EU": {"keys": {"_default": {"certificate": certs["EU"]}}},
            # Countries sharing a certificate (FC, AV... reuse LU's).
            "LU": {"keys": {"_default": {"certificate": certs["LU"]}, FRONTEND_ID: {"certificate": certs["fe"]}}},
            "FC": {"keys": {"_default": {"certificate": certs["LU"]}}},
            "XX": {"keys": {"_default": {"certificate": b"not a certificate"}}},
        }
        return cfg

    def test_issuer_is_each_frontend_url(self, signing_material, certs):
        with patch_configuration(self._config(signing_material, certs)):
            first = build_frontend_metadata(FRONTEND_ID).jwt_vc_issuer
            second = build_frontend_metadata("fe-2").jwt_vc_issuer

        assert first["issuer"] == FRONTEND_URL
        assert second["issuer"] == "https://other-frontend.test"
        assert first["jwks"] == second["jwks"]

    def test_default_country_keys_once(self, signing_material, certs):
        with patch_configuration(self._config(signing_material, certs)):
            keys = build_frontend_metadata(FRONTEND_ID).jwt_vc_issuer["jwks"]["keys"]

        # EU and LU (shared by FC) only: frontend-keyed entries do not sign
        # SD-JWTs and the unparsable certificate is skipped.
        assert [k["x5c"] for k in keys] == [
            [base64.b64encode(certs["EU"]).decode()],
            [base64.b64encode(certs["LU"]).decode()],
        ]
        for key in keys:
            assert key["use"] == "sig" and key["alg"] == "ES256" and key["crv"] == "P-256"
            assert "d" not in key
            thumbprint = json.dumps(
                {"crv": key["crv"], "kty": "EC", "x": key["x"], "y": key["y"]}, separators=(",", ":"), sort_keys=True
            )
            assert key["kid"] == urlsafe_b64encode_nopad(hashlib.sha256(thumbprint.encode()).digest())


class TestEndpoints:
    PATHS = [
        ("get", f"/metadata/{FRONTEND_ID}"),
        ("get", f"/metadata/{FRONTEND_ID}/signed"),
        ("post", "/metadata/metadata_signer"),
    ]

    @pytest.mark.parametrize("method, path", PATHS)
    def test_api_key_required(self, client, config, method, path):
        response = getattr(client, method)(path, json={})
        assert response.status_code == 401

    @pytest.mark.parametrize("method, path", PATHS)
    def test_wrong_api_key(self, client, config, method, path):
        response = getattr(client, method)(path, json={}, headers={"X-Api-Key": "wrong"})
        assert response.status_code == 401

    def test_unsigned_documents(self, client, config):
        response = client.get(f"/metadata/{FRONTEND_ID}", headers=HEADERS)

        assert response.status_code == 200
        body = response.get_json()
        assert set(body) == {"openid_credential_issuer", "jwt_vc_issuer"}
        assert body["openid_credential_issuer"]["credential_issuer"] == FRONTEND_URL
        assert body["jwt_vc_issuer"] == {"issuer": FRONTEND_URL, "jwks": {"keys": []}}

    def test_signed_document(self, client, config, signing_material):
        response = client.get(f"/metadata/{FRONTEND_ID}/signed", headers=HEADERS)

        assert response.status_code == 200
        payload = jwt.decode(
            response.get_json()["signed_metadata"], signing_material["cert"].public_key(), algorithms=["ES256"]
        )
        assert payload["credential_issuer"] == FRONTEND_URL

    @pytest.mark.parametrize("path", ["/metadata/unknown", "/metadata/unknown/signed"])
    def test_unknown_frontend(self, client, config, path):
        response = client.get(path, headers=HEADERS)

        assert response.status_code == 404
        assert response.get_json()["error"] == "unknown_frontend"

    def test_signing_error(self, client, signing_material):
        with patch_configuration(_config(signing_material, metadata_signing_key=b"not a key")):
            response = client.get(f"/metadata/{FRONTEND_ID}/signed", headers=HEADERS)
        assert response.status_code == 500
        assert response.get_json()["error"] == "Failed to load private key"

    def test_metadata_signer_with_key(self, client, config, signing_material):
        response = client.post(
            "/metadata/metadata_signer",
            json={"metadata": {"credential_issuer": FRONTEND_URL}, "issuer_frontend_id": FRONTEND_ID, "iss": "x"},
            headers=HEADERS,
        )

        assert response.status_code == 200
        payload = jwt.decode(
            response.get_json()["signed_metadata"], signing_material["cert"].public_key(), algorithms=["ES256"]
        )
        assert payload["iss"] == "x"
        assert payload["sub"] == FRONTEND_URL

    def test_metadata_signer_validation(self, client, config):
        response = client.post("/metadata/metadata_signer", json={"metadata": {}}, headers=HEADERS)
        assert response.status_code == 400


def test_module_exports_template_dir():
    assert (frontend_metadata.TEMPLATE_DIR / "metadata_config.json").exists()
