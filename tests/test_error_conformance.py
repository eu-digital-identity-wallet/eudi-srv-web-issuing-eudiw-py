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
"""Error conformance of the OpenID4VCI Credential Issuer endpoints.

Every error path asserts the exact ``error`` code, HTTP status, Content-Type
and required headers, per OpenID4VCI 1.0 (final) and the RFCs it builds on:

* Credential endpoint: section 8.3.1.2 (Credential Request Errors).
* Access token errors: OpenID4VCI 8.3.1.1 / 9.3 / 11.3 -> RFC 6750 section 3
  (``WWW-Authenticate``, ``invalid_token``, ``insufficient_scope``) and
  RFC 9449 section 7 (``DPoP`` scheme, ``invalid_dpop_proof``).
* Nonce endpoint: section 7; Deferred Credential endpoint: section 9;
  Notification endpoint: section 11; offers by reference: section 4.1.3.

The routes run with real proof / c_nonce verification
(:mod:`proof_helpers`), a real :class:`SessionManager` and real token
introspection handling; only the authorization server call and the
credential formatter are mocked.
"""

import base64
import hashlib
import json
import time
import uuid
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from flask import Flask
from jwcrypto import jwk

from app.repositories.session_store import SessionManager
from app.routes import oidc as oidc_routes
from app.routes.oidc import oidc
from app.services import credential_issuance as ci
from app.services.dpop import DPOP_ALGORITHMS, jwk_thumbprint
from config_helpers import patch_configuration
from proof_helpers import c_nonce, nonce_key_pem, p256_jwk, proof_config, proof_jwt

SESSION = "0b8c1a52-1b2c-4d3e-8f90-123456789abc"
OTHER_SESSION = "9f1e2d3c-4b5a-4968-8776-655443322110"
PID = "eu.europa.ec.eudi.pid_mdoc"
DEFERRED = ci.DEFERRED_ONLY_CONFIGURATION
#: Supported by the issuer, but not covered by the test access token.
MDL = "eu.europa.ec.eudi.mdl_mdoc"
BATCH_SIZE = 2
TOKEN = "opaque-access-token"
SERVICE_URL = "https://backend.test"
#: error_description characters allowed by OpenID4VCI 8.3.1.2 (%x20-21 / %x23-5B / %x5D-7E).
_ALLOWED_DESCRIPTION = {chr(c) for c in range(0x20, 0x7F)} - {'"', "\\"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class Issuer:
    """The oidc blueprint wired to a real session store and a fake authorization server."""

    def __init__(self, client, sessions, introspection, issue):
        self.client = client
        self.sessions = sessions
        self.introspection = introspection
        self.issue = issue

    def token_is(self, **data):
        """Sets the introspection answer for the access token."""
        self.introspection.json.return_value = data

    def post(self, path, json=None, token=TOKEN, scheme="Bearer", headers=None, **kwargs):
        all_headers = {"Authorization": f"{scheme} {token}"} if token is not None else {}
        all_headers.update(headers or {})
        return self.client.post(path, json=json, headers=all_headers, **kwargs)

    def credential(self, body, **kwargs):
        return self.post("/credential", json=body, **kwargs)


@pytest.fixture
def issuer():
    policy = {"credential_metadata": {"credential_reuse_policy": {"options": [{"details": ["once_only"], "batch_size": BATCH_SIZE}]}}}
    configs = {PID: policy, DEFERRED: policy, MDL: policy}
    config = {**proof_config(service_url=SERVICE_URL), "status_validator": {"enabled": False}}
    sessions = SessionManager()
    sessions.add_session(SESSION, frontend_id="fe1", credentials_requested=[PID, DEFERRED])
    sessions.add_session(OTHER_SESSION, frontend_id="fe1", credentials_requested=[PID, DEFERRED])
    introspection = MagicMock()
    introspection.json.return_value = {"active": True, "username": SESSION}

    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="test")
    app.register_blueprint(oidc)
    with patch_configuration(config), patch.dict(
        ci.oidc_metadata, {"credential_configurations_supported": configs}, clear=True
    ), patch.object(oidc_routes, "session_manager", sessions), patch.object(ci, "session_manager", sessions), patch.object(
        oidc_routes, "introspect", return_value=introspection
    ), patch.object(oidc_routes, "vct2id", return_value=None), patch.object(
        ci, "issue_credentials_for_session", return_value={"credentials": [{"credential": "c"}]}
    ) as issue:
        yield Issuer(app.test_client(), sessions, introspection, issue)


def request_for(*proofs, configuration_id=PID, **extra):
    """A credential request with JWT proofs (fresh valid ones when none are given)."""
    tokens = list(proofs) or [proof_jwt()[0]]
    return {"credential_configuration_id": configuration_id, "proofs": {"jwt": tokens}, **extra}


# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------


def assert_error(response, status, error):
    """A JSON error body with exactly ``error`` (OpenID4VCI 8.3.1.2 / 9.3 / 11.3)."""
    assert response.status_code == status, response.get_data(as_text=True)
    assert response.mimetype == "application/json"
    body = response.get_json()
    assert body["error"] == error
    assert set(body) <= {"error", "error_description"}
    assert set(body.get("error_description", "")) <= _ALLOWED_DESCRIPTION
    return body


def challenge(response):
    return response.headers.get("WWW-Authenticate", "")


def assert_token_error(response, error, scheme, status=401):
    """RFC 6750 section 3 / RFC 9449 section 7.1 access token error."""
    assert_error(response, status, error)
    value = challenge(response)
    assert value.startswith(f'{scheme} error="{error}"'), value
    if scheme == "DPoP":
        assert f'algs="{" ".join(DPOP_ALGORITHMS)}"' in value


def assert_no_credentials_challenge(response):
    """RFC 6750 section 3.1: no credentials -> 401 challenge without an error code."""
    assert response.status_code == 401
    assert response.mimetype == "application/json"
    assert "error" not in response.get_json()
    value = challenge(response)
    assert value.startswith("Bearer") and "error=" not in value
    # RFC 9449 section 7.1 / 7.2: the DPoP scheme is offered too, with its algorithms.
    assert f'DPoP algs="{" ".join(DPOP_ALGORITHMS)}"' in value


# ---------------------------------------------------------------------------
# Credential endpoint: request errors (OpenID4VCI 1.0 section 8.3.1.2)
# ---------------------------------------------------------------------------


class TestCredentialRequestErrors:
    def test_valid_request_is_issued(self, issuer):
        response = issuer.credential(request_for())
        assert response.status_code == 200 and response.mimetype == "application/json"
        assert response.get_json()["credentials"] == [{"credential": "c"}]
        assert isinstance(response.get_json()["notification_id"], str)

    @pytest.mark.parametrize(
        "body",
        [
            {"proofs": {"jwt": ["x"]}},
            {"credential_indentifier": PID, "proofs": {"jwt": ["x"]}},
            # Section 8.2: "When this parameter is used, the credential_configuration_id MUST NOT be present."
            {"credential_identifier": PID, "credential_configuration_id": PID, "proofs": {"jwt": ["x"]}},
            {"credential_configuration_id": [PID], "proofs": {"jwt": ["x"]}},
            {"credential_configuration_id": "", "proofs": {"jwt": ["x"]}},
            {"credential_identifier": {"id": PID}, "proofs": {"jwt": ["x"]}},
        ],
        ids=["no-id", "misspelled-id", "both-ids", "id-not-a-string", "empty-id", "identifier-not-a-string"],
    )
    def test_invalid_credential_request(self, issuer, body):
        assert_error(issuer.credential(body), 400, "invalid_credential_request")
        issuer.issue.assert_not_called()

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"data": "not json", "content_type": "application/json"},
            {"data": "[1, 2]", "content_type": "application/json"},
            # Section 10: an encrypted request the issuer cannot decrypt.
            {"data": "a.b.c", "content_type": "application/jwt"},
        ],
        ids=["not-json", "not-an-object", "undecryptable-jwe"],
    )
    def test_unreadable_body_is_invalid_credential_request(self, issuer, kwargs):
        assert_error(issuer.post("/credential", **kwargs), 400, "invalid_credential_request")

    def test_unknown_credential_configuration(self, issuer):
        assert_error(issuer.credential(request_for(configuration_id="org.example.unknown")), 400, "unknown_credential_configuration")

    def test_unknown_credential_identifier(self, issuer):
        body = {"credential_identifier": "org.example.unknown", "proofs": {"jwt": [proof_jwt()[0]]}}
        assert_error(issuer.credential(body), 400, "unknown_credential_identifier")

    def test_known_credential_identifier_is_issued(self, issuer):
        body = {"credential_identifier": PID, "proofs": {"jwt": [proof_jwt()[0]]}}
        assert issuer.credential(body).status_code == 200

    def test_configuration_outside_the_token_is_insufficient_scope(self, issuer):
        # Section 8.3.1.1: an access token that does not enable issuance of the
        # requested credential -> RFC 6750 section 3.1 insufficient_scope (403).
        response = issuer.credential(request_for(configuration_id=MDL))
        assert_token_error(response, "insufficient_scope", "Bearer", status=403)
        issuer.issue.assert_not_called()

    @pytest.mark.parametrize(
        "proof_fields",
        [
            {},
            {"proof": {"proof_type": "jwt"}},
            {"proof": "eyJ..."},
            {"proofs": ["eyJ..."]},
            {"proofs": {}},
            {"proofs": {"jwt": []}},
            {"proofs": {"jwt": "eyJ..."}},
            {"proofs": {"cwt": ["x"]}},
            # Section 8.2: "contains exactly one parameter named as the proof type".
            {"proofs": {"jwt": ["x"], "attestation": ["y"]}},
            {"proof": {"proof_type": "jwt", "jwt": "x"}, "proofs": {"jwt": ["x"]}},
        ],
        ids=[
            "missing", "single-proof-without-jwt", "proof-not-an-object", "proofs-not-an-object", "proofs-empty",
            "proofs-empty-list", "proofs-not-a-list", "unsupported-proof-type", "two-proof-types", "proof-and-proofs",
        ],
    )
    def test_malformed_proofs_are_invalid_proof(self, issuer, proof_fields):
        assert_error(issuer.credential({"credential_configuration_id": PID, **proof_fields}), 400, "invalid_proof")
        issuer.issue.assert_not_called()

    def _alg_none_proof(self):
        _, public = p256_jwk()
        claims = {"aud": "https://frontend.test", "iat": int(time.time()), "nonce": c_nonce()}
        return pyjwt.encode(claims, None, algorithm="none", headers={"typ": "openid4vci-proof+jwt", "jwk": public})

    @pytest.mark.parametrize(
        "make_proof",
        [
            lambda self: proof_jwt(typ="JWT")[0],
            lambda self: self._alg_none_proof(),
            # Signed with one key, another key in the jwk header.
            lambda self: proof_jwt(include_jwk=False, header_extra={"jwk": p256_jwk()[1]})[0],
            lambda self: proof_jwt(aud="https://evil.test")[0],
            lambda self: proof_jwt(aud=None)[0],
            lambda self: proof_jwt(iat=int(time.time()) - 2 * ci.PROOF_MAX_AGE_SECONDS)[0],
            lambda self: proof_jwt(iat=int(time.time()) + 3600)[0],
            lambda self: "not-a-jwt",
            # Section 8.3.1.2 (3): a key proof without a c_nonce is invalid_proof, not invalid_nonce.
            lambda self: proof_jwt(nonce=None)[0],
        ],
        ids=["wrong-typ", "alg-none", "bad-signature", "wrong-aud", "no-aud", "too-old", "issued-in-future", "malformed", "no-c_nonce"],
    )
    def test_bad_proof_is_invalid_proof(self, issuer, make_proof):
        # assert_error also checks the error_description character set (library
        # messages such as 'missing the "aud" claim' are cleaned).
        assert_error(issuer.credential(request_for(make_proof(self))), 400, "invalid_proof")
        issuer.issue.assert_not_called()

    def test_invalid_c_nonce_is_invalid_nonce(self, issuer):
        assert_error(issuer.credential(request_for(proof_jwt(nonce="not-a-c_nonce")[0])), 400, "invalid_nonce")

    def test_expired_c_nonce_is_invalid_nonce(self, issuer):
        now = int(time.time())
        claims = {"iss": SERVICE_URL, "jti": "j1", "iat": now - 7200, "exp": now - 3600, "aud": [f"{SERVICE_URL}/credential"]}
        stale = ci.encrypt_jwe(claims, jwk.JWK.from_pem(nonce_key_pem()), alg="RSA-OAEP", enc="A256GCM")
        body = assert_error(issuer.credential(request_for(proof_jwt(nonce=stale)[0])), 400, "invalid_nonce")
        assert "expired" in body["error_description"]

    def test_reused_c_nonce_is_invalid_nonce(self, issuer):
        nonce = c_nonce()
        assert issuer.credential(request_for(proof_jwt(nonce=nonce)[0])).status_code == 200
        body = assert_error(issuer.credential(request_for(proof_jwt(nonce=nonce)[0])), 400, "invalid_nonce")
        assert "already been used" in body["error_description"]

    def test_too_many_proofs_is_invalid_credential_request(self, issuer):
        # Section 12.2.4: batch_size is the maximum array size of the proofs parameter.
        proofs = [proof_jwt()[0] for _ in range(BATCH_SIZE + 1)]
        assert_error(issuer.credential(request_for(*proofs)), 400, "invalid_credential_request")
        issuer.issue.assert_not_called()

    def test_proofs_up_to_the_batch_size_are_issued(self, issuer):
        nonce = c_nonce()
        proofs = [proof_jwt(nonce=nonce)[0] for _ in range(BATCH_SIZE)]
        assert issuer.credential(request_for(*proofs)).status_code == 200

    def test_issuance_failure_is_credential_request_denied(self, issuer):
        issuer.issue.side_effect = RuntimeError("signing failed")
        assert_error(issuer.credential(request_for()), 400, "credential_request_denied")


def _ec_public_jwk(**extra):
    return {**p256_jwk()[1], **extra}


@pytest.fixture
def app_context():
    app = Flask(__name__)
    with app.app_context():
        yield


class TestCredentialResponseEncryptionErrors:
    """Section 8.2 credential_response_encryption; errors are never encrypted (8.3.1.2)."""

    @pytest.mark.parametrize(
        "encryption",
        [
            "ECDH-ES",
            {"enc": "A256GCM", "alg": "ECDH-ES"},
            {"jwk": _ec_public_jwk(), "alg": "ECDH-ES"},
            {"jwk": _ec_public_jwk(), "alg": "ECDH-ES", "enc": "A1024GCM"},
            {"jwk": _ec_public_jwk(), "alg": "dir", "enc": "A256GCM"},
            {"jwk": _ec_public_jwk(), "enc": "A256GCM"},
            {"jwk": {**_ec_public_jwk(), "d": "private"}, "alg": "ECDH-ES", "enc": "A256GCM"},
            {"jwk": {"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}, "alg": "ECDH-ES", "enc": "A256GCM"},
        ],
        ids=["not-an-object", "no-jwk", "no-enc", "unsupported-enc", "unsupported-alg", "no-alg", "private-jwk", "invalid-key"],
    )
    def test_invalid_encryption_parameters(self, issuer, encryption):
        response = issuer.credential(request_for(credential_response_encryption=encryption))
        assert_error(response, 400, "invalid_encryption_parameters")
        issuer.issue.assert_not_called()

    def test_valid_encryption_gives_a_jwt_response(self, issuer):
        encryption = {"jwk": _ec_public_jwk(), "alg": "ECDH-ES", "enc": "A256GCM"}
        response = issuer.credential(request_for(credential_response_encryption=encryption))
        assert response.status_code == 200 and response.mimetype == "application/jwt"

    def test_encryption_failure_code(self, app_context):
        # Section 8.3.1.2: the code for unusable encryption parameters is invalid_encryption_parameters.
        response = oidc_routes.encrypt_response({"credential_response_encryption": {"jwk": {"kty": "EC"}, "enc": "A256GCM"}}, {})
        assert_error(response, 400, "invalid_encryption_parameters")


# ---------------------------------------------------------------------------
# Access token errors (RFC 6750 section 3, RFC 9449 section 7)
# ---------------------------------------------------------------------------

#: Protected endpoints and a request that would otherwise be accepted.
PROTECTED = [
    ("/credential", lambda: request_for()),
    ("/deferred_credential", lambda: {"transaction_id": str(uuid.uuid4())}),
    ("/notification", lambda: {"notification_id": "n", "event": "credential_accepted"}),
]


def p256_public(key):
    return json.loads(pyjwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))


def _dpop_proof(key, token=TOKEN, htu=f"{SERVICE_URL}/credential", htm="POST", **extra):
    claims = {
        "jti": str(uuid.uuid4()),
        "htm": htm,
        "htu": htu,
        "iat": int(time.time()),
        "ath": base64.urlsafe_b64encode(hashlib.sha256(token.encode()).digest()).rstrip(b"=").decode(),
        **extra,
    }
    public = json.loads(pyjwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    return pyjwt.encode(claims, key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": public})


@pytest.mark.parametrize("path, make_body", PROTECTED, ids=[p for p, _ in PROTECTED])
class TestAccessTokenErrors:
    def test_no_authorization_header(self, issuer, path, make_body):
        assert_no_credentials_challenge(issuer.post(path, json=make_body(), token=None))

    def test_unsupported_scheme(self, issuer, path, make_body):
        assert_no_credentials_challenge(issuer.post(path, json=make_body(), scheme="Basic"))

    @pytest.mark.parametrize("scheme", ["Bearer", "DPoP"])
    def test_empty_token(self, issuer, path, make_body, scheme):
        assert_token_error(issuer.post(path, json=make_body(), token="", scheme=scheme), "invalid_token", scheme)

    @pytest.mark.parametrize("scheme", ["Bearer", "DPoP"])
    def test_inactive_token(self, issuer, path, make_body, scheme):
        # The challenge uses the scheme the token was sent with.
        issuer.token_is(active=False)
        assert_token_error(issuer.post(path, json=make_body(), scheme=scheme), "invalid_token", scheme)
        issuer.issue.assert_not_called()

    def test_active_token_without_subject(self, issuer, path, make_body):
        issuer.token_is(active=True)
        assert_token_error(issuer.post(path, json=make_body()), "invalid_token", "Bearer")

    def test_dpop_bound_token_sent_as_bearer(self, issuer, path, make_body):
        # RFC 9449 section 7.2: MUST reject a DPoP-bound token received as a bearer token (per RFC 6750).
        key = ec.generate_private_key(ec.SECP256R1())
        issuer.token_is(active=True, username=SESSION, cnf={"jkt": jwk_thumbprint(p256_public(key))})
        response = issuer.post(path, json=make_body(), headers={"DPoP": _dpop_proof(key, htu=SERVICE_URL + path)})
        assert_token_error(response, "invalid_token", "DPoP")
        issuer.issue.assert_not_called()

    @pytest.mark.parametrize("variant", ["missing", "other-key", "wrong-htm", "wrong-htu", "wrong-ath", "stale"])
    def test_invalid_dpop_proof(self, issuer, path, make_body, variant):
        # RFC 9449 section 7.1: invalid_dpop_proof with a DPoP challenge.
        key = ec.generate_private_key(ec.SECP256R1())
        issuer.token_is(active=True, username=SESSION, cnf={"jkt": jwk_thumbprint(p256_public(key))})
        htu = SERVICE_URL + path
        proofs = {
            "missing": None,
            "other-key": _dpop_proof(ec.generate_private_key(ec.SECP256R1()), htu=htu),
            "wrong-htm": _dpop_proof(key, htu=htu, htm="GET"),
            "wrong-htu": _dpop_proof(key, htu=f"{SERVICE_URL}/other"),
            "wrong-ath": _dpop_proof(key, htu=htu, token="other-token"),
            "stale": _dpop_proof(key, htu=htu, iat=int(time.time()) - 3600),
        }
        headers = {"DPoP": proofs[variant]} if proofs[variant] else {}
        response = issuer.post(path, json=make_body(), scheme="DPoP", headers=headers)
        assert_token_error(response, "invalid_dpop_proof", "DPoP")
        issuer.issue.assert_not_called()


class TestAccessTokenSuccessWithDpop:
    def test_valid_dpop_proof_is_accepted(self, issuer):
        key = ec.generate_private_key(ec.SECP256R1())
        issuer.token_is(active=True, username=SESSION, cnf={"jkt": jwk_thumbprint(p256_public(key))})
        response = issuer.credential(request_for(), scheme="DPoP", headers={"DPoP": _dpop_proof(key)})
        assert response.status_code == 200

    def test_session_gone_is_invalid_token(self, issuer):
        issuer.token_is(active=True, username="5c7d0e1f-0000-4000-8000-000000000000")
        assert_token_error(issuer.credential(request_for()), "invalid_token", "Bearer")


# ---------------------------------------------------------------------------
# Nonce endpoint (section 7)
# ---------------------------------------------------------------------------


class TestNonceEndpoint:
    def test_nonce_response(self, issuer):
        # Section 7.1: not a protected resource (no access token needed).
        response = issuer.client.post("/nonce")
        assert response.status_code == 200 and response.mimetype == "application/json"
        assert isinstance(response.get_json()["c_nonce"], str)
        # Section 7.2: "MUST make the response uncacheable ... Cache-Control ... no-store".
        assert "no-store" in response.headers["Cache-Control"]

    def test_nonce_is_accepted_in_a_proof(self, issuer):
        nonce = issuer.client.post("/nonce").get_json()["c_nonce"]
        assert issuer.credential(request_for(proof_jwt(nonce=nonce)[0])).status_code == 200

    @pytest.mark.parametrize("method", ["get", "put", "delete"])
    def test_other_methods_not_allowed(self, issuer, method):
        # Section 7.1: the nonce request is an HTTP POST.
        response = getattr(issuer.client, method)("/nonce")
        assert response.status_code == 405
        assert "POST" in response.headers["Allow"]


# ---------------------------------------------------------------------------
# Deferred Credential endpoint (section 9)
# ---------------------------------------------------------------------------


class TestDeferredCredentialErrors:
    def _start(self, issuer, session=SESSION):
        issuer.token_is(active=True, username=session)
        response = issuer.credential(request_for(configuration_id=DEFERRED))
        assert response.status_code == 202 and response.mimetype == "application/json"
        # Section 8.3: notification_id only accompanies issued credentials.
        assert set(response.get_json()) == {"transaction_id", "interval"}
        return response.get_json()["transaction_id"]

    def test_pending_is_202_with_interval(self, issuer):
        transaction_id = self._start(issuer)
        issuer.issue.return_value = {"error": "Pending"}
        response = issuer.post("/deferred_credential", json={"transaction_id": transaction_id})
        # Section 9.2: 202 with interval and the same transaction_id.
        assert response.status_code == 202 and response.mimetype == "application/json"
        body = response.get_json()
        assert body["transaction_id"] == transaction_id
        assert isinstance(body["interval"], int) and body["interval"] > 0
        assert "error" not in body

    def test_issued_then_transaction_id_is_invalidated(self, issuer):
        transaction_id = self._start(issuer)
        response = issuer.post("/deferred_credential", json={"transaction_id": transaction_id})
        assert response.status_code == 200 and response.get_json()["credentials"] == [{"credential": "c"}]
        # Section 9.1: "MUST invalidate the transaction_id after the Credential ... has been obtained";
        # section 9.3: a used transaction_id is invalid_transaction_id.
        again = issuer.post("/deferred_credential", json={"transaction_id": transaction_id})
        assert_error(again, 400, "invalid_transaction_id")

    @pytest.mark.parametrize("transaction_id", [str(uuid.uuid4()), "not-a-uuid"], ids=["unknown", "not-issued-format"])
    def test_unknown_transaction_id(self, issuer, transaction_id):
        response = issuer.post("/deferred_credential", json={"transaction_id": transaction_id})
        assert_error(response, 400, "invalid_transaction_id")

    def test_transaction_of_another_session(self, issuer):
        transaction_id = self._start(issuer, session=OTHER_SESSION)
        issuer.token_is(active=True, username=SESSION)
        assert_error(issuer.post("/deferred_credential", json={"transaction_id": transaction_id}), 400, "invalid_transaction_id")

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"json": {}},
            {"json": {"transaction_id": 42}},
            {"data": "not json", "content_type": "application/json"},
            {"data": "a.b.c", "content_type": "application/jwt"},
        ],
        ids=["missing", "not-a-string", "not-json", "undecryptable-jwe"],
    )
    def test_malformed_request(self, issuer, kwargs):
        # Section 9.3 -> 8.3.1.2: missing / malformed parameter.
        assert_error(issuer.post("/deferred_credential", **kwargs), 400, "invalid_credential_request")

    def test_invalid_encryption_parameters(self, issuer):
        transaction_id = self._start(issuer)
        body = {"transaction_id": transaction_id, "credential_response_encryption": {"jwk": _ec_public_jwk(), "enc": "nope"}}
        assert_error(issuer.post("/deferred_credential", json=body), 400, "invalid_encryption_parameters")

    def test_issuer_can_no_longer_issue(self, issuer):
        # Section 9.3: credential_request_denied when the issuer can no longer issue.
        transaction_id = self._start(issuer)
        issuer.issue.side_effect = RuntimeError("gone")
        assert_error(issuer.post("/deferred_credential", json={"transaction_id": transaction_id}), 400, "credential_request_denied")


# ---------------------------------------------------------------------------
# Notification endpoint (section 11)
# ---------------------------------------------------------------------------


class TestNotificationErrors:
    @pytest.fixture
    def notification_id(self, issuer):
        response = issuer.credential(request_for())
        return response.get_json()["notification_id"]

    @pytest.mark.parametrize("event", ["credential_accepted", "credential_failure", "credential_deleted"])
    def test_success_is_204(self, issuer, notification_id, event):
        body = {"notification_id": notification_id, "event": event, "event_description": "ok"}
        response = issuer.post("/notification", json=body)
        # Section 11.2: 2xx, 204 (No Content) RECOMMENDED.
        assert response.status_code == 204 and response.get_data() == b""
        # Section 11: notifications are idempotent.
        assert issuer.post("/notification", json=body).status_code == 204

    def test_unknown_notification_id(self, issuer, notification_id):
        body = {"notification_id": "unknown", "event": "credential_accepted"}
        assert_error(issuer.post("/notification", json=body), 400, "invalid_notification_id")

    def test_notification_id_of_another_session(self, issuer, notification_id):
        issuer.token_is(active=True, username=OTHER_SESSION)
        body = {"notification_id": notification_id, "event": "credential_accepted"}
        assert_error(issuer.post("/notification", json=body), 400, "invalid_notification_id")

    @pytest.mark.parametrize(
        "make_kwargs",
        [
            lambda n: {"json": {"event": "credential_accepted"}},
            lambda n: {"json": {"notification_id": [n], "event": "credential_accepted"}},
            lambda n: {"json": {"notification_id": n}},
            lambda n: {"json": {"notification_id": n, "event": "credential_stored"}},
            lambda n: {"json": {"notification_id": n, "event": "CREDENTIAL_ACCEPTED"}},
            lambda n: {"data": "not json", "content_type": "application/json"},
            lambda n: {"json": [n]},
        ],
        ids=["no-id", "id-not-a-string", "no-event", "unknown-event", "event-wrong-case", "not-json", "not-an-object"],
    )
    def test_malformed_request(self, issuer, notification_id, make_kwargs):
        # Section 11.1: notification_id and event (case-sensitive, one of three values) are REQUIRED.
        response = issuer.post("/notification", **make_kwargs(notification_id))
        assert_error(response, 400, "invalid_notification_request")


# ---------------------------------------------------------------------------
# Credential Offer (section 4) and other wallet-facing GETs
# ---------------------------------------------------------------------------


class TestCredentialOfferErrors:
    def test_offer_by_reference_is_single_use_and_no_store(self, issuer):
        from app.repositories.offer_store import credential_offer_references

        offer = {"credential_issuer": "https://frontend.test", "credential_configuration_ids": [PID]}
        with patch.dict(credential_offer_references, {"ref-1": {"credential_offer": offer, "expires": datetime.now() + timedelta(minutes=5)}}):
            response = issuer.client.get("/credential-offer-reference/ref-1")
            assert response.status_code == 200 and response.mimetype == "application/json"
            assert response.get_json() == offer
            assert "no-store" in response.headers["Cache-Control"]
            assert_error(issuer.client.get("/credential-offer-reference/ref-1"), 404, "not_found")

    def test_unknown_or_expired_offer_reference(self, issuer):
        from app.repositories.offer_store import credential_offer_references

        assert_error(issuer.client.get("/credential-offer-reference/unknown"), 404, "not_found")
        expired = {"credential_offer": {}, "expires": datetime.now() - timedelta(seconds=1)}
        with patch.dict(credential_offer_references, {"old": expired}):
            assert_error(issuer.client.get("/credential-offer-reference/old"), 404, "not_found")

    def test_offer_without_configuration_id(self, issuer):
        assert_error(issuer.client.get("/credential_offer_create"), 400, "invalid_request")
