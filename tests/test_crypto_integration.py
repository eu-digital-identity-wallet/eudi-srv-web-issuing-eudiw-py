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
"""End-to-end issuance tests with the real crypto stack (no mocks).

They issue an mdoc (pyMDOC-CBOR / pycose / cbor2 / cwt) and an SD-JWT
(sd-jwt / jwcrypto) with a generated country key, then verify them with the
issuer's own validation code. They guard dependency upgrades of the
CBOR / COSE / JOSE / cryptography libraries.
"""

import base64
import copy
import datetime
from unittest.mock import patch

import cbor2
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.services.formatters import cbor2elems, mdocFormatter, sdjwtFormatter
from app.services.frontend_metadata import _sd_jwt_signing_jwks
from app.services.revocation_status import is_issuer_certificate
from app.services.trust import verify_and_decode_sdjwt
from app.services.vp_validation import validate_certificate
from config_helpers import patch_configuration
from pki_helpers import ca_entry, make_cert
from proof_helpers import proof_config, proof_jwt

DOCTYPE = "eu.europa.ec.eudi.pid.1"
VCT = "urn:eudi:pid:1"


@pytest.fixture(scope="module")
def country_pki(tmp_path_factory):
    """Self-signed country document signer, as PEM key and DER/PEM certificate."""
    key = ec.generate_private_key(ec.SECP256R1())
    cert = make_cert("FC Document Signer", "FC Document Signer", key.public_key(), key, ca=False)
    cert_path = tmp_path_factory.mktemp("pki") / "ds.der"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    return {
        "cert": cert,
        "cert_path": str(cert_path),
        "key_pem": key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
        "cert_der": cert.public_bytes(serialization.Encoding.DER),
    }


@pytest.fixture(scope="module")
def device_key():
    """Holder device key in the issuer's base64url-PEM format."""
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.urlsafe_b64encode(pem).decode()


@pytest.fixture
def issuer_config(country_pki):
    config = {
        "service_url": "https://backend.test",
        "frontend": {"default": "fe", "frontends_config": {"fe": {"url": "https://issuer.test"}}},
        "revocation": {"enabled": False},
        "countries": {
            "FC": {
                "keys": {
                    "_default": {
                        "private_key": country_pki["key_pem"],
                        "private_key_password": None,
                        "certificate": country_pki["cert_der"],
                        "certificate_path": country_pki["cert_path"],
                    }
                }
            }
        },
    }
    with patch_configuration(config):
        yield config


def test_mdoc_issued_and_verified(issuer_config, country_pki, device_key):
    data = {
        DOCTYPE: {
            "family_name": "Doe",
            "given_name": "Jane",
            "birth_date": "1990-01-01",
            "age_over_18": True,
        }
    }
    metadata = {"doctype": DOCTYPE, "issuer_config": {"validity": 30, "namespace": DOCTYPE}}

    encoded = mdocFormatter(data, metadata, "FC", device_key, session_id=None)

    # The issued credential is the bare IssuerSigned structure (OID4VCI mso_mdoc).
    issuer_signed = cbor2.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert set(issuer_signed) == {"nameSpaces", "issuerAuth"}

    # Verify it the way the issuer verifies presented PIDs: wrap it as a document.
    document = {"docType": DOCTYPE, "issuerSigned": issuer_signed}
    with patch.dict("app.core.state.trusted_CAs", {country_pki["cert"].subject: ca_entry(country_pki["cert"])}, clear=True):
        valid, reason = validate_certificate(document)
    assert (valid, reason) == (True, "")

    device_response = base64.urlsafe_b64encode(cbor2.dumps({"documents": [document]})).decode()
    elements = dict(cbor2elems(device_response)[DOCTYPE])
    assert elements["family_name"] == "Doe"
    assert elements["age_over_18"] is True


def test_sdjwt_issued_and_verified(issuer_config, device_key):
    pid = {
        "credential_metadata": {
            "vct": VCT,
            "issuer_config": {"validity": 30},
            "credential_metadata": {"claims": [{"path": ["family_name"]}, {"path": ["given_name"]}]},
        },
        "data": {"claims": {"family_name": "Doe", "given_name": "Jane", "nationalities": ["FC"]}},
        "device_publickey": device_key,
    }

    issuance = sdjwtFormatter(pid, "FC", scope=None, session_id=None)

    issuer_jwt, *disclosures = issuance.rstrip("~").split("~")
    assert len(disclosures) >= 3
    assert jwt.get_unverified_header(issuer_jwt)["typ"] == "dc+sd-jwt"

    # Our own SD-JWT passes the "issued by this issuer" check used by revocation.
    payload = verify_and_decode_sdjwt(issuance, is_issuer_certificate)
    assert payload["vct"] == VCT
    # #161: iss is the frontend (Credential Issuer Identifier), not the backend
    assert payload["iss"] == "https://issuer.test"
    assert payload["exp"] > datetime.datetime.now().timestamp()
    assert "cnf" in payload and payload["cnf"]["jwk"]["kty"] == "EC"
    assert payload["_sd"]  # claims are selectively disclosable


def test_sdjwt_verifies_with_jwt_vc_issuer_metadata(issuer_config, device_key):
    """A verifier resolving the key via /.well-known/jwt-vc-issuer finds it by kid."""
    pid = {
        "credential_metadata": {"vct": VCT, "issuer_config": {"validity": 30}},
        "data": {"claims": {"family_name": "Doe"}},
        "device_publickey": device_key,
    }
    issuer_jwt = sdjwtFormatter(pid, "FC", scope=None, session_id=None).split("~")[0]

    jwks = _sd_jwt_signing_jwks()

    kid = jwt.get_unverified_header(issuer_jwt)["kid"]
    (jwk,) = [k for k in jwks["keys"] if k["kid"] == kid]
    public_key = jwt.PyJWK(jwk).key
    payload = jwt.decode(issuer_jwt, public_key, algorithms=[jwk["alg"]], options={"verify_aud": False})
    # build_frontend_metadata publishes the frontend URL as the issuer.
    assert payload["iss"] == "https://issuer.test"


def test_sdjwt_issuance_does_not_reseed_the_global_prng(issuer_config, device_key):
    """sd_jwt's demo get_jwk() reseeded ``random`` with a constant on every issuance."""
    import random
    from unittest.mock import patch

    pid = {
        "credential_metadata": {
            "vct": VCT,
            "issuer_config": {"validity": 30},
            "credential_metadata": {"claims": [{"path": ["family_name"]}]},
        },
        "data": {"claims": {"family_name": "Doe"}},
        "device_publickey": device_key,
    }
    with patch.object(random, "seed") as seed:
        sdjwtFormatter(pid, "FC", scope=None, session_id=None)
    seed.assert_not_called()


def test_country_key_round_trip(issuer_config):
    from app.services.formatters import KeyData, load_country_signing_key

    key = load_country_signing_key("FC")
    crv, x, y = KeyData(key, "private")
    assert crv == "P-256" and len(x) == 32 and len(y) == 32


@pytest.fixture
def real_credential_metadata(issuer_config):
    """Loads the real credential configurations into the shared state (restored afterwards)."""
    from app.core import state
    from app.services.metadata import setup_metadata

    issuer_config["keys"] = {"credential_encryption_key": b"unused"}

    saved = {name: copy.deepcopy(getattr(state, name)) for name in ("oidc_metadata", "oidc_metadata_clean")}
    with patch("app.services.metadata._build_credential_encryption_metadata", return_value={}):
        setup_metadata()
    yield
    for name, value in saved.items():
        state.replace_contents(getattr(state, name), value)


def test_generate_credentials_end_to_end(issuer_config, country_pki, real_credential_metadata):
    """Proof -> generate_credentials -> in-process credential creation -> signed PID mdoc."""
    from app.core.state import session_manager
    from app.services.credential_issuance import generate_credentials

    issuer_config.update(proof_config())
    proof, _ = proof_jwt()

    session_id = "e2e-session"
    session_manager.add_session(
        session_id=session_id,
        country="FC",
        user_data={
            "family_name": "Doe",
            "given_name": "Jane",
            "birth_date": "1990-01-01",
            "place_of_birth": {"locality": "Utopia"},
            "nationality": ["FC"],
        },
    )
    issuer_config["status_validator"] = {"enabled": False}

    try:
        result = generate_credentials(
            {"credential_configuration_id": "eu.europa.ec.eudi.pid_mdoc", "proof": {"proof_type": "jwt", "jwt": proof}},
            session_id,
        )
    finally:
        session_manager._remove_session_from_all_managers(session_manager._sessions[session_id])

    assert set(result) == {"credentials"} and len(result["credentials"]) == 1
    encoded = result["credentials"][0]["credential"]
    issuer_signed = cbor2.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    document = {"docType": DOCTYPE, "issuerSigned": issuer_signed}
    with patch.dict("app.core.state.trusted_CAs", {country_pki["cert"].subject: ca_entry(country_pki["cert"])}, clear=True):
        assert validate_certificate(document) == (True, "")

    device_response = base64.urlsafe_b64encode(cbor2.dumps({"documents": [document]})).decode()
    elements = dict(cbor2elems(device_response)[DOCTYPE])
    assert elements["family_name"] == "Doe"
    assert elements["issuing_country"] == "FC"
    assert elements["issuing_authority"] == "Test PID issuer"
