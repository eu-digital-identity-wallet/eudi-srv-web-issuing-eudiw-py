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
"""Tests for x5c chain trust: trust validator first, local trusted CAs as fallback."""

import base64
import datetime
from unittest.mock import MagicMock, patch

import jwt
import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.core.errors import CertificateVerificationError
from app.services import trust
from config_helpers import patch_configuration
from pki_helpers import NOW, ca_entry, make_cert, x5c

VALIDATOR_URL = "https://trust-validator.test/trust"

_cert = make_cert
_x5c = x5c
_ca_entry = ca_entry


@pytest.fixture
def pki():
    """Root CA -> intermediate CA -> leaf, plus an unrelated root and leaf."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    inter_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    other_key = ec.generate_private_key(ec.SECP256R1())

    root = _cert("Root CA", "Root CA", root_key.public_key(), root_key, ca=True)
    inter = _cert("Intermediate CA", "Root CA", inter_key.public_key(), root_key, ca=True)
    leaf = _cert("Leaf", "Intermediate CA", leaf_key.public_key(), inter_key, ca=False)
    direct_leaf = _cert("Direct Leaf", "Root CA", leaf_key.public_key(), root_key, ca=False)
    untrusted_leaf = _cert("Untrusted Leaf", "Other Root", leaf_key.public_key(), other_key, ca=False)
    # Claims to be issued by "Root CA" but is signed with another key.
    forged_leaf = _cert("Forged Leaf", "Root CA", leaf_key.public_key(), other_key, ca=False)

    return {
        "root": root,
        "inter": inter,
        "leaf": leaf,
        "direct_leaf": direct_leaf,
        "untrusted_leaf": untrusted_leaf,
        "forged_leaf": forged_leaf,
        "leaf_key": leaf_key,
        "root_key": root_key,
    }


@pytest.fixture
def trusted_root(pki):
    """Local trusted CA store containing only the root CA."""
    with patch.dict("app.core.state.trusted_CAs", {pki["root"].subject: _ca_entry(pki["root"])}, clear=True):
        yield


@pytest.fixture
def empty_store():
    with patch.dict("app.core.state.trusted_CAs", {}, clear=True):
        yield


def _validator_config(enabled):
    return {"trust_validator": {"enabled": enabled, "url": VALIDATOR_URL}}


class TestLocalTrustedCAs:
    """Validator disabled: only the local trusted CA folder is used."""

    @pytest.fixture(autouse=True)
    def _validator_disabled(self):
        with patch_configuration(_validator_config(False)):
            yield

    def test_leaf_directly_issued_by_trusted_root(self, pki, trusted_root):
        cert = trust.verify_x5c_chain(_x5c(pki["direct_leaf"]), "ctx")
        assert cert.subject == pki["direct_leaf"].subject

    def test_leaf_via_intermediate_in_chain(self, pki, trusted_root):
        cert = trust.verify_x5c_chain(_x5c(pki["leaf"], pki["inter"]), "ctx")
        assert cert.subject == pki["leaf"].subject

    def test_missing_intermediate_rejected(self, pki, trusted_root):
        with pytest.raises(CertificateVerificationError, match="not issued by a trusted CA"):
            trust.verify_x5c_chain(_x5c(pki["leaf"]), "ctx")

    def test_untrusted_root_rejected(self, pki, trusted_root):
        with pytest.raises(CertificateVerificationError, match="not issued by a trusted CA"):
            trust.verify_x5c_chain(_x5c(pki["untrusted_leaf"]), "ctx")

    def test_forged_signature_rejected(self, pki, trusted_root):
        with pytest.raises(CertificateVerificationError, match="signature invalid"):
            trust.verify_x5c_chain(_x5c(pki["forged_leaf"]), "ctx")

    def test_expired_leaf_rejected(self, pki, trusted_root):
        expired = _cert(
            "Expired",
            "Root CA",
            pki["leaf_key"].public_key(),
            pki["root_key"],
            ca=False,
            not_before=NOW - datetime.timedelta(days=10),
            not_after=NOW - datetime.timedelta(days=1),
        )
        with pytest.raises(CertificateVerificationError, match="expired"):
            trust.verify_x5c_chain(_x5c(expired), "ctx")

    def test_not_yet_valid_leaf_rejected(self, pki, trusted_root):
        future = _cert(
            "Future",
            "Root CA",
            pki["leaf_key"].public_key(),
            pki["root_key"],
            ca=False,
            not_before=NOW + datetime.timedelta(days=1),
        )
        with pytest.raises(CertificateVerificationError, match="not yet valid"):
            trust.verify_x5c_chain(_x5c(future), "ctx")

    def test_empty_store_rejected(self, pki, empty_store):
        with pytest.raises(CertificateVerificationError, match="No trusted CAs loaded"):
            trust.verify_x5c_chain(_x5c(pki["direct_leaf"]), "ctx")

    def test_validator_not_called_when_disabled(self, pki, trusted_root):
        with patch("app.services.trust.call_trust_validator") as validator:
            trust.verify_x5c_chain(_x5c(pki["direct_leaf"]), "ctx")
        validator.assert_not_called()

    def test_validator_not_configured_uses_local(self, pki, trusted_root):
        with patch_configuration({}), patch("app.services.trust.call_trust_validator") as validator:
            cert = trust.verify_x5c_chain(_x5c(pki["direct_leaf"]), "ctx")
        validator.assert_not_called()
        assert cert.subject == pki["direct_leaf"].subject

    def test_garbage_certificate_rejected(self, trusted_root):
        with pytest.raises(CertificateVerificationError, match="Invalid certificate in x5c chain"):
            trust.verify_x5c_chain([base64.b64encode(b"not a certificate").decode()], "ctx")

    def test_single_certificate_helper(self, pki, trusted_root):
        der = pki["direct_leaf"].public_bytes(serialization.Encoding.DER)
        assert trust.verify_certificate_against_trusted_CA(der).subject == pki["direct_leaf"].subject


class TestTrustValidatorFirst:
    """Validator enabled: it is asked first; local CAs are the fallback when it fails."""

    @pytest.fixture(autouse=True)
    def _validator_enabled(self):
        with patch_configuration(_validator_config(True)):
            yield

    def test_validator_trusted_skips_local_check(self, pki, empty_store):
        with patch("app.services.trust.call_trust_validator", return_value=True) as validator:
            cert = trust.verify_x5c_chain(_x5c(pki["untrusted_leaf"]), "WalletProviderAttestation")
        validator.assert_called_once_with(
            url=VALIDATOR_URL,
            chain=_x5c(pki["untrusted_leaf"]),
            verification_context="WalletProviderAttestation",
            use_case=None,
        )
        assert cert.subject == pki["untrusted_leaf"].subject

    def test_validator_rejection_is_final(self, pki, trusted_root):
        """trusted: false is an answer, not an outage: the local CAs are not asked."""
        with patch("app.services.trust.call_trust_validator", return_value=False), patch(
            "app.services.trust.verify_chain_against_trusted_CAs"
        ) as local:
            with pytest.raises(CertificateVerificationError, match="rejected by the trust validator"):
                trust.verify_x5c_chain(_x5c(pki["direct_leaf"]), "ctx")
        local.assert_not_called()

    def test_validator_rejects_and_local_rejects(self, pki, trusted_root):
        with patch("app.services.trust.call_trust_validator", return_value=False):
            with pytest.raises(CertificateVerificationError):
                trust.verify_x5c_chain(_x5c(pki["untrusted_leaf"]), "ctx")

    def test_validator_error_falls_back_to_local(self, pki, trusted_root):
        with patch("app.services.trust.call_trust_validator", side_effect=ConnectionError("down")):
            cert = trust.verify_x5c_chain(_x5c(pki["leaf"], pki["inter"]), "ctx")
        assert cert.subject == pki["leaf"].subject

    def test_use_case_forwarded_to_validator(self, pki, empty_store):
        with patch("app.services.trust.call_trust_validator", return_value=True) as validator:
            trust.verify_x5c_chain(_x5c(pki["direct_leaf"]), "Custom", use_case="uc-1")
        assert validator.call_args.kwargs["use_case"] == "uc-1"

    def test_validator_bad_request_falls_back_to_local(self, pki, trusted_root, caplog):
        """A 400 (e.g. missing useCase) is logged with its description; local CAs decide."""
        with patch("app.services.trust.requests.post") as post:
            post.return_value.ok = False
            post.return_value.status_code = 400
            post.return_value.json.return_value = {"description": "useCase is required"}
            post.return_value.raise_for_status.side_effect = requests.HTTPError("400")
            cert = trust.verify_x5c_chain(_x5c(pki["direct_leaf"]), "Custom")
        assert cert.subject == pki["direct_leaf"].subject
        assert "useCase is required" in caplog.text

    def test_call_trust_validator_http(self, pki):
        with patch("app.services.trust.requests.post") as post:
            post.return_value.json.return_value = {"trusted": True}
            assert trust.call_trust_validator(VALIDATOR_URL, ["c"], "PID") is True
        post.assert_called_once_with(
            VALIDATOR_URL,
            json={"chain": ["c"], "verificationContext": "PID"},  # no useCase when unset
            headers={"accept": "application/json", "Content-Type": "application/json"},
            timeout=10,
        )


class TestVerifyJwtWithX5c:
    """End-to-end JWT verification with a real signed token."""

    @pytest.fixture(autouse=True)
    def _validator_disabled(self):
        with patch_configuration(_validator_config(False)):
            yield

    def _token(self, pki, claims, chain):
        return jwt.encode(claims, pki["leaf_key"], algorithm="ES256", headers={"x5c": _x5c(*chain)})

    def test_valid_token(self, pki, trusted_root):
        token = self._token(pki, {"sub": "x"}, [pki["leaf"], pki["inter"]])
        assert trust.verify_jwt_with_x5c(token) == {"sub": "x"}

    def test_untrusted_chain(self, pki, trusted_root):
        token = self._token(pki, {"sub": "x"}, [pki["untrusted_leaf"]])
        with pytest.raises(CertificateVerificationError):
            trust.verify_jwt_with_x5c(token)

    def test_signature_from_other_key(self, pki, trusted_root):
        other = ec.generate_private_key(ec.SECP256R1())
        token = jwt.encode({"sub": "x"}, other, algorithm="ES256", headers={"x5c": _x5c(pki["direct_leaf"])})
        with pytest.raises(jwt.InvalidSignatureError):
            trust.verify_jwt_with_x5c(token)

    def test_expired_token(self, pki, trusted_root):
        token = self._token(pki, {"exp": int(NOW.timestamp()) - 10 * trust.JWT_CLOCK_LEEWAY_SECONDS}, [pki["direct_leaf"]])
        with pytest.raises(jwt.ExpiredSignatureError):
            trust.verify_jwt_with_x5c(token)

    def test_small_clock_skew_tolerated(self, pki, trusted_root):
        """A key attestation minted by a wallet provider whose clock is a bit ahead (#166)."""
        import time

        token = self._token(pki, {"sub": "x", "iat": int(time.time()) + 30}, [pki["direct_leaf"]])
        assert trust.verify_jwt_with_x5c(token)["sub"] == "x"

    def test_large_clock_skew_rejected(self, pki, trusted_root):
        import time

        token = self._token(pki, {"iat": int(time.time()) + 10 * trust.JWT_CLOCK_LEEWAY_SECONDS}, [pki["direct_leaf"]])
        with pytest.raises(jwt.ImmatureSignatureError):
            trust.verify_jwt_with_x5c(token)

    def test_expected_typ_from_the_verified_header(self, pki, trusted_root):
        """typ is read from the header verified with the signature (jwt.decode_complete)."""
        def token(typ):
            return jwt.encode({"sub": "x"}, pki["leaf_key"], algorithm="ES256",
                              headers={"x5c": _x5c(pki["leaf"], pki["inter"]), "typ": typ})

        assert trust.verify_jwt_with_x5c(token("key-attestation+jwt"), expected_typ="key-attestation+jwt") == {"sub": "x"}
        with pytest.raises(ValueError, match="typ must be key-attestation\+jwt"):
            trust.verify_jwt_with_x5c(token("JWT"), expected_typ="key-attestation+jwt")

    def test_disallowed_algorithm(self, pki, trusted_root):
        token = self._token(pki, {"sub": "x"}, [pki["direct_leaf"]])
        with pytest.raises(ValueError, match="not allowed"):
            trust.verify_jwt_with_x5c(token, allowed_algorithms=["RS256"])

    def test_missing_x5c(self, pki, trusted_root):
        token = jwt.encode({"sub": "x"}, pki["leaf_key"], algorithm="ES256")
        with pytest.raises(ValueError, match="x5c header not found"):
            trust.verify_jwt_with_x5c(token)

    def test_context_forwarded_to_validator(self, pki, empty_store):
        token = self._token(pki, {"sub": "x"}, [pki["untrusted_leaf"]])
        with patch_configuration(_validator_config(True)), patch(
            "app.services.trust.call_trust_validator", return_value=True
        ) as validator:
            trust.verify_jwt_with_x5c(token, verification_context="MyContext")
        assert validator.call_args.kwargs["verification_context"] == "MyContext"


class TestTrustContext:
    def test_default(self):
        with patch_configuration({"trust_validator": {"enabled": True}}):
            assert trust.trust_context("key_attestation", "Default") == "Default"

    def test_configured(self):
        cfg = {"trust_validator": {"contexts": {"key_attestation": "Custom"}}}
        with patch_configuration(cfg):
            assert trust.trust_context("key_attestation", "Default") == "Custom"


class TestKeyAttestationTrust:
    """Key attestations are verified through verify_x5c_chain with the key_attestation context."""

    @pytest.mark.parametrize(
        "config, expected",
        [
            ({"status_validator": {"enabled": False}}, "WalletProviderAttestation"),
            (
                {"status_validator": {"enabled": False}, "trust_validator": {"contexts": {"key_attestation": "KA"}}},
                "KA",
            ),
        ],
    )
    def test_context(self, config, expected):
        from app.services.credential_issuance import decode_verify_attestation

        claims = {"attested_keys": [], "key_storage_status": {"exp": 4102444800, "status": {"status_list": {"idx": 1, "uri": "u"}}}}

        with patch_configuration(config), patch(
            "app.services.credential_issuance.verify_jwt_with_x5c", return_value=claims
        ) as verify:
            assert decode_verify_attestation("ka.jwt") == claims

        verify.assert_called_once_with(
            jwt_raw="ka.jwt",
            verification_context=expected,
            use_case=None,
            purpose="key_attestation",
            allowed_algorithms=["ES256", "ES384", "ES512"],
            required_claims=("iat", "exp"),
            max_age_seconds=24 * 3600,
            expected_typ="key-attestation+jwt",
        )

    def test_untrusted_attestation_propagates(self, pki, trusted_root):
        from app.services.credential_issuance import decode_verify_attestation

        token = jwt.encode({"attested_keys": []}, pki["leaf_key"], algorithm="ES256", headers={"x5c": _x5c(pki["untrusted_leaf"])})
        with patch_configuration({"trust_validator": {"enabled": False}, "status_validator": {"enabled": False}}):
            with pytest.raises(CertificateVerificationError):
                decode_verify_attestation(token)


class TestCallTrustValidator:
    """Request / response handling against the trust validator OpenAPI contract."""

    def _response(self, status=200, body=None):
        response = MagicMock()
        response.ok = status < 400
        response.status_code = status
        response.json.return_value = body or {}
        if status >= 400:
            response.raise_for_status.side_effect = requests.HTTPError(str(status))
        return response

    def test_use_case_included_when_set(self):
        with patch("app.services.trust.requests.post", return_value=self._response(body={"trusted": True})) as post:
            assert trust.call_trust_validator(VALIDATOR_URL, ["c"], "Custom", use_case="uc") is True
        assert post.call_args.kwargs["json"] == {"chain": ["c"], "verificationContext": "Custom", "useCase": "uc"}

    def test_not_trusted_logs_error(self, caplog):
        body = {"trusted": False, "error": "No trust anchor found"}
        with patch("app.services.trust.requests.post", return_value=self._response(body=body)):
            assert trust.call_trust_validator(VALIDATOR_URL, ["c"], "PID") is False
        assert "No trust anchor found" in caplog.text

    def test_server_error_raises_and_logs_description(self, caplog):
        body = {"description": "No configuration for verification context"}
        with patch("app.services.trust.requests.post", return_value=self._response(500, body)):
            with pytest.raises(requests.HTTPError):
                trust.call_trust_validator(VALIDATOR_URL, ["c"], "QEAA")
        assert "No configuration for verification context" in caplog.text

    def test_unknown_context_warns(self, caplog):
        with patch("app.services.trust.requests.post", return_value=self._response(body={"trusted": True})):
            trust.call_trust_validator(VALIDATOR_URL, ["c"], "WalletUnitAttestation")
        assert "Unknown trust validator verificationContext" in caplog.text

    def test_default_contexts_are_valid(self):
        assert trust.KEY_ATTESTATION_CONTEXT in trust.VERIFICATION_CONTEXTS
        assert trust.CREDENTIAL_OFFER_REQUEST_CONTEXT in trust.VERIFICATION_CONTEXTS

    def test_trust_use_case_from_config(self):
        with patch_configuration({"trust_validator": {"use_cases": {"key_attestation": "uc"}}}):
            assert trust.trust_use_case("key_attestation") == "uc"
            assert trust.trust_use_case("credential_offer_request") is None
