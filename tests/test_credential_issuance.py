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
"""Tests for credential issuance logic: proofs, key attestations, validity, JWE."""

import base64
import json
import time
from unittest.mock import MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto import jwe, jwk

from app.services import credential_issuance as ci
from config_helpers import patch_configuration
from proof_helpers import FRONTEND_URL, c_nonce, p256_jwk, proof_config, proof_jwt
from test_did_proofs import did_jwk, did_key

CONFIG_ID = "eu.europa.ec.eudi.pid_mdoc"


@pytest.fixture
def metadata():
    configs = {
        CONFIG_ID: {
            "issuer_config": {"validity": 30},
            "credential_metadata": {
                "credential_reuse_policy": {"options": [{"details": ["once_only"], "batch_size": 2}]}
            },
        }
    }
    with patch.dict("app.services.credential_issuance.oidc_metadata", {"credential_configurations_supported": configs}, clear=True):
        yield configs


@pytest.fixture
def sessions():
    manager = MagicMock()
    manager.add_key_storage_status.return_value = 0
    manager.get_session.return_value = MagicMock(frontend_id="fe1")
    with patch.object(ci, "session_manager", manager):
        yield manager


@pytest.fixture
def issue():
    with patch.object(ci, "issue_credentials_for_session", return_value={"credentials": []}) as mock:
        yield mock


@pytest.fixture
def config():
    with patch_configuration({"status_validator": {"enabled": False}, **proof_config()}) as cfg:
        yield cfg


def _request(proof_jwts):
    return {"credential_configuration_id": CONFIG_ID, "proofs": {"jwt": list(proof_jwts)}}


def _single(token):
    return {"credential_configuration_id": CONFIG_ID, "proof": {"proof_type": "jwt", "jwt": token}}


class TestHolderKeys:
    def test_pk_from_jwk_round_trip(self):
        key, public_jwk = p256_jwk()
        pem = base64.urlsafe_b64decode(ci.pKfromJWK(public_jwk))
        loaded = serialization.load_pem_public_key(pem)
        assert loaded.public_numbers() == key.public_key().public_numbers()

    @pytest.mark.parametrize("curve", [ec.SECP384R1, ec.SECP521R1])
    def test_pk_from_jwk_accepts_p384_and_p521(self, curve):
        # TS3 2.6: ES384 / ES512 attested keys are bound like P-256 ones.
        key = ec.generate_private_key(curve())
        public_jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
        loaded = serialization.load_pem_public_key(base64.urlsafe_b64decode(ci.pKfromJWK(public_jwk)))
        assert loaded.public_numbers() == key.public_key().public_numbers()

    def test_pk_from_jwk_rejects_other_curves(self):
        key = ec.generate_private_key(ec.SECP256K1())
        public_jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
        assert ci.pKfromJWK(public_jwk)["error"] == "invalid_proof"

    def test_holder_key_rejects_other_curves(self):
        key = ec.generate_private_key(ec.SECP256K1())
        with pytest.raises(ci.InvalidProofError, match="P-256, P-384 and P-521"):
            ci._holder_key(json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key())))


@pytest.mark.usefixtures("sessions", "config")
class TestVerifyCNonce:
    def test_valid(self):
        assert ci.verify_c_nonce(c_nonce())["aud"] == ["https://backend.test/credential"]

    @pytest.mark.parametrize("value", [None, "", 42, "not-a-jwe"])
    def test_malformed(self, value):
        with pytest.raises(ci.InvalidProofError):
            ci.verify_c_nonce(value)

    def test_other_key(self, config):
        foreign = jwk.JWK.generate(kty="RSA", size=2048)
        token = ci.encrypt_jwe({"iss": "https://backend.test"}, foreign, alg="RSA-OAEP", enc="A256GCM")
        with pytest.raises(ci.InvalidProofError, match="not valid"):
            ci.verify_c_nonce(token)

    def _encrypt(self, payload):
        return ci.encrypt_jwe(payload, jwk.JWK.from_pem(proof_config()["keys"]["nonce_key"]), alg="RSA-OAEP", enc="A256GCM")

    def test_expired(self):
        token = self._encrypt({"iss": "https://backend.test", "aud": ["https://backend.test/credential"], "exp": int(time.time()) - 1})
        with pytest.raises(ci.InvalidProofError, match="expired"):
            ci.verify_c_nonce(token)

    def test_wrong_audience(self):
        token = self._encrypt({"iss": "https://backend.test", "aud": ["https://other/credential"], "exp": int(time.time()) + 60})
        with pytest.raises(ci.InvalidProofError, match="not issued"):
            ci.verify_c_nonce(token)


@pytest.mark.usefixtures("sessions", "config")
class TestVerifyProofJwt:
    def test_valid(self):
        token, _ = proof_jwt()
        assert ci.verify_proof_jwt(token, "s1")["aud"] == FRONTEND_URL

    def test_trailing_slash_audience(self):
        token, _ = proof_jwt(aud=FRONTEND_URL + "/")
        ci.verify_proof_jwt(token, "s1")

    def test_unknown_frontend_accepts_any_configured(self, sessions):
        sessions.get_session.return_value = None
        token, _ = proof_jwt()
        ci.verify_proof_jwt(token, "s1")

    @pytest.mark.parametrize(
        "kwargs, message",
        [
            ({"typ": "JWT"}, "typ"),
            ({"aud": "https://evil.test"}, "not valid"),
            ({"aud": None}, "not valid"),
            ({"nonce": None}, "no c_nonce"),
            ({"nonce": "forged"}, "c_nonce is not valid"),
            ({"iat": int(time.time()) + 3600}, "not valid"),
            ({"iat": int(time.time()) - 7200}, "too old"),
            ({"include_jwk": False}, "no usable jwk"),
        ],
    )
    def test_rejected(self, kwargs, message):
        token, _ = proof_jwt(**kwargs)
        with pytest.raises(ci.InvalidProofError, match=message):
            ci.verify_proof_jwt(token, "s1")

    @pytest.mark.parametrize("curve, algorithm", [(ec.SECP384R1, "ES384"), (ec.SECP521R1, "ES512")])
    def test_es384_and_es512_accepted(self, curve, algorithm):
        # TS3 2.6: issuers support ES256, ES384 and ES512.
        token, _ = proof_jwt(ec.generate_private_key(curve()), algorithm=algorithm)
        assert ci.verify_proof_jwt(token, "s1")["aud"] == FRONTEND_URL

    def test_algorithm_on_other_curve_rejected(self):
        # TS3 2.6: no other curve-algorithm combinations (ES256 header, P-384 key).
        other_jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(ec.generate_private_key(ec.SECP384R1()).public_key()))
        token, _ = proof_jwt(include_jwk=False, header_extra={"jwk": other_jwk})
        with pytest.raises(ci.InvalidProofError, match="requires a P-256 key"):
            ci.verify_proof_jwt(token, "s1")

    def test_signature_by_other_key(self):
        token, _ = proof_jwt()
        _, other_jwk = p256_jwk()
        header, payload, signature = token.split(".")
        forged_header = json.loads(base64.urlsafe_b64decode(header + "=="))
        forged_header["jwk"] = other_jwk
        forged = base64.urlsafe_b64encode(json.dumps(forged_header).encode()).rstrip(b"=").decode()
        with pytest.raises(ci.InvalidProofError, match="signature"):
            ci.verify_proof_jwt(f"{forged}.{payload}.{signature}", "s1")

    def test_private_jwk_rejected(self):
        key, _ = p256_jwk()
        private_jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key))
        token, _ = proof_jwt(key, include_jwk=False, header_extra={"jwk": private_jwk})
        with pytest.raises(ci.InvalidProofError, match="private"):
            ci.verify_proof_jwt(token, "s1")

    def test_symmetric_alg_rejected(self):
        token = jwt.encode({"aud": FRONTEND_URL}, "secret-secret-secret-secret-secret", algorithm="HS256", headers={"typ": ci.PROOF_JWT_TYP})
        with pytest.raises(ci.InvalidProofError, match="alg"):
            ci.verify_proof_jwt(token, "s1")

    def test_malformed(self):
        with pytest.raises(ci.InvalidProofError, match="malformed"):
            ci.verify_proof_jwt("garbage", "s1")

    def test_nonce_check_can_be_disabled(self, config):
        config["proof_validation"] = {"require_nonce": False}
        token, _ = proof_jwt(nonce=None)
        ci.verify_proof_jwt(token, "s1")


class TestValidity:
    def test_no_constraints(self):
        assert ci.compute_max_credential_exp(None, None) is None

    def test_ceiling_minus_one(self):
        ceiling = int(time.time()) + 1000
        assert ci.compute_max_credential_exp(ceiling + 50, ceiling) == ceiling - 1

    def test_past_ceiling_raises(self):
        with pytest.raises(ci.CredentialValidityError):
            ci.compute_max_credential_exp(int(time.time()) - 1, None)

    def test_custom_validity_within_ceiling(self):
        before = int(time.time())
        result = ci.compute_max_credential_exp(None, None, custom_validity_seconds=60)
        assert before + 60 <= result <= int(time.time()) + 60

    def test_custom_validity_capped_at_ceiling(self):
        ceiling = int(time.time()) + 100
        assert ci.compute_max_credential_exp(ceiling, None, custom_validity_seconds=10_000) == ceiling - 1

    def test_metadata_lookups(self, metadata):
        assert ci.get_batch_size(CONFIG_ID) == 2
        assert ci.get_custom_validity_seconds(CONFIG_ID) == 30 * 86400


class TestGenerateCredentials:
    def test_single_jwt_proof(self, metadata, sessions, issue, config):
        token, key = proof_jwt()
        ci.generate_credentials(_single(token), "s1")

        request = issue.call_args.args[1]
        assert request["credential_configuration_id"] == CONFIG_ID
        [holder] = request["proofs"]
        pem = base64.urlsafe_b64decode(holder["jwt"])
        assert serialization.load_pem_public_key(pem).public_numbers() == key.public_key().public_numbers()
        sessions.update_is_batch_credential.assert_not_called()
        # Custom validity (30 days) becomes the expiry ceiling.
        assert sessions.update_max_credential_exp.call_args.kwargs["max_credential_exp"] > time.time() + 29 * 86400

    def test_undecodable_single_jwt(self, metadata, sessions, issue, config):
        result = ci.generate_credentials(_single("garbage"), "s1")
        assert result["error"] == "invalid_proof" and not issue.called

    def test_batch_over_batch_size_rejected(self, metadata, sessions, issue, config):
        result = ci.generate_credentials(_request([proof_jwt()[0] for _ in range(3)]), "s1")

        assert result["error"] == "invalid_credential_request" and not issue.called

    def test_batch_within_batch_size(self, metadata, sessions, issue, config):
        ci.generate_credentials(_request([proof_jwt()[0] for _ in range(2)]), "s1")

        assert len(issue.call_args.args[1]["proofs"]) == 2
        sessions.update_is_batch_credential.assert_called_once_with(session_id="s1", is_batch_credential=True)

    def test_invalid_jwt_in_batch_rejects_request(self, metadata, sessions, issue, config):
        result = ci.generate_credentials(_request(["not-a-jwt", proof_jwt()[0]]), "s1")
        assert result["error"] == "invalid_proof" and not issue.called

    def test_wrong_audience_in_batch_rejects_request(self, metadata, sessions, issue, config):
        result = ci.generate_credentials(_request([proof_jwt()[0], proof_jwt(aud="https://evil.test")[0]]), "s1")
        assert result["error"] == "invalid_proof" and not issue.called

    def test_batch_jwt_without_jwk_is_invalid_proof(self, metadata, sessions, issue, config):
        token, _ = proof_jwt(include_jwk=False)
        result = ci.generate_credentials(_request([token]), "s1")
        assert result["error"] == "invalid_proof" and not issue.called

    @pytest.mark.parametrize("request_body", [{"proofs": {"cwt": ["x"]}}, {"proof": {"proof_type": "cwt"}}, {"proofs": {"jwt": []}}])
    def test_unsupported_or_empty_proofs(self, metadata, sessions, issue, config, request_body):
        result = ci.generate_credentials({"credential_configuration_id": CONFIG_ID, **request_body}, "s1")
        assert result["error"] == "invalid_proof" and not issue.called

    def test_no_proof(self, metadata, sessions, issue, config):
        result = ci.generate_credentials({"credential_configuration_id": CONFIG_ID}, "s1")
        assert result == {"error": "invalid_proof", "error_description": "No valid proof"}

    def _attestation_claims(self, exp, nonce=True):
        key_a, jwk_a = p256_jwk()
        _, jwk_b = p256_jwk()
        claims = {
            "attested_keys": [jwk_a, jwk_b],
            "key_storage_status": {"exp": exp, "status": {"status_list": {"idx": 7, "uri": "u"}}},
        }
        if nonce:
            claims["nonce"] = c_nonce()
        return claims, key_a

    @pytest.mark.parametrize("shape", ["proofs", "single", "jwt_header"])
    def test_key_attestation_registers_keys(self, metadata, sessions, issue, config, shape):
        exp = int(time.time()) + 3600
        claims, attested_key = self._attestation_claims(exp)
        if shape == "proofs":
            request = {"credential_configuration_id": CONFIG_ID, "proofs": {"attestation": ["ka.jwt"]}}
        elif shape == "single":
            request = {"credential_configuration_id": CONFIG_ID, "proof": {"proof_type": "attestation", "attestation": "ka.jwt"}}
        else:
            token, _ = proof_jwt(attested_key, include_jwk=False, header_extra={"key_attestation": "ka.jwt"})
            request = _request([token])

        with patch.object(ci, "decode_verify_attestation", return_value=claims) as verify:
            ci.generate_credentials(request, "s1")

        verify.assert_called_once_with("ka.jwt")
        sessions.add_key_storage_status.assert_called_once_with(session_id="s1", status={"status_list": {"idx": 7, "uri": "u"}})
        assert sessions.add_key_to_key_storage_status.call_count == 2
        assert [list(p) for p in issue.call_args.args[1]["proofs"]] == [["attestation"], ["attestation"]]
        # The KA expiry is the ceiling (validity 30 days would be later).
        assert sessions.update_max_credential_exp.call_args.kwargs["max_credential_exp"] == exp - 1

    def test_attestation_proof_requires_nonce(self, metadata, sessions, issue, config):
        claims, _ = self._attestation_claims(int(time.time()) + 3600, nonce=False)
        with patch.object(ci, "decode_verify_attestation", return_value=claims):
            result = ci.generate_credentials({"credential_configuration_id": CONFIG_ID, "proofs": {"attestation": ["ka"]}}, "s1")
        assert result["error"] == "invalid_proof" and not issue.called

    def test_jwt_proof_must_be_signed_by_attested_key(self, metadata, sessions, issue, config):
        claims, _ = self._attestation_claims(int(time.time()) + 3600)
        token, _ = proof_jwt(header_extra={"key_attestation": "ka.jwt"})  # signed by an unattested key
        with patch.object(ci, "decode_verify_attestation", return_value=claims):
            result = ci.generate_credentials(_request([token]), "s1")
        assert result == {"error": "invalid_proof", "error_description": "Proof JWT signature is not valid"}
        assert not issue.called

    def test_attestation_without_keys(self, metadata, sessions, issue, config):
        with patch.object(ci, "decode_verify_attestation", return_value={"attested_keys": []}):
            result = ci.generate_credentials({"credential_configuration_id": CONFIG_ID, "proofs": {"attestation": ["ka"]}}, "s1")
        assert result["error_description"] == "Key attestation has no attested_keys"

    @pytest.mark.parametrize("error", [ci.KARevokedError("revoked"), ci.KeyAttestationStatusError("unverifiable")])
    def test_rejected_key_attestation(self, metadata, sessions, issue, config, error):
        with patch.object(ci, "decode_verify_attestation", side_effect=error):
            result = ci.generate_credentials({"credential_configuration_id": CONFIG_ID, "proofs": {"attestation": ["ka"]}}, "s1")
        assert result == {"error": "invalid_proof", "error_description": str(error)}
        assert not issue.called

    def test_expired_wia_is_invalid_proof(self, metadata, sessions, issue, config):
        token, _ = proof_jwt()
        result = ci.generate_credentials(_single(token), "s1", wia_client_status={"exp": int(time.time()) - 10})
        assert result["error"] == "invalid_proof" and not issue.called


class TestDecodeVerifyAttestation:
    def test_status_checked_when_validator_enabled(self):
        claims = {"key_storage_status": {"exp": int(time.time()) + 3600, "status": {"status_list": {"idx": 1, "uri": "u"}}}}
        cfg = {"status_validator": {"enabled": True, "url": "https://validator.test"}}
        with patch_configuration(cfg), patch.object(ci, "verify_jwt_with_x5c", return_value=claims), patch.object(
            ci, "check_status_list_revocation", return_value=False
        ) as check:
            assert ci.decode_verify_attestation("ka") == claims
        check.assert_called_once_with(url="https://validator.test", status_idx=1, status_uri="u")

    @pytest.mark.parametrize(
        "key_storage_status, message",
        [
            (None, "no key_storage_status"),
            ({"status": {"status_list": {"idx": 1, "uri": "u"}}}, "exp is missing"),
            ({"exp": "soon", "status": {"status_list": {"idx": 1, "uri": "u"}}}, "exp is missing"),
            ({"exp": 4102444800}, "status is malformed"),
            ({"exp": 4102444800, "status": {"status_list": {"idx": "1", "uri": "u"}}}, "status is malformed"),
            ({"exp": 4102444800, "status": {"status_list": {"idx": 1}}}, "status is malformed"),
        ],
    )
    def test_key_storage_status_required(self, key_storage_status, message):
        # TS3 2.3.2 / 2.4.1: rejected even with the status validator switched off.
        claims = {"attested_keys": []}
        if key_storage_status is not None:
            claims["key_storage_status"] = key_storage_status
        with patch_configuration({"status_validator": {"enabled": False}}), patch.object(
            ci, "verify_jwt_with_x5c", return_value=claims
        ):
            with pytest.raises(ValueError, match=message):
                ci.decode_verify_attestation("ka")


class TestJwe:
    @pytest.fixture
    def encryption_key(self):
        key = jwk.JWK.generate(kty="EC", crv="P-256")
        with patch_configuration({"keys": {"credential_encryption_key": key.export_to_pem(private_key=True, password=None)}}):
            yield key

    def _encrypt(self, payload: bytes, key: jwk.JWK) -> str:
        token = jwe.JWE(payload, protected=json.dumps({"alg": "ECDH-ES", "enc": "A256GCM"}))
        token.add_recipient(key)
        return token.serialize(compact=True)

    def test_decrypt_round_trip(self, encryption_key):
        request = {"credential_configuration_id": CONFIG_ID, "proof": {"proof_type": "jwt", "jwt": "x"}}
        assert ci.decrypt_jwe_credential_request(self._encrypt(json.dumps(request).encode(), encryption_key)) == request

    def test_not_a_jwe(self, encryption_key):
        with pytest.raises(ValueError, match="expected 5 parts"):
            ci.decrypt_jwe_credential_request("a.b.c")

    def test_payload_not_json(self, encryption_key):
        with pytest.raises(ValueError, match="not valid JSON"):
            ci.decrypt_jwe_credential_request(self._encrypt(b"not json", encryption_key))

    def test_wrong_key(self, encryption_key):
        other = jwk.JWK.generate(kty="EC", crv="P-256")
        with pytest.raises(ValueError, match="Failed to decrypt JWE"):
            ci.decrypt_jwe_credential_request(self._encrypt(b"{}", other))

    def test_encrypt_jwe_drops_none_header_values(self):
        key = jwk.JWK.generate(kty="EC", crv="P-256")
        token = ci.encrypt_jwe({"a": 1}, key, alg="ECDH-ES", enc="A128GCM", kid=None, typ="x")
        parsed = jwe.JWE()
        parsed.deserialize(token, key=key)
        header = json.loads(parsed.objects["protected"])
        assert {k: header[k] for k in ("alg", "enc", "typ")} == {"alg": "ECDH-ES", "enc": "A128GCM", "typ": "x"}
        assert "kid" not in header and "epk" in header  # ECDH-ES ephemeral key
        assert json.loads(parsed.payload) == {"a": 1}


def _holder_numbers(issue_mock):
    [holder] = issue_mock.call_args.args[1]["proofs"]
    return serialization.load_pem_public_key(base64.urlsafe_b64decode(holder["jwt"])).public_numbers()


@pytest.mark.usefixtures("sessions", "config")
class TestKidProofs:
    """JWT proofs whose holder key is a kid DID URL (OpenID4VCI 1.0 appendix F.1, #86)."""

    @pytest.mark.parametrize("shape", ["proofs", "single"])
    @pytest.mark.parametrize("method", ["did:key", "did:jwk"])
    def test_kid_proof_binds_did_key(self, metadata, sessions, issue, config, shape, method):
        key, public_jwk = p256_jwk()
        kid = did_key(key) if method == "did:key" else did_jwk(public_jwk) + "#0"
        token, _ = proof_jwt(key, include_jwk=False, header_extra={"kid": kid})

        ci.generate_credentials(_request([token]) if shape == "proofs" else _single(token), "s1")

        assert _holder_numbers(issue) == key.public_key().public_numbers()

    def test_kid_proof_signed_by_another_key_is_rejected(self, metadata, sessions, issue, config):
        holder = ec.generate_private_key(ec.SECP256R1())
        token, _ = proof_jwt(include_jwk=False, header_extra={"kid": did_key(holder)})  # signed by a fresh key

        result = ci.generate_credentials(_request([token]), "s1")

        assert result == {"error": "invalid_proof", "error_description": "Proof JWT signature is not valid"}
        assert not issue.called

    @pytest.mark.parametrize("extra", [{"x5c": ["MIIB"]}, {}])
    def test_kid_is_exclusive_with_jwk_and_x5c(self, metadata, sessions, issue, config, extra):
        key = ec.generate_private_key(ec.SECP256R1())
        include_jwk = not extra
        token, _ = proof_jwt(key, include_jwk=include_jwk, header_extra={"kid": did_key(key), **extra})

        result = ci.generate_credentials(_request([token]), "s1")

        assert result["error"] == "invalid_proof" and "must not combine" in result["error_description"]
        assert not issue.called

    def test_unsupported_did_method_is_invalid_proof(self, metadata, sessions, issue, config):
        token, _ = proof_jwt(include_jwk=False, header_extra={"kid": "did:web:example.com#key-1"})

        result = ci.generate_credentials(_request([token]), "s1")

        assert result["error"] == "invalid_proof" and not issue.called

    def test_kid_with_key_attestation_references_attested_key(self, metadata, sessions, issue, config):
        # The OpenID4VCI 1.0 appendix F.1 example: {"kid": "0", "key_attestation": ...}
        attested_key, attested_jwk = p256_jwk()
        _, other_jwk = p256_jwk()
        claims = {
            "attested_keys": [attested_jwk, other_jwk],
            "key_storage_status": {"exp": int(time.time()) + 3600, "status": {"status_list": {"idx": 1, "uri": "u"}}},
            "nonce": c_nonce(),
        }
        token, _ = proof_jwt(attested_key, include_jwk=False, header_extra={"kid": "0", "key_attestation": "ka.jwt"})

        with patch.object(ci, "decode_verify_attestation", return_value=claims):
            result = ci.generate_credentials(_request([token]), "s1")

        assert "error" not in result
        assert len(issue.call_args.args[1]["proofs"]) == 2
