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
"""Tests for the public / signing JWK helpers of app.utils.crypto."""

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwcrypto import jwk

from app.utils.crypto import ec_public_jwk, ec_signing_jwk_from_cert
from pki_helpers import make_cert


def _cert_der(key):
    cert = make_cert("Test DS", "Test DS", key.public_key(), key, ca=False)
    return cert.public_bytes(serialization.Encoding.DER)


class TestEcPublicJwk:
    @pytest.mark.parametrize(
        "curve, crv",
        [(ec.SECP256R1(), "P-256"), (ec.SECP384R1(), "P-384"), (ec.SECP521R1(), "P-521")],
    )
    def test_matches_jwcrypto(self, curve, crv):
        key = ec.generate_private_key(curve)
        expected = jwk.JWK.from_pem(
            key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        )

        result = ec_public_jwk(key.public_key())

        assert result["crv"] == crv
        assert result["kid"] == expected.thumbprint()
        assert {k: result[k] for k in ("kty", "crv", "x", "y")} == {
            k: v for k, v in expected.export_public(as_dict=True).items() if k in ("kty", "crv", "x", "y")
        }

    def test_private_key_exports_only_the_public_part(self):
        key = ec.generate_private_key(ec.SECP256R1())

        result = ec_public_jwk(key)

        assert result == ec_public_jwk(key.public_key())
        assert "d" not in result

    def test_rejects_non_ec_key(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with pytest.raises(ValueError):
            ec_public_jwk(key.public_key())


class TestEcSigningJwkFromCert:
    def test_fields(self):
        key = ec.generate_private_key(ec.SECP256R1())
        cert_der = _cert_der(key)

        result = ec_signing_jwk_from_cert(cert_der)

        assert result["use"] == "sig"
        assert result["alg"] == "ES256"
        assert result["kid"] == ec_public_jwk(key.public_key())["kid"]
        assert result["x5c"] == [base64.b64encode(cert_der).decode()]
        assert result["x5t#S256"] == base64.urlsafe_b64encode(hashlib.sha256(cert_der).digest()).decode().rstrip("=")
        assert "d" not in result

    def test_p384_uses_es384(self):
        assert ec_signing_jwk_from_cert(_cert_der(ec.generate_private_key(ec.SECP384R1())))["alg"] == "ES384"

    def test_invalid_certificate(self):
        with pytest.raises(ValueError):
            ec_signing_jwk_from_cert(b"not a certificate")
