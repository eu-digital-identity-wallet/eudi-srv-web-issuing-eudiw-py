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
"""Tests for kid DID URL resolution (OpenID4VCI 1.0 appendix F.1, #86)."""

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.utils.did import jwk_from_did_url
from proof_helpers import p256_jwk

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rem = divmod(number, 58)
        out = _B58[rem] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def did_key(key: ec.EllipticCurvePrivateKey, prefix: bytes = b"\x80\x24", compressed: bool = True) -> str:
    point_format = serialization.PublicFormat.CompressedPoint if compressed else serialization.PublicFormat.UncompressedPoint
    point = key.public_key().public_bytes(serialization.Encoding.X962, point_format)
    return "did:key:z" + _b58encode(prefix + point)


def did_jwk(public_jwk: dict) -> str:
    return "did:jwk:" + base64.urlsafe_b64encode(json.dumps(public_jwk).encode()).rstrip(b"=").decode()


class TestJwkFromDidUrl:
    def test_did_key_round_trip(self):
        key = ec.generate_private_key(ec.SECP256R1())
        resolved = jwk_from_did_url(did_key(key))
        numbers = key.public_key().public_numbers()
        assert resolved["crv"] == "P-256" and resolved["kty"] == "EC"
        assert int.from_bytes(base64.urlsafe_b64decode(resolved["x"] + "="), "big") == numbers.x
        assert int.from_bytes(base64.urlsafe_b64decode(resolved["y"] + "="), "big") == numbers.y

    def test_did_key_fragment_must_be_the_key(self):
        did = did_key(ec.generate_private_key(ec.SECP256R1()))
        assert jwk_from_did_url(f"{did}#{did[len('did:key:'):]}")
        with pytest.raises(ValueError):
            jwk_from_did_url(f"{did}#other")

    def test_did_jwk_round_trip_and_fragment(self):
        _, public_jwk = p256_jwk()
        assert jwk_from_did_url(did_jwk(public_jwk) + "#0") == public_jwk
        with pytest.raises(ValueError):
            jwk_from_did_url(did_jwk(public_jwk) + "#1")

    @pytest.mark.parametrize(
        "kid",
        [
            None,
            "0",
            "https://example.com/key",
            "did:web:example.com#key-1",
            "did:key:",
            "did:key:zInvalid0OIl",
            "did:jwk:!!!",
            "did:jwk:" + base64.urlsafe_b64encode(b"[1]").decode(),
            "x" * 5000,
        ],
    )
    def test_rejects_unsupported_or_malformed(self, kid):
        with pytest.raises(ValueError):
            jwk_from_did_url(kid)

    def test_rejects_other_multicodec(self):
        # 0xed01: Ed25519 public key
        with pytest.raises(ValueError, match="P-256"):
            jwk_from_did_url("did:key:z" + _b58encode(b"\xed\x01" + bytes(32)))

    def test_rejects_uncompressed_did_key(self):
        with pytest.raises(ValueError, match="compressed"):
            jwk_from_did_url(did_key(ec.generate_private_key(ec.SECP256R1()), compressed=False))

    def test_rejects_did_jwk_with_private_key(self):
        _, public_jwk = p256_jwk()
        private = {**public_jwk, "d": "AAAA"}
        with pytest.raises(ValueError, match="private"):
            jwk_from_did_url(did_jwk(private))
