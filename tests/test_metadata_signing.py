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
"""Tests for metadata signing, encryption metadata and metadata loading errors."""

import datetime
import json
from unittest.mock import patch

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID
from jwcrypto import jwk

from app.services import metadata
from app.services.metadata import MetadataSigningError
from config_helpers import patch_configuration
from pki_helpers import make_cert

FRONTEND_URL = "https://frontend.test"


def _pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _self_signed(key):
    """Self-signed certificate; Ed25519 signatures take no hash algorithm."""
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        return make_cert("Signer", "Signer", key.public_key(), key, ca=False)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Signer")])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, None)
    )


def _frontend_config(key, cert_pem=None):
    cert = _self_signed(key) if cert_pem is None else None
    return {
        "frontend": {
            "default": "fe",
            "frontends_config": {
                "fe": {
                    "url": FRONTEND_URL,
                    "metadata_signing_key": _pem(key),
                    "metadata_signing_key_password": None,
                    "metadata_access_certificate": cert_pem or cert.public_bytes(serialization.Encoding.PEM),
                }
            },
        }
    }


class TestSigningAlgorithm:
    @pytest.mark.parametrize(
        "curve, alg", [(ec.SECP256R1(), "ES256"), (ec.SECP384R1(), "ES384"), (ec.SECP521R1(), "ES512"), (ec.SECP256K1(), "ES256")]
    )
    def test_ec(self, curve, alg):
        assert metadata.signing_algorithm(ec.generate_private_key(curve)) == alg

    @pytest.mark.parametrize("size, alg", [(2048, "RS256"), (3072, "RS384"), (4096, "RS512")])
    def test_rsa(self, size, alg):
        assert metadata.signing_algorithm(rsa.generate_private_key(public_exponent=65537, key_size=size)) == alg

    def test_ed25519(self):
        assert metadata.signing_algorithm(ed25519.Ed25519PrivateKey.generate()) == "EdDSA"

    def test_unsupported(self):
        with pytest.raises(MetadataSigningError, match="Unsupported key type"):
            metadata.signing_algorithm(object())


class TestSignIssuerMetadata:
    @pytest.mark.parametrize(
        "key_factory, alg",
        [
            (lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048), "RS256"),
            (ed25519.Ed25519PrivateKey.generate, "EdDSA"),
            (lambda: ec.generate_private_key(ec.SECP384R1()), "ES384"),
        ],
    )
    def test_signed_with_frontend_key(self, key_factory, alg):
        key = key_factory()
        with patch_configuration(_frontend_config(key)):
            token = metadata.sign_issuer_metadata({"credential_issuer": FRONTEND_URL}, "fe", iss="https://attester.test")

        header = jwt.get_unverified_header(token)
        assert header["alg"] == alg and header["typ"] == metadata.SIGNED_METADATA_TYP and len(header["x5c"]) == 1
        claims = jwt.decode(token, key.public_key(), algorithms=[alg])
        assert claims["sub"] == FRONTEND_URL and claims["iss"] == "https://attester.test"
        assert claims["credential_issuer"] == FRONTEND_URL and isinstance(claims["iat"], int)

    def test_iss_is_optional(self):
        key = ec.generate_private_key(ec.SECP256R1())
        with patch_configuration(_frontend_config(key)):
            claims = jwt.decode(metadata.sign_issuer_metadata({}, "fe"), key.public_key(), algorithms=["ES256"])
        assert "iss" not in claims

    def test_bad_certificate(self):
        key = ec.generate_private_key(ec.SECP256R1())
        with patch_configuration(_frontend_config(key, cert_pem=b"not a certificate")):
            with pytest.raises(MetadataSigningError, match="Failed to load certificate"):
                metadata.sign_issuer_metadata({}, "fe")

    def test_unknown_frontend(self):
        key = ec.generate_private_key(ec.SECP256R1())
        with patch_configuration(_frontend_config(key)):
            with pytest.raises(KeyError):
                metadata.sign_issuer_metadata({}, "other")


class TestCredentialEncryptionMetadata:
    def test_public_jwk_and_thumbprint(self):
        key = jwk.JWK.generate(kty="EC", crv="P-256")
        block = metadata._build_credential_encryption_metadata(key.export_to_pem(private_key=True, password=None))

        published = block["jwks"]["keys"][0]
        public = key.export_public(as_dict=True)
        assert (published["x"], published["y"], published["crv"]) == (public["x"], public["y"], "P-256")
        assert "d" not in published
        assert published["kid"] == key.thumbprint()  # RFC 7638, SHA-256
        assert block["encryption_required"] is False and "A256GCM" in block["enc_values_supported"]

    def test_rejects_non_ec_key(self):
        rsa_pem = _pem(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        with pytest.raises(ValueError, match="P-256"):
            metadata._build_credential_encryption_metadata(rsa_pem)


class TestSetupErrors:
    def test_missing_directory(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            metadata.setup_metadata(tmp_path / "nope")

    def test_invalid_json(self, tmp_path):
        (tmp_path / "credentials_supported").mkdir()
        (tmp_path / "credentials_supported" / "bad.json").write_text("{")
        with pytest.raises(json.JSONDecodeError):
            metadata.setup_metadata(tmp_path)

    def test_unexpected_error(self, tmp_path):
        (tmp_path / "credentials_supported").mkdir()
        with patch.object(metadata, "_load_json", side_effect=PermissionError("denied")):
            (tmp_path / "credentials_supported" / "x.json").write_text("{}")
            with pytest.raises(PermissionError):
                metadata.setup_metadata(tmp_path)

    def test_encryption_builder_failure(self, tmp_path):
        (tmp_path / "credentials_supported").mkdir()
        with patch_configuration({"keys": {"credential_encryption_key": b"garbage"}}):
            with pytest.raises(ValueError):
                metadata.setup_metadata(tmp_path)

    def test_trusted_cas_missing_directory(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            metadata.setup_trusted_cas(str(tmp_path / "nope"))

    def test_trusted_cas_invalid_pem(self, tmp_path):
        (tmp_path / "bad.pem").write_text("not a certificate")
        with pytest.raises(ValueError):
            metadata.setup_trusted_cas(str(tmp_path))

    def test_trusted_cas_ignores_other_files(self, tmp_path):
        from app.core import state

        (tmp_path / "readme.txt").write_text("ignored")
        with patch.dict(state.trusted_CAs, {"old": {}}, clear=True):
            metadata.setup_trusted_cas(str(tmp_path))
            assert state.trusted_CAs == {}


class TestJsonHelpers:
    def test_remove_keys_drops_emptied_containers(self):
        data = {"keep": 1, "drop": 2, "nested": {"drop": 3}, "items": [{"drop": 4}, {"keep": 5}]}
        assert metadata.remove_keys(data, {"drop"}) == {"keep": 1, "nested": None, "items": [{"keep": 5}]}

    def test_remove_keys_everything_removed(self):
        assert metadata.remove_keys([{"drop": 1}], {"drop"}) is None

    def test_replace_domain_leaves_non_strings(self):
        assert metadata.replace_domain({"a": ["https://old/x", 3, None]}, "https://old", "https://new") == {
            "a": ["https://new/x", 3, None]
        }

    def test_fix_key_attestations(self):
        data = {"c": [{"proof": {"key_attestations_required": None}}, {"key_attestations_required": {"x": 1}}]}
        assert metadata.fix_key_attestations(data) == {
            "c": [{"proof": {"key_attestations_required": {}}}, {"key_attestations_required": {"x": 1}}]
        }
