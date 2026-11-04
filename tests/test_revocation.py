# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
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

import base64
import io
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
import jwt
import requests

from app.core import state
from app.routes import revocation
# The strict base64url decoder of the old revocation module is now
# app.utils.encoding.b64url_decode_strict.
from app.core.errors import CertificateVerificationError
from app.utils.encoding import b64url_decode_strict as b64url_decode
from app.services.trust import verify_and_decode_sdjwt, x5c_leaf_certificate
from app.services.revocation_status import get_status_sdjwt, get_status_mdoc, is_issuer_certificate
from config_helpers import set_configuration


def _verifier_response(vp_token):
    """Builds a mocked verifier HTTP 200 response with a DCQL ``vp_token``."""
    response = Mock()
    response.status_code = 200
    response.json.return_value = {"vp_token": vp_token}
    return response


def _set_session(client, **values):
    """Stores values in the test client's Flask session."""
    with client.session_transaction() as flask_session:
        flask_session.update(values)


@pytest.fixture
def client():
    """Create a test client for the Flask app."""
    from flask import Flask

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret-key"
    app.config["TESTING"] = True
    app.register_blueprint(revocation.revocation)

    with app.test_client() as client:
        # The cross-device transaction oid4vp_call created for this browser.
        _set_session(client, oid4vp_cross_device_id="valid_id")
        yield client


@pytest.fixture
def mock_config(monkeypatch):
    """Mock configuration in every app module (route, frontend, oid4vp, revocation_status)."""

    mock_config = {
        "service_url": "http://test.com/",
        "dynamic_presentation_url": "http://test.com/presentation/",
        "frontend": {
            "default": "default",
            "frontends_config": {
                "default": {
                    "url": "http://frontend.test.com"
                }
            }
        },
        "expiry": {
            "revocation_code": 10
        },
        "revocation": {
            "set_url": "http://test.com/revoke",
            "api_key": "test_api_key"
        },
        "oid4vp_scheme": "haip-vp://",
        "intended_use_id": "test_intended_use",
    }
    set_configuration(monkeypatch, mock_config)
    yield mock_config


@pytest.fixture
def mock_oidc_metadata():
    """Mock OIDC metadata."""
    metadata = {
        "credential_configurations_supported": {
            "test_sdjwt_credential": {
                "format": "dc+sd-jwt",
                "vct": "test_vct",
                "credential_metadata": {
                    "display": [{"name": "Test SD-JWT Credential"}],
                    "claims": [{"path": ["claim1"]}, {"path": ["claim2"], "mandatory": True}],
                },
            },
            "test_mdoc_credential": {
                "format": "mso_mdoc",
                "doctype": "test.doctype",
                "scope": "test.doctype.scope",
                "credential_metadata": {
                    "display": [{"name": "Test mDoc Credential"}],
                    "claims": [
                        {"path": ["namespace", "claim1"]},
                        {"path": ["namespace", "claim2"], "mandatory": True},
                    ],
                },
            },
        }
    }
    # oidc_metadata is shared (app.core.state) and read by several modules.
    with patch.dict(state.oidc_metadata, metadata, clear=True):
        yield metadata


@pytest.fixture
def rsa_key_pair():
    """Generate RSA key pair for testing."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


@pytest.fixture
def ec_key_pair():
    """Generate EC key pair for testing."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


@pytest.fixture
def ed25519_key_pair():
    """Generate Ed25519 key pair for testing."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


@pytest.fixture
def ed448_key_pair():
    """Generate Ed448 key pair for testing."""
    private_key = ed448.Ed448PrivateKey.generate()
    return private_key, private_key.public_key()


@pytest.fixture
def x509_cert(rsa_key_pair):
    """Generate a self-signed X.509 certificate for testing."""
    private_key, public_key = rsa_key_pair

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )

    return cert


class TestUtilityFunctions:
    """Test utility functions."""

    def test_b64url_decode_valid(self):
        """Test base64url decoding with valid input."""
        data = "SGVsbG8gV29ybGQ"
        result = b64url_decode(data)
        assert result == b"Hello World"

    def test_b64url_decode_with_padding(self):
        """Test base64url decoding that requires padding."""
        data = "SGVsbG8"
        result = b64url_decode(data)
        assert result == b"Hello"

    def test_b64url_decode_invalid(self):
        """Test base64url decoding with invalid input."""
        with pytest.raises(Exception):  # Can raise binascii.Error or ValueError
            b64url_decode("!!!invalid!!!")


class TestX5cLeafCertificate:
    """Test x5c_leaf_certificate (untrusted leaf extraction)."""

    def test_extract_rsa_public_key(self, rsa_key_pair, x509_cert):
        """Test extracting RSA public key from x5c header."""
        private_key, _ = rsa_key_pair

        cert_der = x509_cert.public_bytes(serialization.Encoding.DER)
        cert_b64 = base64.b64encode(cert_der).decode("utf-8").rstrip("=")

        payload = {"test": "data"}
        token = jwt.encode(
            payload, private_key, algorithm="RS256", headers={"x5c": [cert_b64]}
        )

        certificate, alg = x5c_leaf_certificate(token)

        assert isinstance(certificate.public_key(), rsa.RSAPublicKey)
        assert alg == "RS256"

    def test_extract_missing_x5c(self, rsa_key_pair):
        """Test extracting public key when x5c header is missing."""
        private_key, _ = rsa_key_pair

        payload = {"test": "data"}
        token = jwt.encode(payload, private_key, algorithm="RS256")

        with pytest.raises(ValueError, match="x5c header not found in JWT"):
            x5c_leaf_certificate(token)

    def test_extract_invalid_x5c_cert(self, rsa_key_pair):
        """Test extracting public key with invalid certificate."""
        private_key, _ = rsa_key_pair

        payload = {"test": "data"}
        token = jwt.encode(
            payload,
            private_key,
            algorithm="RS256",
            headers={"x5c": ["invalid_cert_data"]},
        )

        with pytest.raises(ValueError):
            x5c_leaf_certificate(token)


class TestVerifyAndDecodeSdjwt:
    """Test verify_and_decode_sdjwt function."""

    def test_verify_rsa_sdjwt(self, rsa_key_pair, x509_cert):
        """Test verifying SD-JWT with RSA signature."""
        private_key, _ = rsa_key_pair

        cert_der = x509_cert.public_bytes(serialization.Encoding.DER)
        cert_b64 = base64.b64encode(cert_der).decode("utf-8").rstrip("=")

        payload = {"status": {"idx": 123}, "test": "data"}
        token = jwt.encode(
            payload, private_key, algorithm="RS256", headers={"x5c": [cert_b64]}
        )

        # Create SD-JWT format (token without disclosures)
        sd_jwt = token + "~"

        with patch("app.services.trust.SDJWTHolder") as mock_holder:
            mock_holder.return_value._unverified_input_sd_jwt = token
            result = verify_and_decode_sdjwt(sd_jwt, lambda certificate: True)

        assert result["test"] == "data"
        assert "status" in result

    def test_verify_ec_sdjwt(self, ec_key_pair):
        """Test verifying SD-JWT with EC signature."""
        private_key, public_key = ec_key_pair

        # Create certificate with EC key
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )

        cert_der = cert.public_bytes(serialization.Encoding.DER)
        cert_b64 = base64.b64encode(cert_der).decode("utf-8").rstrip("=")

        payload = {"status": {"idx": 456}, "test": "ec_data"}
        token = jwt.encode(
            payload, private_key, algorithm="ES256", headers={"x5c": [cert_b64]}
        )

        sd_jwt = token + "~"

        with patch("app.services.trust.SDJWTHolder") as mock_holder:
            mock_holder.return_value._unverified_input_sd_jwt = token
            result = verify_and_decode_sdjwt(sd_jwt, lambda certificate: True)

        assert result["test"] == "ec_data"

    def test_verify_ed25519_sdjwt(self, ed25519_key_pair):
        """Test verifying SD-JWT with Ed25519 signature."""
        private_key, public_key = ed25519_key_pair

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .sign(private_key, algorithm=None)
        )

        cert_der = cert.public_bytes(serialization.Encoding.DER)
        cert_b64 = base64.b64encode(cert_der).decode("utf-8").rstrip("=")

        payload = {"status": {"idx": 789}, "test": "ed25519_data"}
        token = jwt.encode(
            payload, private_key, algorithm="EdDSA", headers={"x5c": [cert_b64]}
        )

        sd_jwt = token + "~"

        with patch("app.services.trust.SDJWTHolder") as mock_holder:
            mock_holder.return_value._unverified_input_sd_jwt = token
            result = verify_and_decode_sdjwt(sd_jwt, lambda certificate: True)

        assert result["test"] == "ed25519_data"

    def test_verify_unsupported_key_type(self):
        """Test verifying SD-JWT with unsupported key type."""
        sd_jwt = "test~"

        with patch("app.services.trust.SDJWTHolder") as mock_holder, patch(
            "app.services.trust.x5c_leaf_certificate"
        ) as mock_extract:

            mock_holder.return_value._unverified_input_sd_jwt = "test_token"
            # Mock a certificate with an unsupported key type
            certificate = Mock()
            certificate.public_key.return_value = Mock(spec=object)
            mock_extract.return_value = (certificate, "RS256")

            with pytest.raises(ValueError, match="Unsupported key type"):
                verify_and_decode_sdjwt(sd_jwt, lambda c: True)

    def test_untrusted_signer_rejected_before_signature_check(self, rsa_key_pair, x509_cert):
        """A correctly signed SD-JWT from an untrusted signer is rejected."""
        private_key, _ = rsa_key_pair
        cert_b64 = base64.b64encode(x509_cert.public_bytes(serialization.Encoding.DER)).decode()
        token = jwt.encode({"status": {}}, private_key, algorithm="RS256", headers={"x5c": [cert_b64]})

        seen = []
        with patch("app.services.trust.SDJWTHolder") as mock_holder:
            mock_holder.return_value._unverified_input_sd_jwt = token
            with pytest.raises(CertificateVerificationError, match="Untrusted SD-JWT signer"):
                verify_and_decode_sdjwt(token + "~", lambda c: seen.append(c) or False)
        assert seen[0].subject == x509_cert.subject


class TestGetStatusSdjwt:
    """Test get_status_sdjwt function."""

    def test_get_status_sdjwt_success(self):
        """Test successfully getting status from SD-JWT."""
        sd_jwt = "test_jwt~"
        expected_status = {"status_list": {"idx": 123, "uri": "http://test.com"}}

        with patch("app.services.revocation_status.verify_and_decode_sdjwt") as mock_verify:
            mock_verify.return_value = {"status": expected_status, "other": "data"}

            result = get_status_sdjwt(sd_jwt)

            assert result == expected_status
            mock_verify.assert_called_once_with(sd_jwt, is_issuer_certificate)


def _issue_mdoc_with_status(signing_key, cert_der_path, status_idx):
    """Issues a real mdoc (via the issuer's formatter) carrying a status list entry."""
    from app.services.formatters import mdocFormatter

    device = ec.generate_private_key(ec.SECP256R1()).public_key()
    device_key = base64.urlsafe_b64encode(
        device.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).decode()
    reservation = {
        "status_list": {"idx": status_idx, "uri": "https://issuer.test/token_status_list/FC/pid/list-1"},
        "identifier_list": {"id": str(status_idx), "uri": "https://issuer.test/identifier_list/FC/pid/list-1"},
    }
    config = {
        "revocation": {"enabled": True},
        "countries": {
            "FC": {
                "keys": {
                    "_default": {
                        "private_key": signing_key.private_bytes(
                            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                        ),
                        "private_key_password": None,
                        "certificate_path": cert_der_path,
                    }
                }
            }
        },
    }
    session = Mock(country="FC", is_batch_credential=False, max_credential_exp=None)
    with patch("app.services.formatters.CONFIGURATION", config), patch(
        "app.services.formatters.reserve_status_entry", return_value=reservation
    ), patch("app.services.formatters.session_manager") as sessions:
        sessions.get_session.return_value = session
        encoded = mdocFormatter(
            {"eu.europa.ec.eudi.pid.1": {"family_name": "Doe"}},
            {"doctype": "eu.europa.ec.eudi.pid.1", "issuer_config": {"validity": 30, "namespace": "eu.europa.ec.eudi.pid.1"}},
            "FC",
            device_key,
            "s1",
        )
    issuer_signed = cbor2.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    return {"docType": "eu.europa.ec.eudi.pid.1", "issuerSigned": issuer_signed}


def _device_response(*documents):
    return base64.urlsafe_b64encode(cbor2.dumps({"documents": list(documents), "status": 0})).decode().rstrip("=")


class TestGetStatusMdoc:
    """get_status_mdoc only trusts MSOs signed by this issuer's document signers."""

    @pytest.fixture
    def signers(self, tmp_path):
        result = {}
        for name in ("own", "foreign"):
            key = ec.generate_private_key(ec.SECP256R1())
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{name} DS")])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow() - timedelta(days=1))
                .not_valid_after(datetime.utcnow() + timedelta(days=30))
                .sign(key, hashes.SHA256())
            )
            der = cert.public_bytes(serialization.Encoding.DER)
            path = tmp_path / f"{name}.der"
            path.write_bytes(der)
            result[name] = {"key": key, "der": der, "path": str(path)}
        return result

    @pytest.fixture
    def own_issuer(self, signers):
        config = {"countries": {"FC": {"keys": {"_default": {"certificate": signers["own"]["der"]}}}}}
        with patch("app.services.revocation_status.CONFIGURATION", config):
            yield

    def test_single_document(self, signers, own_issuer):
        document = _issue_mdoc_with_status(signers["own"]["key"], signers["own"]["path"], 7)

        status = get_status_mdoc(_device_response(document))

        assert status["status_list"] == {"idx": 7, "uri": "https://issuer.test/token_status_list/FC/pid/list-1"}

    def test_multiple_documents(self, signers, own_issuer):
        documents = [_issue_mdoc_with_status(signers["own"]["key"], signers["own"]["path"], i) for i in (1, 2)]

        statuses = get_status_mdoc(_device_response(*documents))

        assert [s["status_list"]["idx"] for s in statuses] == [1, 2]

    def test_foreign_signer_rejected(self, signers, own_issuer):
        document = _issue_mdoc_with_status(signers["foreign"]["key"], signers["foreign"]["path"], 9)

        with pytest.raises(CertificateVerificationError, match="Untrusted mdoc signer"):
            get_status_mdoc(_device_response(document))

    def test_tampered_mso_rejected(self, signers, own_issuer):
        document = _issue_mdoc_with_status(signers["own"]["key"], signers["own"]["path"], 3)
        issuer_auth = document["issuerSigned"]["issuerAuth"]
        signature = bytearray(issuer_auth[3])
        signature[0] ^= 0xFF
        issuer_auth[3] = bytes(signature)

        with pytest.raises(CertificateVerificationError, match="signature not valid"):
            get_status_mdoc(_device_response(document))

    def test_unsigned_mso_rejected(self, own_issuer):
        """The old behaviour (reading the status from an unsigned MSO) is gone."""
        payload = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps({"status": {"status_list": {"idx": 1, "uri": "u"}}})))
        document = {"issuerSigned": {"issuerAuth": [None, None, payload]}}

        with pytest.raises(CertificateVerificationError):
            get_status_mdoc(_device_response(document))


class TestRevocationChoice:
    """Test /revocation_choice endpoint."""

    def test_revocation_choice_get(
        self, client, mock_config, mock_oidc_metadata
    ):
        """Test GET request to revocation_choice."""
        with patch("app.routes.revocation.post_redirect_with_payload") as mock_redirect:
            mock_redirect.return_value = "redirect_response"

            response = client.get("/revocation/revocation_choice")

            assert mock_redirect.called
            call_args = mock_redirect.call_args

            assert "display_revocation_choice" in call_args[1]["target_url"]
            assert "cred" in call_args[1]["data_payload"]
            assert "sd-jwt vc format" in call_args[1]["data_payload"]["cred"]
            assert "mdoc format" in call_args[1]["data_payload"]["cred"]

    @pytest.fixture
    def two_frontends(self, mock_config, mock_oidc_metadata):
        """A default frontend listing everything and one listing only the SD-JWT credential."""
        mock_config["frontend"]["frontends_config"]["sdjwt_only"] = {
            "url": "http://sdjwt.frontend.test",
            "credentials_supported": ["test_sdjwt_credential"],
        }

    def _choice(self, client, **query):
        with patch("app.routes.revocation.post_redirect_with_payload", return_value="ok") as mock_redirect:
            response = client.get("/revocation/revocation_choice", query_string=query)
        return response, mock_redirect.call_args

    def test_lists_only_credentials_published_by_the_frontend(self, client, two_frontends):
        _, call_args = self._choice(client, frontend_id="sdjwt_only")

        assert call_args[1]["target_url"] == "http://sdjwt.frontend.test/display_revocation_choice"
        assert call_args[1]["data_payload"]["cred"] == {
            "sd-jwt vc format": {"test_sdjwt_credential": "Test SD-JWT Credential"},
            "mdoc format": {},
        }

    def test_without_frontend_id_uses_the_default_frontend(self, client, two_frontends):
        _, call_args = self._choice(client)

        assert call_args[1]["target_url"] == "http://frontend.test.com/display_revocation_choice"
        assert call_args[1]["data_payload"]["cred"]["mdoc format"] == {"test_mdoc_credential": "Test mDoc Credential"}

    def test_unknown_frontend_is_rejected(self, client, two_frontends):
        response, call_args = self._choice(client, frontend_id="nope")

        assert response.status_code == 404
        assert call_args is None

    def test_later_pages_go_to_the_starting_frontend(self, client, two_frontends):
        self._choice(client, frontend_id="sdjwt_only")

        with client.application.test_request_context(), client.session_transaction() as sess:
            from flask import session

            session.update(sess)
            assert revocation._flow_frontend_url() == "http://sdjwt.frontend.test"

    def _call(self, client, *selected):
        with patch("app.routes.revocation.start_presentation") as start, patch(
            "app.routes.revocation.qr_data_uri", return_value="data:"
        ), patch("app.routes.revocation.post_redirect_with_payload", return_value="ok"):
            start.return_value = Mock(
                same_device_id="sd", cross_device_id="cd", nonce="n", deeplink_url="d", qr_code_url="q",
                cross_device={"transaction_id": "t"},
            )
            response = client.post("/revocation/oid4vp_call", data={**dict.fromkeys(selected, "on"), "proceed": "true"})
        return response, start

    def test_call_rejects_credentials_the_frontend_does_not_publish(self, client, two_frontends):
        self._choice(client, frontend_id="sdjwt_only")

        response, start = self._call(client, "test_sdjwt_credential", "test_mdoc_credential")

        assert response.status_code == 400
        assert response.get_json()["error_description"] == "Unsupported credential"
        assert not start.called

    def test_call_accepts_published_credentials(self, client, two_frontends):
        self._choice(client, frontend_id="sdjwt_only")

        response, start = self._call(client, "test_sdjwt_credential")

        assert response.status_code == 200
        assert start.called

    def test_call_rejects_unknown_credentials(self, client, two_frontends):
        response, start = self._call(client, "nope")

        assert response.status_code == 400
        assert not start.called

    def test_call_rejects_non_revocable_credentials(self, client, two_frontends):
        state.oidc_metadata["credential_configurations_supported"]["age"] = {
            "format": "mso_mdoc",
            "doctype": "age.doctype",
            "scope": revocation.NON_REVOCABLE_MDOC_SCOPES[0],
            "credential_metadata": {"display": [{"name": "Age"}], "claims": [{"path": ["ns", "over_18"]}]},
        }

        response, start = self._call(client, "age")

        assert response.status_code == 400
        assert not start.called


class TestOid4vpCall:
    """Test /oid4vp_call endpoint."""

    def test_revoke_with_identifier_list(
        self, client, mock_config
    ):
        """Test revoking credentials with identifier_list."""
        revocation_id = "test_revoc_id"

        with patch(
            "app.routes.revocation.revocation_requests",
            {
                revocation_id: {
                    "status_lists": {
                        "dc+sd-jwt": [],
                        "mso_mdoc": [
                            {
                                "identifier_list": {
                                    "uri": "http://test.com/identifier",
                                    "id": b"abc123",
                                }
                            }
                        ],
                    },
                    "expires": datetime.now() + timedelta(minutes=10),
                }
            },
        ), patch("app.services.revocation_status.requests.post") as mock_post, patch(
            "app.routes.revocation.post_redirect_with_payload"
        ) as mock_redirect:

            mock_post.return_value.status_code = 200
            mock_redirect.return_value = "redirect_response"

            _set_session(client, revocation_id=revocation_id)

            response = client.post(
                "/revocation/revoke", data={"revocation_identifier": revocation_id}
            )

            assert mock_post.called

            # Verify the payload format
            call_args = mock_post.call_args
            assert call_args.args[0] == mock_config["revocation"]["set_url"]
            assert call_args.kwargs["data"] == {
                "id": "abc123",
                "status": 1,
                "uri": "http://test.com/identifier",
            }
            assert call_args.kwargs["headers"]["X-Api-Key"] == "test_api_key"
            assert "timeout" in call_args.kwargs

    def test_revoke_missing_identifier(self, client, mock_config):
        """Test revoke endpoint with missing identifier."""
        response = client.post("/revocation/revoke", data={})

        assert response.status_code == 400

    def test_revoke_invalid_identifier(self, client, mock_config):
        """Test revoke endpoint with invalid identifier."""
        with patch("app.routes.revocation.revocation_requests", {}):
            _set_session(client, revocation_id="invalid_id")
            response = client.post(
                "/revocation/revoke", data={"revocation_identifier": "invalid_id"}
            )

            assert response.status_code == 404

    def test_revoke_api_failure(self, client, mock_config):
        """Test revoke when API call fails."""
        revocation_id = "test_revoc_id"

        with patch(
            "app.routes.revocation.revocation_requests",
            {
                revocation_id: {
                    "status_lists": {
                        "dc+sd-jwt": [
                            {
                                "status_list": {
                                    "uri": "http://test.com/status",
                                    "idx": 123,
                                }
                            }
                        ],
                        "mso_mdoc": [],
                    },
                    "expires": datetime.now() + timedelta(minutes=10),
                }
            },
        ), patch("app.services.revocation_status.requests.post") as mock_post, patch(
            "app.routes.revocation.post_redirect_with_payload"
        ) as mock_redirect:

            mock_post.return_value.status_code = 500
            mock_post.return_value.text = "Server error"
            mock_redirect.return_value = "redirect_response"

            _set_session(client, revocation_id=revocation_id)

            response = client.post(
                "/revocation/revoke", data={"revocation_identifier": revocation_id}
            )

            # Should still redirect even if API fails
            assert mock_redirect.called

    def test_revoke_api_exception(self, client, mock_config):
        """Test revoke when API call raises exception."""
        revocation_id = "test_revoc_id"

        with patch(
            "app.routes.revocation.revocation_requests",
            {
                revocation_id: {
                    "status_lists": {
                        "dc+sd-jwt": [
                            {
                                "status_list": {
                                    "uri": "http://test.com/status",
                                    "idx": 123,
                                }
                            }
                        ],
                        "mso_mdoc": [],
                    },
                    "expires": datetime.now() + timedelta(minutes=10),
                }
            },
        ) as mock_revoc_req, patch("app.services.revocation_status.requests.post") as mock_post, patch(
            "app.routes.revocation.post_redirect_with_payload"
        ) as mock_redirect:

            mock_post.side_effect = requests.ConnectionError("Connection error")
            mock_redirect.return_value = "redirect_response"

            _set_session(client, revocation_id=revocation_id)

            response = client.post(
                "/revocation/revoke", data={"revocation_identifier": revocation_id}
            )

            # Should still redirect and clean up
            assert mock_redirect.called
            assert revocation_id not in mock_revoc_req

    def test_revoke_both_list_types(self, client, mock_config):
        """Test revoking credentials with both status_list and identifier_list."""
        revocation_id = "test_revoc_id"

        with patch(
            "app.routes.revocation.revocation_requests",
            {
                revocation_id: {
                    "status_lists": {
                        "dc+sd-jwt": [
                            {
                                "status_list": {
                                    "uri": "http://test.com/status",
                                    "idx": 123,
                                },
                                "identifier_list": {
                                    "uri": "http://test.com/identifier",
                                    "id": b"xyz789",
                                },
                            }
                        ],
                        "mso_mdoc": [],
                    },
                    "expires": datetime.now() + timedelta(minutes=10),
                }
            },
        ), patch("app.services.revocation_status.requests.post") as mock_post, patch(
            "app.routes.revocation.post_redirect_with_payload"
        ) as mock_redirect:

            mock_post.return_value.status_code = 200
            mock_redirect.return_value = "redirect_response"

            _set_session(client, revocation_id=revocation_id)

            response = client.post(
                "/revocation/revoke", data={"revocation_identifier": revocation_id}
            )

            # Should make 2 API calls (one for identifier_list, one for status_list)
            assert mock_post.call_count == 2

    def test_revoke_multiple_credentials(
        self, client, mock_config
    ):
        """Test revoking multiple credentials."""
        revocation_id = "test_revoc_id"

        with patch(
            "app.routes.revocation.revocation_requests",
            {
                revocation_id: {
                    "status_lists": {
                        "dc+sd-jwt": [
                            {
                                "status_list": {
                                    "uri": "http://test.com/status1",
                                    "idx": 100,
                                }
                            },
                            {
                                "status_list": {
                                    "uri": "http://test.com/status2",
                                    "idx": 200,
                                }
                            },
                        ],
                        "mso_mdoc": [
                            {
                                "identifier_list": {
                                    "uri": "http://test.com/identifier",
                                    "id": b"doc1",
                                }
                            }
                        ],
                    },
                    "expires": datetime.now() + timedelta(minutes=10),
                }
            },
        ), patch("app.services.revocation_status.requests.post") as mock_post, patch(
            "app.routes.revocation.post_redirect_with_payload"
        ) as mock_redirect:

            mock_post.return_value.status_code = 200
            mock_redirect.return_value = "redirect_response"

            _set_session(client, revocation_id=revocation_id)

            response = client.post(
                "/revocation/revoke", data={"revocation_identifier": revocation_id}
            )

            # Should make 3 API calls
            assert mock_post.call_count == 3

    def test_revoke_cleans_up_request(self, client, mock_config):
        """Test that revoke removes the request from storage."""
        revocation_id = "test_revoc_id"

        mock_revoc_req = {
            revocation_id: {
                "status_lists": {
                    "dc+sd-jwt": [
                        {"status_list": {"uri": "http://test.com/status", "idx": 123}}
                    ],
                    "mso_mdoc": [],
                },
                "expires": datetime.now() + timedelta(minutes=10),
            }
        }

        with patch("app.routes.revocation.revocation_requests", mock_revoc_req), patch(
            "app.services.revocation_status.requests.post"
        ) as mock_post, patch(
            "app.routes.revocation.post_redirect_with_payload"
        ) as mock_redirect:

            mock_post.return_value.status_code = 200
            mock_redirect.return_value = "redirect_response"

            # Verify identifier exists before
            assert revocation_id in mock_revoc_req

            _set_session(client, revocation_id=revocation_id)

            response = client.post(
                "/revocation/revoke", data={"revocation_identifier": revocation_id}
            )

            # Verify identifier is removed after
            assert revocation_id not in mock_revoc_req


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_vp_token_list(self, client, mock_config):
        """Test handling of empty vp_token list."""
        with patch("app.services.oid4vp.requests.request") as mock_request, patch(
            "app.routes.revocation.post_redirect_with_payload"
        ) as mock_redirect, patch(
            "app.routes.revocation.generate_unique_id"
        ) as mock_id, patch(
            "app.routes.revocation.revocation_requests", {}
        ), patch(
            "app.routes.revocation.session", {"oid4vp_cross_device_id": "valid_id"}
        ) as mock_session:

            mock_id.return_value = "unique_id"

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "vp_token": {},
                "presentation_submission": {"descriptor_map": []},
            }
            mock_request.return_value = mock_response

            mock_redirect.return_value = "redirect_response"
            
            mock_session['session_id'] = "session_abc123"

            response = client.get("/revocation/getoid4vp?presentation_id=valid_id")

            # Should handle gracefully
            assert mock_redirect.called

    def test_status_without_uri_parsing(self, client, mock_config):
        """A status list URI too short to parse is kept for revocation but not displayed."""
        with patch("app.services.oid4vp.requests.request") as mock_request, patch(
            "app.routes.revocation.get_status_sdjwt"
        ) as mock_status_sdjwt, patch(
            "app.routes.revocation.post_redirect_with_payload"
        ) as mock_redirect, patch(
            "app.routes.revocation.generate_unique_id", return_value="unique_id"
        ), patch.dict(
            "app.routes.revocation.revocation_requests", {}, clear=True
        ) as requests_store:
            _set_session(client, session_id="session_abc123", query_0="dc+sd-jwt")
            mock_request.return_value = _verifier_response({"query_0": ["sdjwt_token"]})
            status = {"status_list": {"uri": "http://test.com/short", "idx": 123}}
            mock_status_sdjwt.return_value = status
            mock_redirect.return_value = "redirect_response"

            response = client.get("/revocation/getoid4vp?presentation_id=valid_id")

            assert response.status_code == 200
            payload = mock_redirect.call_args[1]["data_payload"]
            assert payload["display_list"] == {"dc+sd-jwt": [], "mso_mdoc": []}
            assert requests_store["unique_id"]["status_lists"]["dc+sd-jwt"] == [status]

    def test_status_without_status_list_or_identifier_list(
        self, client, mock_config
    ):
        """Test credential status without status_list or identifier_list."""
        revocation_id = "test_revoc_id"

        with patch(
            "app.routes.revocation.revocation_requests",
            {
                revocation_id: {
                    "status_lists": {
                        "dc+sd-jwt": [{"other_field": "no status or identifier list"}],
                        "mso_mdoc": [],
                    },
                    "expires": datetime.now() + timedelta(minutes=10),
                }
            },
        ), patch("app.services.revocation_status.requests.post") as mock_post, patch(
            "app.routes.revocation.post_redirect_with_payload"
        ) as mock_redirect:

            mock_redirect.return_value = "redirect_response"

            _set_session(client, revocation_id=revocation_id)

            response = client.post(
                "/revocation/revoke", data={"revocation_identifier": revocation_id}
            )

            # Should not make any API calls
            assert not mock_post.called
            # But should still redirect
            assert mock_redirect.called

    def test_url_quote_encoding(self, client, mock_config):
        """Test that URIs are properly URL-encoded."""
        revocation_id = "test_revoc_id"

        with patch(
            "app.routes.revocation.revocation_requests",
            {
                revocation_id: {
                    "status_lists": {
                        "dc+sd-jwt": [
                            {
                                "status_list": {
                                    "uri": "http://test.com/status?param=value&other=test",
                                    "idx": 123,
                                }
                            }
                        ],
                        "mso_mdoc": [],
                    },
                    "expires": datetime.now() + timedelta(minutes=10),
                }
            },
        ), patch("app.services.revocation_status.requests.post") as mock_post, patch(
            "app.routes.revocation.post_redirect_with_payload"
        ) as mock_redirect:
            # no need to patch revocation_api_key separately
            mock_post.return_value.status_code = 200
            mock_redirect.return_value = "redirect_response"

            _set_session(client, revocation_id=revocation_id)

            response = client.post(
                "/revocation/revoke", data={"revocation_identifier": revocation_id}
            )

            # Ensure the endpoint worked
            assert response.status_code in (200, 302)

            # Verify that the request payload properly encoded the URI
            call_args = mock_post.call_args
            assert call_args is not None, "requests.post was not called"
            payload = call_args.kwargs.get("data") or call_args[1]["data"]

            # The payload is now a dict: requests form-encodes it, so the raw
            # URI must be passed through unchanged (no manual quoting).
            assert payload["uri"] == "http://test.com/status?param=value&other=test"
            assert payload["idx"] == 123
            assert payload["status"] == 1

    def test_qr_code_generation(
        self, client, mock_config, mock_oidc_metadata
    ):
        """Test QR code generation process."""
        with patch("app.services.oid4vp.requests.request") as mock_request, patch(
            "app.utils.qr.segno.make"
        ) as mock_qr, patch(
            "app.routes.revocation.post_redirect_with_payload"
        ) as mock_redirect:

            mock_response = Mock()
            mock_response.json.return_value = {
                "client_id": "test_client",
                "request_uri": "http://test.com/request",
                "transaction_id": "test_transaction",
            }
            mock_request.return_value = mock_response

            # Create a mock QR code object
            mock_qr_obj = Mock()
            mock_out = io.BytesIO()
            mock_out.write(b"fake_png_data")
            mock_out.seek(0)

            def save_side_effect(out, **kwargs):
                out.write(b"fake_png_data")

            mock_qr_obj.save = Mock(side_effect=save_side_effect)
            mock_qr.return_value = mock_qr_obj

            mock_redirect.return_value = "redirect_response"

            response = client.post(
                "/revocation/oid4vp_call",
                data={"test_sdjwt_credential": "on", "proceed": "true"},
            )

            # Verify QR code was generated
            assert mock_qr.called
            assert mock_qr_obj.save.called

            # Verify redirect was called with QR code data
            call_args = mock_redirect.call_args
            assert "qrcode" in call_args[1]["data_payload"]
            assert call_args[1]["data_payload"]["qrcode"].startswith(
                "data:image/png;base64,"
            )


class TestDataStructures:
    """Test data structure handling and transformations."""

    def test_dcql_query_structure_sdjwt(
        self, client, mock_config, mock_oidc_metadata
    ):
        """Test DCQL query structure for SD-JWT credentials."""
        with patch("app.services.oid4vp.requests.request") as mock_request, patch(
            "app.utils.qr.segno.make"
        ), patch("app.routes.revocation.post_redirect_with_payload"):

            mock_response = Mock()
            mock_response.json.return_value = {
                "client_id": "test_client",
                "request_uri": "http://test.com/request",
                "transaction_id": "test_transaction",
            }
            mock_request.return_value = mock_response

            client.post(
                "/revocation/oid4vp_call",
                data={"test_sdjwt_credential": "on", "proceed": "true"},
            )

            # Verify the request payload structure
            call_args = mock_request.call_args_list[0]  # First call (cross-device)
            payload = json.loads(call_args[1]["data"])

            assert "dcql_query" in payload
            assert "credentials" in payload["dcql_query"]
            assert len(payload["dcql_query"]["credentials"]) == 1

            cred = payload["dcql_query"]["credentials"][0]
            assert cred["format"] == "dc+sd-jwt"
            assert "meta" in cred
            assert "vct_values" in cred["meta"]
            # Only the first mandatory claim; SD-JWT omits intent_to_retain.
            assert cred["claims"] == [{"path": ["claim2"]}]

    def test_dcql_query_structure_mdoc(
        self, client, mock_config, mock_oidc_metadata
    ):
        """Test DCQL query structure for mDoc credentials."""
        with patch("app.services.oid4vp.requests.request") as mock_request, patch(
            "app.utils.qr.segno.make"
        ), patch("app.routes.revocation.post_redirect_with_payload"):

            mock_response = Mock()
            mock_response.json.return_value = {
                "client_id": "test_client",
                "request_uri": "http://test.com/request",
                "transaction_id": "test_transaction",
            }
            mock_request.return_value = mock_response

            client.post(
                "/revocation/oid4vp_call",
                data={"test_mdoc_credential": "on", "proceed": "true"},
            )

            call_args = mock_request.call_args_list[0]
            payload = json.loads(call_args[1]["data"])

            cred = payload["dcql_query"]["credentials"][0]
            assert cred["format"] == "mso_mdoc"
            assert "meta" in cred
            assert "doctype_value" in cred["meta"]
            assert cred["claims"] == [{"path": ["namespace", "claim2"], "intent_to_retain": False}]

    def test_display_list_parsing(self, client, mock_config):
        """Status list URIs are parsed into the doctype / list identifier display list."""
        with patch("app.services.oid4vp.requests.request") as mock_request, patch(
            "app.routes.revocation.get_status_sdjwt"
        ) as mock_status, patch(
            "app.routes.revocation.post_redirect_with_payload"
        ) as mock_redirect, patch(
            "app.routes.revocation.generate_unique_id", return_value="revocation_id"
        ), patch.dict("app.routes.revocation.revocation_requests", {}, clear=True):
            _set_session(client, session_id="session_abc123", query_0="dc+sd-jwt")
            mock_request.return_value = _verifier_response({"query_0": ["xyz789"]})
            mock_status.return_value = {
                "status_list": {
                    "uri": "http://test.com/api/status/my_doctype/list_identifier_123",
                    "idx": 456,
                }
            }
            mock_redirect.return_value = "redirect_response"

            client.get("/revocation/getoid4vp?presentation_id=valid_id")

            mock_status.assert_called_once_with("xyz789")
            payload = mock_redirect.call_args[1]["data_payload"]
            assert payload["revocation_identifier"] == "revocation_id"
            display_list = payload["display_list"]
            assert display_list["mso_mdoc"] == []
            assert display_list["dc+sd-jwt"] == [
                {"doctype": "my_doctype", "status_list_identifier": "list_identifier_123"}
            ]

    def test_oid4vp_call_post_with_mdoc(
        self, client, mock_config, mock_oidc_metadata
    ):
        """Test POST request to oid4vp_call with mDoc credential."""
        with patch("app.services.oid4vp.requests.request") as mock_request, patch(
            "app.utils.qr.segno.make"
        ) as mock_qr, patch(
            "app.routes.revocation.post_redirect_with_payload"
        ) as mock_redirect:

            mock_response = Mock()
            mock_response.json.return_value = {
                "client_id": "test_client",
                "request_uri": "http://test.com/request",
                "transaction_id": "test_transaction",
            }
            mock_request.return_value = mock_response

            mock_qr_obj = Mock()
            mock_qr_obj.save = Mock()
            mock_qr.return_value = mock_qr_obj

            mock_redirect.return_value = "redirect_response"

            response = client.post(
                "/revocation/oid4vp_call",
                data={"test_mdoc_credential": "on", "proceed": "true"},
            )

            assert mock_request.call_count == 2
            assert mock_redirect.called

            # Same-device transaction id is kept in the browser session.
            with client.session_transaction() as sess:
                assert sess["oid4vp_transaction_id"] == "test_transaction"
                assert sess["query_0"] == "mso_mdoc"

    def test_oid4vp_call_post_with_multiple_credentials(
        self, client, mock_config, mock_oidc_metadata
    ):
        """Test POST request to oid4vp_call with multiple credentials."""
        with patch("app.services.oid4vp.requests.request") as mock_request, patch(
            "app.utils.qr.segno.make"
        ) as mock_qr, patch(
            "app.routes.revocation.post_redirect_with_payload"
        ) as mock_redirect:

            mock_response = Mock()
            mock_response.json.return_value = {
                "client_id": "test_client",
                "request_uri": "http://test.com/request",
                "transaction_id": "test_transaction",
            }
            mock_request.return_value = mock_response

            mock_qr_obj = Mock()
            mock_qr_obj.save = Mock()
            mock_qr.return_value = mock_qr_obj

            mock_redirect.return_value = "redirect_response"

            response = client.post(
                "/revocation/oid4vp_call",
                data={
                    "test_sdjwt_credential": "on",
                    "test_mdoc_credential": "on",
                    "proceed": "true",
                },
            )

            assert mock_request.call_count == 2
            assert mock_redirect.called

class TestOid4vpGet:
    """Test /getoid4vp endpoint."""

    def test_oid4vp_get_invalid_presentation_id(self, client, mock_config):
        """A presentation_id with unexpected characters is rejected."""
        _set_session(client, session_id="session_abc123")
        response = client.get("/revocation/getoid4vp?presentation_id=invalid/id!")
        assert response.status_code == 400
        assert "Invalid Presentation id format" in response.get_json()["error_description"]

    def test_oid4vp_get_missing_parameters(self, client, mock_config):
        """Neither same-device nor cross-device parameters -> 400 (no session needed)."""
        response = client.get("/revocation/getoid4vp")

        assert response.status_code == 400
        assert b"Missing required parameters" in response.data

    def test_oid4vp_get_api_error(self, client, mock_config):
        """A verifier error is reported as 400 with its status code."""
        _set_session(client, session_id="session_abc123")
        with patch("app.services.oid4vp.requests.request") as mock_request:
            mock_request.return_value = Mock(status_code=500)

            response = client.get("/revocation/getoid4vp?presentation_id=valid_id")

            assert response.status_code == 400
            assert response.get_json() == {"error": "500"}
            assert mock_request.call_args[0][1] == "http://test.com/presentation/valid_id"

    def test_oid4vp_get_same_device_uses_stored_transaction(self, client, mock_config):
        """The same-device flow fetches the result of the transaction stored by oid4vp_call."""
        _set_session(client, session_id="session_abc123", oid4vp_transaction_id="tx_same")
        with patch("app.services.oid4vp.requests.request") as mock_request:
            mock_request.return_value = Mock(status_code=500)

            client.get("/revocation/getoid4vp?response_code=rc123&session_id=session_abc123")

            url = mock_request.call_args[0][1]
            assert url.endswith("/tx_same?response_code=rc123")

    def test_oid4vp_get_mixed_credentials(self, client, mock_config):
        """SD-JWT and mdoc presentations are both turned into revocation entries."""
        with patch("app.services.oid4vp.requests.request") as mock_request, patch(
            "app.routes.revocation.get_status_sdjwt"
        ) as mock_status_sdjwt, patch(
            "app.routes.revocation.get_status_mdoc"
        ) as mock_status_mdoc, patch(
            "app.routes.revocation.post_redirect_with_payload"
        ) as mock_redirect, patch(
            "app.routes.revocation.generate_unique_id", return_value="unique_revoc_id"
        ), patch.dict(
            "app.routes.revocation.revocation_requests", {}, clear=True
        ) as requests_store:
            _set_session(client, session_id="session_abc123", query_0="dc+sd-jwt", query_1="mso_mdoc")
            mock_request.return_value = _verifier_response(
                {"query_0": ["sdjwt_token"], "query_1": ["mdoc_token"]}
            )
            sdjwt_status = {"status_list": {"uri": "http://test.com/api/status/sdjwt/id", "idx": 1}}
            mdoc_statuses = [
                {"status_list": {"uri": "http://test.com/api/status/mdoc/id", "idx": 2}},
                {"status_list": {"uri": "http://test.com/api/status/mdoc/id2", "idx": 3}},
            ]
            mock_status_sdjwt.return_value = sdjwt_status
            mock_status_mdoc.return_value = mdoc_statuses  # multi-document mdoc
            mock_redirect.return_value = "redirect_response"

            response = client.get("/revocation/getoid4vp?presentation_id=valid_id")

            assert response.status_code == 200
            mock_status_sdjwt.assert_called_once_with("sdjwt_token")
            mock_status_mdoc.assert_called_once_with("mdoc_token")
            stored = requests_store["unique_revoc_id"]["status_lists"]
            assert stored == {"dc+sd-jwt": [sdjwt_status], "mso_mdoc": mdoc_statuses}
            display_list = mock_redirect.call_args[1]["data_payload"]["display_list"]
            assert display_list["dc+sd-jwt"] == [{"doctype": "sdjwt", "status_list_identifier": "id"}]
            assert [d["status_list_identifier"] for d in display_list["mso_mdoc"]] == ["id", "id2"]


class TestRevokeBatch:
    """Revoking one presented instance revokes its whole batch (#167)."""

    def test_siblings_are_revoked_once(self, client, mock_config):
        revocation_id = "batch_revoc_id"
        presented = {"status_list": {"uri": "http://test.com/status", "idx": 1}}
        siblings = [
            {"status_list": {"uri": "http://test.com/status", "idx": idx}, "identifier_list": {"uri": "http://test.com/ids", "id": f"id{idx}"}}
            for idx in range(3)
        ]

        with patch(
            "app.routes.revocation.revocation_requests",
            {
                revocation_id: {
                    "status_lists": {"dc+sd-jwt": [], "mso_mdoc": [presented]},
                    "expires": datetime.now() + timedelta(minutes=10),
                }
            },
        ), patch("app.routes.revocation.batch_status_entries", return_value=siblings) as lookup, patch(
            "app.services.revocation_status.requests.post"
        ) as mock_post, patch("app.routes.revocation.post_redirect_with_payload", return_value="ok"):
            mock_post.return_value.status_code = 200
            _set_session(client, revocation_id=revocation_id)

            client.post("/revocation/revoke", data={"revocation_identifier": revocation_id})

        lookup.assert_called_once_with(presented)
        sent = [c.kwargs["data"] for c in mock_post.call_args_list]
        # 3 status_list idx + 3 identifier_list ids; the presented idx 1 only once
        assert mock_post.call_count == 6
        assert sorted(d["idx"] for d in sent if "idx" in d) == [0, 1, 2]
        assert sorted(d["id"] for d in sent if "id" in d) == ["id0", "id1", "id2"]

    def test_unknown_batch_revokes_presented_entry(self, client, mock_config):
        revocation_id = "single_revoc_id"
        with patch(
            "app.routes.revocation.revocation_requests",
            {
                revocation_id: {
                    "status_lists": {"dc+sd-jwt": [{"status_list": {"uri": "http://test.com/status", "idx": 5}}], "mso_mdoc": []},
                    "expires": datetime.now() + timedelta(minutes=10),
                }
            },
        ), patch("app.routes.revocation.batch_status_entries", return_value=[]), patch(
            "app.services.revocation_status.requests.post"
        ) as mock_post, patch("app.routes.revocation.post_redirect_with_payload", return_value="ok"):
            mock_post.return_value.status_code = 200
            _set_session(client, revocation_id=revocation_id)

            client.post("/revocation/revoke", data={"revocation_identifier": revocation_id})

        assert [c.kwargs["data"]["idx"] for c in mock_post.call_args_list] == [5]
