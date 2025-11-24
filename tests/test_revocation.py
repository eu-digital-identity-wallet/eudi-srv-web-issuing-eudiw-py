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
import uuid
from datetime import datetime, timedelta
from unittest.mock import MagicMock, Mock, patch, call
import cbor2
import pytest
import segno
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
import jwt

from app import revocation
from app.revocation import (
    b64url_decode,
    extract_public_key_from_x5c,
    verify_and_decode_sdjwt,
    get_status_sdjwt,
    get_status_mdoc,
)


@pytest.fixture
def client():
    """Create a test client for the Flask app."""
    from flask import Flask

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret-key"
    app.config["TESTING"] = True
    app.register_blueprint(revocation.revocation)

    with app.test_client() as client:
        yield client


@pytest.fixture
def mock_config():
    """Mock configuration service."""
    with patch("app.revocation.cfgservice") as mock:
        mock.service_url = "http://test.com/"
        mock.dynamic_presentation_url = "http://test.com/presentation/"
        mock.default_frontend = "default"
        mock.deffered_expiry = 15
        mock.revocation_code_expiry = 10
        mock.revoke_service_url = "http://test.com/revoke"
        mock.revocation_api_key = "test_api_key"
        mock.app_logger = MagicMock()
        yield mock


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
                    "claims": [{"path": ["claim1"]}, {"path": ["claim2"]}],
                },
            },
            "test_mdoc_credential": {
                "format": "mso_mdoc",
                "doctype": "test.doctype",
                "credential_metadata": {
                    "display": [{"name": "Test mDoc Credential"}],
                    "claims": [
                        {"path": ["namespace", "claim1"]},
                        {"path": ["namespace", "claim2"]},
                    ],
                },
            },
        }
    }
    with patch("app.revocation.oidc_metadata", metadata):
        yield metadata


@pytest.fixture
def mock_frontend_config():
    """Mock frontend configuration."""
    with patch("app.revocation.ConfFrontend") as mock:
        mock.registered_frontends = {"default": {"url": "http://frontend.test.com"}}
        yield mock


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


class TestExtractPublicKeyFromX5c:
    """Test extract_public_key_from_x5c function."""

    def test_extract_rsa_public_key(self, rsa_key_pair, x509_cert):
        """Test extracting RSA public key from x5c header."""
        private_key, _ = rsa_key_pair

        cert_der = x509_cert.public_bytes(serialization.Encoding.DER)
        cert_b64 = base64.urlsafe_b64encode(cert_der).decode("utf-8").rstrip("=")

        payload = {"test": "data"}
        token = jwt.encode(
            payload, private_key, algorithm="RS256", headers={"x5c": [cert_b64]}
        )

        public_key, alg = extract_public_key_from_x5c(token)

        assert isinstance(public_key, rsa.RSAPublicKey)
        assert alg == "RS256"

    def test_extract_missing_x5c(self, rsa_key_pair):
        """Test extracting public key when x5c header is missing."""
        private_key, _ = rsa_key_pair

        payload = {"test": "data"}
        token = jwt.encode(payload, private_key, algorithm="RS256")

        with pytest.raises(ValueError, match="x5c header not found in JWT"):
            extract_public_key_from_x5c(token)

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
            extract_public_key_from_x5c(token)


class TestVerifyAndDecodeSdjwt:
    """Test verify_and_decode_sdjwt function."""

    def test_verify_rsa_sdjwt(self, rsa_key_pair, x509_cert):
        """Test verifying SD-JWT with RSA signature."""
        private_key, _ = rsa_key_pair

        cert_der = x509_cert.public_bytes(serialization.Encoding.DER)
        cert_b64 = base64.urlsafe_b64encode(cert_der).decode("utf-8").rstrip("=")

        payload = {"status": {"idx": 123}, "test": "data"}
        token = jwt.encode(
            payload, private_key, algorithm="RS256", headers={"x5c": [cert_b64]}
        )

        # Create SD-JWT format (token without disclosures)
        sd_jwt = token + "~"

        with patch("app.revocation.SDJWTHolder") as mock_holder:
            mock_holder.return_value._unverified_input_sd_jwt = token
            result = verify_and_decode_sdjwt(sd_jwt)

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
        cert_b64 = base64.urlsafe_b64encode(cert_der).decode("utf-8").rstrip("=")

        payload = {"status": {"idx": 456}, "test": "ec_data"}
        token = jwt.encode(
            payload, private_key, algorithm="ES256", headers={"x5c": [cert_b64]}
        )

        sd_jwt = token + "~"

        with patch("app.revocation.SDJWTHolder") as mock_holder:
            mock_holder.return_value._unverified_input_sd_jwt = token
            result = verify_and_decode_sdjwt(sd_jwt)

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
        cert_b64 = base64.urlsafe_b64encode(cert_der).decode("utf-8").rstrip("=")

        payload = {"status": {"idx": 789}, "test": "ed25519_data"}
        token = jwt.encode(
            payload, private_key, algorithm="EdDSA", headers={"x5c": [cert_b64]}
        )

        sd_jwt = token + "~"

        with patch("app.revocation.SDJWTHolder") as mock_holder:
            mock_holder.return_value._unverified_input_sd_jwt = token
            result = verify_and_decode_sdjwt(sd_jwt)

        assert result["test"] == "ed25519_data"

    def test_verify_unsupported_key_type(self):
        """Test verifying SD-JWT with unsupported key type."""
        sd_jwt = "test~"

        with patch("app.revocation.SDJWTHolder") as mock_holder, patch(
            "app.revocation.extract_public_key_from_x5c"
        ) as mock_extract:

            mock_holder.return_value._unverified_input_sd_jwt = "test_token"
            # Mock an unsupported key type
            mock_extract.return_value = (Mock(spec=object), "RS256")

            with pytest.raises(ValueError, match="Unsupported key type"):
                verify_and_decode_sdjwt(sd_jwt)


class TestGetStatusSdjwt:
    """Test get_status_sdjwt function."""

    def test_get_status_sdjwt_success(self):
        """Test successfully getting status from SD-JWT."""
        sd_jwt = "test_jwt~"
        expected_status = {"status_list": {"idx": 123, "uri": "http://test.com"}}

        with patch("app.revocation.verify_and_decode_sdjwt") as mock_verify:
            mock_verify.return_value = {"status": expected_status, "other": "data"}

            result = get_status_sdjwt(sd_jwt)

            assert result == expected_status
            mock_verify.assert_called_once_with(sd_jwt)


class TestGetStatusMdoc:
    """Test get_status_mdoc function."""

    def test_get_status_single_document(self):
        """Test getting status from mdoc with single document."""
        status_data = {"status_list": {"idx": 1, "uri": "http://test.com"}}

        # Create mock mdoc structure
        issuer_auth = cbor2.dumps(
            cbor2.CBORTag(24, cbor2.dumps({"status": status_data}))
        )
        mdoc_data = {
            "documents": [{"issuerSigned": {"issuerAuth": [None, None, issuer_auth]}}]
        }

        mdoc_bytes = cbor2.dumps(mdoc_data)
        mdoc_b64 = base64.urlsafe_b64encode(mdoc_bytes).decode("utf-8").rstrip("=")

        result = get_status_mdoc(mdoc_b64)

        assert result == status_data
        assert isinstance(result, dict)

    def test_get_status_multiple_documents(self):
        """Test getting status from mdoc with multiple documents."""
        status_data_1 = {"status_list": {"idx": 1, "uri": "http://test1.com"}}
        status_data_2 = {"status_list": {"idx": 2, "uri": "http://test2.com"}}

        issuer_auth_1 = cbor2.dumps(
            cbor2.CBORTag(24, cbor2.dumps({"status": status_data_1}))
        )
        issuer_auth_2 = cbor2.dumps(
            cbor2.CBORTag(24, cbor2.dumps({"status": status_data_2}))
        )

        mdoc_data = {
            "documents": [
                {"issuerSigned": {"issuerAuth": [None, None, issuer_auth_1]}},
                {"issuerSigned": {"issuerAuth": [None, None, issuer_auth_2]}},
            ]
        }

        mdoc_bytes = cbor2.dumps(mdoc_data)
        mdoc_b64 = base64.urlsafe_b64encode(mdoc_bytes).decode("utf-8").rstrip("=")

        result = get_status_mdoc(mdoc_b64)

        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0] == status_data_1
        assert result[1] == status_data_2


class TestRevocationChoice:
    """Test /revocation_choice endpoint."""

    def test_revocation_choice_get(
        self, client, mock_config, mock_oidc_metadata, mock_frontend_config
    ):
        """Test GET request to revocation_choice."""
        with patch("app.revocation.post_redirect_with_payload") as mock_redirect:
            mock_redirect.return_value = "redirect_response"

            response = client.get("/revocation/revocation_choice")

            assert mock_redirect.called
            call_args = mock_redirect.call_args

            assert "display_revocation_choice" in call_args[1]["target_url"]
            assert "cred" in call_args[1]["data_payload"]
            assert "sd-jwt vc format" in call_args[1]["data_payload"]["cred"]
            assert "mdoc format" in call_args[1]["data_payload"]["cred"]


class TestOid4vpCall:
    """Test /oid4vp_call endpoint."""

    def test_revoke_with_identifier_list(
        self, client, mock_config, mock_frontend_config
    ):
        """Test revoking credentials with identifier_list."""
        revocation_id = "test_revoc_id"

        with patch(
            "app.revocation.revocation_requests",
            {
                revocation_id: {
                    "status_lists": {
                        "dc+sd-jwt": [],
                        "mso_mdoc": [
                            {
                                "identifier_list": {
                                    "uri": "http://test.com/identifier",
                                    "id": "abc123",
                                }
                            }
                        ],
                    },
                    "expires": datetime.now() + timedelta(minutes=10),
                }
            },
        ), patch("app.revocation.requests.post") as mock_post, patch(
            "app.revocation.post_redirect_with_payload"
        ) as mock_redirect:

            mock_post.return_value.status_code = 200
            mock_redirect.return_value = "redirect_response"

            response = client.post(
                "/revocation/revoke", data={"revocation_identifier": revocation_id}
            )

            assert mock_post.called

            # Verify the payload format
            call_args = mock_post.call_args
            assert "uri=" in call_args[1]["data"]
            assert "id=abc123" in call_args[1]["data"]
            assert "status=1" in call_args[1]["data"]

    def test_revoke_missing_identifier(self, client, mock_config):
        """Test revoke endpoint with missing identifier."""
        response = client.post("/revocation/revoke", data={})

        assert response.status_code == 400

    def test_revoke_invalid_identifier(self, client, mock_config):
        """Test revoke endpoint with invalid identifier."""
        with patch("app.revocation.revocation_requests", {}):
            response = client.post(
                "/revocation/revoke", data={"revocation_identifier": "invalid_id"}
            )

            assert response.status_code == 404

    def test_revoke_api_failure(self, client, mock_config, mock_frontend_config):
        """Test revoke when API call fails."""
        revocation_id = "test_revoc_id"

        with patch(
            "app.revocation.revocation_requests",
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
        ), patch("app.revocation.requests.post") as mock_post, patch(
            "app.revocation.post_redirect_with_payload"
        ) as mock_redirect:

            mock_post.return_value.status_code = 500
            mock_post.return_value.text = "Server error"
            mock_redirect.return_value = "redirect_response"

            response = client.post(
                "/revocation/revoke", data={"revocation_identifier": revocation_id}
            )

            # Should still redirect even if API fails
            assert mock_redirect.called

    def test_revoke_api_exception(self, client, mock_config, mock_frontend_config):
        """Test revoke when API call raises exception."""
        revocation_id = "test_revoc_id"

        with patch(
            "app.revocation.revocation_requests",
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
        ) as mock_revoc_req, patch("app.revocation.requests.post") as mock_post, patch(
            "app.revocation.post_redirect_with_payload"
        ) as mock_redirect:

            mock_post.side_effect = Exception("Connection error")
            mock_redirect.return_value = "redirect_response"

            response = client.post(
                "/revocation/revoke", data={"revocation_identifier": revocation_id}
            )

            # Should still redirect and clean up
            assert mock_redirect.called
            assert revocation_id not in mock_revoc_req

    def test_revoke_both_list_types(self, client, mock_config, mock_frontend_config):
        """Test revoking credentials with both status_list and identifier_list."""
        revocation_id = "test_revoc_id"

        with patch(
            "app.revocation.revocation_requests",
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
                                    "id": "xyz789",
                                },
                            }
                        ],
                        "mso_mdoc": [],
                    },
                    "expires": datetime.now() + timedelta(minutes=10),
                }
            },
        ), patch("app.revocation.requests.post") as mock_post, patch(
            "app.revocation.post_redirect_with_payload"
        ) as mock_redirect:

            mock_post.return_value.status_code = 200
            mock_redirect.return_value = "redirect_response"

            response = client.post(
                "/revocation/revoke", data={"revocation_identifier": revocation_id}
            )

            # Should make 2 API calls (one for identifier_list, one for status_list)
            assert mock_post.call_count == 2

    def test_revoke_multiple_credentials(
        self, client, mock_config, mock_frontend_config
    ):
        """Test revoking multiple credentials."""
        revocation_id = "test_revoc_id"

        with patch(
            "app.revocation.revocation_requests",
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
                                    "id": "doc1",
                                }
                            }
                        ],
                    },
                    "expires": datetime.now() + timedelta(minutes=10),
                }
            },
        ), patch("app.revocation.requests.post") as mock_post, patch(
            "app.revocation.post_redirect_with_payload"
        ) as mock_redirect:

            mock_post.return_value.status_code = 200
            mock_redirect.return_value = "redirect_response"

            response = client.post(
                "/revocation/revoke", data={"revocation_identifier": revocation_id}
            )

            # Should make 3 API calls
            assert mock_post.call_count == 3

    def test_revoke_cleans_up_request(self, client, mock_config, mock_frontend_config):
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

        with patch("app.revocation.revocation_requests", mock_revoc_req), patch(
            "app.revocation.requests.post"
        ) as mock_post, patch(
            "app.revocation.post_redirect_with_payload"
        ) as mock_redirect:

            mock_post.return_value.status_code = 200
            mock_redirect.return_value = "redirect_response"

            # Verify identifier exists before
            assert revocation_id in mock_revoc_req

            response = client.post(
                "/revocation/revoke", data={"revocation_identifier": revocation_id}
            )

            # Verify identifier is removed after
            assert revocation_id not in mock_revoc_req


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_vp_token_list(self, client, mock_config, mock_frontend_config):
        """Test handling of empty vp_token list."""
        with patch("app.revocation.requests.request") as mock_request, patch(
            "app.revocation.post_redirect_with_payload"
        ) as mock_redirect, patch(
            "app.revocation.generate_unique_id"
        ) as mock_id, patch(
            "app.revocation.revocation_requests", {}
        ):

            mock_id.return_value = "unique_id"

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "vp_token": [],
                "presentation_submission": {"descriptor_map": []},
            }
            mock_request.return_value = mock_response

            mock_redirect.return_value = "redirect_response"

            response = client.get("/revocation/getoid4vp?presentation_id=valid_id")

            # Should handle gracefully
            assert mock_redirect.called

    def test_status_without_uri_parsing(
        self, client, mock_config, mock_frontend_config
    ):
        """Test credential status with malformed URI that can't be parsed properly."""
        with patch("app.revocation.requests.request") as mock_request, patch(
            "app.revocation.get_status_sdjwt"
        ) as mock_status_sdjwt, patch(
            "app.revocation.post_redirect_with_payload"
        ) as mock_redirect, patch(
            "app.revocation.generate_unique_id"
        ) as mock_id, patch(
            "app.revocation.revocation_requests", {}
        ):

            mock_id.return_value = "unique_id"

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "vp_token": ["test_token"],
                "presentation_submission": {
                    "descriptor_map": [{"format": "dc+sd-jwt", "path": "$[0]"}]
                },
            }
            mock_request.return_value = mock_response

            # Return status with short URI path (will cause IndexError)
            mock_status_sdjwt.return_value = {
                "status_list": {
                    "uri": "http://test.com/short",  # Only has 1 path part
                    "idx": 123,
                }
            }

            mock_redirect.return_value = "redirect_response"

            # This will raise IndexError due to insufficient path parts
            with pytest.raises(IndexError):
                client.get("/revocation/getoid4vp?presentation_id=valid_id")

    def test_status_without_status_list_or_identifier_list(
        self, client, mock_config, mock_frontend_config
    ):
        """Test credential status without status_list or identifier_list."""
        revocation_id = "test_revoc_id"

        with patch(
            "app.revocation.revocation_requests",
            {
                revocation_id: {
                    "status_lists": {
                        "dc+sd-jwt": [{"other_field": "no status or identifier list"}],
                        "mso_mdoc": [],
                    },
                    "expires": datetime.now() + timedelta(minutes=10),
                }
            },
        ), patch("app.revocation.requests.post") as mock_post, patch(
            "app.revocation.post_redirect_with_payload"
        ) as mock_redirect:

            mock_redirect.return_value = "redirect_response"

            response = client.post(
                "/revocation/revoke", data={"revocation_identifier": revocation_id}
            )

            # Should not make any API calls
            assert not mock_post.called
            # But should still redirect
            assert mock_redirect.called

    def test_url_quote_encoding(self, client, mock_config, mock_frontend_config):
        """Test that URIs are properly URL-encoded."""
        revocation_id = "test_revoc_id"

        with patch(
            "app.revocation.revocation_requests",
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
        ), patch("app.revocation.requests.post") as mock_post, patch(
            "app.revocation.post_redirect_with_payload"
        ) as mock_redirect:
            # no need to patch revocation_api_key separately
            mock_post.return_value.status_code = 200
            mock_redirect.return_value = "redirect_response"

            response = client.post(
                "/revocation/revoke", data={"revocation_identifier": revocation_id}
            )

            # Ensure the endpoint worked
            assert response.status_code in (200, 302)

            # Verify that the request payload properly encoded the URI
            call_args = mock_post.call_args
            assert call_args is not None, "requests.post was not called"
            payload = call_args.kwargs.get("data") or call_args[1]["data"]

            # Make sure the payload contains a properly encoded URI
            assert "uri=" in payload
            # Either encoded '?' (%3F) or at least the param=value pair appears
            assert "%3F" in payload or "param=value" in payload

    def test_qr_code_generation(
        self, client, mock_config, mock_oidc_metadata, mock_frontend_config
    ):
        """Test QR code generation process."""
        with patch("app.revocation.requests.request") as mock_request, patch(
            "app.revocation.segno.make"
        ) as mock_qr, patch(
            "app.revocation.post_redirect_with_payload"
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
        self, client, mock_config, mock_oidc_metadata, mock_frontend_config
    ):
        """Test DCQL query structure for SD-JWT credentials."""
        with patch("app.revocation.requests.request") as mock_request, patch(
            "app.revocation.segno.make"
        ), patch("app.revocation.post_redirect_with_payload"):

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
            assert "claims" in cred

    def test_dcql_query_structure_mdoc(
        self, client, mock_config, mock_oidc_metadata, mock_frontend_config
    ):
        """Test DCQL query structure for mDoc credentials."""
        with patch("app.revocation.requests.request") as mock_request, patch(
            "app.revocation.segno.make"
        ), patch("app.revocation.post_redirect_with_payload"):

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

    def test_display_list_parsing(self, client, mock_config, mock_frontend_config):
        """Test parsing of status URIs into display list."""
        with patch("app.revocation.requests.request") as mock_request, patch(
            "app.revocation.get_status_sdjwt"
        ) as mock_status, patch(
            "app.revocation.post_redirect_with_payload"
        ) as mock_redirect, patch(
            "app.revocation.generate_unique_id"
        ), patch(
            "app.revocation.revocation_requests", {}
        ):

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "vp_token": ["test_token"],
                "presentation_submission": {
                    "descriptor_map": [{"format": "dc+sd-jwt", "path": "$[0]"}]
                },
            }
            mock_request.return_value = mock_response

            mock_status.return_value = {
                "status_list": {
                    "uri": "http://test.com/api/status/my_doctype/list_identifier_123",
                    "idx": 456,
                }
            }

            mock_redirect.return_value = "redirect_response"

            client.get("/revocation/getoid4vp?presentation_id=valid_id")

            # Verify display list parsing
            call_args = mock_redirect.call_args
            display_list = call_args[1]["data_payload"]["display_list"]

            assert "dc+sd-jwt" in display_list
            assert len(display_list["dc+sd-jwt"]) == 1
            assert display_list["dc+sd-jwt"][0]["doctype"] == "my_doctype"
            assert (
                display_list["dc+sd-jwt"][0]["status_list_identifier"]
                == "list_identifier_123"
            )

    def test_oid4vp_call_post_with_mdoc(
        self, client, mock_config, mock_oidc_metadata, mock_frontend_config
    ):
        """Test POST request to oid4vp_call with mDoc credential."""
        with patch("app.revocation.requests.request") as mock_request, patch(
            "app.revocation.segno.make"
        ) as mock_qr, patch(
            "app.revocation.post_redirect_with_payload"
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

    def test_oid4vp_call_post_with_multiple_credentials(
        self, client, mock_config, mock_oidc_metadata, mock_frontend_config
    ):
        """Test POST request to oid4vp_call with multiple credentials."""
        with patch("app.revocation.requests.request") as mock_request, patch(
            "app.revocation.segno.make"
        ) as mock_qr, patch(
            "app.revocation.post_redirect_with_payload"
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
        """Test GET request with invalid presentation_id."""
        with pytest.raises(ValueError, match="Invalid presentation_id"):
            client.get("/revocation/getoid4vp?presentation_id=invalid/id!")

    def test_oid4vp_get_missing_parameters(self, client, mock_config):
        """Test GET request with missing parameters."""
        response = client.get("/revocation/getoid4vp")

        assert response.status_code == 400
        assert b"Missing required parameters" in response.data

    def test_oid4vp_get_api_error(self, client, mock_config):
        """Test GET request when API returns error."""
        with patch("app.revocation.requests.request") as mock_request:
            mock_response = Mock()
            mock_response.status_code = 500
            mock_request.return_value = mock_response

            response = client.get("/revocation/getoid4vp?presentation_id=valid_id")

            assert response.status_code == 400

    def test_oid4vp_get_mixed_credentials(
        self, client, mock_config, mock_frontend_config
    ):
        """Test GET request with mixed SD-JWT and mDoc credentials."""
        with patch("app.revocation.requests.request") as mock_request, patch(
            "app.revocation.get_status_sdjwt"
        ) as mock_status_sdjwt, patch(
            "app.revocation.get_status_mdoc"
        ) as mock_status_mdoc, patch(
            "app.revocation.post_redirect_with_payload"
        ) as mock_redirect, patch(
            "app.revocation.generate_unique_id"
        ) as mock_id, patch(
            "app.revocation.revocation_requests", {}
        ):

            mock_id.return_value = "unique_revoc_id"

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "vp_token": ["sdjwt_token", "mdoc_token"],
                "presentation_submission": {
                    "descriptor_map": [
                        {"format": "dc+sd-jwt", "path": "$[0]"},
                        {"format": "mso_mdoc", "path": "$[1]"},
                    ]
                },
            }
            mock_request.return_value = mock_response

            mock_status_sdjwt.return_value = {
                "status_list": {"uri": "http://test.com/api/status/sdjwt/id", "idx": 1}
            }
            mock_status_mdoc.return_value = {
                "status_list": {"uri": "http://test.com/api/status/mdoc/id", "idx": 2}
            }

            mock_redirect.return_value = "redirect_response"

            response = client.get("/revocation/getoid4vp?presentation_id=valid_id")

            assert mock_status_sdjwt.called
            assert mock_status_mdoc.called
