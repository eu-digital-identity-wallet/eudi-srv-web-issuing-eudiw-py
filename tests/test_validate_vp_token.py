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
import pytest
import base64
import cbor2
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone
from pycose.headers import X5chain

from app.validate_vp_token import validate_vp_token, validate_certificate


class TestValidateVpToken:
    def test_missing_vp_token(self):
        result = validate_vp_token({}, credentials_requested=[])
        assert result == (
            True,
            "The path value from presentation_submission is not valid.",
        )

    def test_missing_query_0(self):
        result = validate_vp_token({"vp_token": {}}, credentials_requested=[])
        assert result == (
            True,
            "The path value from presentation_submission is not valid.",
        )

    def test_vp_token_invalid_base64_padding(self):
        """Invalid Base64 should raise a decode error."""
        valid_cbor = {"status": 0, "documents": [{}]}
        encoded = base64.urlsafe_b64encode(cbor2.dumps(valid_cbor)).decode()
        data = {"vp_token": {"query_0": [encoded[:-2]]}}  # corrupted padding

        with patch(
            "app.validate_vp_token.cbor2.decoder.loads",
            side_effect=ValueError("bad b64"),
        ), patch("app.validate_vp_token.validate_certificate", return_value=(True, "")):
            with pytest.raises(ValueError, match="bad b64"):
                validate_vp_token(data, credentials_requested=[])

    def test_vp_token_invalid_status(self):
        mdoc_cbor = {"status": 1}
        encoded = base64.urlsafe_b64encode(cbor2.dumps(mdoc_cbor)).decode()
        data = {"vp_token": {"query_0": [encoded]}}
        result = validate_vp_token(data, credentials_requested=[])
        assert result == (True, "Status invalid:1")

    def test_vp_token_calls_validate_certificate(self):
        mdoc_cbor = {"status": 0, "documents": [{}]}
        encoded = base64.urlsafe_b64encode(cbor2.dumps(mdoc_cbor)).decode()
        data = {"vp_token": {"query_0": [encoded]}}
        with patch(
            "app.validate_vp_token.validate_certificate", return_value=(True, "")
        ) as mock_val:
            result = validate_vp_token(data, credentials_requested=[])
        mock_val.assert_called_once()
        assert result == (False, "")


class TestValidateCertificate:
    def make_mock_cert(self, issuer="Fake CA"):
        mock_cert = MagicMock()
        mock_cert.issuer = issuer

        mock_pub_numbers = MagicMock()
        mock_pub_numbers.x = MagicMock()
        mock_pub_numbers.y = MagicMock()
        mock_pub_numbers.x.to_bytes.return_value = b"x"
        mock_pub_numbers.y.to_bytes.return_value = b"y"

        mock_pub_key = MagicMock()
        mock_pub_key.public_numbers.return_value = mock_pub_numbers
        mock_cert.public_key.return_value = mock_pub_key

        mock_cert.signature = b"sig"
        mock_cert.tbs_certificate_bytes = b"bytes"
        mock_cert.signature_hash_algorithm = MagicMock()
        return mock_cert

    @patch("app.validate_vp_token.trusted_CAs", {})
    def test_certificate_not_trusted(self):
        mock_cert = self.make_mock_cert("Fake CA")
        mdoc = {"issuerSigned": {"issuerAuth": b"auth"}}
        with patch("app.validate_vp_token.Sign1Message.decode") as mock_decode, patch(
            "app.validate_vp_token.x509.load_der_x509_certificate",
            return_value=mock_cert,
        ):
            message = MagicMock()
            message.payload = b"payload"
            message.phdr = {}
            message.uhdr = {X5chain: b"chain"}
            message.signature = b"sig"
            mock_decode.return_value = message
            result = validate_certificate(mdoc)
        assert result == (False, "Certificate wasn't emitted by a Trusted CA ")

    @patch(
        "app.validate_vp_token.trusted_CAs",
        {
            "Fake CA": {
                "public_key": MagicMock(),
                "not_valid_before": datetime.now(timezone.utc) - timedelta(days=1),
                "not_valid_after": datetime.now(timezone.utc) + timedelta(days=1),
            }
        },
    )
    def test_certificate_expired(self):
        mock_cert = self.make_mock_cert()
        mdoc = {
            "issuerSigned": {"issuerAuth": b"auth", "nameSpaces": {"ns": []}},
            "docType": "PID",
        }
        with patch("app.validate_vp_token.Sign1Message.decode") as mock_decode, patch(
            "app.validate_vp_token.x509.load_der_x509_certificate",
            return_value=mock_cert,
        ), patch("app.validate_vp_token.datetime") as mock_datetime:
            message = MagicMock()
            message.payload = cbor2.dumps(
                cbor2.CBORTag(
                    24,
                    cbor2.dumps(
                        {
                            "docType": "PID",
                            "digestAlgorithm": "SHA-256",
                            "valueDigests": {"ns": {}},
                            "validityInfo": {
                                "signed": datetime.now(timezone.utc),
                                "validFrom": datetime.now(timezone.utc)
                                - timedelta(days=2),
                                "validUntil": datetime.now(timezone.utc)
                                + timedelta(days=2),
                            },
                        }
                    ),
                )
            )
            message.phdr = {}
            message.uhdr = {X5chain: b"chain"}
            message.signature = b"sig"
            mock_decode.return_value = message
            mock_datetime.datetime.now.return_value = datetime.now(
                timezone.utc
            ) + timedelta(days=10)
            mock_datetime.timezone.utc = timezone.utc
            result = validate_certificate(mdoc)
        assert result == (False, "Certificate not valid")

    @patch(
        "app.validate_vp_token.trusted_CAs",
        {
            "Fake CA": {
                "public_key": MagicMock(),
                "not_valid_before": datetime.now(timezone.utc) - timedelta(days=1),
                "not_valid_after": datetime.now(timezone.utc) + timedelta(days=1),
            }
        },
    )
    def test_valid_certificate_success(self):
        mock_cert = self.make_mock_cert()
        mdoc = {
            "issuerSigned": {"issuerAuth": b"auth", "nameSpaces": {"ns": []}},
            "docType": "PID",
        }
        with patch("app.validate_vp_token.Sign1Message.decode") as mock_decode, patch(
            "app.validate_vp_token.x509.load_der_x509_certificate",
            return_value=mock_cert,
        ):
            message = MagicMock()
            message.payload = cbor2.dumps(
                cbor2.CBORTag(
                    24,
                    cbor2.dumps(
                        {
                            "docType": "PID",
                            "digestAlgorithm": "SHA-256",
                            "valueDigests": {"ns": {}},
                            "validityInfo": {
                                "signed": datetime.now(timezone.utc),
                                "validFrom": datetime.now(timezone.utc)
                                - timedelta(days=2),
                                "validUntil": datetime.now(timezone.utc)
                                + timedelta(days=2),
                            },
                        }
                    ),
                )
            )
            message.phdr = {}
            message.uhdr = {X5chain: b"chain"}
            message.signature = b"sig"
            message.verify_signature.return_value = True
            mock_decode.return_value = message
            result = validate_certificate(mdoc)
        assert result == (True, "")

    def test_decode_failure(self):
        """If Sign1Message.decode fails, the exception should propagate."""
        with patch(
            "app.validate_vp_token.Sign1Message.decode",
            side_effect=ValueError("decode fail"),
        ):
            with pytest.raises(ValueError, match="decode fail"):
                validate_certificate({"issuerSigned": {"issuerAuth": b"auth"}})

    def test_type_error_in_ec_key(self):
        mock_cert = self.make_mock_cert()
        mock_cert.public_key().public_numbers().x.to_bytes.side_effect = TypeError(
            "bad type"
        )
        with patch("app.validate_vp_token.Sign1Message.decode") as mock_decode, patch(
            "app.validate_vp_token.x509.load_der_x509_certificate",
            return_value=mock_cert,
        ), patch(
            "app.validate_vp_token.trusted_CAs",
            {
                "Fake CA": {
                    "public_key": MagicMock(),
                    "not_valid_before": datetime.now(timezone.utc),
                    "not_valid_after": datetime.now(timezone.utc) + timedelta(days=1),
                }
            },
        ):
            message = MagicMock()
            message.payload = b"payload"
            message.uhdr = {X5chain: b"chain"}
            mock_decode.return_value = message
            with pytest.raises(TypeError):
                validate_certificate({"issuerSigned": {"issuerAuth": b"auth"}})
