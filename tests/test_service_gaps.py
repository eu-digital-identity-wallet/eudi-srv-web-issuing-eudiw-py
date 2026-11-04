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
"""Edge and failure paths: mdoc verification, country IdP connectors, small helpers."""

import base64
import datetime
from unittest.mock import MagicMock, patch

import cbor2
import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.core import state
from app.services import countries, revocation_status, vp_validation
from app.services.countries import CountryConnectorError
from app.services.formatters import mdocFormatter
from app.utils import encoding
from config_helpers import patch_configuration
from pki_helpers import ca_entry, make_cert

DOCTYPE = "eu.europa.ec.eudi.pid.1"


# ---------------------------------------------------------------------------
# mdoc verification (real signed mdoc, then tampered)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ds_key = ec.generate_private_key(ec.SECP256R1())
    ca = make_cert("Test IACA", "Test IACA", ca_key.public_key(), ca_key, ca=True)
    ds = make_cert("Test DS", "Test IACA", ds_key.public_key(), ca_key, ca=False)
    cert_path = tmp_path_factory.mktemp("pki") / "ds.der"
    cert_path.write_bytes(ds.public_bytes(serialization.Encoding.DER))
    return {
        "ca": ca,
        "ds_key_pem": ds_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
        "cert_path": str(cert_path),
    }


@pytest.fixture(scope="module")
def issued_document(pki):
    """A real PID mdoc document signed by a DS certificate under ``pki['ca']``."""
    device = ec.generate_private_key(ec.SECP256R1()).public_key()
    device_key = base64.urlsafe_b64encode(
        device.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).decode()
    config = {
        "revocation": {"enabled": False},
        "countries": {
            "FC": {
                "keys": {
                    "_default": {
                        "private_key": pki["ds_key_pem"],
                        "private_key_password": None,
                        "certificate_path": pki["cert_path"],
                    }
                }
            }
        },
    }
    with patch_configuration(config):
        encoded = mdocFormatter(
            {DOCTYPE: {"family_name": "Doe", "given_name": "Jane"}},
            {"doctype": DOCTYPE, "issuer_config": {"validity": 30, "namespace": DOCTYPE}},
            "FC",
            device_key,
            session_id=None,
        )
    issuer_signed = cbor2.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    return {"docType": DOCTYPE, "issuerSigned": issuer_signed}


@pytest.fixture
def trusted(pki):
    with patch.dict("app.core.state.trusted_CAs", {pki["ca"].subject: ca_entry(pki["ca"])}, clear=True):
        yield


def _device_response(document, status=0):
    return base64.urlsafe_b64encode(cbor2.dumps({"version": "1.0", "documents": [document], "status": status})).decode()


class TestValidateCertificate:
    def test_valid_chain(self, issued_document, trusted):
        assert vp_validation.validate_certificate(issued_document) == (True, "")

    def test_unknown_ca(self, issued_document):
        with patch.dict("app.core.state.trusted_CAs", {}, clear=True):
            assert vp_validation.validate_certificate(issued_document) == (False, vp_validation._UNTRUSTED_CA)

    def test_ca_signature_mismatch(self, issued_document, pki):
        impostor_key = ec.generate_private_key(ec.SECP256R1())
        impostor = make_cert("Test IACA", "Test IACA", impostor_key.public_key(), impostor_key, ca=True)
        with patch.dict("app.core.state.trusted_CAs", {impostor.subject: ca_entry(impostor)}, clear=True):
            assert vp_validation.validate_certificate(issued_document) == (False, vp_validation._UNTRUSTED_CA)

    def test_ca_outside_validity(self, issued_document, pki):
        entry = ca_entry(pki["ca"])
        entry["not_valid_after"] = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        with patch.dict("app.core.state.trusted_CAs", {pki["ca"].subject: entry}, clear=True):
            assert vp_validation.validate_certificate(issued_document) == (False, "Certificate not valid")

    def test_tampered_signature(self, issued_document, trusted):
        document = cbor2.loads(cbor2.dumps(issued_document))  # cbor2's C CBORTag cannot be deep-copied
        signature = bytearray(document["issuerSigned"]["issuerAuth"][3])
        signature[0] ^= 0xFF
        document["issuerSigned"]["issuerAuth"][3] = bytes(signature)
        assert vp_validation.validate_certificate(document) == (False, "Signature not valid")

    def test_doctype_mismatch(self, issued_document, trusted):
        document = {**issued_document, "docType": "org.iso.18013.5.1.mDL"}
        assert vp_validation.validate_certificate(document) == (False, "Doctype from MSO not equal to doctype in document")

    def test_tampered_element_fails_digest(self, issued_document, trusted):
        document = cbor2.loads(cbor2.dumps(issued_document))  # cbor2's C CBORTag cannot be deep-copied
        elements = document["issuerSigned"]["nameSpaces"][DOCTYPE]
        item = cbor2.loads(elements[0].value)
        item["elementValue"] = "Mallory"
        elements[0] = cbor2.CBORTag(24, cbor2.dumps(item))
        valid, reason = vp_validation.validate_certificate(document)
        assert valid is False and reason.startswith("Missing digests")

    def test_expired_document_signer_rejected(self, issued_document, trusted):
        """The DS certificate's own validity is checked, not only the CA's."""
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        with patch.object(vp_validation, "certificate_validity", return_value=(past - datetime.timedelta(days=30), past)):
            assert vp_validation.validate_certificate(issued_document) == (False, "Document signer certificate not valid")

    def test_validity_info_expired(self, issued_document, trusted):
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)

        class FrozenDatetime(datetime.datetime):
            @classmethod
            def now(cls, tz=None):
                return future

        # Keep the CA and DS certificates valid at the frozen time; only the MSO validity has expired.
        with patch.object(vp_validation.datetime, "datetime", FrozenDatetime), patch.object(
            vp_validation,
            "certificate_validity",
            return_value=(future - datetime.timedelta(days=400), future + datetime.timedelta(days=1)),
        ), patch.dict(
            "app.core.state.trusted_CAs",
            {
                k: {**v, "not_valid_after": future + datetime.timedelta(days=1)}
                for k, v in state.trusted_CAs.items()
            },
        ):
            assert vp_validation.validate_certificate(issued_document) == (False, "Period defined in ValidityInfo is invalid")


class TestValidateVpToken:
    def test_valid(self, issued_document, trusted):
        assert vp_validation.validate_vp_token({"vp_token": {"query_0": [_device_response(issued_document)]}}, []) == (False, "")

    def test_unpadded_token_is_accepted(self, issued_document, trusted):
        token = _device_response(issued_document).rstrip("=")
        assert vp_validation.validate_vp_token({"vp_token": {"query_0": [token]}}, [])[0] is False

    @pytest.mark.parametrize("body", [{}, {"vp_token": {}}, {"vp_token": {"query_1": []}}])
    def test_missing_token(self, body):
        assert vp_validation.validate_vp_token(body, []) == (True, "The path value from presentation_submission is not valid.")

    def test_error_status(self, issued_document):
        assert vp_validation.validate_vp_token({"vp_token": {"query_0": [_device_response(issued_document, 10)]}}, []) == (
            True,
            "Status invalid:10",
        )

    def test_untrusted_document(self, issued_document):
        with patch.dict("app.core.state.trusted_CAs", {}, clear=True):
            result = vp_validation.validate_vp_token({"vp_token": {"query_0": [_device_response(issued_document)]}}, [])
        assert result == (True, vp_validation._UNTRUSTED_CA)


# ---------------------------------------------------------------------------
# Country identity provider connectors
# ---------------------------------------------------------------------------


def _response(status=200, body=None, text=None):
    response = MagicMock(status_code=status)
    response.json.return_value = body or {}
    response.text = text if text is not None else ""
    if status >= 400:
        response.raise_for_status.side_effect = requests.HTTPError(str(status))
    return response


@pytest.fixture
def country_config():
    cfg = {
        "countries": {
            "XX": {
                "connection_type": "oauth",
                "auth": {
                    "base_url": "https://idp.test",
                    "client_id": "cid",
                    "client_secret": "secret",
                    "redirect_uri": "https://backend.test/dynamic/redirect",
                    "token_endpoint_headers": {"X-Extra": "1"},
                },
            },
            "EE": {
                "connection_type": "openid",
                "auth": {"base_url": "https://ee.test", "authorization_headers": {"X-A": "b"}},
                "custom_modifiers": {"_default": {"family_name": "surname"}},
            },
            "ZZ": {"connection_type": "saml"},
            "NOAUTH": {"connection_type": "oauth"},
        }
    }
    with patch_configuration(cfg) as config:
        yield config


class TestCountryConnectors:
    def test_metadata_falls_back_and_fails(self, country_config):
        with patch("app.services.countries.requests.get", side_effect=[_response(404), requests.ConnectionError("x")]):
            with pytest.raises(ValueError, match="No valid OAuth/OIDC metadata"):
                countries.get_metadata("https://idp.test")

    def test_metadata_second_document(self, country_config):
        with patch(
            "app.services.countries.requests.get",
            side_effect=[_response(200, {"issuer": "x"}), _response(200, {"token_endpoint": "https://idp.test/token"})],
        ) as get:
            assert countries.get_metadata("https://idp.test")["token_endpoint"] == "https://idp.test/token"
        assert get.call_args.args[0] == "https://idp.test/.well-known/openid-configuration"

    def test_token_exchange_basic_auth(self, country_config):
        with patch("app.services.countries.get_metadata", return_value={"token_endpoint": "https://idp.test/token"}), patch(
            "app.services.countries.requests.post", return_value=_response(200, {"access_token": "at"})
        ) as post:
            assert countries.exchange_authorization_code("XX", "code") == "at"
        headers = post.call_args.kwargs["headers"]
        assert headers["Authorization"] == "Basic " + base64.b64encode(b"cid:secret").decode()
        assert headers["X-Extra"] == "1"
        assert post.call_args.kwargs["data"]["code"] == "code"

    def test_preformatted_basic_secret(self, country_config):
        country_config["countries"]["XX"]["auth"]["client_secret"] = "Basic abc"
        with patch("app.services.countries.get_metadata", return_value={"token_endpoint": "t"}), patch(
            "app.services.countries.requests.post", return_value=_response(200, {"access_token": "at"})
        ) as post:
            countries.exchange_authorization_code("XX", "code")
        assert post.call_args.kwargs["headers"]["Authorization"] == "Basic abc"

    def test_token_exchange_without_auth_config(self, country_config):
        with pytest.raises(CountryConnectorError, match="Missing 'auth'"):
            countries.exchange_authorization_code("NOAUTH", "code")

    def test_token_exchange_without_client_secret(self, country_config):
        del country_config["countries"]["XX"]["auth"]["client_secret"]
        with patch("app.services.countries.get_metadata", return_value={"token_endpoint": "t"}):
            with pytest.raises(CountryConnectorError, match="Missing client_id or client_secret"):
                countries.exchange_authorization_code("XX", "code")

    @pytest.mark.parametrize("response", [_response(500), _response(200, {})])
    def test_token_exchange_failures(self, country_config, response):
        with patch("app.services.countries.get_metadata", return_value={"token_endpoint": "t"}), patch(
            "app.services.countries.requests.post", return_value=response
        ):
            with pytest.raises(CountryConnectorError):
                countries.exchange_authorization_code("XX", "code")

    def test_openid_ee_uses_query_token_and_modifiers(self, country_config):
        with patch("app.services.countries.get_metadata", return_value={"userinfo_endpoint": "https://ee.test/userinfo"}), patch(
            "app.services.countries.requests.get", return_value=_response(text='{"surname": "Tamm", "given_name": "Mari"}')
        ) as get, patch.object(countries.session_manager, "update_user_data") as store:
            data = countries.collect_user_data("EE", "s1", "at")

        assert get.call_args.args[0] == "https://ee.test/userinfo?access_token=at"
        assert "Authorization" not in get.call_args.kwargs["headers"]
        assert data["family_name"] == "Tamm" and "surname" not in data
        assert data["nationality"] == ["EE"] and data["birth_place"] == "Tallinn"
        store.assert_called_once_with(session_id="s1", user_data=data)

    def test_openid_failure(self, country_config):
        with patch("app.services.countries.get_metadata", return_value={"userinfo_endpoint": "u"}), patch(
            "app.services.countries.requests.get", return_value=_response(text="not json")
        ):
            with pytest.raises(CountryConnectorError, match="openid connection failed"):
                countries.collect_user_data("EE", "s1", "at")

    def test_unsupported_connection_type(self, country_config):
        with pytest.raises(CountryConnectorError, match="Not supported"):
            countries.collect_user_data("ZZ", "s1", "at")

    def test_form_country_without_data(self, country_config):
        with patch.object(countries.session_manager, "get_session", return_value=MagicMock(user_data="Data not found")):
            assert countries.collect_user_data("FC", "s1", None) == {"error": "error", "error_description": "Data not found"}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


class TestEncoding:
    @pytest.mark.parametrize("value", ["abc+def", "@@@"])
    def test_strict_base64url_rejects_alphabet(self, value):
        with pytest.raises(ValueError, match="Invalid base64url characters"):
            encoding.b64url_decode_strict(value)

    def test_strict_base64url_invalid_length(self):
        with pytest.raises(ValueError, match="Invalid base64 data"):
            encoding.b64url_decode_strict("A")

    def test_x5c_rejects_alphabet_and_length(self):
        with pytest.raises(ValueError, match="Invalid base64 characters"):
            encoding.b64_decode_x5c("abc-_")
        with pytest.raises(ValueError, match="Invalid base64 in x5c"):
            encoding.b64_decode_x5c("A")

    def test_b64url_uint_fixed_length(self):
        assert encoding.b64url_uint(1, 4) == encoding.urlsafe_b64encode_nopad(b"\x00\x00\x00\x01")


class TestRevocationStatusClient:
    @pytest.fixture
    def config(self):
        with patch_configuration({"revocation": {"enabled": False, "api_key": "k", "take_url": "t", "set_url": "s"}}):
            yield

    def test_reservation_failure_returns_none(self, config):
        with patch("app.services.revocation_status.requests.post", return_value=_response(503)):
            assert revocation_status.reserve_status_entry("doctype", "FC", "2030-01-01") is None

    def test_set_skipped_when_disabled(self, config):
        with patch("app.services.revocation_status.requests.post") as post:
            assert revocation_status.set_token_status("idx", 1, "uri") is False
        post.assert_not_called()

    def test_describe_status_without_status_list(self):
        assert revocation_status.describe_status_list({"identifier_list": {}}) is None
