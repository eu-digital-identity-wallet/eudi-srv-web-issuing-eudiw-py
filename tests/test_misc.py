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
import datetime
from unittest.mock import MagicMock, patch, call
from io import BytesIO
import base64
import json

from app.core import errors
from app.core.errors import CertificateVerificationError
from app.services import attributes, trust
from app.utils import dates, encoding, ids


# ------------------------------------------------------------------------------
# --- Fixtures and Mocks Setup -------------------------------------------------
# ------------------------------------------------------------------------------


@pytest.fixture(scope="session")
def mock_oidc_metadata():
    """Session-scoped mock for oidc_metadata."""
    return {
        "credential_configurations_supported": {
            "pid_mdoc": {
                "format": "mso_mdoc",
                "scope": "eu.europa.ec.eudi.pid_mdoc",
                "doctype": "eu.europa.ec.eudi.pid.1",
                "issuer_config": {"doctype": "eu.europa.ec.eudi.pid.1"},
                "credential_metadata": {
                    "claims": [
                        {
                            "path": ["eu.europa.ec.eudi.pid.1", "family_name"],
                            "mandatory": True,
                            "value_type": "string",
                            "source": "user",
                        },
                        {
                            "path": ["eu.europa.ec.eudi.pid.1", "birth_date"],
                            "mandatory": True,
                            "value_type": "full-date",
                            "source": "user",
                        },
                        {
                            "path": ["eu.europa.ec.eudi.pid.1", "place_of_birth"],
                            "mandatory": True,
                            "value_type": "places",
                            "source": "user",
                            "issuer_conditions": {
                                "cardinality": {"min": 0, "max": 1},
                                "places": {
                                    "country": {
                                        "mandatory": False,
                                        "value_type": "string",
                                        "source": "user",
                                    }
                                },
                                "issuer_conditions_attributes": [
                                    {
                                        "attribute": "test_list_item",
                                        "value_type": "test_list_item_attrs",
                                        "issuer_conditions": {
                                            "cardinality": {"min": 1, "max": 1},
                                            "test_list_item_attributes": {
                                                "sub_attr": {
                                                    "value_type": "string",
                                                    "mandatory": True,
                                                }
                                            },
                                        },
                                    }
                                ],
                            },
                        },
                        {
                            "path": ["eu.europa.ec.eudi.pid.1", "issuance_date"],
                            "mandatory": True,
                            "source": "issuer",
                        },
                        {
                            "path": ["eu.europa.ec.eudi.pid.1", "document_number"],
                            "mandatory": False,
                            "value_type": "string",
                            "source": "user",
                        },
                        {
                            "overall_issuer_conditions": {
                                "age_over_18": {
                                    "value_type": "boolean",
                                    "source": "issuer",
                                }
                            }
                        },
                    ]
                },
            },
            "eu.europa.ec.eudi.pid_vc_sd_jwt": {
                "format": "dc+sd-jwt",
                "scope": "eu.europa.ec.eudi.pid_vc_sd_jwt",
                "vct": "urn:eudi:pid:1",
                "issuer_config": {"doctype": "eu.europa.ec.eudi.pid.1"},
                "credential_metadata": {
                    "claims": [
                        {
                            "path": ["family_name"],
                            "mandatory": True,
                            "value_type": "string",
                            "source": "user",
                        },
                        {
                            "path": ["birthdate"],
                            "mandatory": True,
                            "value_type": "full-date",
                            "source": "user",
                        },
                        {
                            "path": ["nationalities"],
                            "mandatory": True,
                            "source": "user",
                            "value_type": "list",
                            "issuer_conditions": {
                                "cardinality": {"min": 0, "max": "n"},
                                "nationalities_attributes": {
                                    "country_code": {
                                        "mandatory": True,
                                        "value_type": "string",
                                        "source": "user",
                                    }
                                },
                            },
                        },
                        {
                            "path": ["date_of_issuance"],
                            "mandatory": True,
                            "source": "issuer",
                        },
                        {
                            "path": ["document_number"],
                            "mandatory": False,
                            "value_type": "string",
                            "source": "user",
                        },
                        {
                            "path": ["address"],
                            "mandatory": False,
                            "source": "user",
                            "value_type": "test",
                            "issuer_conditions": {"cardinality": {"min": 0, "max": 1}},
                        },
                        {
                            "path": ["address", "street_address"],
                            "mandatory": False,
                            "source": "user",
                            "value_type": "string",
                        },
                        {
                            "path": ["address", "details"],
                            "mandatory": False,
                            "source": "user",
                            "value_type": "details",
                        },
                        {
                            "path": ["address", "details", "post_box"],
                            "mandatory": False,
                            "source": "user",
                            "value_type": "string",
                        },
                    ]
                },
            },
        }
    }


@pytest.fixture(autouse=True)
def setup_mocks_for_module(mock_oidc_metadata):
    """Sets up global mocks (oidc_metadata, trusted CAs) before any test runs."""
    with patch.dict("app.services.attributes.oidc_metadata", mock_oidc_metadata, clear=True), patch(
        "app.core.state.trusted_CAs", {}
    ):
        yield


# ------------------------------------------------------------------------------
# --- Test Class for Simple Utility Functions ----------------------------------
# ------------------------------------------------------------------------------


class TestSimpleUtilities:
    """Tests for basic, non-credential-specific helper functions."""

    def test_urlsafe_b64encode_nopad(self):
        assert encoding.urlsafe_b64encode_nopad(b"abcde") == "YWJjZGU"

    # Save the real datetime.date before patching
    real_date = datetime.date

    @patch("app.utils.dates.datetime.date")
    @patch("app.utils.dates.datetime.datetime")
    def test_calculate_age_before_birthday(self, mock_datetime, mock_date):
        current_date_obj = self.real_date(2025, 10, 27)
        dob_str = "2000-12-31"
        expected_age = 24

        mock_date.today.return_value = current_date_obj
        mock_date.side_effect = lambda *args, **kwargs: self.real_date(*args, **kwargs)

        mock_dt_instance = mock_datetime.strptime.return_value
        mock_dt_instance.date.return_value = self.real_date(2000, 12, 31)

        assert dates.calculate_age(dob_str) == expected_age

    @patch("app.utils.dates.datetime.date")
    @patch("app.utils.dates.datetime.datetime")
    def test_calculate_age_on_birthday(self, mock_datetime, mock_date):
        current_date_obj = self.real_date(2025, 10, 27)
        dob_str = "2000-10-27"
        expected_age = 25

        mock_date.today.return_value = current_date_obj
        mock_date.side_effect = lambda *args, **kwargs: self.real_date(*args, **kwargs)

        mock_dt_instance = mock_datetime.strptime.return_value
        mock_dt_instance.date.return_value = self.real_date(2000, 10, 27)

        assert dates.calculate_age(dob_str) == expected_age

    @patch("app.utils.dates.datetime.date")
    @patch("app.utils.dates.datetime.datetime")
    def test_calculate_age_after_birthday(self, mock_datetime, mock_date):
        current_date_obj = self.real_date(2025, 10, 27)
        dob_str = "2000-01-01"
        expected_age = 25

        mock_date.today.return_value = current_date_obj
        mock_date.side_effect = lambda *args, **kwargs: self.real_date(*args, **kwargs)

        mock_dt_instance = mock_datetime.strptime.return_value
        mock_dt_instance.date.return_value = self.real_date(2000, 1, 1)

        assert dates.calculate_age(dob_str) == expected_age

    @patch("app.utils.ids.uuid")
    def test_generate_unique_id(self, mock_uuid):
        mock_uuid.uuid4.return_value = MagicMock(__str__=lambda self: "mock-uuid-42")
        assert ids.generate_unique_id() == "mock-uuid-42"

# ------------------------------------------------------------------------------
# --- Test Class for Credential Configuration and Lookup -----------------------
# ------------------------------------------------------------------------------


class TestCredentialLookup:
    """Tests for functions related to looking up credential metadata (VCTs, scopes, etc.)."""

    def test_vct2id(self):
        assert attributes.vct2id("urn:eudi:pid:1") == "eu.europa.ec.eudi.pid_vc_sd_jwt"

    def test_getNamespaces(self, mock_oidc_metadata):
        claims = mock_oidc_metadata["credential_configurations_supported"]["pid_mdoc"][
            "credential_metadata"
        ]["claims"]
        namespaces = attributes.getNamespaces(claims)
        assert namespaces == ["eu.europa.ec.eudi.pid.1"]


# ------------------------------------------------------------------------------
# --- Test Class for Attribute Processing and Forms ----------------------------
# ------------------------------------------------------------------------------


class TestAttributeProcessing:
    """Tests for functions that process claims and generate form structures."""

    def test_process_nested_attributes_no_match(self):
        conditions = {"key1": 1, "key2": "value"}
        assert attributes._process_nested_attributes(conditions) == {}

    def test_process_nested_attributes_list_structure_fix(self):
        conditions_to_process = {
            "workplace_attributes": {
                "name": {"value_type": "string", "mandatory": True, "source": "user"}
            }
        }
        result = attributes._process_nested_attributes(
            conditions_to_process, parent_value_type="workplace_attrs"
        )
        assert "name" in result
        assert result["name"]["mandatory"] is True

    def test_getMandatoryAttributes_pid_mdoc(self):
        credentials_requested = ["pid_mdoc"]
        result = attributes.getAttributesForm(credentials_requested)
        assert "family_name" in result
        assert "birth_date" in result

    def test_getOptionalAttributes_pid_mdoc(self):
        credentials_requested = ["pid_mdoc"]
        result = attributes.getAttributesForm2(credentials_requested)
        assert "document_number" in result

    def test_getMandatoryAttributes_pid_sdjwt(self):
        credentials_requested = ["eu.europa.ec.eudi.pid_vc_sd_jwt"]
        result = attributes.getAttributesForm(credentials_requested)
        assert "family_name" in result
        assert "birthdate" in result
        assert "birth_date" not in result

    def test_getOptionalAttributes_pid_sdjwt_nested(self):
        credentials_requested = ["eu.europa.ec.eudi.pid_vc_sd_jwt"]
        result = attributes.getAttributesForm2(credentials_requested)
        address_attrs_list = result["address"]["attributes"]
        details_entry = next(item for item in address_attrs_list if "details" in item)
        details_attr = details_entry["details"]
        post_box_attr = details_attr["attributes"][0]["post_box"]
        assert post_box_attr["type"] == "string"

    def test_getIssuerFilledAttributes_pid_mdoc(self, mock_oidc_metadata):
        claims = mock_oidc_metadata["credential_configurations_supported"]["pid_mdoc"][
            "credential_metadata"
        ]["claims"]
        namespace = "eu.europa.ec.eudi.pid.1"
        result = attributes.getIssuerFilledAttributes(claims, namespace)
        assert result == {"issuance_date": ""}

    def test_getIssuerFilledAttributesSDJWT(self, mock_oidc_metadata):
        claims = mock_oidc_metadata["credential_configurations_supported"][
            "eu.europa.ec.eudi.pid_vc_sd_jwt"
        ]["credential_metadata"]["claims"]
        result = attributes.getIssuerFilledAttributesSDJWT(claims)
        assert result == {"date_of_issuance": ""}


# ------------------------------------------------------------------------------
# --- Test Class for Error/Flask Utilities & Certificate -----------------------
# ------------------------------------------------------------------------------


class TestErrorAndFlask:

    @patch("app.core.errors.secrets")
    @patch("app.core.errors.jsonify")
    def test_credential_error_resp(self, mock_jsonify, mock_secrets):
        mock_secrets.token_urlsafe.return_value = "mock_nonce"
        mock_response = MagicMock()
        mock_jsonify.return_value = mock_response

        response, status = errors.credential_error_resp("invalid_request", "bad param")

        assert status == 400
        mock_jsonify.assert_called_with(
            {
                "error": "invalid_request",
                "error_description": "bad param",
                "c_nonce": "mock_nonce",
                "c_nonce_expires_in": 86400,
            }
        )

    @patch("app.core.errors.redirect")
    @patch("app.core.errors.url_get")
    def test_auth_error_redirect_with_description(self, mock_url_get, mock_redirect):
        return_uri = "https://wallet.com/callback"
        mock_url_get.return_value = (
            f"{return_uri}?error=access_denied&error_description=User%20rejected"
        )
        errors.auth_error_redirect(return_uri, "access_denied", "User rejected")
        mock_redirect.assert_called_with(mock_url_get.return_value, code=302)


class TestAdditionalCoverage:

    def test_b64url_decode_padding(self):
        data = "YWJjZGU"  # b"abcde"
        decoded = encoding.b64url_decode(data)
        assert decoded == b"abcde"

    def test_scope2details_builds_configuration_ids(self):
        result = attributes.scope2details(["openid", "eu.europa.ec.eudi.pid_mdoc"])
        assert any(isinstance(c, dict) for c in result)

    @patch("app.services.trust.jwt.decode_complete")
    @patch("app.services.trust.extract_public_key_from_x5c")
    def test_verify_jwt_with_x5c_calls_decode(self, mock_extract, mock_jwt_decode):
        mock_pubkey = MagicMock()
        mock_extract.return_value = (mock_pubkey, "ES256")
        mock_jwt_decode.return_value = {"header": {"alg": "ES256"}, "payload": {"sub": "x"}}
        claims = trust.verify_jwt_with_x5c(
            "jwtstring", audience="aud", issuer="iss", verify_exp=False
        )
        assert claims == {"sub": "x"}
        mock_jwt_decode.assert_called_once_with(
            "jwtstring",
            key=mock_pubkey,
            algorithms=["ES256"],
            audience="aud",
            issuer="iss",
            options={"verify_exp": False, "require": []},
            leeway=trust.JWT_CLOCK_LEEWAY_SECONDS,
        )

    # ---------------------------
    # Test calculate_age with invalid date format
    # ---------------------------
    @patch("app.utils.dates.datetime.date")
    @patch("app.utils.dates.datetime.datetime")
    def test_calculate_age_invalid_format(self, mock_datetime, mock_date):
        # Use the real datetime.date class to avoid recursion
        real_date = datetime.date
        mock_date.today.return_value = real_date(2025, 10, 27)
        mock_date.side_effect = lambda year, month, day: real_date(year, month, day)
        mock_datetime.strptime.side_effect = lambda s, f: (_ for _ in ()).throw(
            ValueError("invalid date format")
        )

        with pytest.raises(ValueError):
            dates.calculate_age("invalid-date")

    # ---------------------------
    # Test generate_unique_id exception handling
    # ---------------------------
    @patch("app.utils.ids.uuid")
    def test_generate_unique_id_exception(self, mock_uuid):
        mock_uuid.uuid4.side_effect = Exception("UUID error")
        with pytest.raises(Exception, match="UUID error"):
            ids.generate_unique_id()

    # ---------------------------
    # Test _process_nested_attributes edge with missing keys
    # ---------------------------
    def test_process_nested_attributes_empty_dict(self):
        assert attributes._process_nested_attributes({}) == {}

    # ---------------------------
    # Test getIssuerFilledAttributes with empty claims
    # ---------------------------
    def test_getIssuerFilledAttributes_empty_claims(self):
        result = attributes.getIssuerFilledAttributes([], "namespace")
        assert result == {}

    # ---------------------------
    # Test credential_error_resp optional branch
    # ---------------------------
    @patch("app.core.errors.secrets")
    @patch("app.core.errors.jsonify")
    def test_credential_error_resp_without_description(
        self, mock_jsonify, mock_secrets
    ):
        mock_secrets.token_urlsafe.return_value = "nonce"
        mock_response = MagicMock()
        mock_jsonify.return_value = mock_response
        resp, status = errors.credential_error_resp("error_only", "")
        assert status == 400
        assert mock_jsonify.called
        data = mock_jsonify.call_args[0][0]
        assert data["c_nonce"] == "nonce"

    # ---------------------------
    # Test auth_error_redirect optional branch with no description
    # ---------------------------
    @patch("app.core.errors.redirect")
    @patch("app.core.errors.url_get")
    def test_auth_error_redirect_no_description(self, mock_url_get, mock_redirect):
        return_uri = "https://wallet.com/callback"
        mock_url_get.return_value = f"{return_uri}?error=access_denied"
        errors.auth_error_redirect(return_uri, "access_denied")
        mock_redirect.assert_called_with(mock_url_get.return_value, code=302)

    # -----------------------------
    # generate_unique_id exception
    # -----------------------------
    @patch("app.utils.ids.uuid")
    def test_generate_unique_id_raises_exception(self, mock_uuid):
        mock_uuid.uuid4.side_effect = Exception("uuid fail")
        with pytest.raises(Exception, match="uuid fail"):
            ids.generate_unique_id()

    # -----------------------------
    # credential_error_resp with desc empty
    # -----------------------------
    @patch("app.core.errors.secrets")
    @patch("app.core.errors.jsonify")
    def test_credential_error_resp_empty_desc(self, mock_jsonify, mock_secrets):
        mock_secrets.token_urlsafe.return_value = "nonce"
        mock_jsonify.return_value = MagicMock()
        resp, status = errors.credential_error_resp("error_only", "")
        assert status == 400
        assert resp is not None

    # -----------------------------
    # auth_error_redirect with missing description
    # -----------------------------
    @patch("app.core.errors.redirect")
    @patch("app.core.errors.url_get")
    def test_auth_error_redirect_missing_desc(self, mock_url_get, mock_redirect):
        return_uri = "https://wallet.com/callback"
        mock_url_get.return_value = f"{return_uri}?error=error_only"
        errors.auth_error_redirect(return_uri, "error_only")
        mock_redirect.assert_called_with(mock_url_get.return_value, code=302)

    # -----------------------------
    # getIssuerFilledAttributesSDJWT empty claims
    # -----------------------------
    def test_getIssuerFilledAttributesSDJWT_empty_claims(self):
        result = attributes.getIssuerFilledAttributesSDJWT([])
        assert result == {}

    # -----------------------------
    # scope2details with empty list input
    # -----------------------------
    def test_scope2details_empty_list(self):
        result = attributes.scope2details([])
        assert result == ["openid"]
