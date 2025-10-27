import pytest
import datetime
from unittest.mock import MagicMock, patch, call
from io import BytesIO
import base64
import json

# Ensure the misc module is importable
try:
    from app import misc
    from app.misc import CertificateVerificationError
except ImportError:
    import sys

    sys.path.append(".")
    import misc
    from misc import CertificateVerificationError

    print("WARNING: Using direct 'import misc' fallback.")


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
    """Sets up global mocks (oidc_metadata, cfgservice) before any test runs."""
    with patch.dict("app.misc.oidc_metadata", mock_oidc_metadata, clear=True), patch(
        "app.misc.cfgservice", MagicMock()
    ), patch("app.misc.trusted_CAs", {}):
        yield


# ------------------------------------------------------------------------------
# --- Test Class for Simple Utility Functions ----------------------------------
# ------------------------------------------------------------------------------


class TestSimpleUtilities:
    """Tests for basic, non-credential-specific helper functions."""

    def test_create_dict(self):
        input_dict = {"key1": {"value": 10, "label": "Ten"}, "key2": {"value": 20}}
        assert misc.create_dict(input_dict, "label") == {"key1": "Ten"}

    def test_urlsafe_b64encode_nopad(self):
        assert misc.urlsafe_b64encode_nopad(b"abcde") == "YWJjZGU"

    # Save the real datetime.date before patching
    real_date = datetime.date

    @patch("app.misc.datetime.date")
    @patch("app.misc.datetime.datetime")
    def test_calculate_age_before_birthday(self, mock_datetime, mock_date):
        current_date_obj = self.real_date(2025, 10, 27)
        dob_str = "2000-12-31"
        expected_age = 24

        mock_date.today.return_value = current_date_obj
        mock_date.side_effect = lambda *args, **kwargs: self.real_date(*args, **kwargs)

        mock_dt_instance = mock_datetime.strptime.return_value
        mock_dt_instance.date.return_value = self.real_date(2000, 12, 31)

        assert misc.calculate_age(dob_str) == expected_age

    @patch("app.misc.datetime.date")
    @patch("app.misc.datetime.datetime")
    def test_calculate_age_on_birthday(self, mock_datetime, mock_date):
        current_date_obj = self.real_date(2025, 10, 27)
        dob_str = "2000-10-27"
        expected_age = 25

        mock_date.today.return_value = current_date_obj
        mock_date.side_effect = lambda *args, **kwargs: self.real_date(*args, **kwargs)

        mock_dt_instance = mock_datetime.strptime.return_value
        mock_dt_instance.date.return_value = self.real_date(2000, 10, 27)

        assert misc.calculate_age(dob_str) == expected_age

    @patch("app.misc.datetime.date")
    @patch("app.misc.datetime.datetime")
    def test_calculate_age_after_birthday(self, mock_datetime, mock_date):
        current_date_obj = self.real_date(2025, 10, 27)
        dob_str = "2000-01-01"
        expected_age = 25

        mock_date.today.return_value = current_date_obj
        mock_date.side_effect = lambda *args, **kwargs: self.real_date(*args, **kwargs)

        mock_dt_instance = mock_datetime.strptime.return_value
        mock_dt_instance.date.return_value = self.real_date(2000, 1, 1)

        assert misc.calculate_age(dob_str) == expected_age

    @patch("app.misc.uuid")
    def test_generate_unique_id(self, mock_uuid):
        mock_uuid.uuid4.return_value = MagicMock(__str__=lambda self: "mock-uuid-42")
        assert misc.generate_unique_id() == "mock-uuid-42"

    @patch("app.misc.Image")
    def test_convert_png_to_jpeg(self, mock_Image):
        mock_png_bytes = b"png data"
        input_buffer = BytesIO(mock_png_bytes)
        mock_jpeg_buffer = BytesIO()
        mock_image_instance = mock_Image.open.return_value

        def save_side_effect(buffer, format):
            buffer.write(b"jpeg data")

        mock_image_instance.convert.return_value.save.side_effect = save_side_effect

        with patch("app.misc.BytesIO", side_effect=[input_buffer, mock_jpeg_buffer]):
            jpeg_bytes = misc.convert_png_to_jpeg(mock_png_bytes)

        mock_Image.open.assert_called_with(input_buffer)
        assert jpeg_bytes == b"jpeg data"


# ------------------------------------------------------------------------------
# --- Test Class for Credential Configuration and Lookup -----------------------
# ------------------------------------------------------------------------------


class TestCredentialLookup:
    """Tests for functions related to looking up credential metadata (VCTs, scopes, etc.)."""

    def test_vct2scope(self):
        assert misc.vct2scope("urn:eudi:pid:1") == "eu.europa.ec.eudi.pid_vc_sd_jwt"
        assert misc.vct2scope("nonexistent_vct") is None

    def test_vct2doctype_sdjwt(self):
        assert misc.vct2doctype("urn:eudi:pid:1") == "eu.europa.ec.eudi.pid.1"

    def test_vct2doctype_no_vct(self):
        assert misc.vct2doctype("nonexistent_vct") is None

    def test_vct2id(self):
        assert misc.vct2id("urn:eudi:pid:1") == "eu.europa.ec.eudi.pid_vc_sd_jwt"

    def test_doctype2credential(self):
        result = misc.doctype2credential("eu.europa.ec.eudi.pid.1", "mso_mdoc")
        assert result["format"] == "mso_mdoc"
        assert result["scope"] == "eu.europa.ec.eudi.pid_mdoc"

    def test_doctype2credentialSDJWT(self):
        result = misc.doctype2credentialSDJWT("eu.europa.ec.eudi.pid.1", "dc+sd-jwt")
        assert result["format"] == "dc+sd-jwt"

    def test_doctype2vct(self):
        assert misc.doctype2vct("eu.europa.ec.eudi.pid_vc_sd_jwt") == "urn:eudi:pid:1"

    def test_getNamespaces(self, mock_oidc_metadata):
        claims = mock_oidc_metadata["credential_configurations_supported"]["pid_mdoc"][
            "credential_metadata"
        ]["claims"]
        namespaces = misc.getNamespaces(claims)
        assert namespaces == ["eu.europa.ec.eudi.pid.1"]


# ------------------------------------------------------------------------------
# --- Test Class for Attribute Processing and Forms ----------------------------
# ------------------------------------------------------------------------------


class TestAttributeProcessing:
    """Tests for functions that process claims and generate form structures."""

    def test_process_nested_attributes_no_match(self):
        conditions = {"key1": 1, "key2": "value"}
        assert misc._process_nested_attributes(conditions) == {}

    def test_process_nested_attributes_list_structure_fix(self):
        conditions_to_process = {
            "workplace_attributes": {
                "name": {"value_type": "string", "mandatory": True, "source": "user"}
            }
        }
        result = misc._process_nested_attributes(
            conditions_to_process, parent_value_type="workplace_attrs"
        )
        assert "name" in result
        assert result["name"]["mandatory"] is True

    def test_getMandatoryAttributes_pid_mdoc(self):
        credentials_requested = ["pid_mdoc"]
        result = misc.getAttributesForm(credentials_requested)
        assert "family_name" in result
        assert "birth_date" in result

    def test_getOptionalAttributes_pid_mdoc(self):
        credentials_requested = ["pid_mdoc"]
        result = misc.getAttributesForm2(credentials_requested)
        assert "document_number" in result

    def test_getMandatoryAttributes_pid_sdjwt(self):
        credentials_requested = ["eu.europa.ec.eudi.pid_vc_sd_jwt"]
        result = misc.getAttributesForm(credentials_requested)
        assert "family_name" in result
        assert "birthdate" in result
        assert "birth_date" not in result

    def test_getOptionalAttributes_pid_sdjwt_nested(self):
        credentials_requested = ["eu.europa.ec.eudi.pid_vc_sd_jwt"]
        result = misc.getAttributesForm2(credentials_requested)
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
        result = misc.getIssuerFilledAttributes(claims, namespace)
        assert result == {"issuance_date": ""}

    def test_getIssuerFilledAttributesSDJWT(self, mock_oidc_metadata):
        claims = mock_oidc_metadata["credential_configurations_supported"][
            "eu.europa.ec.eudi.pid_vc_sd_jwt"
        ]["credential_metadata"]["claims"]
        result = misc.getIssuerFilledAttributesSDJWT(claims)
        assert result == {"date_of_issuance": ""}


# ------------------------------------------------------------------------------
# --- Test Class for Error/Flask Utilities & Certificate -----------------------
# ------------------------------------------------------------------------------


class TestErrorAndFlask:

    @patch("app.misc.secrets")
    @patch("app.misc.jsonify")
    def test_credential_error_resp(self, mock_jsonify, mock_secrets):
        mock_secrets.token_urlsafe.return_value = "mock_nonce"
        mock_response = MagicMock()
        mock_jsonify.return_value = mock_response

        response, status = misc.credential_error_resp("invalid_request", "bad param")

        assert status == 400
        mock_jsonify.assert_called_with(
            {
                "error": "invalid_request",
                "error_description": "bad param",
                "c_nonce": "mock_nonce",
                "c_nonce_expires_in": 86400,
            }
        )

    @patch("app.misc.redirect")
    @patch("app.misc.url_get")
    def test_auth_error_redirect_with_description(self, mock_url_get, mock_redirect):
        return_uri = "https://wallet.com/callback"
        mock_url_get.return_value = (
            f"{return_uri}?error=access_denied&error_description=User%20rejected"
        )
        misc.auth_error_redirect(return_uri, "access_denied", "User rejected")
        mock_redirect.assert_called_with(mock_url_get.return_value, code=302)


class TestCertificateVerification:

    def test_certificate_verification_mocked_success(self, setup_mocks_for_module):
        mock_cert_der = b"mock-der-data"
        mock_certificate = MagicMock()
        mock_load_der = patch(
            "app.misc.x509.load_der_x509_certificate", return_value=mock_certificate
        ).start()
        mock_datetime = patch("app.misc.datetime.datetime", autospec=True).start()
        mock_datetime.utcnow.return_value = datetime.datetime.utcnow()

        result_cert = misc.verify_certificate_against_trusted_CA(mock_cert_der)

        mock_load_der.assert_called_once()
        assert result_cert == mock_certificate

        patch.stopall()


class TestAdditionalCoverage:

    def test_b64url_decode_padding(self):
        data = "YWJjZGU"  # b"abcde"
        decoded = misc.b64url_decode(data)
        assert decoded == b"abcde"

    @patch("app.misc.render_template_string")
    def test_post_redirect_with_payload(self, mock_render):
        target_url = "https://wallet.com/callback"
        payload = {"key": "value"}

        # Call the function
        misc.post_redirect_with_payload(target_url, payload)

        # Ensure render_template_string was called
        assert mock_render.called

        # Grab kwargs
        args, kwargs = mock_render.call_args
        data_passed = kwargs.get("data")

        # Decode the payload passed to the template
        decoded_payload = json.loads(data_passed)

        # Check that the payload matches
        assert decoded_payload["key"] == "value"

        # Check that the URL was passed correctly (key is 'url', not 'target_url')
        assert kwargs.get("url") == target_url

    @patch("app.misc.oidc_metadata", new_callable=dict)
    def test_getSubClaims_returns_correct(self, mock_oidc):
        mock_oidc["credential_configurations_supported"] = {
            "cred1": {
                "vct": "vct1",
                "claims": [{"path": ["claimLv1", "sub1"]}],
            }
        }
        subclaims = misc.getSubClaims("claimLv1", "vct1")
        assert subclaims == [["claimLv1", "sub1"]]

    def test_scope2details_builds_configuration_ids(self):
        result = misc.scope2details(["openid", "eu.europa.ec.eudi.pid_mdoc"])
        assert any(isinstance(c, dict) for c in result)

    @patch("app.misc.Image.open")
    def test_validate_image_dimensions_invalid(self, mock_open):
        mock_image = MagicMock()
        mock_image.size = (100, 100)
        mock_open.return_value = mock_image
        valid, msg = misc.validate_image(MagicMock(filename="test.png"))
        assert not valid
        assert "dimensions" in msg

    def test_validate_image_no_file(self):
        file_mock = MagicMock(filename="")
        valid, msg = misc.validate_image(file_mock)
        assert not valid
        assert "No selected" in msg

    @patch("app.misc.Image.open", side_effect=Exception("fail"))
    def test_validate_image_fail_open(self, mock_open):
        file_mock = MagicMock(filename="file.png")
        valid, msg = misc.validate_image(file_mock)
        assert not valid
        assert "Failed to open" in msg

    @patch("app.misc.verify_certificate_against_trusted_CA")
    @patch("app.misc.b64url_decode")
    @patch("app.misc.jwt.get_unverified_header")
    def test_extract_public_key_from_x5c_success(
        self, mock_header, mock_b64, mock_verify
    ):
        mock_header.return_value = {"x5c": ["cert"], "alg": "ES256"}
        mock_b64.return_value = b"derbytes"
        mock_cert = MagicMock()
        mock_verify.return_value = mock_cert
        pubkey, alg = misc.extract_public_key_from_x5c("jwt")
        assert alg == "ES256"
        assert pubkey == mock_cert.public_key()

    @patch("app.misc.jwt.decode")
    @patch("app.misc.extract_public_key_from_x5c")
    def test_verify_jwt_with_x5c_calls_decode(self, mock_extract, mock_jwt_decode):
        mock_pubkey = MagicMock()
        mock_extract.return_value = (mock_pubkey, "ES256")
        misc.verify_jwt_with_x5c(
            "jwtstring", audience="aud", issuer="iss", verify_exp=False
        )
        mock_jwt_decode.assert_called_once_with(
            "jwtstring",
            key=mock_pubkey,
            algorithms=["ES256"],
            audience="aud",
            issuer="iss",
            options={"verify_exp": False},
        )

    # ---------------------------
    # Test post_redirect_with_payload edge cases
    # ---------------------------
    @patch("app.misc.render_template_string")
    def test_post_redirect_empty_payload(self, mock_render):
        target_url = "https://wallet.com/callback"
        payload = {}
        misc.post_redirect_with_payload(target_url, payload)
        args, kwargs = mock_render.call_args
        data_passed = kwargs.get("data")
        decoded_payload = json.loads(data_passed)
        assert decoded_payload == {}
        assert kwargs.get("url") == target_url

    # ---------------------------
    # Test calculate_age with invalid date format
    # ---------------------------
    @patch("app.misc.datetime.date")
    @patch("app.misc.datetime.datetime")
    def test_calculate_age_invalid_format(self, mock_datetime, mock_date):
        # Use the real datetime.date class to avoid recursion
        real_date = datetime.date
        mock_date.today.return_value = real_date(2025, 10, 27)
        mock_date.side_effect = lambda year, month, day: real_date(year, month, day)
        mock_datetime.strptime.side_effect = lambda s, f: (_ for _ in ()).throw(
            ValueError("invalid date format")
        )

        with pytest.raises(ValueError):
            misc.calculate_age("invalid-date")

    # ---------------------------
    # Test generate_unique_id exception handling
    # ---------------------------
    @patch("app.misc.uuid")
    def test_generate_unique_id_exception(self, mock_uuid):
        mock_uuid.uuid4.side_effect = Exception("UUID error")
        with pytest.raises(Exception, match="UUID error"):
            misc.generate_unique_id()

    # ---------------------------
    # Test convert_png_to_jpeg with exception in Image.open
    # ---------------------------
    @patch("app.misc.Image")
    def test_convert_png_to_jpeg_open_fail(self, mock_Image):
        mock_Image.open.side_effect = IOError("cannot open image")
        with pytest.raises(IOError, match="cannot open image"):
            misc.convert_png_to_jpeg(b"bad data")

    # ---------------------------
    # Test _process_nested_attributes edge with missing keys
    # ---------------------------
    def test_process_nested_attributes_empty_dict(self):
        assert misc._process_nested_attributes({}) == {}

    # ---------------------------
    # Test getIssuerFilledAttributes with empty claims
    # ---------------------------
    def test_getIssuerFilledAttributes_empty_claims(self):
        result = misc.getIssuerFilledAttributes([], "namespace")
        assert result == {}

    # ---------------------------
    # Test verify_certificate_against_trusted_CA with invalid cert
    # ---------------------------
    @patch("app.misc.x509.load_der_x509_certificate")
    def test_verify_certificate_invalid(self, mock_load):
        mock_load.side_effect = ValueError("bad cert")
        with pytest.raises(ValueError, match="bad cert"):
            misc.verify_certificate_against_trusted_CA(b"invalid-cert")

    # ---------------------------
    # Test credential_error_resp optional branch
    # ---------------------------
    @patch("app.misc.secrets")
    @patch("app.misc.jsonify")
    def test_credential_error_resp_without_description(
        self, mock_jsonify, mock_secrets
    ):
        mock_secrets.token_urlsafe.return_value = "nonce"
        mock_response = MagicMock()
        mock_jsonify.return_value = mock_response
        resp, status = misc.credential_error_resp("error_only", "")
        assert status == 400
        assert mock_jsonify.called
        data = mock_jsonify.call_args[0][0]
        assert data["c_nonce"] == "nonce"

    # ---------------------------
    # Test auth_error_redirect optional branch with no description
    # ---------------------------
    @patch("app.misc.redirect")
    @patch("app.misc.url_get")
    def test_auth_error_redirect_no_description(self, mock_url_get, mock_redirect):
        return_uri = "https://wallet.com/callback"
        mock_url_get.return_value = f"{return_uri}?error=access_denied"
        misc.auth_error_redirect(return_uri, "access_denied")
        mock_redirect.assert_called_with(mock_url_get.return_value, code=302)

    # -----------------------------
    # verify_certificate_against_trusted_CA exception path
    # -----------------------------
    @patch("app.misc.x509.load_der_x509_certificate")
    def test_verify_certificate_raises_value_error(self, mock_load):
        mock_load.side_effect = ValueError("bad cert")
        with pytest.raises(ValueError):
            misc.verify_certificate_against_trusted_CA(b"bad cert bytes")

    # -----------------------------
    # generate_unique_id exception
    # -----------------------------
    @patch("app.misc.uuid")
    def test_generate_unique_id_raises_exception(self, mock_uuid):
        mock_uuid.uuid4.side_effect = Exception("uuid fail")
        with pytest.raises(Exception, match="uuid fail"):
            misc.generate_unique_id()

    # -----------------------------
    # convert_png_to_jpeg exception path for save fail
    # -----------------------------
    @patch("app.misc.Image")
    def test_convert_png_to_jpeg_save_exception(self, mock_Image):
        mock_img = MagicMock()
        mock_Image.open.return_value = mock_img
        mock_img.convert.return_value.save.side_effect = IOError("save failed")
        with pytest.raises(IOError, match="save failed"):
            misc.convert_png_to_jpeg(b"data")

    # -----------------------------
    # post_redirect_with_payload empty string payload
    # -----------------------------
    @patch("app.misc.render_template_string")
    def test_post_redirect_with_payload_empty_string(self, mock_render):
        target_url = "https://example.com"
        payload = {"key": ""}
        misc.post_redirect_with_payload(target_url, payload)
        args, kwargs = mock_render.call_args
        decoded_payload = json.loads(kwargs["data"])
        assert decoded_payload["key"] == ""

    # -----------------------------
    # credential_error_resp with desc empty
    # -----------------------------
    @patch("app.misc.secrets")
    @patch("app.misc.jsonify")
    def test_credential_error_resp_empty_desc(self, mock_jsonify, mock_secrets):
        mock_secrets.token_urlsafe.return_value = "nonce"
        mock_jsonify.return_value = MagicMock()
        resp, status = misc.credential_error_resp("error_only", "")
        assert status == 400
        assert resp is not None

    # -----------------------------
    # auth_error_redirect with missing description
    # -----------------------------
    @patch("app.misc.redirect")
    @patch("app.misc.url_get")
    def test_auth_error_redirect_missing_desc(self, mock_url_get, mock_redirect):
        return_uri = "https://wallet.com/callback"
        mock_url_get.return_value = f"{return_uri}?error=error_only"
        misc.auth_error_redirect(return_uri, "error_only")
        mock_redirect.assert_called_with(mock_url_get.return_value, code=302)

    # -----------------------------
    # getIssuerFilledAttributesSDJWT empty claims
    # -----------------------------
    def test_getIssuerFilledAttributesSDJWT_empty_claims(self):
        result = misc.getIssuerFilledAttributesSDJWT([])
        assert result == {}

    # -----------------------------
    # scope2details with empty list input
    # -----------------------------
    def test_scope2details_empty_list(self):
        result = misc.scope2details([])
        assert result == ["openid"]

    # -----------------------------
    # getSubClaims with missing vct
    # -----------------------------
    def test_getSubClaims_missing_vct(self):
        result = misc.getSubClaims("nonexistent", "missing_vct")
        assert result == []
