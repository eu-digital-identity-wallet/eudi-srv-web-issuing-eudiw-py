import pytest
import datetime
from unittest.mock import MagicMock, patch

# Assuming misc.py is in the app directory
from app import misc

# --- Fixtures and Mocks Setup ---


@pytest.fixture(scope="session")
def mock_oidc_metadata():
    """
    Session-scoped mock for oidc_metadata. pid_mdoc no longer contains a 'vct'.
    """
    return {
        "credential_configurations_supported": {
            # --- PID mdoc CONFIGURATION (VCT REMOVED) ---
            "pid_mdoc": {
                "format": "mso_mdoc",
                "scope": "eu.europa.ec.eudi.pid_mdoc",
                # VCT REMOVED: No 'vct' field here
                "issuer_config": {"doctype": "eu.europa.ec.eudi.pid.1"},
                "credential_metadata": {
                    "claims": [
                        # MANDATORY CLAIMS (User Source)
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
                        # MANDATORY NESTED
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
                            },
                        },
                        # MANDATORY ISSUER CLAIMS
                        {
                            "path": ["eu.europa.ec.eudi.pid.1", "issuance_date"],
                            "mandatory": True,
                            "source": "issuer",
                        },
                        # OPTIONAL CLAIMS
                        {
                            "path": ["eu.europa.ec.eudi.pid.1", "document_number"],
                            "mandatory": False,
                            "value_type": "string",
                            "source": "user",
                        },
                    ]
                },
            },
            # --- PID SD-JWT CONFIGURATION ---
            "eu.europa.ec.eudi.pid_vc_sd_jwt": {
                "format": "dc+sd-jwt",
                "scope": "eu.europa.ec.eudi.pid_vc_sd_jwt",
                "vct": "urn:eudi:pid:1",  # Real VCT for testing
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
                                "nationalities": {
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
                            "path": ["document_number"],
                            "mandatory": False,
                            "value_type": "string",
                            "source": "user",
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
    ):
        yield


# ------------------------------------------------------------------------------
# --- Test Class for Simple Utility Functions ----------------------------------
# ------------------------------------------------------------------------------


class TestSimpleUtilities:
    """Tests for basic, non-credential-specific helper functions."""

    def test_create_dict(self):
        input_dict = {"key1": {"value": 10, "label": "Ten"}}
        assert misc.create_dict(input_dict, "label") == {"key1": "Ten"}

    def test_urlsafe_b64encode_nopad(self):
        assert misc.urlsafe_b64encode_nopad(b"abcde") == "YWJjZGU"

    def test_calculate_age(self):
        today = datetime.date.today()
        current_year = today.year
        dob_today = today.replace(year=current_year - 25).strftime("%Y-%m-%d")
        assert misc.calculate_age(dob_today) == 25

    @patch("app.misc.Image")
    def test_validate_image_success(self, mock_Image):
        mock_file = MagicMock(filename="photo.jpg")
        mock_image_instance = mock_Image.open.return_value
        mock_image_instance.size = (360, 433)
        is_valid, error = misc.validate_image(mock_file)
        assert is_valid is True


# ------------------------------------------------------------------------------
# --- Test Class for Credential Configuration and Lookup (Updated) -------------
# ------------------------------------------------------------------------------


class TestCredentialLookup:
    """Tests for functions related to looking up credential metadata (VCTs, scopes, etc.)."""

    def test_vct2scope(self):
        # Checks PID SD-JWT VCT (Only VCT that exists in the mock data)
        assert misc.vct2scope("urn:eudi:pid:1") == "eu.europa.ec.eudi.pid_vc_sd_jwt"
        # Checks a non-existent VCT (using the new fake_vct string)
        assert misc.vct2scope("fake_vct") is None
        assert misc.vct2scope("nonexistent_vct") is None

    def test_vct2doctype(self):
        # The mdoc entry has no VCT, so we check the fake_vct returns None
        assert misc.vct2doctype("fake_vct") is None
        # Checks PID SD-JWT doctype
        assert misc.vct2doctype("urn:eudi:pid:1") == "eu.europa.ec.eudi.pid.1"

    def test_vct2id(self):
        # The mdoc entry has no VCT, so we check the fake_vct returns None
        assert misc.vct2id("fake_vct") is None
        # Checks PID SD-JWT ID
        assert misc.vct2id("urn:eudi:pid:1") == "eu.europa.ec.eudi.pid_vc_sd_jwt"
        assert misc.vct2id("nonexistent_vct") is None

    def test_scope2details(self):
        # Test: Combined PID mdoc and PID SD-JWT scope
        scope_in = [
            "openid",
            "eu.europa.ec.eudi.pid_mdoc",
            "eu.europa.ec.eudi.pid_vc_sd_jwt",
        ]
        expected_out = [
            {"credential_configuration_id": "pid_mdoc"},
            {"credential_configuration_id": "eu.europa.ec.eudi.pid_vc_sd_jwt"},
        ]
        assert misc.scope2details(scope_in) == expected_out


# ------------------------------------------------------------------------------
# --- Test Class for Attribute Processing and Form Generation ------------------
# ------------------------------------------------------------------------------


class TestAttributeProcessing:
    """Tests for functions that process claims and generate form structures."""

    def test_process_nested_attributes_simple(self):
        conditions = {
            "sub_attr1": {"value_type": "integer", "mandatory": True, "source": "user"}
        }
        expected = {
            "sub_attr1": {
                "type": "integer",
                "mandatory": True,
                "source": "user",
                "filled_value": None,
            }
        }
        assert misc._process_nested_attributes(conditions) == expected

    def test_getMandatoryAttributes_pid_sdjwt(self):
        """
        Tests mandatory attribute extraction for the pid_vc_sd_jwt fixture.
        """
        credentials_requested = ["eu.europa.ec.eudi.pid_vc_sd_jwt"]
        result = misc.getAttributesForm(credentials_requested)

        # 1. Check simple mandatory claims (Level 1)
        assert "family_name" in result

        # 2. Check nested mandatory claim: nationalities (List)
        nationality = result["nationalities"]
        nat_attrs = nationality["attributes"]

        # Access the first (and only) element in the attributes list.
        country_code_attrs = nat_attrs[0]
        assert country_code_attrs["country_code"]["mandatory"] is True

        # 3. Check for excluded claims
        assert "date_of_issuance" not in result  # source: issuer -> excluded

    def test_getOptionalAttributes_pid_sdjwt_nested(self):
        """
        Tests optional attribute extraction, focusing on the optional multi-level 'address' claim.
        """
        credentials_requested = ["eu.europa.ec.eudi.pid_vc_sd_jwt"]
        result = misc.getAttributesForm2(
            credentials_requested
        )  # Uses getOptionalAttributes

        # 1. Check optional Level-1 claims
        assert "document_number" in result

        # 2. Check optional Level-2 nested claim: 'address'
        assert "address" in result
        address = result["address"]
        address_attrs_list = address["attributes"]

        # The nested attributes are in a list of dictionaries, so we must iterate/find.
        street_address_entry = next(
            item for item in address_attrs_list if "street_address" in item
        )
        street_address_attr = street_address_entry["street_address"]

        assert street_address_attr["type"] == "string"

        # 3. Check for excluded claims
        assert "family_name" not in result  # Mandatory claims excluded
