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
from unittest.mock import MagicMock, patch, ANY
import datetime
import json
import uuid
from app.dynamic_func import (
    dynamic_formatter,
    formatter,
    get_requested_credential,
    update_dates_and_special_claims,
    normalize_list_and_type_fields,
    populate_pdata,
    shape_claims,
    check_presence_conditions,
    check_form_data,
    checked_iban,
    mask_iban,
    national_bank_code,
)
from app.dynamic_func import (
    doctype2credential,  # Imported for mocking
    doctype2credentialSDJWT,  # Imported for mocking
)

# --- Fixtures and Mocks ---

# Mock the current date to ensure stable date calculations
MOCK_TODAY = datetime.date(2025, 10, 27)


@pytest.fixture(autouse=True)
def mock_external_dependencies():
    """Mocks all necessary external dependencies for the entire module."""
    mocks = {
        # datetime is used to get 'today'
        "datetime.date": MagicMock(wraps=datetime.date),
        # Dependencies from misc
        "app.dynamic_func.calculate_age": MagicMock(return_value=20),
        "app.dynamic_func.doctype2credential": MagicMock(),
        "app.dynamic_func.doctype2credentialSDJWT": MagicMock(),
        "app.dynamic_func.getNamespaces": MagicMock(return_value=["ns1", "ns2"]),
        "app.dynamic_func.getMandatoryAttributes": MagicMock(
            side_effect=[[("mdoc_mand1_key", "mdoc_mand1_key")], [("mdoc_mand2_key", "mdoc_mand2_key")]]
        ),
        "app.dynamic_func.getOptionalAttributes": MagicMock(
            side_effect=[[("mdoc_opt1_key", "mdoc_opt1_value")], [("mdoc_opt2_key", "mdoc_opt2_value")]]
        ),
        "app.dynamic_func.getIssuerFilledAttributes": MagicMock(
            side_effect=[[("mdoc_iss1_key", "mdoc_iss1_value"), ("issuance_date_key", "issuance_date_value")], [("mdoc_iss2_key", "mdoc_iss2_value")]]
        ),
        "app.dynamic_func.getMandatoryAttributesSDJWT": MagicMock(
            return_value=["sdjwt_mand1"]
        ),
        "app.dynamic_func.getOptionalAttributesSDJWT": MagicMock(
            return_value=["sdjwt_opt1"]
        ),
        "app.dynamic_func.getIssuerFilledAttributesSDJWT": MagicMock(
            return_value=["sdjwt_iss1", "issue_date"]
        ),
        # Dependencies from app_config
        "app.dynamic_func.CONFIGURATION": {},
        #"app.dynamic_func.cfgcountries": MagicMock(),
        # Dependency from redirect_func
        "app.dynamic_func.json_post": MagicMock(),
        # Dependencies from app
        "app.dynamic_func.session_manager": MagicMock(),
        # Dependencies from formatter_func
        "app.dynamic_func.mdocFormatter": MagicMock(),
        "app.dynamic_func.sdjwtFormatter": MagicMock(),
    }

    # Specific setup for datetime mock
    mocks["datetime.date"].today.return_value = MOCK_TODAY

    # Specific setup for cfgcountries mock
    mocks["app.dynamic_func.CONFIGURATION"]['countries'] = {
        "PT": {"un_distinguishing_sign": "PRT"}
    }

    # Create a dummy session object
    current_session = MagicMock()
    current_session.country = "PT"
    mocks["app.dynamic_func.session_manager"].get_session.return_value = current_session

    # Patch and yield
    patchers = [patch(target, mock) for target, mock in mocks.items()]
    for p in patchers:
        p.start()
    yield mocks  # Make mocks available if needed for specific assertions
    for p in patchers:
        p.stop()


# --- Test `dynamic_formatter` (The main entry point) ---


class TestDynamicFormatter:

    MOCK_FORM_DATA = {"given_name": "Test"}
    MOCK_DEVICE_KEY = "device_key"
    MOCK_SESSION_ID = "session123"

    @pytest.mark.parametrize(
        "scope, expected_un_sign",
        [
            ("eu.europa.ec.eudi.mdl_mdoc", "PRT"),
            ("eu.europa.ec.eudi.pid.1", ""),  # Non-mDL should have empty sign
        ],
    )
    def test_mso_mdoc_success(
        self, mock_external_dependencies, scope, expected_un_sign
    ):
        """Tests the mso_mdoc format flow."""
        mock_credential = b"mock_mdoc_data"
        mock_external_dependencies["app.dynamic_func.mdocFormatter"].return_value = (
            mock_credential
        )

        # Mock formatter return (data, requested_credential)
        mock_formatter_data = {"mdl_attr": "value"}
        mock_formatter_cred = {
            "credential_metadata": {"claims": {}},
            "issuer_config": {"validity": 365},
        }

        with patch(
            "app.dynamic_func.formatter",
            return_value=(mock_formatter_data, mock_formatter_cred),
        ) as mock_formatter:
            result = dynamic_formatter(
                format="mso_mdoc",
                scope=scope,
                form_data=self.MOCK_FORM_DATA,
                device_publickey=self.MOCK_DEVICE_KEY,
                session_id=self.MOCK_SESSION_ID,
            )

            # Assertions
            mock_external_dependencies[
                "app.dynamic_func.session_manager"
            ].get_session.assert_called_once_with(session_id=self.MOCK_SESSION_ID)
            mock_formatter.assert_called_once()
            assert mock_formatter.call_args[0][1] == expected_un_sign

            mock_external_dependencies[
                "app.dynamic_func.mdocFormatter"
            ].assert_called_once_with(
                data=mock_formatter_data,
                credential_metadata=mock_formatter_cred,
                country="PT",
                device_publickey=self.MOCK_DEVICE_KEY,
                session_id=self.MOCK_SESSION_ID,
            )
            assert result == mock_credential

    def test_dc_sd_jwt_success(self, mock_external_dependencies):
        """Tests the dc+sd-jwt format flow with successful json_post."""
        mock_sd_jwt = "mock.sd-jwt.data"
        mock_external_dependencies["app.dynamic_func.CONFIGURATION"]['service_url'] = (
            "http://formatter"
        )
        mock_external_dependencies[
            "app.dynamic_func.json_post"
        ].return_value.json.return_value = {
            "error_code": 0,
            "sd-jwt": mock_sd_jwt,
        }

        # Mock formatter return (data, requested_credential)
        mock_formatter_data = {"sdjwt_attr": "value"}
        mock_formatter_cred = {
            "credential_metadata": {"claims": {}},
            "issuer_config": {"validity": 365},
        }
        mock_scope = "eu.europa.ec.eudi.pid.1"

        with patch(
            "app.dynamic_func.formatter",
            return_value=(mock_formatter_data, mock_formatter_cred),
        ) as mock_formatter:
            result = dynamic_formatter(
                format="dc+sd-jwt",
                scope=mock_scope,
                form_data=self.MOCK_FORM_DATA,
                device_publickey=self.MOCK_DEVICE_KEY,
                session_id=self.MOCK_SESSION_ID,
            )

            # Assertions
            mock_formatter.assert_called_once()
            mock_external_dependencies[
                "app.dynamic_func.json_post"
            ].assert_called_once_with(
                "http://formatter/formatter/sd-jwt",
                {
                    "country": "PT",
                    "credential_metadata": mock_formatter_cred,
                    "scope": mock_scope,
                    "device_publickey": self.MOCK_DEVICE_KEY,
                    "data": mock_formatter_data,
                },
            )
            assert result == mock_sd_jwt

    def test_dc_sd_jwt_error(self, mock_external_dependencies):
        """Tests the dc+sd-jwt format flow when json_post returns an error."""
        mock_external_dependencies[
            "app.dynamic_func.json_post"
        ].return_value.json.return_value = {
            "error_code": 1,
            "error_message": "Post failed",
        }
        
        mock_external_dependencies[
            "app.dynamic_func.CONFIGURATION"
        ]["service_url"] = "http://formatter"

        # Mock formatter return
        mock_formatter_data = {"sdjwt_attr": "value"}
        mock_formatter_cred = {
            "credential_metadata": {"claims": {}},
            "issuer_config": {"validity": 365},
        }

        with patch(
            "app.dynamic_func.formatter",
            return_value=(mock_formatter_data, mock_formatter_cred),
        ):
            result = dynamic_formatter(
                format="dc+sd-jwt",
                scope="eu.europa.ec.eudi.pid.1",
                form_data=self.MOCK_FORM_DATA,
                device_publickey=self.MOCK_DEVICE_KEY,
                session_id=self.MOCK_SESSION_ID,
            )

            # Assertions
            assert result == "Error"


# --- Test `formatter` ---


class TestFormatter:

    # Mock return values for get_requested_credential
    MOCK_MDOC_CRED = {
        "credential_metadata": {"claims": "mdoc_claims_data"},
        "issuer_config": {"validity": 365},
    }
    MOCK_SDJWT_CRED = {
        "credential_metadata": {"claims": "sdjwt_claims_data"},
        "issuer_config": {"validity": 365},
    }

    @pytest.mark.parametrize(
        "format, mock_cred, num_namespaces, un_sign",
        [
            ("mso_mdoc", MOCK_MDOC_CRED, 2, "PRT"),
            ("dc+sd-jwt", MOCK_SDJWT_CRED, 0, ""),
        ],
    )
    @patch("app.dynamic_func.get_requested_credential")
    @patch("app.dynamic_func.update_dates_and_special_claims")
    @patch("app.dynamic_func.normalize_list_and_type_fields")
    @patch("app.dynamic_func.populate_pdata")
    def test_formatter_flow(
        self,
        mock_populate_pdata,
        mock_normalize,
        mock_update,
        mock_get_cred,
        format,
        mock_cred,
        num_namespaces,
        un_sign,
        mock_external_dependencies,
    ):
        """Tests the overall flow of the formatter function for both formats."""
        mock_get_cred.return_value = (mock_cred, {"initial": "pdata"})

        data_in = {"given_name": "Test", "issuing_country": "PT"}
        pdata_out, cred_out = formatter(data_in, un_sign, "doctype", format)

        # Assertions
        mock_get_cred.assert_called_once()
        mock_update.assert_called_once()
        mock_normalize.assert_called_once()
        mock_populate_pdata.assert_called_once()

        # Mdoc specific check (namespace calls)
        if format == "mso_mdoc":
            mock_external_dependencies[
                "app.dynamic_func.getNamespaces"
            ].assert_called_once()
            assert (
                mock_external_dependencies[
                    "app.dynamic_func.getMandatoryAttributes"
                ].call_count
                == num_namespaces
            )
        else:  # SD-JWT specific check
            mock_external_dependencies[
                "app.dynamic_func.getMandatoryAttributesSDJWT"
            ].assert_called_once()

        assert cred_out == mock_cred
        # pdata_out is the modified version of the initial pdata
        assert pdata_out["initial"] == "pdata"


# --- Test `get_requested_credential` ---


class TestGetRequestedCredential:

    MOCK_DATA = {"issuing_country": "PT"}

    @patch(
        "app.dynamic_func.oidc_metadata",
        {
            "credential_configurations_supported": {
                "mdl": {
                    "cred_mdoc": "data",
                    "issuer_config": {
                        "validity": 365
                    }
                }
            } 
        },
    )
    def test_mdoc(self):
        """Tests credential retrieval for mso_mdoc format."""
        cred, pdata = get_requested_credential(
            self.MOCK_DATA, "mdl", "mso_mdoc", MOCK_TODAY
        )
        #mock_oidc_metadata.assert_called_once_with("mdl", "mso_mdoc")
        assert cred["cred_mdoc"] == "data"
        assert pdata == {}

    @patch(
        "app.dynamic_func.oidc_metadata",
        {
            "credential_configurations_supported": {
                "pid": {
                    "cred_sdjwt": "data",
                    "issuer_config": {
                        "validity": 365,
                        "organization_name": "OrgName",
                        "organization_id": "OrgID",
                    },
                    "vct": "pid"
                }
            }
        },
    )
    def test_sdjwt(self):
        """Tests credential retrieval and pdata initialization for dc+sd-jwt format."""
        cred, pdata = get_requested_credential(
            self.MOCK_DATA, "pid", "dc+sd-jwt", MOCK_TODAY
        )
        #mock_doctype2credentialSDJWT.assert_called_once_with("pid", "dc+sd-jwt")
        assert cred["cred_sdjwt"] == "data"
        assert pdata["claims"] == {}
        assert pdata["evidence"][0]["type"] == "pid"
        assert pdata["evidence"][0]["source"]["organization_name"] == "OrgName"


# --- Test `update_dates_and_special_claims` ---


class TestUpdateDatesAndSpecialClaims:

    MOCK_TODAY_STR = MOCK_TODAY.strftime("%Y-%m-%d")
    MOCK_EXPIRY_STR = (MOCK_TODAY + datetime.timedelta(days=365)).strftime("%Y-%m-%d")

    MOCK_CREDENTIAL = {
        "scope": "test_scope",
        "issuer_config": {
            "issuing_authority_id": "IA_ID",
            "issuing_authority": "IA_NAME",
            "credential_type": "CTYPE",
        },
    }

    MOCK_EU_CREDENTIAL = {
        "scope": "eu.europa.ec.eudi.ehic_sd_jwt_vc",
        "issuer_config": MOCK_CREDENTIAL["issuer_config"],
    }

    def test_all_updates(self, mock_external_dependencies):
        """Tests all update logic branches."""

        # Setup input data with a birth date that makes age > 18
        mock_external_dependencies["app.dynamic_func.calculate_age"].return_value = 25
        data = {"birth_date": "2000-01-01"}

        # Setup all possible issuer claims
        issuer_claims = {
            "age_over_18",
            "un_distinguishing_sign",
            "issuance_date",
            "date_of_issuance",
            "issue_date",
            "expiry_date",
            "date_of_expiry",
            "issuing_authority",
            "issuing_authority_unicode",
            "credential_type",
        }

        # Execute update
        update_dates_and_special_claims(
            data,
            issuer_claims,
            "PRT",
            MOCK_TODAY,
            MOCK_TODAY + datetime.timedelta(days=365),
            self.MOCK_CREDENTIAL,
            self.MOCK_CREDENTIAL["issuer_config"],
        )

        # Assertions
        assert data["age_over_18"] is True
        assert data["un_distinguishing_sign"] == "PRT"
        assert data["issuance_date"] == self.MOCK_TODAY_STR
        assert data["date_of_issuance"] == self.MOCK_TODAY_STR
        assert data["issue_date"] == self.MOCK_TODAY_STR
        assert data["expiry_date"] == self.MOCK_EXPIRY_STR
        assert data["date_of_expiry"] == self.MOCK_EXPIRY_STR

        # Standard issuing_authority format
        assert data["issuing_authority"] == "IA_NAME"
        assert data["issuing_authority_unicode"] == "IA_NAME"
        assert data["credential_type"] == "CTYPE"

    def test_age_under_18(self, mock_external_dependencies):
        """Tests age_over_18 when the calculated age is under 18."""
        mock_external_dependencies["app.dynamic_func.calculate_age"].return_value = 17
        data = {"birth_date": "2010-01-01"}
        issuer_claims = {"age_over_18"}

        update_dates_and_special_claims(
            data,
            issuer_claims,
            "",
            MOCK_TODAY,
            MOCK_TODAY,
            self.MOCK_CREDENTIAL,
            self.MOCK_CREDENTIAL["issuer_config"],
        )
        assert data["age_over_18"] is False

    def test_eu_issuing_authority(self):
        """Tests the special dictionary format for EU issuing authority."""
        data = {}
        issuer_claims = {"issuing_authority"}

        update_dates_and_special_claims(
            data,
            issuer_claims,
            "",
            MOCK_TODAY,
            MOCK_TODAY,
            self.MOCK_EU_CREDENTIAL,
            self.MOCK_EU_CREDENTIAL["issuer_config"],
        )

        assert data["issuing_authority"] == {
            "id": "IA_ID",
            "name": "IA_NAME",
        }

    def test_attestation_legal_category_from_issuer_config(self):
        """The legal category is the credential's own, from its issuer_config."""
        issuer_config = {"attestation_legal_category": "non-qualified-EAA"}
        data = {}

        update_dates_and_special_claims(
            data,
            {"attestation_legal_category"},
            "",
            MOCK_TODAY,
            MOCK_TODAY,
            {"scope": "test_scope", "issuer_config": issuer_config},
            issuer_config,
        )

        assert data["attestation_legal_category"] == "non-qualified-EAA"

    def test_credential_id_is_a_new_urn_uuid_each_time(self):
        """credential_id identifies the issued credential, so it never repeats."""
        ids = []
        for _ in range(2):
            data = {}
            update_dates_and_special_claims(
                data,
                {"credential_id"},
                "",
                MOCK_TODAY,
                MOCK_TODAY,
                self.MOCK_CREDENTIAL,
                self.MOCK_CREDENTIAL["issuer_config"],
            )
            assert data["credential_id"].startswith("urn:uuid:")
            uuid.UUID(data["credential_id"].removeprefix("urn:uuid:"))
            ids.append(data["credential_id"])

        assert ids[0] != ids[1]

    def test_card_network_and_card_id_from_the_issuer(self):
        """A test card: network as configured, card_id a fresh opaque UUID."""
        issuer_config = {"network": "mastercard"}
        cards = []
        for _ in range(2):
            data = {}
            update_dates_and_special_claims(
                data,
                {"network", "card_id"},
                "",
                MOCK_TODAY,
                MOCK_TODAY,
                {"scope": "test_scope", "issuer_config": issuer_config},
                issuer_config,
            )
            assert data["network"] == "mastercard"
            uuid.UUID(data["card_id"])
            cards.append(data["card_id"])

        assert cards[0] != cards[1]

    def test_rulebook_claims_only_when_issuer_filled(self):
        """No rulebook claim is added to a credential that does not declare it."""
        data = {}

        update_dates_and_special_claims(
            data,
            {"issuing_authority"},
            "",
            MOCK_TODAY,
            MOCK_TODAY,
            self.MOCK_CREDENTIAL,
            self.MOCK_CREDENTIAL["issuer_config"],
        )

        assert "attestation_legal_category" not in data
        assert "credential_id" not in data
        assert "network" not in data
        assert "card_id" not in data

    def test_we_build_issuer_data(self):
        """sub is generated; account provider and issuing country come from
        the issuer configuration."""
        provider = {"provider_name": "Bank", "bic_swift": "TESTGRAA"}
        config = {"account_provider": provider, "issuing_country": "GR"}
        data = {"issuing_country": "FC"}

        update_dates_and_special_claims(
            data,
            {"sub", "account_provider", "issuing_country"},
            "",
            MOCK_TODAY,
            MOCK_TODAY,
            {"scope": "test_scope", "issuer_config": config},
            config,
        )

        assert data["sub"].startswith("urn:uuid:")
        uuid.UUID(data["sub"][len("urn:uuid:"):])
        assert data["account_provider"] == provider
        assert data["issuing_country"] == "GR"

    def test_issuing_country_without_config_is_kept(self):
        data = {"issuing_country": "FC"}

        update_dates_and_special_claims(
            data,
            {"issuing_country"},
            "",
            MOCK_TODAY,
            MOCK_TODAY,
            self.MOCK_CREDENTIAL,
            self.MOCK_CREDENTIAL["issuer_config"],
        )

        assert data["issuing_country"] == "FC"


# --- Test `shape_claims` ---


class TestShapeClaims:

    def test_group_occurring_once_is_an_object(self):
        claims = [
            {"path": ["merchant"], "value_type": "merchant_attributes",
             "issuer_conditions": {"cardinality": {"min": 1, "max": 1}}},
            {"path": ["merchant", "address"], "value_type": "address_attributes",
             "issuer_conditions": {"cardinality": {"min": 1, "max": 1}}},
            {"path": ["products"], "value_type": "products_attributes",
             "issuer_conditions": {"cardinality": {"min": 1, "max": "n"}}},
        ]
        data = {
            "merchant": [{"name": "Shop", "address": [{"city": "Athens"}]}],
            "products": [{"name": "Coffee"}],
        }

        shape_claims(data, claims)

        assert data["merchant"] == {"name": "Shop", "address": {"city": "Athens"}}
        assert data["products"] == [{"name": "Coffee"}]

    def test_value_types(self):
        claims = [
            {"path": ["total"], "value_type": "int"},
            {"path": ["products", "price"], "value_type": "int"},
            {"path": ["latitude"], "value_type": "number"},
            {"path": ["at"], "value_type": "date-time"},
            {"path": ["currencies"], "value_type": "list_string"},
            {"path": ["name"], "value_type": "string"},
        ]
        data = {
            "total": "-250",
            "products": [{"price": "120"}, {"price": "80"}],
            "latitude": "37.98",
            "at": "2026-10-22T10:30",
            "currencies": "EUR",
            "name": "42",
        }

        shape_claims(data, claims)

        assert data == {
            "total": -250,
            "products": [{"price": 120}, {"price": 80}],
            "latitude": 37.98,
            "at": "2026-10-22T10:30:00Z",
            "currencies": ["EUR"],
            "name": "42",
        }

    def test_single_groups_kept_as_lists_when_asked(self):
        claims = [
            {"path": ["authentic_source"], "value_type": "authentic_source_attributes",
             "issuer_conditions": {"cardinality": {"min": 1, "max": 1}}},
            {"path": ["total"], "value_type": "int"},
        ]
        data = {"authentic_source": [{"id": "A", "name": "B"}], "total": "5"}

        shape_claims(data, claims, single_groups_as_objects=False)

        assert data == {"authentic_source": [{"id": "A", "name": "B"}], "total": 5}

    def test_values_that_do_not_parse_are_kept(self):
        claims = [
            {"path": ["total"], "value_type": "int"},
            {"path": ["at"], "value_type": "date-time"},
        ]
        data = {"total": "twelve", "at": "2026-10-22T10:30:00Z"}

        shape_claims(data, claims)

        assert data == {"total": "twelve", "at": "2026-10-22T10:30:00Z"}


# --- Test `normalize_list_and_type_fields` ---


class TestNormalizeListAndTypeFields:

    MOCK_ATTRIBUTES_REQ = {"driving_privileges", "age_in_years"}
    MOCK_ATTRIBUTES_OPT = {"residence_address", "age_birth_year"}

    def test_normalize_list_fields_json_string(self):
        """Tests normalization of list fields passed as JSON strings."""
        data = {
            "residence_address": '[{"street": "Main St"}]',  # In MOCK_ATTRIBUTES_OPT
        }

        normalize_list_and_type_fields(
            data, self.MOCK_ATTRIBUTES_REQ, self.MOCK_ATTRIBUTES_OPT
        )

        assert data["residence_address"] == {"street": "Main St"}

    def test_normalize_list_fields_python_list(self):
        """Tests normalization of list fields passed as Python lists."""
        data = {
            "residence_address": [{"street": "Main St"}],  # In MOCK_ATTRIBUTES_OPT
        }

        normalize_list_and_type_fields(
            data, self.MOCK_ATTRIBUTES_REQ, self.MOCK_ATTRIBUTES_OPT
        )

        # It should take the first element from the list
        assert data["residence_address"] == {"street": "Main St"}

    def test_numeric_conversions(self):
        """Tests conversion of age fields from string to int."""
        data = {
            "age_in_years": "30",
            "age_birth_year": "1995",
            "gender": "1",  # Numeric gender string
        }

        normalize_list_and_type_fields(
            data, self.MOCK_ATTRIBUTES_REQ, self.MOCK_ATTRIBUTES_OPT
        )

        assert data["age_in_years"] == 30
        assert data["age_birth_year"] == 1995
        assert data["gender"] == 1

    def test_non_list_or_numeric_fields_ignored(self):
        """Tests that fields not in the list or numeric conversion logic are left alone."""
        data = {
            "gender": "male",  # Non-digit gender string
            "family_name": "Smith",
        }

        original_data = data.copy()
        normalize_list_and_type_fields(
            data, self.MOCK_ATTRIBUTES_REQ, self.MOCK_ATTRIBUTES_OPT
        )

        assert data == original_data


# --- Test `populate_pdata` ---


class TestPopulatePdata:

    MOCK_DATA = {
        "mdoc_mand1": "val1",
        "mdoc_opt1": "val2",
        "mdoc_iss1": "val3",
        "not_in_claims": "val_ignore",
        "sdjwt_mand1": "val4",
        "sdjwt_opt1": "val5",
        "sdjwt_iss1": "val6",
    }

    MOCK_NAMESPACES = ["ns1", "ns2"]
    MOCK_ATTRIBUTES_REQ = {"mdoc_mand1"}
    MOCK_ATTRIBUTES_OPT = {"mdoc_opt1"}
    MOCK_ISSUER_CLAIMS = {"mdoc_iss1"}
    MOCK_ATTRIBUTES_BY_NAMESPACE = { "ns1": { "mandatory": ["mdoc_mand1"], "optional": ["mdoc_opt1"], "issuer": ["mdoc_iss1"] }, "ns2": { "mandatory": ["mdoc_mand1"], "optional": ["mdoc_opt1"], "issuer": ["mdoc_iss1"] } }

    MOCK_ATTRIBUTES_REQ_SDJWT = {"sdjwt_mand1"}
    MOCK_ATTRIBUTES_OPT_SDJWT = {"sdjwt_opt1"}
    MOCK_ISSUER_CLAIMS_SDJWT = {"sdjwt_iss1"}

    def test_mso_mdoc_population(self):
        """Tests population logic for mso_mdoc (namespace-based dictionary)."""
        pdata = {}

        # Mocking multi-namespace attribute retrieval for the formatter logic
        attributes_req_ns1 = self.MOCK_ATTRIBUTES_REQ
        # FIX: Changed {} (dict) to set()
        attributes_req_ns2 = (
            set()
        )  # Simulate second namespace having no required claims

        # Mocking multi-namespace attribute retrieval for the formatter logic
        attributes_opt_ns1 = self.MOCK_ATTRIBUTES_OPT
        # FIX: Changed {} (dict) to set()
        attributes_opt_ns2 = set()

        issuer_claims_ns1 = self.MOCK_ISSUER_CLAIMS
        # FIX: Changed {} (dict) to set()
        issuer_claims_ns2 = set()

        # Combine all claims to simulate what is passed to populate_pdata per namespace
        all_claims_ns1 = attributes_req_ns1.union(attributes_opt_ns1).union(
            issuer_claims_ns1
        )
        all_claims_ns2 = attributes_req_ns2.union(attributes_opt_ns2).union(
            issuer_claims_ns2
        )

        # We use the combined set for all groups to simulate the final lists passed to populate_pdata.
        populate_pdata(
            self.MOCK_DATA,
            pdata,
            "mso_mdoc",
            self.MOCK_NAMESPACES,
            self.MOCK_ATTRIBUTES_REQ,
            self.MOCK_ATTRIBUTES_OPT,
            self.MOCK_ISSUER_CLAIMS,
            self.MOCK_ATTRIBUTES_BY_NAMESPACE,
        )

        # Assertions
        assert "ns1" in pdata
        assert "ns2" in pdata

        expected_ns_data = {
            "mdoc_mand1": "val1",
            "mdoc_opt1": "val2",
            "mdoc_iss1": "val3",
        }

        # Because the code iterates over the *same* attribute sets for *each* namespace:
        assert pdata["ns1"] == expected_ns_data
        assert pdata["ns2"] == expected_ns_data

    def test_sdjwt_population(self):
        """Tests population logic for dc+sd-jwt (single 'claims' object)."""
        pdata = {"claims": {"initial": "claim"}}

        # The sd-jwt attribute sets are separate
        all_attrs_sdjwt = self.MOCK_ATTRIBUTES_REQ_SDJWT.union(
            self.MOCK_ATTRIBUTES_OPT_SDJWT
        ).union(self.MOCK_ISSUER_CLAIMS_SDJWT)

        populate_pdata(
            self.MOCK_DATA,
            pdata,
            "dc+sd-jwt",
            None,
            self.MOCK_ATTRIBUTES_REQ_SDJWT,
            self.MOCK_ATTRIBUTES_OPT_SDJWT,
            self.MOCK_ISSUER_CLAIMS_SDJWT,
        )

        # Assertions
        expected_claims = {
            "initial": "claim",
            "sdjwt_mand1": "val4",
            "sdjwt_opt1": "val5",
            "sdjwt_iss1": "val6",
        }
        assert pdata["claims"] == expected_claims


# --- Test `check_presence_conditions` ---


class TestPresenceConditions:
    """rb-iban-ov 3.4 (used_if) and rb-eucc (not_used_if)."""

    OWNERSHIP = [
        {"path": ["account_ownership", "owner_name"],
         "issuer_conditions": {"used_if": {"attribute": "owner_type", "values": ["entity"]}}},
        {"path": ["account_ownership", "legal_person_identifiers"],
         "issuer_conditions": {"used_if": {"attribute": "owner_type", "values": ["entity"]}}},
        {"path": ["account_ownership", "given_name"],
         "issuer_conditions": {"used_if": {"attribute": "owner_type", "values": ["person"]}}},
        {"path": ["account_ownership", "surname"],
         "issuer_conditions": {"used_if": {"attribute": "owner_type", "values": ["person"]}}},
    ]

    REPRESENTATIVES = [
        {"path": ["legal_representative", None, "natural_person"],
         "issuer_conditions": {"not_used_if": {"logic": "any", "attributes": ["legal_person"]}}},
        {"path": ["legal_representative", None, "legal_person"],
         "issuer_conditions": {"not_used_if": {"logic": "any", "attributes": ["natural_person"]}}},
    ]

    def test_claims_of_the_other_owner_type_are_dropped(self):
        data = {"account_ownership": {
            "owner_type": "person", "given_name": "Maria", "surname": "K",
            "owner_name": "ACME", "legal_person_identifiers": [{"type": "LEI", "value": "x"}],
        }}
        check_presence_conditions(data, self.OWNERSHIP)
        assert data["account_ownership"] == {
            "owner_type": "person", "given_name": "Maria", "surname": "K",
        }

    def test_missing_claim_of_the_owner_type_fails(self):
        data = {"account_ownership": {"owner_type": "entity", "owner_name": "ACME"}}
        with pytest.raises(ValueError, match="legal_person_identifiers is required"):
            check_presence_conditions(data, self.OWNERSHIP)

    def test_representative_is_one_kind_of_person(self):
        data = {"legal_representative": [
            {"natural_person": {"full_name": "A"}},
            {"legal_person": {"name": "B"}},
        ]}
        check_presence_conditions(data, self.REPRESENTATIVES)

        data["legal_representative"][1]["natural_person"] = {"full_name": "C"}
        with pytest.raises(ValueError, match="cannot be combined"):
            check_presence_conditions(data, self.REPRESENTATIVES)

    POWERS = [
        {"path": ["powers"], "value_type": "list_string",
         "issuer_conditions": {
             "options": ["A", "B"],
             "other_values": {"label": "Limitation details",
                              "used_if": {"attribute": "substitution", "values": ["limited"]}}}},
    ]

    def test_limited_substitution_needs_limitation_details(self):
        """rb-eu-poa IR-04."""
        check_presence_conditions(
            {"powers": ["A", "Only up to EUR 10000"], "substitution": "limited"}, self.POWERS)
        check_presence_conditions({"powers": ["A", "B"], "substitution": "allowed"}, self.POWERS)
        check_presence_conditions({"powers": ["A"]}, self.POWERS)

        with pytest.raises(ValueError, match="needs Limitation details"):
            check_presence_conditions({"powers": ["A"], "substitution": "limited"}, self.POWERS)
        with pytest.raises(ValueError, match="only takes the listed values"):
            check_presence_conditions({"powers": ["A", "x"], "substitution": "allowed"}, self.POWERS)

    def test_empty_list_values_are_dropped(self):
        data = {"powers": ["A", ""]}
        shape_claims(data, self.POWERS)
        assert data == {"powers": ["A"]}


# --- SCA-IBAN: masked IBAN and national bank code (rb-sca-iban IR-01, IR-02) ---


class TestScaIban:

    def test_checked_iban(self):
        assert checked_iban("gr16 0110 1250 0000 0001 2300 695") == "GR1601101250000000012300695"
        with pytest.raises(ValueError, match="check digits"):
            checked_iban("GR1701101250000000012300695")
        with pytest.raises(ValueError, match="not well-formed"):
            checked_iban("")

    def test_mask_and_bank_code(self):
        iban = "CZ5508000000001234567899"  # the rulebook's example
        assert mask_iban(iban) == "CZ55***********7899"  # as the rulebook shows it
        assert national_bank_code(iban) == "0800"
        assert national_bank_code("DE89370400440532013000") == "37040044"
        assert national_bank_code("GR1601101250000000012300695") == "011"
        assert national_bank_code("PL61109010140000071219812874") is None

    def _issue(self, data):
        update_dates_and_special_claims(
            data, {"masked_iban", "national_bank_code"}, "", MOCK_TODAY, MOCK_TODAY, {}, {})
        return data

    def test_derived_from_the_iban(self):
        data = self._issue({
            "iban": "DE89 3704 0044 0532 0130 00",
            "masked_iban": "GR16***********0695",  # typed: ignored
            "national_bank_code": "999",           # typed: ignored
        })
        assert data == {
            "iban": "DE89370400440532013000",
            "masked_iban": "DE89***********3000",
            "national_bank_code": "37040044",
        }

    def test_unknown_bank_code_position_is_left_out(self):
        data = self._issue({"iban": "PL61109010140000071219812874", "national_bank_code": "1"})
        assert "national_bank_code" not in data

    def test_bad_iban_fails_issuance(self):
        with pytest.raises(ValueError):
            self._issue({"iban": "DE00370400440532013000"})


# --- Test `check_form_data` ---


class TestCheckFormData:
    """Data the credential endpoint would reject is turned down at the form."""

    CONFIGS = {"sca_iban": {"format": "dc+sd-jwt"}, "pid": {"format": "mso_mdoc"}}

    def test_reason_of_a_failing_check(self):
        with patch.dict("app.dynamic_func.oidc_metadata",
                        {"credential_configurations_supported": self.CONFIGS}), \
             patch("app.dynamic_func.formatter",
                   side_effect=ValueError("The IBAN check digits are wrong")) as formatter:
            data = {"iban": "DE00"}
            assert check_form_data(data, ["sca_iban"]) == "The IBAN check digits are wrong"
            # On a copy: the form data itself is left as it is
            assert formatter.call_args.args[0] is not data
            assert formatter.call_args.args[2:] == ("sca_iban", "dc+sd-jwt")

    def test_other_errors_are_left_to_the_credential_endpoint(self):
        with patch.dict("app.dynamic_func.oidc_metadata",
                        {"credential_configurations_supported": self.CONFIGS}), \
             patch("app.dynamic_func.formatter", side_effect=KeyError("x")):
            assert check_form_data({}, ["sca_iban", "unknown"]) is None

    def test_valid_data(self):
        with patch.dict("app.dynamic_func.oidc_metadata",
                        {"credential_configurations_supported": self.CONFIGS}), \
             patch("app.dynamic_func.formatter", return_value=({}, {})):
            assert check_form_data({}, ["sca_iban", "pid"]) is None
