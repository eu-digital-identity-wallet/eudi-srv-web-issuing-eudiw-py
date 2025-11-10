import pytest
from unittest.mock import MagicMock, patch, ANY
import datetime
import json
from app.dynamic_func import (
    dynamic_formatter,
    formatter,
    get_requested_credential,
    update_dates_and_special_claims,
    normalize_list_and_type_fields,
    populate_pdata,
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
            side_effect=[["mdoc_mand1"], ["mdoc_mand2"]]
        ),
        "app.dynamic_func.getOptionalAttributes": MagicMock(
            side_effect=[["mdoc_opt1"], ["mdoc_opt2"]]
        ),
        "app.dynamic_func.getIssuerFilledAttributes": MagicMock(
            side_effect=[["mdoc_iss1", "issuance_date"], ["mdoc_iss2"]]
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
        "app.dynamic_func.cfgserv": MagicMock(),
        "app.dynamic_func.cfgcountries": MagicMock(),
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
    mocks["app.dynamic_func.cfgcountries"].supported_countries = {
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
        "doctype, expected_un_sign",
        [
            ("org.iso.18013.5.1.mDL", "PRT"),
            ("eu.europa.ec.eudi.pid.1", ""),  # Non-mDL should have empty sign
        ],
    )
    def test_mso_mdoc_success(
        self, mock_external_dependencies, doctype, expected_un_sign
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
                doctype=doctype,
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
        mock_external_dependencies["app.dynamic_func.cfgserv"].service_url = (
            "http://formatter/"
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

        with patch(
            "app.dynamic_func.formatter",
            return_value=(mock_formatter_data, mock_formatter_cred),
        ) as mock_formatter:
            result = dynamic_formatter(
                format="dc+sd-jwt",
                doctype="eu.europa.ec.eudi.pid.1",
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
                doctype="eu.europa.ec.eudi.pid.1",
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
        "app.dynamic_func.doctype2credential",
        return_value={"cred_mdoc": "data", "issuer_config": {"validity": 365}},
    )
    def test_mdoc(self, mock_doctype2credential):
        """Tests credential retrieval for mso_mdoc format."""
        cred, pdata = get_requested_credential(
            self.MOCK_DATA, "mdl", "mso_mdoc", MOCK_TODAY
        )
        mock_doctype2credential.assert_called_once_with("mdl", "mso_mdoc")
        assert cred["cred_mdoc"] == "data"
        assert pdata == {}

    @patch(
        "app.dynamic_func.doctype2credentialSDJWT",
        return_value={
            "cred_sdjwt": "data",
            "issuer_config": {
                "validity": 365,
                "organization_name": "OrgName",
                "organization_id": "OrgID",
            },
        },
    )
    def test_sdjwt(self, mock_doctype2credentialSDJWT):
        """Tests credential retrieval and pdata initialization for dc+sd-jwt format."""
        cred, pdata = get_requested_credential(
            self.MOCK_DATA, "pid", "dc+sd-jwt", MOCK_TODAY
        )
        mock_doctype2credentialSDJWT.assert_called_once_with("pid", "dc+sd-jwt")
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


# --- Test `normalize_list_and_type_fields` ---


class TestNormalizeListAndTypeFields:

    MOCK_ATTRIBUTES_REQ = {"driving_privileges", "age_in_years"}
    MOCK_ATTRIBUTES_OPT = {"residence_address", "age_birth_year"}

    def test_normalize_list_fields_json_string(self):
        """Tests normalization of list fields passed as JSON strings."""
        data = {
            "driving_privileges": '[{"class": "B"}]',  # In MOCK_ATTRIBUTES_REQ
            "residence_address": '[{"street": "Main St"}]',  # In MOCK_ATTRIBUTES_OPT
        }

        normalize_list_and_type_fields(
            data, self.MOCK_ATTRIBUTES_REQ, self.MOCK_ATTRIBUTES_OPT
        )

        assert data["driving_privileges"] == {"class": "B"}
        assert data["residence_address"] == {"street": "Main St"}

    def test_normalize_list_fields_python_list(self):
        """Tests normalization of list fields passed as Python lists."""
        data = {
            "driving_privileges": [{"class": "B"}],  # In MOCK_ATTRIBUTES_REQ
            "residence_address": [{"street": "Main St"}],  # In MOCK_ATTRIBUTES_OPT
        }

        normalize_list_and_type_fields(
            data, self.MOCK_ATTRIBUTES_REQ, self.MOCK_ATTRIBUTES_OPT
        )

        # It should take the first element from the list
        assert data["driving_privileges"] == {"class": "B"}
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
