# tests/test_formatter_func.py
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
from unittest.mock import patch, MagicMock, mock_open
from app.formatter_func import (
    DATA_sd_jwt,
    DatestringFormatter,
    KeyData,
    cbor2elems,
    mdocFormatter,
    recursive,
    sdjwtFormatter,
    sdjwtNestedClaims,
    SDObj,
)


@pytest.fixture
def sample_data():
    return {
        "Person": {
            "name": "John Doe",
            "image": "aW1hZ2VEYXRh",  # base64 for 'imageData'
            "portrait": "cG9ydHJhaXREYXRh",  # base64 for 'portraitData'
            "user_pseudonym": "johndoe123",
        }
    }


@pytest.fixture
def credential_metadata():
    return {
        "doctype": "Person",
        "issuer_config": {"namespace": "Person", "validity": 365},
    }


@pytest.fixture
def device_publickey():
    return "sample_device_public_key"


@pytest.fixture
def session_id():
    return "test-session-id"


@pytest.fixture
def country():
    return "FC"


class TestMdocFormatter:

    @patch("builtins.open", new_callable=mock_open, read_data=b"fake_key_data")
    @patch("app.formatter_func.serialization.load_pem_private_key")
    @patch("app.formatter_func.urlsafe_b64encode_nopad", return_value=b"signed_mdoc")
    @patch("app.formatter_func.MdocCborIssuer")
    @patch("app.formatter_func.requests.post")
    @patch("app.formatter_func.cfgservice")
    @patch("app.formatter_func.cfgcountries")
    @patch("app.formatter_func.session_manager")
    def test_basic_mdocFormatter(
        self,
        mock_session_manager,
        mock_cfgcountries,
        mock_cfgservice,
        mock_requests_post,
        mock_MdocCborIssuer,
        mock_b64encode,
        mock_load_key,
        mock_open,
        sample_data,
        credential_metadata,
        country,
        device_publickey,
        session_id,
    ):
        """Basic path: non-batch credential, no revocation"""
        # Mock session
        mock_session = MagicMock()
        mock_session.is_batch_credential = False
        mock_session_manager.get_session.return_value = mock_session

        # Mock private key
        mock_private_key = MagicMock()
        mock_private_key.private_numbers.return_value.private_value = 12345
        mock_load_key.return_value = mock_private_key

        # Mock country config
        mock_cfgcountries.supported_countries = {
            country: {
                "pid_mdoc_privkey": "fake_path",
                "pid_mdoc_privkey_passwd": None,
                "pid_mdoc_cert": "fake_cert_path",
            }
        }

        # Disable revocation
        global revocation_api_key
        revocation_api_key = None

        # Mock MdocCborIssuer instance
        mock_mdoci_instance = MagicMock()
        mock_MdocCborIssuer.return_value = mock_mdoci_instance

        result = mdocFormatter(
            data=sample_data,
            credential_metadata=credential_metadata,
            country=country,
            device_publickey=device_publickey,
            session_id=session_id,
        )

        # Assertions
        mock_open.assert_called_once_with("fake_path", "rb")
        mock_load_key.assert_called_once()
        mock_MdocCborIssuer.assert_called_once()
        mock_mdoci_instance.new.assert_called_once()
        mock_b64encode.assert_called_once_with(mock_mdoci_instance.dump())
        assert result == b"signed_mdoc"
        # Images decoded
        assert isinstance(sample_data["Person"]["image"], bytes)
        assert isinstance(sample_data["Person"]["portrait"], bytes)
        # Pseudonym encoded
        assert sample_data["Person"]["user_pseudonym"] == b"johndoe123"

    @patch("builtins.open", new_callable=mock_open, read_data=b"fake_key_data")
    @patch("app.formatter_func.serialization.load_pem_private_key")
    @patch(
        "app.formatter_func.urlsafe_b64encode_nopad", return_value=b"signed_mdoc_batch"
    )
    @patch("app.formatter_func.MdocCborIssuer")
    @patch("app.formatter_func.requests.post")
    @patch("app.formatter_func.cfgservice")
    @patch("app.formatter_func.cfgcountries")
    @patch("app.formatter_func.session_manager")
    def test_batch_credential(
        self,
        mock_session_manager,
        mock_cfgcountries,
        mock_cfgservice,
        mock_requests_post,
        mock_MdocCborIssuer,
        mock_b64encode,
        mock_load_key,
        mock_open,
        sample_data,
        credential_metadata,
        country,
        device_publickey,
        session_id,
    ):
        """Batch credential: issuance_date adjusted to 00:00:00"""
        # Mock session
        mock_session = MagicMock()
        mock_session.is_batch_credential = True
        mock_session_manager.get_session.return_value = mock_session

        # Mock private key
        mock_private_key = MagicMock()
        mock_private_key.private_numbers.return_value.private_value = 12345
        mock_load_key.return_value = mock_private_key

        # Mock country config
        mock_cfgcountries.supported_countries = {
            country: {
                "pid_mdoc_privkey": "fake_path",
                "pid_mdoc_privkey_passwd": None,
                "pid_mdoc_cert": "fake_cert_path",
            }
        }

        # Disable revocation
        global revocation_api_key
        revocation_api_key = None

        # Mock MdocCborIssuer instance
        mock_mdoci_instance = MagicMock()
        mock_MdocCborIssuer.return_value = mock_mdoci_instance

        result = mdocFormatter(
            data=sample_data,
            credential_metadata=credential_metadata,
            country=country,
            device_publickey=device_publickey,
            session_id=session_id,
        )

        # Check that issuance_date has time set to 00:00:00
        called_validity = mock_mdoci_instance.new.call_args.kwargs["validity"]
        assert called_validity["issuance_date"].hour == 0
        assert called_validity["issuance_date"].minute == 0
        assert called_validity["issuance_date"].second == 0

        assert result == b"signed_mdoc_batch"

    @patch("builtins.open", new_callable=mock_open, read_data=b"fake_key_data")
    @patch("app.formatter_func.serialization.load_pem_private_key")
    @patch(
        "app.formatter_func.urlsafe_b64encode_nopad",
        return_value=b"signed_mdoc_revocation",
    )
    @patch("app.formatter_func.MdocCborIssuer")
    @patch("app.formatter_func.requests.post")
    @patch("app.formatter_func.cfgservice")
    @patch("app.formatter_func.cfgcountries")
    @patch("app.formatter_func.session_manager")
    def test_revocation_branch(
        self,
        mock_session_manager,
        mock_cfgcountries,
        mock_cfgservice,
        mock_requests_post,
        mock_MdocCborIssuer,
        mock_b64encode,
        mock_load_key,
        mock_open,
        sample_data,
        credential_metadata,
        country,
        device_publickey,
        session_id,
    ):
        """Test revocation API branch"""
        # Mock session
        mock_session = MagicMock()
        mock_session.is_batch_credential = False
        mock_session_manager.get_session.return_value = mock_session

        # Mock private key
        mock_private_key = MagicMock()
        mock_private_key.private_numbers.return_value.private_value = 12345
        mock_load_key.return_value = mock_private_key

        # Mock country config
        mock_cfgcountries.supported_countries = {
            country: {
                "pid_mdoc_privkey": "fake_path",
                "pid_mdoc_privkey_passwd": None,
                "pid_mdoc_cert": "fake_cert_path",
            }
        }

        # Enable revocation
        global revocation_api_key
        revocation_api_key = "FAKE_API_KEY"

        # Mock requests.post to return JSON
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"revoked": False}
        mock_requests_post.return_value = mock_response

        # Mock MdocCborIssuer instance
        mock_mdoci_instance = MagicMock()
        mock_MdocCborIssuer.return_value = mock_mdoci_instance

        result = mdocFormatter(
            data=sample_data,
            credential_metadata=credential_metadata,
            country=country,
            device_publickey=device_publickey,
            session_id=session_id,
        )

        mock_requests_post.assert_called_once()
        called_revocation = mock_mdoci_instance.new.call_args.kwargs["revocation"]
        assert called_revocation == {"revoked": False}

        assert result == b"signed_mdoc_revocation"


# ------------------- Test class for cbor2elems -------------------


class TestCbor2Elems:

    @patch("app.formatter_func.cbor2.decoder.loads")
    @patch("app.formatter_func.base64.urlsafe_b64decode")
    def test_basic_elements(self, mock_b64decode, mock_cbor_loads):
        """Test normal elements and date elements"""
        fake_mdoc = "FAKE_BASE64"
        mock_b64decode.return_value = b"decoded_bytes"

        mock_cbor_loads.side_effect = [
            {  # CBOR for mdoc
                "documents": [
                    {
                        "issuerSigned": {
                            "nameSpaces": {
                                "ns1": [
                                    MagicMock(
                                        value=b'{"elementIdentifier":"name","elementValue":"Alice"}'
                                    ),
                                    MagicMock(
                                        value=b'{"elementIdentifier":"birth_date","elementValue":{"value":"2000-01-01"}}'
                                    ),
                                ]
                            }
                        }
                    }
                ]
            },
            {"elementIdentifier": "name", "elementValue": "Alice"},
            {
                "elementIdentifier": "birth_date",
                "elementValue": MagicMock(value="2000-01-01"),
            },
        ]

        result = cbor2elems(fake_mdoc)

        mock_b64decode.assert_called_once_with(fake_mdoc)
        assert ("name", "Alice") in result["ns1"]
        assert ("birth_date", "2000-01-01") in result["ns1"]

    @patch("app.formatter_func.cbor2.decoder.loads")
    @patch("app.formatter_func.base64.urlsafe_b64decode")
    def test_multiple_namespaces(self, mock_b64decode, mock_cbor_loads):
        """Test multiple namespaces with different elements"""
        fake_mdoc = "FAKE_BASE64_2"
        mock_b64decode.return_value = b"decoded_bytes"

        ns1_elem = MagicMock(value=b'{"elementIdentifier":"id","elementValue":"123"}')
        ns2_elem = MagicMock(
            value=b'{"elementIdentifier":"expiry_date","elementValue":{"value":"2030-12-31"}}'
        )

        mock_cbor_loads.side_effect = [
            {  # CBOR for mdoc
                "documents": [
                    {
                        "issuerSigned": {
                            "nameSpaces": {
                                "ns1": [ns1_elem],
                                "ns2": [ns2_elem],
                            }
                        }
                    }
                ]
            },
            {"elementIdentifier": "id", "elementValue": "123"},
            {
                "elementIdentifier": "expiry_date",
                "elementValue": MagicMock(value="2030-12-31"),
            },
        ]

        result = cbor2elems(fake_mdoc)

        assert result["ns1"] == [("id", "123")]
        assert result["ns2"] == [("expiry_date", "2030-12-31")]


class TestSDJWTNestedClaims:

    def test_scalar_claim(self):
        claims = {"name": "Alice"}
        credential_metadata = {}
        result = sdjwtNestedClaims(claims, credential_metadata)
        # Should wrap claim with SDObj
        key = list(result.keys())[0]
        assert isinstance(key, SDObj)
        assert result[key] == "Alice"

    def test_dict_claim(self):
        claims = {"address": {"street": "Main St", "city": "Paris"}}
        credential_metadata = {}
        result = sdjwtNestedClaims(claims, credential_metadata)
        key = list(result.keys())[0]
        sub = result[key]
        assert isinstance(sub, dict)
        for k in sub.keys():
            assert isinstance(k, SDObj)
        assert sub[SDObj("street")] == "Main St"
        assert sub[SDObj("city")] == "Paris"

    def test_list_claim_length_1(self):
        claims = {"employment": [{"company": "ABC"}]}
        credential_metadata = {}
        result = sdjwtNestedClaims(claims, credential_metadata)
        key = list(result.keys())[0]
        sub = result[key]
        assert isinstance(sub, dict)
        assert sub[SDObj("company")] == "ABC"

    def test_list_claim_length_gt1(self):
        claims = {"roles": [{"role": "admin"}, {"role": "user"}]}
        credential_metadata = {}
        result = sdjwtNestedClaims(claims, credential_metadata)
        key = list(result.keys())[0]
        sub = result[key]
        assert isinstance(sub, list)
        assert sub[0][SDObj("role")] == "admin"
        assert sub[1][SDObj("role")] == "user"

    def test_nationalities_list(self):
        claims = {"nationalities": ["FR", "DE"]}
        credential_metadata = {}
        result = sdjwtNestedClaims(claims, credential_metadata)
        key = list(result.keys())[0]
        sub = result[key]
        assert isinstance(sub, list)
        assert all(isinstance(n, SDObj) for n in sub)
        assert [n.value for n in sub] == ["FR", "DE"]

    def test_sd_map_false(self):
        claims = {"age": 30}
        credential_metadata = {
            "credential_metadata": {
                "claims": [{"path": ["age"], "selective_disclosure": False}]
            }
        }
        result = sdjwtNestedClaims(claims, credential_metadata)
        # Should NOT wrap with SDObj because selective_disclosure=False
        assert "age" in result
        assert result["age"] == 30

    def test_list_length_1_with_dict_element(self):
        claims = {"skills": [{"name": "Python"}]}
        credential_metadata = {}
        result = sdjwtNestedClaims(claims, credential_metadata)
        key = list(result.keys())[0]
        sub = result[key]
        assert isinstance(sub, dict)
        assert sub[SDObj("name")] == "Python"

    def test_list_length_gt1_with_dict_element(self):
        claims = {"projects": [{"name": "A"}, {"name": "B"}]}
        credential_metadata = {}
        result = sdjwtNestedClaims(claims, credential_metadata)
        key = list(result.keys())[0]
        sub = result[key]
        assert isinstance(sub, list)
        assert sub[0][SDObj("name")] == "A"
        assert sub[1][SDObj("name")] == "B"


class TestSDJWTFormatter:

    @patch("builtins.open", new_callable=mock_open, read_data=b"fake_cert_data")
    @patch("app.formatter_func.base64.b64encode", side_effect=lambda x: b"encoded_cert")
    @patch("app.formatter_func.serialization.load_pem_private_key")
    @patch(
        "app.formatter_func.base64.urlsafe_b64decode",
        side_effect=lambda x: b"decoded_device_key",
    )
    @patch("app.formatter_func.serialization.load_pem_public_key")
    @patch(
        "app.formatter_func.KeyData",
        side_effect=lambda key, t: ("crv", b"x_bytes", b"y_bytes"),
    )
    @patch(
        "app.formatter_func.get_jwk",
        return_value={"issuer_key": "issuer_key_obj", "holder_key": "holder_key_obj"},
    )
    @patch("app.formatter_func.SDJWTIssuer")
    @patch(
        "app.formatter_func.sdjwtNestedClaims", return_value={"claim_wrapped": "value"}
    )
    @patch("app.formatter_func.vct2doctype", side_effect=lambda vct: "Person")
    @patch("app.formatter_func.cfgcountries")
    @patch("app.formatter_func.cfgservice")
    @patch("app.formatter_func.requests.post")
    def test_basic_sdjwtFormatter(
        self,
        mock_requests_post,
        mock_cfgservice,
        mock_cfgcountries,
        mock_vct2doctype,
        mock_sdjwtNestedClaims,
        mock_SDJWTIssuer,
        mock_get_jwk,
        mock_KeyData,
        mock_load_public_key,
        mock_urlsafe_b64decode,
        mock_load_private_key,
        mock_b64encode,
        mock_open_file,
    ):
        # Mock PID input
        PID = {
            "data": {"claims": {"name": "Alice"}},
            "credential_metadata": {
                "issuer_config": {"validity": 365},
                "vct": "vct_value",
            },
            "device_publickey": "fake_device_key_base64",
        }
        country = "FC"

        # Mock private key
        mock_private_key = MagicMock()
        mock_private_key.private_numbers.return_value.private_value = 12345
        mock_load_private_key.return_value = mock_private_key

        # Mock cfgcountries
        mock_cfgcountries.supported_countries = {
            country: {
                "pid_mdoc_cert": "fake_cert_path",
                "pid_mdoc_privkey": "fake_key_path",
                "pid_mdoc_privkey_passwd": None,
            }
        }

        # Disable revocation
        global revocation_api_key
        revocation_api_key = None

        # Mock SDJWTIssuer instance
        mock_sdjwt_instance = MagicMock()
        mock_sdjwt_instance.sd_jwt_issuance = "sdjwt_token"
        mock_SDJWTIssuer.return_value = mock_sdjwt_instance

        result = sdjwtFormatter(PID, country)

        # Assertions
        mock_open_file.assert_any_call("fake_cert_path", "rb")
        mock_open_file.assert_any_call("fake_key_path", "rb")
        mock_load_private_key.assert_called_once()
        mock_load_public_key.assert_called_once()
        mock_sdjwtNestedClaims.assert_called_once_with(
            PID["data"]["claims"], PID["credential_metadata"]
        )
        mock_SDJWTIssuer.assert_called_once()
        assert result == "sdjwt_token"

    @patch("builtins.open", new_callable=mock_open, read_data=b"fake_cert_data")
    @patch("app.formatter_func.base64.b64encode", side_effect=lambda x: b"encoded_cert")
    @patch("app.formatter_func.serialization.load_pem_private_key")
    @patch(
        "app.formatter_func.base64.urlsafe_b64decode",
        side_effect=lambda x: b"decoded_device_key",
    )
    @patch("app.formatter_func.serialization.load_pem_public_key")
    @patch(
        "app.formatter_func.KeyData",
        side_effect=lambda key, t: ("crv", b"x_bytes", b"y_bytes"),
    )
    @patch(
        "app.formatter_func.get_jwk",
        return_value={"issuer_key": "issuer_key_obj", "holder_key": "holder_key_obj"},
    )
    @patch("app.formatter_func.SDJWTIssuer")
    @patch(
        "app.formatter_func.sdjwtNestedClaims", return_value={"claim_wrapped": "value"}
    )
    @patch("app.formatter_func.vct2doctype", side_effect=lambda vct: "Person")
    @patch("app.formatter_func.cfgcountries")
    @patch("app.formatter_func.cfgservice")
    @patch("app.formatter_func.requests.post")
    def test_revocation_branch(
        self,
        mock_requests_post,
        mock_cfgservice,
        mock_cfgcountries,
        mock_vct2doctype,
        mock_sdjwtNestedClaims,
        mock_SDJWTIssuer,
        mock_get_jwk,
        mock_KeyData,
        mock_load_public_key,
        mock_urlsafe_b64decode,
        mock_load_private_key,
        mock_b64encode,
        mock_open_file,
    ):
        # Mock PID input
        PID = {
            "data": {"claims": {"name": "Alice"}},
            "credential_metadata": {
                "issuer_config": {"validity": 365},
                "vct": "vct_value",
            },
            "device_publickey": "fake_device_key_base64",
        }
        country = "FC"

        # Mock private key
        mock_private_key = MagicMock()
        mock_private_key.private_numbers.return_value.private_value = 12345
        mock_load_private_key.return_value = mock_private_key

        # Mock cfgcountries
        mock_cfgcountries.supported_countries = {
            country: {
                "pid_mdoc_cert": "fake_cert_path",
                "pid_mdoc_privkey": "fake_key_path",
                "pid_mdoc_privkey_passwd": None,
            }
        }

        # Enable revocation
        global revocation_api_key
        revocation_api_key = "FAKE_API_KEY"

        # Mock requests.post to return JSON
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"revoked": False}
        mock_requests_post.return_value = mock_response

        # Mock SDJWTIssuer instance
        mock_sdjwt_instance = MagicMock()
        mock_sdjwt_instance.sd_jwt_issuance = "sdjwt_token_revocation"
        mock_SDJWTIssuer.return_value = mock_sdjwt_instance

        result = sdjwtFormatter(PID, country)

        mock_requests_post.assert_called_once()
        mock_sdjwtNestedClaims.assert_called_once()
        mock_SDJWTIssuer.assert_called_once()
        assert result == "sdjwt_token_revocation"


class TestDATA_SDJWT:

    @patch("app.formatter_func.SDObj", side_effect=lambda value: f"SDObj({value})")
    @patch("app.formatter_func.recursive", side_effect=lambda d: f"recursive({d})")
    @patch("app.formatter_func.cfgservice")
    def test_all_registered_claims_branches(
        self, mock_cfgservice, mock_recursive, mock_SDObj
    ):
        """Test age_equal_or_over, place_of_birth, address, and default registered claims"""
        PID = {
            "age": 25,
            "birth_place": "Paris",
            "home_address": "Main St",
            "email": "alice@example.com",
            "custom_claim": "custom_value",
        }

        mock_cfgservice.Registered_claims = {
            "age": "Person.age_equal_or_over",
            "birth_place": "Person.place_of_birth",
            "home_address": "Person.address",
            "email": "Person.email",
        }

        result = DATA_sd_jwt(PID)

        # Corrected assertions
        assert (
            result["SDObj(age_equal_or_over)"] == "recursive({'age_equal_or_over': 25})"
        )
        assert (
            result["SDObj(place_of_birth)"] == "recursive({'place_of_birth': 'Paris'})"
        )
        assert result["SDObj(address)"] == "recursive({'address': 'Main St'})"
        assert result["SDObj(Person.email)"] == "alice@example.com"
        assert result["SDObj(custom_claim)"] == "custom_value"

    @patch("app.formatter_func.SDObj", side_effect=lambda value: f"SDObj({value})")
    @patch("app.formatter_func.recursive", side_effect=lambda d: f"recursive({d})")
    @patch("app.formatter_func.cfgservice")
    def test_empty_registered_claims(self, mock_cfgservice, mock_recursive, mock_SDObj):
        """Test when Registered_claims is empty"""
        PID = {"nickname": "Ally", "hobby": "Chess"}

        mock_cfgservice.Registered_claims = {}

        result = DATA_sd_jwt(PID)

        assert result["SDObj(nickname)"] == "Ally"
        assert result["SDObj(hobby)"] == "Chess"


class TestRecursive:

    def test_normal_dict(self):
        input_dict = {"name": "Alice", "age": 30}
        result = recursive(input_dict)

        # Check that all keys are wrapped in SDObj
        for k, v in input_dict.items():
            assert SDObj(k) in result
            assert result[SDObj(k)] == v

    def test_empty_dict(self):
        input_dict = {}
        result = recursive(input_dict)
        assert result == {}


class TestDatestringFormatter:

    def test_normal_date(self):
        date_str = "2025-10-28"
        expected_timestamp = int(
            datetime.datetime.strptime(date_str, "%Y-%m-%d").timestamp()
        )
        result = DatestringFormatter(date_str)
        assert result == expected_timestamp

    def test_epoch_date(self):
        date_str = "1970-01-01"
        expected_timestamp = int(
            datetime.datetime.strptime(date_str, "%Y-%m-%d").timestamp()
        )
        result = DatestringFormatter(date_str)
        assert result == expected_timestamp


class TestKeyData:

    @pytest.mark.parametrize(
        "curve_name,expected_identifier",
        [
            ("secp256r1", "P-256"),
            ("secp384r1", "P-384"),
            ("secp521r1", "P-521"),
        ],
    )
    def test_public_key(self, curve_name, expected_identifier):
        # Mock key
        mock_key = MagicMock()
        mock_key.curve.name = curve_name
        mock_public_numbers = MagicMock()
        mock_public_numbers.x = 123456
        mock_public_numbers.y = 654321
        mock_key.public_numbers.return_value = mock_public_numbers

        curve_id, x_bytes, y_bytes = KeyData(mock_key, "public")

        assert curve_id == expected_identifier
        assert isinstance(x_bytes, bytes)
        assert isinstance(y_bytes, bytes)
        # Check that x and y are padded correctly
        assert len(x_bytes) == 32
        assert len(y_bytes) == 32

    @pytest.mark.parametrize(
        "curve_name,expected_identifier",
        [
            ("secp256r1", "P-256"),
            ("secp384r1", "P-384"),
            ("secp521r1", "P-521"),
        ],
    )
    def test_private_key(self, curve_name, expected_identifier):
        # Mock key
        mock_key = MagicMock()
        mock_key.curve.name = curve_name
        mock_public_numbers = MagicMock()
        mock_public_numbers.x = 123456
        mock_public_numbers.y = 654321
        mock_private_numbers = MagicMock()
        mock_private_numbers.public_numbers = mock_public_numbers
        mock_key.private_numbers.return_value = mock_private_numbers

        curve_id, x_bytes, y_bytes = KeyData(mock_key, "private")

        assert curve_id == expected_identifier
        assert isinstance(x_bytes, bytes)
        assert isinstance(y_bytes, bytes)
        assert len(x_bytes) == 32
        assert len(y_bytes) == 32
