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
import base64
import cbor2
import pytest
import datetime
from unittest.mock import patch, MagicMock, mock_open
from cryptography.hazmat.primitives.asymmetric import ec
from config_helpers import patch_configuration, set_configuration
from app.services.formatters import DatestringFormatter, KeyData, cbor2elems, mdocFormatter, picture_data_url, sdjwtFormatter, sdjwtNestedClaims, SDObj


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

    @patch("app.services.formatters.serialization.load_pem_private_key")
    @patch("app.services.formatters.urlsafe_b64encode_nopad", return_value=b"signed_mdoc")
    @patch("app.services.formatters.MdocCborIssuer")
    @patch("app.services.revocation_status.requests.post")
    @patch("app.services.formatters.session_manager")
    @patch_configuration({ # Mock country config
        "countries": {
            "FC": {
                "name": "FormEU",
                "keys": {
                    "_default": {
                        "private_key_path": "fake_path",
                        "private_key": "PK Sample Content",
                        "private_key_password": None,
                        "certificate_path": "fake_cert_path"
                    }
                }
            }
        },
        "revocation": {
            "enabled": False
        }
    })
    def test_basic_mdocFormatter(
        self,
        mock_session_manager,
        mock_requests_post,
        mock_MdocCborIssuer,
        mock_b64encode,
        mock_load_key,
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
        mock_session.country = 'FC'
        mock_session_manager.get_session.return_value = mock_session

        # Mock private key
        mock_private_key = MagicMock()
        mock_private_key.private_numbers.return_value.private_value = 12345
        mock_load_key.return_value = mock_private_key

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
        #mock_open.assert_called_once_with("fake_path", "rb")
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

    @patch("app.services.formatters.serialization.load_pem_private_key")
    @patch(
        "app.services.formatters.urlsafe_b64encode_nopad", return_value=b"signed_mdoc_batch"
    )
    @patch("app.services.formatters.MdocCborIssuer")
    @patch("app.services.revocation_status.requests.post")
    @patch("app.services.formatters.session_manager")
    @patch_configuration({ # Mock country config
        "countries": {
            "FC": {
                "name": "FormEU",
                "keys": {
                    "_default": {
                        "private_key_path": "fake_path",
                        "private_key": "PK Sample Content",
                        "private_key_password": None,
                        "certificate_path": "fake_cert_path"
                    }
                }
            }
        },
        "revocation": {
            "enabled": False
        }
    })
    def test_batch_credential(
        self,
        mock_session_manager,
        mock_requests_post,
        mock_MdocCborIssuer,
        mock_b64encode,
        mock_load_key,
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
        mock_session.country = 'FC'
        mock_session_manager.get_session.return_value = mock_session

        # Mock private key
        mock_private_key = MagicMock()
        mock_private_key.private_numbers.return_value.private_value = 12345
        mock_load_key.return_value = mock_private_key

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

    @patch("app.services.formatters.serialization.load_pem_private_key")
    @patch(
        "app.services.formatters.urlsafe_b64encode_nopad",
        return_value=b"signed_mdoc_revocation",
    )
    @patch("app.services.formatters.MdocCborIssuer")
    @patch("app.services.revocation_status.requests.post")
    @patch("app.services.formatters.session_manager")
    @patch_configuration({ # Mock country config
        "countries": {
            "FC": {
                "name": "FormEU",
                "keys": {
                    "_default": {
                        "private_key_path": "fake_path",
                        "private_key": "PK Sample Content",
                        "private_key_password": None,
                        "certificate_path": "fake_cert_path"
                    }
                }
            }
        },
        "revocation": {
            "enabled": True,
            "api_key": "Fake API-Key",
            "take_url": "Fake Take URL"
        }
    })
    def test_revocation_branch(
        self,
        mock_session_manager,
        mock_requests_post,
        mock_MdocCborIssuer,
        mock_b64encode,
        mock_load_key,
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
        mock_session.country = 'FC'
        mock_session_manager.get_session.return_value = mock_session

        # Mock private key
        mock_private_key = MagicMock()
        mock_private_key.private_numbers.return_value.private_value = 12345
        mock_load_key.return_value = mock_private_key

        # Enable revocation
        global revocation_api_key
        revocation_api_key = "FAKE_API_KEY"

        # Mock requests.post to return JSON
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = { "revoked": False, "identifier_list": {"id": "abc123" } }
        mock_requests_post.return_value = mock_response

        # Mock MdocCborIssuer instance
        mock_mdoci_instance = MagicMock()
        mock_MdocCborIssuer.return_value = mock_mdoci_instance

        with patch("app.services.formatters.record_issued_status") as record:
            result = mdocFormatter(
                data=sample_data,
                credential_metadata=credential_metadata,
                country=country,
                device_publickey=device_publickey,
                session_id=session_id,
            )

        mock_requests_post.assert_called_once()
        assert mock_requests_post.call_args.args[0] == "Fake Take URL"
        assert mock_requests_post.call_args.kwargs["timeout"]
        mock_session_manager.update_key_status_by_key.assert_called_once()
        called_revocation = mock_mdoci_instance.new.call_args.kwargs["revocation"]
        assert called_revocation == { "revoked": False, "identifier_list": {"id": b'abc123' } }
        # #167: recorded for batch revocation
        record.assert_called_once()
        assert record.call_args.args[:2] == (session_id, credential_metadata["doctype"])

        assert result == b"signed_mdoc_revocation"


    @patch("app.services.formatters.serialization.load_pem_private_key")
    @patch("app.services.formatters.urlsafe_b64encode_nopad", return_value=b"signed_mdoc")
    @patch("app.services.formatters.MdocCborIssuer")
    @patch("app.services.formatters.session_manager")
    @patch_configuration({
        "countries": {
            "FC": {
                "keys": {
                    "_default": {
                        "private_key": "PK Sample Content",
                        "private_key_password": None,
                        "certificate_path": "fake_cert_path",
                    }
                }
            }
        },
        "revocation": {"enabled": False},
    })
    def test_no_session_and_namespace_differs_from_doctype(
        self, mock_session_manager, mock_MdocCborIssuer, mock_b64encode, mock_load_key, device_publickey
    ):
        """Standalone call (session_id=None) works; pseudonym encoded under the namespace."""
        mock_load_key.return_value.private_numbers.return_value.private_value = 12345
        data = {"eu.europa.ec.eudi.pid.1": {"user_pseudonym": "johndoe123"}}
        metadata = {
            "doctype": "eu.europa.ec.eudi.pid.1.doctype",
            "issuer_config": {"namespace": "eu.europa.ec.eudi.pid.1", "validity": 10},
        }

        result = mdocFormatter(
            data=data,
            credential_metadata=metadata,
            country="FC",
            device_publickey=device_publickey,
            session_id=None,
        )

        mock_session_manager.get_session.assert_not_called()
        assert data["eu.europa.ec.eudi.pid.1"]["user_pseudonym"] == b"johndoe123"
        assert mock_MdocCborIssuer.return_value.new.call_args.kwargs["revocation"] is None
        assert result == b"signed_mdoc"


# ------------------- Test class for cbor2elems -------------------


class TestCbor2Elems:

    @patch("app.services.formatters.cbor2.loads")
    @patch("app.services.formatters.base64.urlsafe_b64decode")
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
                "elementValue": cbor2.CBORTag(1004, "2000-01-01"),  # cbor2 < 5.5
            },
        ]

        result = cbor2elems(fake_mdoc)

        mock_b64decode.assert_called_once_with(fake_mdoc)
        assert ("name", "Alice") in result["ns1"]
        assert ("birth_date", "2000-01-01") in result["ns1"]

    @patch("app.services.formatters.cbor2.loads")
    @patch("app.services.formatters.base64.urlsafe_b64decode")
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
                "elementValue": datetime.date(2030, 12, 31),  # cbor2 >= 5.5
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
        assert isinstance(sub, list)
        assert sub[0][SDObj("company")] == "ABC"

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
        assert isinstance(sub, list)
        assert sub[0][SDObj("name")] == "Python"

    def test_list_length_gt1_with_dict_element(self):
        claims = {"projects": [{"name": "A"}, {"name": "B"}]}
        credential_metadata = {}
        result = sdjwtNestedClaims(claims, credential_metadata)
        key = list(result.keys())[0]
        sub = result[key]
        assert isinstance(sub, list)
        assert sub[0][SDObj("name")] == "A"
        assert sub[1][SDObj("name")] == "B"


class TestPictureDataUrl:

    def test_base64url_picture_becomes_jpeg_data_url(self):
        jpeg = b"\xff\xd8\xff\xe0\xfb\xff"
        claims = {"picture": base64.urlsafe_b64encode(jpeg).decode().rstrip("="), "family_name": "Doe"}

        result = picture_data_url(claims)

        assert result["picture"] == "data:image/jpeg;base64," + base64.b64encode(jpeg).decode()
        assert result["family_name"] == "Doe"
        assert claims["picture"] != result["picture"]  # input not mutated

    def test_data_url_and_missing_picture_unchanged(self):
        claims = {"picture": "data:image/jpeg;base64,AAAA"}
        assert picture_data_url(claims) is claims
        assert picture_data_url({"family_name": "Doe"}) == {"family_name": "Doe"}


class TestSDJWTFormatter:

    @patch("app.services.formatters.base64.b64encode", side_effect=lambda x: b"encoded_cert")
    @patch("app.services.formatters.serialization.load_pem_private_key")
    @patch(
        "app.services.formatters.base64.urlsafe_b64decode",
        side_effect=lambda x: b"decoded_device_key",
    )
    @patch("app.services.formatters.serialization.load_pem_public_key")
    @patch(
        "app.services.formatters.KeyData",
        side_effect=lambda key, t: ("crv", b"x_bytes", b"y_bytes"),
    )
    @patch("app.services.formatters.ec_public_jwk", new=lambda key: {"kid": "country-kid"})
    @patch("app.services.formatters.JWK")
    @patch("app.services.formatters.SDJWTIssuer")
    @patch(
        "app.services.formatters.sdjwtNestedClaims", return_value={"claim_wrapped": "value"}
    )
    @patch("app.services.formatters.session_manager")
    @patch("app.services.revocation_status.requests.post")
    @patch_configuration({ # Mock country config
        "service_url": "Fake_URL",
        "frontend": {"default": "fe", "frontends_config": {"fe": {"url": "Fake_Frontend_URL"}}},
        "countries": {
            "FC": {
                "name": "FormEU",
                "keys": {
                    "_default": {
                        "private_key_path": "fake_path",
                        "private_key": "PK Sample Content",
                        "private_key_password": None,
                        "certificate_path": "fake_cert_path",
                        "certificate": "Fake_Certificate_Content"
                    }
                }
            }
        },
        "revocation": {
            "enabled": False,
        }
    })
    def test_basic_sdjwtFormatter(
        self,
        mock_requests_post,
        mock_sdjwt_session_manager,
        mock_sdjwtNestedClaims,
        mock_SDJWTIssuer,
        mock_get_jwk,
        mock_KeyData,
        mock_load_public_key,
        mock_urlsafe_b64decode,
        mock_load_private_key,
        mock_b64encode,
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

        # Disable revocation
        global revocation_api_key
        revocation_api_key = None

        # Mock SDJWTIssuer instance
        mock_sdjwt_instance = MagicMock()
        mock_sdjwt_instance.sd_jwt_issuance = "sdjwt_token"
        mock_SDJWTIssuer.return_value = mock_sdjwt_instance

        # Standalone formatter call: no issuance session
        result = sdjwtFormatter(
            PID, country, "eu.europa.ec.eudi.learning_credential_vc_sd_jwt", session_id=None
        )

        # Assertions
        mock_sdjwt_session_manager.get_session.assert_not_called()
        mock_requests_post.assert_not_called()
        claims = mock_SDJWTIssuer.call_args.args[0]
        assert claims["iss"] == "Fake_Frontend_URL"
        assert claims["vct"] == "vct_value"
        assert "jti" in claims  # learning credential scope
        assert "status" not in claims
        assert mock_SDJWTIssuer.call_args.kwargs["extra_header_parameters"] == {
            "x5c": ["encoded_cert"],
            "kid": "country-kid",
        }
        mock_load_private_key.assert_called_once()
        mock_load_public_key.assert_called_once()
        mock_sdjwtNestedClaims.assert_called_once_with(
            PID["data"]["claims"], PID["credential_metadata"]
        )
        mock_SDJWTIssuer.assert_called_once()
        assert result == "sdjwt_token"

    @patch("builtins.open", new_callable=mock_open, read_data=b"fake_cert_data")
    @patch("app.services.formatters.base64.b64encode", side_effect=lambda x: b"encoded_cert")
    @patch("app.services.formatters.serialization.load_pem_private_key")
    @patch(
        "app.services.formatters.base64.urlsafe_b64decode",
        side_effect=lambda x: b"decoded_device_key",
    )
    @patch("app.services.formatters.serialization.load_pem_public_key")
    @patch(
        "app.services.formatters.KeyData",
        side_effect=lambda key, t: ("crv", b"x_bytes", b"y_bytes"),
    )
    @patch("app.services.formatters.ec_public_jwk", new=lambda key: {"kid": "country-kid"})
    @patch("app.services.formatters.JWK")
    @patch("app.services.formatters.SDJWTIssuer")
    @patch(
        "app.services.formatters.sdjwtNestedClaims", return_value={"claim_wrapped": "value"}
    )
    @patch("app.services.formatters.session_manager")
    @patch("app.services.revocation_status.requests.post")
    @patch_configuration({ # Mock country config
        "service_url": "Fake_URL",
        "frontend": {"default": "fe", "frontends_config": {"fe": {"url": "Fake_Frontend_URL"}}},
        "countries": {
            "FC": {
                "name": "FormEU",
                "keys": {
                    "_default": {
                        "private_key_path": "fake_path",
                        "private_key": "PK Sample Content",
                        "private_key_password": None,
                        "certificate_path": "fake_cert_path",
                        "certificate": "Fake_Certificate_Content"
                    }
                }
            }
        },
        "revocation": {
            "enabled": True,
            "api_key": "Fake API-Key",
            "take_url": "Fake Take URL"
        }
    })
    def test_revocation_branch(
        self,
        mock_requests_post,
        mock_sdjwt_session_manager,
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

        mock_session = MagicMock()
        mock_session.max_credential_exp = None
        mock_sdjwt_session_manager.get_session.return_value = mock_session

        with patch("app.services.formatters.record_issued_status") as record:
            result = sdjwtFormatter(
                PID,
                country,
                "eu.europa.ec.eudi.learning_credential_vc_sd_jwt",
                session_id="test-session-id",
            )

        mock_requests_post.assert_called_once()
        assert mock_requests_post.call_args.args[0] == "Fake Take URL"
        assert mock_requests_post.call_args.kwargs["headers"]["X-Api-Key"] == "Fake API-Key"
        assert "doctype=vct_value&country=FC" in mock_requests_post.call_args.kwargs["data"]
        assert mock_requests_post.call_args.kwargs["timeout"]
        mock_sdjwt_session_manager.update_key_status_by_key.assert_called_once_with(
            session_id="test-session-id",
            key="fake_device_key_base64",
            key_status={"revoked": False},
        )
        claims = mock_SDJWTIssuer.call_args.args[0]
        assert claims["status"] == {"revoked": False}
        record.assert_called_once_with("test-session-id", "vct_value", {"revoked": False})
        mock_sdjwtNestedClaims.assert_called_once()
        mock_SDJWTIssuer.assert_called_once()
        assert result == "sdjwt_token_revocation"


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
        "curve_name,expected_identifier,expected_length",
        [
            ("secp256r1", "P-256", 32),
            ("secp384r1", "P-384", 48),
            ("secp521r1", "P-521", 66),
        ],
    )
    def test_public_key(self, curve_name, expected_identifier, expected_length):
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
        # x and y are padded to the curve's coordinate length
        assert len(x_bytes) == expected_length
        assert len(y_bytes) == expected_length

    @pytest.mark.parametrize(
        "curve_name,expected_identifier,expected_length",
        [
            ("secp256r1", "P-256", 32),
            ("secp384r1", "P-384", 48),
            ("secp521r1", "P-521", 66),
        ],
    )
    def test_private_key(self, curve_name, expected_identifier, expected_length):
        # Mock key
        # spec= so the key is detected as a private key (KeyData no longer
        # relies on the "type" argument)
        mock_key = MagicMock(spec=ec.EllipticCurvePrivateKey)
        mock_key.curve = MagicMock()
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
        assert len(x_bytes) == expected_length
        assert len(y_bytes) == expected_length


class TestCredentialIssuerUrl:
    """SD-JWT VC iss is the session's frontend URL (#161)."""

    CONFIG = {
        "service_url": "https://backend.issuer.test",
        "frontend": {
            "default": "fe-default",
            "frontends_config": {
                "fe-default": {"url": "https://issuer.test"},
                "fe-other": {"url": "https://other.issuer.test"},
            },
        },
    }

    @pytest.fixture(autouse=True)
    def config(self, monkeypatch):
        set_configuration(monkeypatch, self.CONFIG)

    def test_session_frontend(self):
        from app.services.formatters import credential_issuer_url

        assert credential_issuer_url(MagicMock(frontend_id="fe-other")) == "https://other.issuer.test"

    @pytest.mark.parametrize("frontend_id", [None, "", "unknown"])
    def test_default_frontend(self, frontend_id):
        from app.services.formatters import credential_issuer_url

        assert credential_issuer_url(MagicMock(frontend_id=frontend_id)) == "https://issuer.test"

    def test_no_session(self):
        from app.services.formatters import credential_issuer_url

        assert credential_issuer_url(None) == "https://issuer.test"
