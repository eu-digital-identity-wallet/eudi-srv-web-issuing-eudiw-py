# tests/test_route_dynamic.py
import pytest
from flask import Flask, session
from unittest.mock import patch, MagicMock
from app.route_dynamic import dynamic, dynamic_R2_data_collect, credentialCreation


# -----------------------
# Flask fixtures
# -----------------------
@pytest.fixture
def app():
    """Create and configure a test Flask application"""
    app = Flask(__name__)
    app.secret_key = "test_secret"
    app.register_blueprint(dynamic)
    return app


@pytest.fixture
def client(app):
    """Create a test client for the Flask application"""
    return app.test_client()


# -----------------------
# Mock Classes
# -----------------------
class MockConfFrontend:
    """Mock configuration frontend class"""

    registered_frontends = {"frontend1": {"url": "https://frontend.test"}}


class MockConfService:
    """Mock configuration service class"""

    service_url = "https://service.test"
    app_logger = MagicMock()


# -----------------------
# Test: Dynamic Route - Country Selection
# -----------------------
class TestSupportedCountries:
    """Test class for country selection logic in /dynamic/ route"""

    @patch("app.route_dynamic.dynamic_R1")
    @patch("app.route_dynamic.session_manager.get_session")
    @patch.dict(
        "app.route_dynamic.cfgcountries.supported_countries",
        {
            "EU": {
                "name": "nodeEU",
                "supported_credentials": [
                    "eu.europa.ec.eudi.pid_mdoc",
                    "eu.europa.ec.eudi.pid_vc_sd_jwt",
                    "eu.europa.ec.eudi.pid_mdoc_deferred",
                ],
            },
            "FORM": {
                "name": "FormEU",
                "supported_credentials": [
                    "eu.europa.ec.eudi.pid_mdoc",
                    "eu.europa.ec.eudi.loyalty_mdoc",
                    "eu.europa.ec.eudi.photoid",
                ],
            },
        },
        clear=True,
    )
    def test_single_country(self, mock_get_session, mock_dynamic_r1, client):
        """Test single available country automatically triggers dynamic_R1"""
        mock_dynamic_r1.return_value = b"dynamic_r1_called"

        # Use a credential that exists only in EU
        mock_get_session.return_value = MagicMock(
            credentials_requested=["eu.europa.ec.eudi.pid_vc_sd_jwt"],
            frontend_id="frontend1",
            authorization_details={"token": "abcd"},
        )

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session"

        response = client.get("/dynamic/")

        mock_dynamic_r1.assert_called_once_with("EU")
        assert response.data == b"dynamic_r1_called"

    @patch("app.route_dynamic.session_manager.get_session")
    @patch("app.route_dynamic.post_redirect_with_payload")
    @patch("app.route_dynamic.ConfFrontend", new_callable=lambda: MockConfFrontend)
    @patch.dict(
        "app.route_dynamic.cfgcountries.supported_countries",
        {
            "EU": {
                "name": "nodeEU",
                "supported_credentials": [
                    "eu.europa.ec.eudi.pid_mdoc",
                    "eu.europa.ec.eudi.pid_vc_sd_jwt",
                    "eu.europa.ec.eudi.pid_mdoc_deferred",
                ],
            },
            "FORM": {
                "name": "FormEU",
                "supported_credentials": [
                    "eu.europa.ec.eudi.pid_mdoc",
                    "eu.europa.ec.eudi.loyalty_mdoc",
                    "eu.europa.ec.eudi.photoid",
                ],
            },
        },
        clear=True,
    )
    def test_multiple_countries(
        self, mock_conf, mock_post_redirect, mock_get_session, client
    ):
        """Test multiple available countries shows country selection form"""
        # Use a credential that exists in both EU and FORM
        mock_get_session.return_value = MagicMock(
            credentials_requested=["eu.europa.ec.eudi.pid_mdoc"],
            frontend_id="frontend1",
            authorization_details={"token": "abcd"},
        )
        mock_post_redirect.return_value = b"redirected_payload"

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session"

        response = client.get("/dynamic/")

        mock_post_redirect.assert_called_once()
        assert response.data == b"redirected_payload"


# -----------------------
# Test: Country Selection Route
# -----------------------
class TestCountrySelected:
    """Test class for /dynamic/country_selected route"""

    @patch("app.route_dynamic.dynamic_R1")
    @patch("app.route_dynamic.cfgserv", new=MockConfService)
    def test_country_selected_calls_dynamic_r1(self, mock_dynamic_r1, client):
        """Test that selecting a country calls dynamic_R1"""
        mock_dynamic_r1.return_value = b"dynamic_r1_called"

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session"

        response = client.post("/dynamic/country_selected", data={"country": "EU"})

        mock_dynamic_r1.assert_called_once_with("EU")
        assert response.data == b"dynamic_r1_called"


# -----------------------
# Test: Dynamic R1 Route
# -----------------------
class TestDynamicR1:
    """Test class for dynamic_R1 function"""

    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        """Setup common mocks for dynamic_R1 tests"""
        self.cleanups = []

        # Mock session_manager functions
        patcher_update_country = patch(
            "app.route_dynamic.session_manager.update_country"
        )
        self.mock_update_country = patcher_update_country.start()
        self.cleanups.append(patcher_update_country.stop)

        patcher_get_session = patch("app.route_dynamic.session_manager.get_session")
        self.mock_get_session = patcher_get_session.start()
        self.cleanups.append(patcher_get_session.stop)

        # Mock session dict
        self.session_dict = {"session_id": "test_session"}
        patch("app.route_dynamic.session", self.session_dict).start()

        # Mock cfgserv
        class MockCfgServ:
            service_url = "https://service.test"
            OpenID_first_endpoint = "https://openid.test/first"
            sample_data = {"key": "value"}

        patch("app.route_dynamic.cfgserv", new=MockCfgServ).start()

        # Mock ConfFrontend
        patch("app.route_dynamic.ConfFrontend", new=MockConfFrontend).start()

        # Mock oidc_metadata
        patch(
            "app.route_dynamic.oidc_metadata",
            new={"credential_configurations_supported": ["cred1", "cred2"]},
        ).start()

        # Mock post_redirect_with_payload
        patcher_post_redirect = patch("app.route_dynamic.post_redirect_with_payload")
        self.mock_post_redirect = patcher_post_redirect.start()
        self.mock_post_redirect.return_value = b"redirected_payload"
        self.cleanups.append(patcher_post_redirect.stop)

        # Mock redirect
        patcher_redirect = patch("app.route_dynamic.redirect")
        self.mock_redirect = patcher_redirect.start()
        self.mock_redirect.side_effect = lambda url: f"redirect:{url}"
        self.cleanups.append(patcher_redirect.stop)

        # Mock url_get
        patcher_url_get = patch("app.route_dynamic.url_get")
        self.mock_url_get = patcher_url_get.start()
        self.mock_url_get.side_effect = lambda url, params: f"url_get:{url}"
        self.cleanups.append(patcher_url_get.stop)

        # Mock form attribute functions
        patch(
            "app.route_dynamic.getAttributesForm",
            return_value={"name": {"type": "string", "filled_value": "John"}},
        ).start()
        patch(
            "app.route_dynamic.getAttributesForm2",
            return_value={"email": {"type": "string"}},
        ).start()

        # Mock cfgcountries
        patch(
            "app.route_dynamic.cfgcountries.supported_countries",
            new={
                "FC": {"connection_type": "form"},
                "sample": {"connection_type": "openid"},
                "EU": {
                    "connection_type": "oauth",
                    "oauth_auth": {
                        "base_url": "https://eu.test",
                        "redirect_uri": "https://redirect.test",
                        "scope": "profile",
                        "client_id": "id",
                        "client_secret": "secret",
                        "response_type": "code",
                    },
                },
            },
        ).start()

        yield

        # Cleanup
        for cleanup in self.cleanups:
            cleanup()

    @patch("app.route_dynamic.uuid4", return_value="uuid123")
    def test_fc_country(self, mock_uuid):
        """Test dynamic_R1 with form country (FC)"""
        mock_session = MagicMock(
            credentials_requested=["cred1"], frontend_id="frontend1"
        )
        self.mock_get_session.return_value = mock_session

        from app.route_dynamic import dynamic_R1

        result = dynamic_R1("FC")

        self.mock_post_redirect.assert_called_once()
        assert result == b"redirected_payload"

    def test_sample_country(self):
        """Test dynamic_R1 with sample country (OpenID)"""
        mock_session = MagicMock(
            jws_token="token123",
            credentials_requested=["cred1"],
            frontend_id="frontend1",
        )
        self.mock_get_session.return_value = mock_session

        from app.route_dynamic import dynamic_R1

        result = dynamic_R1("sample")

        assert result.startswith("redirect:")

    def test_oauth_country(self):
        """Test dynamic_R1 with OAuth country"""
        mock_session = MagicMock(
            credentials_requested=["cred1"], frontend_id="frontend1"
        )
        self.mock_get_session.return_value = mock_session

        # Mock requests.get to prevent real HTTP calls
        mock_requests_get = patch("app.route_dynamic.requests.get").start()
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "authorization_endpoint": "https://eu.test/auth"
        }
        mock_requests_get.return_value = mock_response

        from app.route_dynamic import dynamic_R1

        result = dynamic_R1("EU")

        assert "redirect:" in result
        patch.stopall()

    @patch("app.route_dynamic.uuid4", return_value="uuid123")
    def test_fc_country_with_user_pseudonym(self, mock_uuid):
        """Test dynamic_R1 adds filled_value when 'user_pseudonym' in mandatory attributes"""
        # Mock session object
        mock_session = MagicMock(
            credentials_requested=["cred1"], frontend_id="frontend1"
        )
        self.mock_get_session.return_value = mock_session

        # Patch getAttributesForm to include 'user_pseudonym'
        with patch(
            "app.route_dynamic.getAttributesForm",
            return_value={
                "user_pseudonym": {"type": "string"},
                "name": {"type": "string", "filled_value": "John"},
            },
        ):
            from app.route_dynamic import dynamic_R1

            result = dynamic_R1("FC")

            # Verify post_redirect_with_payload was called
            self.mock_post_redirect.assert_called_once()

            # Extract the payload argument from the mock call
            called_args, called_kwargs = self.mock_post_redirect.call_args
            payload = called_kwargs["data_payload"]

            # Ensure 'user_pseudonym' got a filled_value equal to mocked UUID
            mandatory = payload["mandatory_attributes"]
            assert "user_pseudonym" in mandatory
            assert mandatory["user_pseudonym"]["filled_value"] == "uuid123"

            # Confirm the function returned expected redirect value
            assert result == b"redirected_payload"

    def test_openid_country(self):
        """Test dynamic_R1 with OpenID connection type"""
        mock_session = MagicMock(
            jws_token="token123",
            credentials_requested=["cred1"],
            frontend_id="frontend1",
        )
        self.mock_get_session.return_value = mock_session

        # Add an OpenID country (EE) to supported_countries
        cfgcountries_supported = {
            "EE": {
                "connection_type": "openid",
                "oidc_auth": {
                    "base_url": "https://ee.test",
                    "redirect_uri": "https://redirect.ee",
                    "client_id": "client123",
                    "scope": "openid",
                    "response_type": "code",
                },
            }
        }

        # Patch cfgcountries with the new OpenID entry
        with patch(
            "app.route_dynamic.cfgcountries.supported_countries",
            new=cfgcountries_supported,
        ):
            # Mock requests.get to return a fake authorization endpoint
            mock_requests_get = patch("app.route_dynamic.requests.get").start()
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "authorization_endpoint": "https://ee.test/auth"
            }
            mock_requests_get.return_value = mock_response

            from app.route_dynamic import dynamic_R1

            result = dynamic_R1("EE")

            # Verify redirect was called with the constructed URL
            assert result.startswith("redirect:")

            # Extract the redirect URL from the mock call
            redirect_url = result.replace("redirect:", "")

            # The URL should contain all parameters from oidc_auth (except excluded ones)
            assert "https://ee.test/auth" in redirect_url
            assert "redirect_uri=https://redirect.ee" in redirect_url
            assert "client_id=client123" in redirect_url
            assert "scope=openid" in redirect_url
            assert "response_type=code" in redirect_url

            # The 'state' should be correctly appended for EE
            assert "state=EE.token123" in redirect_url

            patch.stopall()


# -----------------------
# Test: Dynamic Redirect Route
# -----------------------
class TestDynamicRedirect:
    """Test class for /dynamic/redirect route"""

    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        """Setup common mocks for redirect tests"""
        # Mock session_manager
        patcher_get_session = patch("app.route_dynamic.session_manager.get_session")
        self.mock_get_session = patcher_get_session.start()

        # Mock session dict
        self.session_dict = {"session_id": "test_session"}
        patch("app.route_dynamic.session", self.session_dict).start()

        # Mock cfgserv
        class MockCfgServ:
            service_url = "https://service.test"
            current_version = "1.0"
            app_logger = MagicMock()

        patch("app.route_dynamic.cfgserv", new=MockCfgServ).start()

        # Mock ConfFrontend
        patch("app.route_dynamic.ConfFrontend", new=MockConfFrontend).start()

        # Mock oidc_metadata with realistic credential configuration
        patch(
            "app.route_dynamic.oidc_metadata",
            new={
                "credential_configurations_supported": {
                    "eu.europa.ec.eudi.pid_mdoc": {
                        "scope": "eu.europa.ec.eudi.pid_mdoc",
                        "credential_metadata": {
                            "display": [{"name": "PID (MSO Mdoc)", "locale": "en"}],
                            "claims": [
                                {
                                    "path": ["eu.europa.ec.eudi.pid.1", "family_name"],
                                    "mandatory": True,
                                },
                                {
                                    "path": ["eu.europa.ec.eudi.pid.1", "given_name"],
                                    "mandatory": True,
                                },
                                {
                                    "path": ["eu.europa.ec.eudi.pid.1", "birth_date"],
                                    "mandatory": True,
                                },
                            ],
                        },
                        "issuer_config": {
                            "issuing_authority": "Test PID issuer",
                            "validity": 90,
                        },
                    }
                }
            },
        ).start()

        # Mock data collection
        patch(
            "app.route_dynamic.dynamic_R2_data_collect",
            return_value={
                "family_name": "Doe",
                "given_name": "John",
                "birth_date": "1990-01-01",
            },
        ).start()

        # Mock post redirect
        patch(
            "app.route_dynamic.post_redirect_with_payload",
            return_value=b"redirected_payload",
        ).start()

        # Mock HTTP requests
        patch(
            "app.route_dynamic.requests.get",
            return_value=MagicMock(
                json=lambda: {"token_endpoint": "https://token.test"}
            ),
        ).start()
        patch(
            "app.route_dynamic.requests.post",
            return_value=MagicMock(
                json=lambda: {"access_token": "fake_token"},
                status_code=200,
                raise_for_status=lambda: None,
            ),
        ).start()

        yield
        patch.stopall()

    def test_redirect_route(self, client):
        """Test OAuth redirect route with authorization code"""
        mock_session = MagicMock(
            country="EU",
            frontend_id="frontend1",
            credentials_requested=["eu.europa.ec.eudi.pid_mdoc"],
        )
        self.mock_get_session.return_value = mock_session

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session"

        response = client.get(
            "/dynamic/redirect",
            query_string={
                "code": "abc123",
                "scope": "eu.europa.ec.eudi.pid_mdoc",
                "state": "state1",
            },
        )

        assert response.data == b"redirected_payload"

    def test_redirect_missing_code(self, client):
        """Test that /dynamic/redirect returns 500 if 'code' is missing"""
        mock_session = MagicMock(
            country="EU", frontend_id="frontend1", credentials_requested=[]
        )
        self.mock_get_session.return_value = mock_session

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session"

        response = client.get(
            "/dynamic/redirect",
            query_string={"scope": "eu.europa.ec.eudi.pid_mdoc", "state": "state1"},
        )

        assert response.status_code == 500


# -----------------------
# Test: Dynamic R2 Route
# -----------------------
class TestDynamicR2Route:
    """Test class for /dynamic_R2 route"""

    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        """Setup common mocks for R2 route tests"""
        patcher_get_session = patch("app.route_dynamic.session_manager.get_session")
        self.mock_get_session = patcher_get_session.start()

        # Mock cfgserv
        class MockCfgServ:
            current_version = "1.0"
            service_url = "https://service.test"
            app_logger = MagicMock()

        patch("app.route_dynamic.cfgserv", new=MockCfgServ).start()

        # Mock credentialCreation
        patch(
            "app.route_dynamic.credentialCreation",
            return_value={"credentials": [{"credential": "mock_credential"}]},
        ).start()

        yield
        patch.stopall()

    def test_dynamic_r2_success(self, client):
        """Test successful credential issuance via /dynamic_R2"""
        mock_session = MagicMock(
            country="EU",
            user_data={
                "family_name": "Doe",
                "given_name": "John",
                "birth_date": "1990-01-01",
            },
        )
        self.mock_get_session.return_value = mock_session

        response = client.post(
            "/dynamic/dynamic_R2",
            json={
                "user_id": "test_user",
                "credential_requests": ["eu.europa.ec.eudi.pid_mdoc"],
            },
        )

        response_json = response.get_json()
        assert "credentials" in response_json
        assert len(response_json["credentials"]) == 1

    def test_dynamic_r2_missing_fields(self, client):
        """Test error handling when required fields are missing"""
        response = client.post("/dynamic/dynamic_R2", json={"user_id": "test_user"})

        response_json = response.get_json()
        assert response_json["error"] == "invalid_credential_request"
        assert "missing fields" in response_json["error_description"].lower()


# -----------------------
# Test: Dynamic R2 Data Collection
# -----------------------
@pytest.mark.usefixtures("app")
class TestDynamicR2DataCollect:
    """Test class for dynamic_R2_data_collect function"""

    @patch("app.route_dynamic.session_manager.get_session")
    def test_fc_country_returns_user_data(self, mock_get_session):
        """Test data collection for form country (FC)"""
        mock_session = MagicMock(user_data={"family_name": "Doe", "given_name": "John"})
        mock_get_session.return_value = mock_session

        result = dynamic_R2_data_collect(
            country="FC", session_id="test_id", access_token=None
        )

        assert result == {"family_name": "Doe", "given_name": "John"}

    @patch("app.route_dynamic.session_manager.get_session")
    def test_sample_country_returns_user_data(self, mock_get_session):
        """Test data collection for sample country"""
        mock_session = MagicMock(user_data={"data": "sample"})
        mock_get_session.return_value = mock_session

        result = dynamic_R2_data_collect(
            country="sample", session_id="test_id", access_token=None
        )

        assert result == {"data": "sample"}

    @patch("app.route_dynamic.requests.get")
    @patch("app.route_dynamic.session_manager.update_user_data")
    @patch("app.route_dynamic.session_manager.get_session")
    @patch.dict(
        "app.route_dynamic.cfgcountries.supported_countries",
        {
            "EU": {
                "connection_type": "oauth",
                "oauth_auth": {"base_url": "https://eidas.projj.eu"},
                "custom_modifiers": {
                    "family_name": "CurrentFamilyName",
                    "given_name": "CurrentGivenName",
                    "birth_date": "DateOfBirth",
                },
            }
        },
        clear=True,
    )
    def test_oauth_connection_cleans_data(
        self, mock_get_session, mock_update, mock_requests, app
    ):
        """Test OAuth data collection with custom field mapping"""
        mock_session = MagicMock(
            user_data={
                "CurrentFamilyName": "Doe",
                "CurrentGivenName": "John",
                "DateOfBirth": "1990-01-01",
            }
        )
        mock_get_session.return_value = mock_session

        # Mock metadata and userinfo endpoints
        mock_requests.side_effect = [
            MagicMock(
                json=MagicMock(
                    return_value={
                        "userinfo_endpoint": "https://eidas.projj.eu/userinfo"
                    }
                )
            ),
            MagicMock(
                json=MagicMock(
                    return_value={
                        "CurrentFamilyName": "Doe",
                        "CurrentGivenName": "John",
                        "DateOfBirth": "1990-01-01",
                    }
                )
            ),
        ]

        with app.app_context():
            result = dynamic_R2_data_collect(
                country="EU", session_id="test_id", access_token="token"
            )

        # Verify field mapping occurred correctly
        assert result["family_name"] == "Doe"
        assert result["given_name"] == "John"
        assert result["birth_date"] == "1990-01-01"
        assert "nationality" in result

    @patch("app.route_dynamic.requests.get")
    @patch("app.route_dynamic.session_manager.get_session")
    @patch.dict(
        "app.route_dynamic.cfgcountries.supported_countries",
        {
            "OPENID": {
                "connection_type": "openid",
                "attribute_request": {"header": {}},
                "oidc_auth": {"base_url": "https://example.com"},
            }
        },
        clear=True,
    )
    def test_openid_connection(self, mock_get_session, mock_requests, app):
        """Test OpenID data collection"""
        mock_session = MagicMock()
        mock_get_session.return_value = mock_session

        def mocked_requests_get(url, headers=None):
            if ".well-known/openid-configuration" in url:
                response = MagicMock()
                response.json.return_value = {
                    "userinfo_endpoint": "https://example.com/userinfo"
                }
                return response
            else:
                response = MagicMock()
                response.text = '{"field":"value"}'
                response.json.return_value = {"field": "value"}
                return response

        mock_requests.side_effect = mocked_requests_get

        with app.test_request_context("/dummy_url"):
            from flask import session

            session["country"] = "OPENID"

            result = dynamic_R2_data_collect(
                country="OPENID", session_id="test_id", access_token="token"
            )

        assert result["field"] == "value"


# -----------------------
# Test: Credential Creation
# -----------------------
class TestCredentialCreation:
    """Test class for credentialCreation function"""

    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        """Setup common mocks for credential creation tests"""
        # Mock oidc_metadata with credential configurations
        self.mock_metadata = {
            "credential_configurations_supported": {
                "eu.europa.ec.eudi.pid_mdoc": {
                    "scope": "eu.europa.ec.eudi.pid.1",
                    "format": "mso_mdoc",
                    "doctype": "eu.europa.ec.eudi.pid.1",
                },
                "eu.europa.ec.eudi.pid_vc_sd_jwt": {
                    "vct": "https://example.com/pid",
                    "format": "vc+sd-jwt",
                },
                "eu.europa.ec.eudi.loyalty_mdoc": {
                    "scope": "eu.europa.ec.eudi.loyalty.1",
                    "format": "mso_mdoc",
                    "doctype": "eu.europa.ec.eudi.loyalty.1",
                },
            }
        }
        patch("app.route_dynamic.oidc_metadata", self.mock_metadata).start()

        # Mock cfgserv
        class MockCfgServ:
            document_mappings = {
                "eu.europa.ec.eudi.pid.1": {
                    "formatting_functions": {
                        "mso_mdoc": {"formatting_function": "format_mdoc"}
                    }
                }
            }

        patch("app.route_dynamic.cfgserv", MockCfgServ).start()

        # Mock cfgcountries with various connection types
        self.mock_countries = {
            "FC": {"connection_type": "form"},
            "sample": {"connection_type": "sample"},
            "EU": {
                "connection_type": "oauth",
                "oauth_auth": {"base_url": "https://oauth.example.com"},
            },
            "PT": {
                "connection_type": "openid",
                "oidc": {
                    "scope": {
                        "eu.europa.ec.eudi.pid.1": {
                            "family_name": "FamilyName",
                            "given_name": "GivenName",
                            "birth_date": "BirthDate",
                            "Portrait": "Portrait",
                        }
                    }
                },
            },
            "EIDAS": {"connection_type": "eidasnode"},
        }
        patch(
            "app.route_dynamic.cfgcountries.supported_countries", self.mock_countries
        ).start()

        # Mock dynamic_formatter
        self.mock_formatter = patch("app.route_dynamic.dynamic_formatter").start()
        self.mock_formatter.return_value = "formatted_credential_data"

        # Mock vct2doctype
        patch(
            "app.route_dynamic.vct2doctype", return_value="eu.europa.ec.eudi.pid.1"
        ).start()

        yield
        patch.stopall()

    def test_missing_credential_identifier_and_configuration_id(self):
        """Test error when neither credential_identifier nor credential_configuration_id is present"""
        credential_request = {"proofs": [{"jwt": "mock_jwt_token"}]}
        data = {"family_name": "Doe"}

        result = credentialCreation(credential_request, data, "FC", "session_123")

        assert result["error"] == "invalid_credential_request"
        assert result["error_description"] == "invalid request"

    def test_credential_identifier_format(self):
        """Test credential creation using credential_identifier"""
        credential_request = {
            "credential_identifier": "eu.europa.ec.eudi.pid_mdoc",
            "proofs": [{"jwt": "mock_jwt_token"}],
        }
        data = {"family_name": "Doe", "given_name": "John"}

        result = credentialCreation(credential_request, data, "FC", "session_123")

        assert "credentials" in result
        assert len(result["credentials"]) == 1
        assert result["credentials"][0]["credential"] == "formatted_credential_data"
        self.mock_formatter.assert_called_once()

    def test_credential_configuration_id_with_vct(self):
        """Test credential creation using credential_configuration_id with VCT"""
        credential_request = {
            "credential_configuration_id": "eu.europa.ec.eudi.pid_vc_sd_jwt",
            "proofs": [{"jwt": "mock_jwt_token"}],
        }
        data = {"family_name": "Doe"}

        result = credentialCreation(credential_request, data, "sample", "session_123")

        assert "credentials" in result
        assert len(result["credentials"]) == 1

    def test_credential_configuration_id_with_doctype(self):
        """Test credential creation using credential_configuration_id with doctype"""
        credential_request = {
            "credential_configuration_id": "eu.europa.ec.eudi.pid_mdoc",
            "proofs": [{"jwt": "mock_jwt_token"}],
        }
        data = {"family_name": "Doe"}

        result = credentialCreation(credential_request, data, "FC", "session_123")

        assert "credentials" in result
        assert len(result["credentials"]) == 1

    def test_jwt_proof_type(self):
        """Test handling of JWT proof type"""
        credential_request = {
            "credential_identifier": "eu.europa.ec.eudi.pid_mdoc",
            "proofs": [{"jwt": "jwt_token_value"}],
        }
        data = {"family_name": "Doe"}

        credentialCreation(credential_request, data, "FC", "session_123")

        call_args = self.mock_formatter.call_args
        assert call_args[0][3] == "jwt_token_value"

    def test_attestation_proof_type(self):
        """Test handling of attestation proof type"""
        credential_request = {
            "credential_identifier": "eu.europa.ec.eudi.pid_mdoc",
            "proofs": [{"attestation": "attestation_token_value"}],
        }
        data = {"family_name": "Doe"}

        credentialCreation(credential_request, data, "FC", "session_123")

        call_args = self.mock_formatter.call_args
        assert call_args[0][3] == "attestation_token_value"

    def test_multiple_proofs(self):
        """Test credential creation with multiple proofs (batch issuance)"""
        credential_request = {
            "credential_identifier": "eu.europa.ec.eudi.pid_mdoc",
            "proofs": [
                {"jwt": "jwt_token_1"},
                {"jwt": "jwt_token_2"},
                {"jwt": "jwt_token_3"},
            ],
        }
        data = {"family_name": "Doe"}

        result = credentialCreation(credential_request, data, "FC", "session_123")

        assert len(result["credentials"]) == 3
        assert self.mock_formatter.call_count == 3

    def test_fc_country_data_handling(self):
        """Test data handling for form country (FC)"""
        credential_request = {
            "credential_identifier": "eu.europa.ec.eudi.pid_mdoc",
            "proofs": [{"jwt": "mock_jwt"}],
        }
        data = {"family_name": "Doe", "given_name": "John", "birth_date": "1990-01-01"}

        credentialCreation(credential_request, data, "FC", "session_123")

        call_args = self.mock_formatter.call_args
        form_data = call_args[0][2]
        assert form_data["family_name"] == "Doe"
        assert form_data["given_name"] == "John"
        assert form_data["birth_date"] == "1990-01-01"
        assert form_data["issuing_country"] == "FC"

    def test_sample_country_data_handling(self):
        """Test data handling for sample country"""
        credential_request = {
            "credential_identifier": "eu.europa.ec.eudi.pid_mdoc",
            "proofs": [{"jwt": "mock_jwt"}],
        }
        data = {"test_field": "test_value"}

        credentialCreation(credential_request, data, "sample", "session_123")

        call_args = self.mock_formatter.call_args
        form_data = call_args[0][2]
        assert form_data["test_field"] == "test_value"
        assert form_data["issuing_country"] == "sample"

    def test_eidasnode_country_data_handling(self):
        """Test data handling for eIDAS node connection"""
        credential_request = {
            "credential_identifier": "eu.europa.ec.eudi.pid_mdoc",
            "proofs": [{"jwt": "mock_jwt"}],
        }
        data = {"family_name": "Smith", "given_name": "Jane"}

        credentialCreation(credential_request, data, "EIDAS", "session_123")

        call_args = self.mock_formatter.call_args
        form_data = call_args[0][2]
        assert form_data["family_name"] == "Smith"
        assert form_data["issuing_country"] == "EIDAS"

    def test_oauth_country_data_handling(self):
        """Test data handling for OAuth connection"""
        credential_request = {
            "credential_identifier": "eu.europa.ec.eudi.pid_mdoc",
            "proofs": [{"jwt": "mock_jwt"}],
        }
        data = {
            "family_name": "Doe",
            "given_name": "John",
            "birth_date": "1990-01-01",
            "nationality": "EU",
        }

        credentialCreation(credential_request, data, "EU", "session_123")

        call_args = self.mock_formatter.call_args
        form_data = call_args[0][2]
        assert form_data["family_name"] == "Doe"
        assert form_data["given_name"] == "John"
        assert form_data["issuing_country"] == "EU"

    def test_openid_country_data_handling_non_pt(self):
        """Test data handling for OpenID connection (non-PT country)"""
        self.mock_countries["OPENID_TEST"] = {"connection_type": "openid"}

        credential_request = {
            "credential_identifier": "eu.europa.ec.eudi.pid_mdoc",
            "proofs": [{"jwt": "mock_jwt"}],
        }
        data = {"custom_field": "custom_value"}

        credentialCreation(credential_request, data, "OPENID_TEST", "session_123")

        call_args = self.mock_formatter.call_args
        form_data = call_args[0][2]
        assert form_data["custom_field"] == "custom_value"
        assert form_data["issuing_country"] == "OPENID_TEST"

    @patch("app.route_dynamic.datetime")
    @patch("app.route_dynamic.convert_png_to_jpeg")
    @patch("app.route_dynamic.base64")
    def test_openid_portugal_data_handling(self, mock_b64, mock_convert, mock_datetime):
        """Test Portugal-specific OpenID data handling with field mapping and transformations"""
        # Setup date conversion mock
        mock_datetime.strptime.return_value.strftime.return_value = "1990-01-01"

        # Setup image conversion mocks
        mock_convert.return_value = b"jpeg_data"
        mock_b64.b64decode.return_value = b"png_data"
        mock_b64.urlsafe_b64encode.return_value.decode.return_value = "encoded_jpeg"

        credential_request = {
            "credential_identifier": "eu.europa.ec.eudi.pid_mdoc",
            "proofs": [{"jwt": "mock_jwt"}],
        }
        data = [
            {"name": "FamilyName", "value": "Silva"},
            {"name": "GivenName", "value": "Maria"},
            {"name": "BirthDate", "value": "01-01-1990"},
            {"name": "Portrait", "value": "base64_png_data"},
        ]

        credentialCreation(credential_request, data, "PT", "session_123")

        call_args = self.mock_formatter.call_args
        form_data = call_args[0][2]

        # Verify field mapping
        assert form_data["family_name"] == "Silva"
        assert form_data["given_name"] == "Maria"

        # Verify date reformatting
        assert form_data["birth_date"] == "1990-01-01"

        # Verify image conversion
        assert form_data["portrait"] == "encoded_jpeg"

        assert form_data["issuing_country"] == "PT"

    def test_invalid_country_connection_type(self):
        """Test error handling for unsupported connection type"""
        self.mock_countries["INVALID"] = {"connection_type": "unknown_type"}

        credential_request = {
            "credential_identifier": "eu.europa.ec.eudi.pid_mdoc",
            "proofs": [{"jwt": "mock_jwt"}],
        }
        data = {"field": "value"}

        result = credentialCreation(credential_request, data, "INVALID", "session_123")

        assert result["error"] == "invalid_credential_request"
        assert result["error_description"] == "invalid request"

    def test_dynamic_formatter_called_with_correct_parameters(self):
        """Test that dynamic_formatter receives correct parameters"""
        credential_request = {
            "credential_identifier": "eu.europa.ec.eudi.pid_mdoc",
            "proofs": [{"jwt": "test_jwt_token"}],
        }
        data = {"family_name": "Test"}
        session_id = "session_xyz"

        credentialCreation(credential_request, data, "FC", session_id)

        self.mock_formatter.assert_called_once()
        call_args = self.mock_formatter.call_args[0]

        # Verify all parameters
        assert call_args[0] == "mso_mdoc"  # format
        assert call_args[1] == "eu.europa.ec.eudi.pid.1"  # doctype
        assert call_args[2]["family_name"] == "Test"  # form_data
        assert call_args[2]["issuing_country"] == "FC"
        assert call_args[3] == "test_jwt_token"  # device_publickey
        assert call_args[4] == session_id  # session_id

    def test_credential_response_structure(self):
        """Test the structure of credential response matches expected format"""
        credential_request = {
            "credential_identifier": "eu.europa.ec.eudi.pid_mdoc",
            "proofs": [{"jwt": "jwt_1"}, {"jwt": "jwt_2"}],
        }
        data = {"family_name": "Doe"}

        result = credentialCreation(credential_request, data, "FC", "session_123")

        assert isinstance(result, dict)
        assert "credentials" in result
        assert isinstance(result["credentials"], list)
        assert len(result["credentials"]) == 2
        assert all("credential" in cred for cred in result["credentials"])


# -----------------------
# Test: Auth Method Route
# -----------------------
class TestAuthMethod:
    """Test class for /auth_method route"""

    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        """Setup common mocks for auth method tests"""
        # Mock session_manager
        patcher_get_session = patch("app.route_dynamic.session_manager.get_session")
        self.mock_get_session = patcher_get_session.start()

        # Mock cfgserv
        class MockCfgServ:
            service_url = "https://service.test/"
            app_logger = MagicMock()

        patch("app.route_dynamic.cfgserv", new=MockCfgServ).start()

        yield
        patch.stopall()

    def test_link1_redirects_to_oid4vp(self, client):
        """Test selecting link1 redirects to oid4vp endpoint"""
        mock_session = MagicMock()
        self.mock_get_session.return_value = mock_session

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session"

        response = client.post("/dynamic/auth_method", data={"optionsRadios": "link1"})

        assert response.status_code == 302  # Redirect status code
        assert response.location == "https://service.test/oid4vp"

    def test_link2_redirects_to_dynamic(self, client):
        """Test selecting link2 redirects to dynamic endpoint"""
        mock_session = MagicMock()
        self.mock_get_session.return_value = mock_session

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session"

        response = client.post("/dynamic/auth_method", data={"optionsRadios": "link2"})

        assert response.status_code == 302  # Redirect status code
        assert response.location == "https://service.test/dynamic/"

    def test_get_request_returns_none(self, client):
        """Test GET request returns 500 due to missing return statement"""
        mock_session = MagicMock()
        self.mock_get_session.return_value = mock_session

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session"

        response = client.get("/dynamic/auth_method")

        # Function doesn't handle GET, returns None -> 500 error
        assert response.status_code == 500

    def test_session_manager_get_session_called(self, client):
        """Test that session_manager.get_session is called with correct session_id"""
        mock_session = MagicMock()
        self.mock_get_session.return_value = mock_session

        with client.session_transaction() as sess:
            sess["session_id"] = "specific_session_id"

        client.post("/dynamic/auth_method", data={"optionsRadios": "link1"})

        self.mock_get_session.assert_called_once_with(session_id="specific_session_id")

    def test_no_option_selected_returns_500(self, client):
        """Test behavior when no radio option is selected returns 500"""
        mock_session = MagicMock()
        self.mock_get_session.return_value = mock_session

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session"

        response = client.post("/dynamic/auth_method", data={})

        # No matching condition, returns None -> 500 error
        assert response.status_code == 500

    def test_invalid_option_selected_returns_500(self, client):
        """Test behavior when invalid option is selected returns 500"""
        mock_session = MagicMock()
        self.mock_get_session.return_value = mock_session

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session"

        response = client.post(
            "/dynamic/auth_method", data={"optionsRadios": "invalid_link"}
        )

        # No matching condition, returns None -> 500 error
        assert response.status_code == 500

    def test_missing_session_id_returns_500(self, client):
        """Test behavior when session_id is missing returns 500"""
        mock_session = MagicMock()
        self.mock_get_session.return_value = mock_session

        # Don't set session_id
        response = client.post("/dynamic/auth_method", data={"optionsRadios": "link1"})

        # KeyError is caught by Flask and returns 500
        assert response.status_code == 500


# -----------------------
# Test: Form Formatter Function
# -----------------------
class TestFormFormatter:
    """Test class for form_formatter function"""

    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        """Setup common mocks for form formatter tests"""

        # Mock cfgserv
        class MockCfgServ:
            portrait1 = "base64_portrait1_data"
            portrait2 = "base64_portrait2_data"
            signature_usual_mark_issuing_officer = "base64_signature_data"

        patch("app.route_dynamic.cfgserv", MockCfgServ).start()

        # Mock session_manager
        mock_session = MagicMock()
        mock_session.country = "EU"
        mock_session.scope = "eu.europa.ec.eudi.pid_mdoc"

        patcher_get_session = patch("app.route_dynamic.session_manager.get_session")
        self.mock_get_session = patcher_get_session.start()
        self.mock_get_session.return_value = mock_session

        # Mock oidc_metadata
        self.mock_metadata = {
            "credential_configurations_supported": {
                "eu.europa.ec.eudi.pid_mdoc": {
                    "issuer_config": {
                        "issuing_authority": "Test Authority",
                        "validity": 90,
                    }
                }
            }
        }
        patch("app.route_dynamic.oidc_metadata", self.mock_metadata).start()

        # Mock session dict
        self.session_dict = {"session_id": "test_session"}
        patch("app.route_dynamic.session", self.session_dict).start()

        yield
        patch.stopall()

    def test_simple_key_value_pairs(self):
        """Test handling of simple key-value pairs"""
        from app.route_dynamic import form_formatter

        form_data = {
            "family_name": "Doe",
            "given_name": "John",
            "birth_date": "1990-01-01",
        }

        result = form_formatter(form_data)

        assert result["family_name"] == "Doe"
        assert result["given_name"] == "John"
        assert result["birth_date"] == "1990-01-01"
        assert result["issuing_country"] == "EU"
        assert result["issuing_authority"] == "Test Authority"

    def test_skip_empty_values(self):
        """Test that empty values are skipped"""
        from app.route_dynamic import form_formatter

        form_data = {"family_name": "Doe", "given_name": "", "middle_name": None}

        result = form_formatter(form_data)

        assert "family_name" in result
        assert "given_name" not in result
        assert "middle_name" not in result

    def test_skip_control_buttons(self):
        """Test that form control buttons are skipped"""
        from app.route_dynamic import form_formatter

        form_data = {
            "family_name": "Doe",
            "proceed": "Submit",
            "Cancelled": "Cancel",
            "NumberCategories": "5",
        }

        result = form_formatter(form_data)

        assert "family_name" in result
        assert "proceed" not in result
        assert "Cancelled" not in result
        assert "NumberCategories" not in result

    def test_skip_option_on_values(self):
        """Test that radio button 'on' values are skipped"""
        from app.route_dynamic import form_formatter

        form_data = {"family_name": "Doe", "option1": "on", "option2": "selected_value"}

        result = form_formatter(form_data)

        assert "family_name" in result
        assert "option1" not in result
        assert result["option2"] == "selected_value"

    @patch("app.route_dynamic.datetime")
    def test_effective_from_date_formatting(self, mock_datetime):
        """Test RFC3339 date formatting for effective_from_date"""
        from app.route_dynamic import form_formatter

        # Mock datetime behavior
        mock_dt = MagicMock()
        mock_dt.isoformat.return_value = "2024-01-01T00:00:00+00:00"
        mock_datetime.strptime.return_value.replace.return_value = mock_dt

        form_data = {"effective_from_date": "2024-01-01T12:00:00", "family_name": "Doe"}

        result = form_formatter(form_data)

        assert result["effective_from_date"] == "2024-01-01T00:00:00Z"
        assert result["family_name"] == "Doe"

    def test_nested_list_structure(self):
        """Test parsing of nested list structures like capacities[0][codes][1]"""
        from app.route_dynamic import form_formatter

        form_data = {
            "capacities[0][name]": "Manager",
            "capacities[0][codes][0][code]": "MGR",
            "capacities[0][codes][1][code]": "EXEC",
            "capacities[1][name]": "Director",
        }

        result = form_formatter(form_data)

        assert "capacities" in result
        assert isinstance(result["capacities"], list)
        assert len(result["capacities"]) == 2
        assert result["capacities"][0]["name"] == "Manager"
        assert result["capacities"][0]["codes"][0]["code"] == "MGR"
        assert result["capacities"][0]["codes"][1]["code"] == "EXEC"
        assert result["capacities"][1]["name"] == "Director"

    def test_places_of_work_aggregation(self):
        """Test aggregation of places_of_work data"""
        from app.route_dynamic import form_formatter

        form_data = {
            "places_of_work[0][no_fixed_place][0][country_code]": "PT",
            "places_of_work[1][no_fixed_place][0][country_code]": "ES",
        }

        result = form_formatter(form_data)

        assert "places_of_work" in result
        assert isinstance(result["places_of_work"], list)
        assert len(result["places_of_work"]) == 1
        assert "no_fixed_place" in result["places_of_work"][0]
        assert len(result["places_of_work"][0]["no_fixed_place"]) == 2

    def test_nationality_transformation(self):
        """Test nationality list transformation from dict to country codes"""
        from app.route_dynamic import form_formatter

        form_data = {
            "nationality[0][country_code]": "PT",
            "nationality[1][country_code]": "ES",
        }

        result = form_formatter(form_data)

        assert "nationality" in result
        assert isinstance(result["nationality"], list)
        assert result["nationality"] == ["PT", "ES"]

    def test_nationalities_transformation(self):
        """Test nationalities (plural) list transformation"""
        from app.route_dynamic import form_formatter

        form_data = {
            "nationalities[0][country_code]": "FR",
            "nationalities[1][country_code]": "DE",
            "nationalities[2][country_code]": "IT",
        }

        result = form_formatter(form_data)

        assert "nationalities" in result
        assert isinstance(result["nationalities"], list)
        assert result["nationalities"] == ["FR", "DE", "IT"]

    def test_portrait_port1_replacement(self):
        """Test portrait Port1 value replacement with base64 data"""
        from app.route_dynamic import form_formatter

        form_data = {"portrait": "Port1", "family_name": "Doe"}

        result = form_formatter(form_data)

        assert result["portrait"] == "base64_portrait1_data"
        assert result["family_name"] == "Doe"

    def test_portrait_port2_replacement(self):
        """Test portrait Port2 value replacement with base64 data"""
        from app.route_dynamic import form_formatter

        form_data = {
            "portrait": "Port2",
        }

        result = form_formatter(form_data)

        assert result["portrait"] == "base64_portrait2_data"

    def test_portrait_custom_value(self):
        """Test portrait custom base64 value is preserved"""
        from app.route_dynamic import form_formatter

        custom_portrait = "custom_base64_portrait_data"
        form_data = {
            "portrait": custom_portrait,
        }

        result = form_formatter(form_data)

        assert result["portrait"] == custom_portrait

    def test_image_port1_replacement(self):
        """Test image Port1 value replacement"""
        from app.route_dynamic import form_formatter

        form_data = {
            "image": "Port1",
        }

        result = form_formatter(form_data)

        assert result["image"] == "base64_portrait1_data"

    def test_image_port2_replacement(self):
        """Test image Port2 value replacement"""
        from app.route_dynamic import form_formatter

        form_data = {
            "image": "Port2",
        }

        result = form_formatter(form_data)

        assert result["image"] == "base64_portrait2_data"

    def test_signature_usual_mark_replacement(self):
        """Test signature_usual_mark Sig1 value replacement"""
        from app.route_dynamic import form_formatter

        form_data = {
            "signature_usual_mark": "Sig1",
        }

        result = form_formatter(form_data)

        assert result["signature_usual_mark"] == "base64_signature_data"

    def test_signature_usual_mark_issuing_officer_replacement(self):
        """Test signature_usual_mark_issuing_officer Sig1 replacement"""
        from app.route_dynamic import form_formatter

        form_data = {
            "signature_usual_mark_issuing_officer": "Sig1",
        }

        result = form_formatter(form_data)

        assert result["signature_usual_mark_issuing_officer"] == "base64_signature_data"

    def test_picture_field_replacement(self):
        """Test picture field Port1/Port2 replacement"""
        from app.route_dynamic import form_formatter

        form_data = {
            "picture": "Port1",
        }

        result = form_formatter(form_data)

        assert result["picture"] == "base64_portrait1_data"

    def test_multiple_image_fields(self):
        """Test multiple image-related fields with different values"""
        from app.route_dynamic import form_formatter

        form_data = {
            "portrait": "Port1",
            "image": "Port2",
            "picture": "custom_base64_data",
            "signature_usual_mark": "Sig1",
        }

        result = form_formatter(form_data)

        assert result["portrait"] == "base64_portrait1_data"
        assert result["image"] == "base64_portrait2_data"
        assert result["picture"] == "custom_base64_data"
        assert result["signature_usual_mark"] == "base64_signature_data"

    def test_complex_nested_structure(self):
        """Test complex nested structure with mixed dictionaries and lists"""
        from app.route_dynamic import form_formatter

        form_data = {
            "capacities[0][type]": "legal",
            "capacities[0][codes][0][code]": "A1",
            "capacities[0][codes][0][description]": "Admin",
            "capacities[0][codes][1][code]": "B2",
            "capacities[1][type]": "natural",
        }

        result = form_formatter(form_data)

        assert result["capacities"][0]["type"] == "legal"
        assert result["capacities"][0]["codes"][0]["code"] == "A1"
        assert result["capacities"][0]["codes"][0]["description"] == "Admin"
        assert result["capacities"][0]["codes"][1]["code"] == "B2"
        assert result["capacities"][1]["type"] == "natural"

    def test_issuing_country_and_authority_added(self):
        """Test that issuing_country and issuing_authority are added"""
        from app.route_dynamic import form_formatter

        form_data = {
            "family_name": "Doe",
        }

        result = form_formatter(form_data)

        assert result["issuing_country"] == "EU"
        assert result["issuing_authority"] == "Test Authority"

    def test_empty_form_data(self):
        """Test handling of empty form data"""
        from app.route_dynamic import form_formatter

        form_data = {}

        result = form_formatter(form_data)

        # Should still have issuer-filled data
        assert result["issuing_country"] == "EU"
        assert result["issuing_authority"] == "Test Authority"

    def test_session_manager_called_correctly(self):
        """Test that session_manager.get_session is called with correct session_id"""
        from app.route_dynamic import form_formatter

        form_data = {"family_name": "Doe"}

        form_formatter(form_data)

        # Should be called at least twice (for country and scope)
        assert self.mock_get_session.call_count >= 2

        # Check that all calls used the correct session_id
        # The function is called as: session_manager.get_session(session["session_id"])
        # This means session_id is a positional argument
        for call in self.mock_get_session.call_args_list:
            # call[0] is a tuple of positional arguments
            # call[1] is a dict of keyword arguments
            assert len(call[0]) > 0 and call[0][0] == "test_session"


# -----------------------
# Test: Presentation Formatter Function
# -----------------------
class TestPresentationFormatter:
    """Test class for presentation_formatter function"""

    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        """Setup common mocks for presentation formatter tests"""
        # Mock session dict
        self.session_dict = {"session_id": "test_session"}
        patch("app.route_dynamic.session", self.session_dict).start()

        # Mock session_manager
        mock_session = MagicMock()
        mock_session.country = "EU"
        mock_session.credentials_requested = ["eu.europa.ec.eudi.pid_mdoc"]

        patcher_get_session = patch("app.route_dynamic.session_manager.get_session")
        self.mock_get_session = patcher_get_session.start()
        self.mock_get_session.return_value = mock_session

        # Mock oidc_metadata
        self.mock_metadata = {
            "credential_configurations_supported": {
                "eu.europa.ec.eudi.pid_mdoc": {
                    "scope": "eu.europa.ec.eudi.pid.1",
                    "credential_metadata": {
                        "display": [{"name": "PID (mDL)", "locale": "en"}]
                    },
                    "issuer_config": {
                        "issuing_authority": "Test Authority",
                        "validity": 90,
                    },
                },
                "eu.europa.ec.eudi.seafarer_mdoc": {
                    "scope": "eu.europa.ec.eudi.seafarer.1",
                    "credential_metadata": {
                        "display": [
                            {"name": "Seafarer Identity Document", "locale": "en"}
                        ]
                    },
                    "issuer_config": {
                        "issuing_authority": "Maritime Authority",
                        "validity": 365,
                    },
                },
                "eu.europa.ec.eudi.ehic_sd_jwt_vc": {
                    "scope": "eu.europa.ec.eudi.ehic.1",
                    "credential_metadata": {
                        "display": [
                            {"name": "European Health Insurance Card", "locale": "en"}
                        ]
                    },
                    "issuer_config": {
                        "issuing_authority": "Health Authority",
                        "issuing_authority_id": "HA-123",
                        "validity": 180,
                    },
                },
                "org.iso.18013.5.1.mDL": {
                    "scope": "org.iso.18013.5.1.mDL",
                    "credential_metadata": {
                        "display": [{"name": "Mobile Driving License", "locale": "en"}]
                    },
                    "issuer_config": {
                        "issuing_authority": "DMV",
                        "validity": 1825,
                        "credential_type": "mDL",
                    },
                },
            }
        }
        patch("app.route_dynamic.oidc_metadata", self.mock_metadata).start()

        # Mock cfgserv
        class MockCfgServ:
            issuing_authority_logo = "dGVzdF9sb2dv"  # base64url encoded "test_logo"

        patch("app.route_dynamic.cfgserv", MockCfgServ).start()

        # Mock getAttributesForm functions
        patch(
            "app.route_dynamic.getAttributesForm",
            return_value={"family_name": {}, "given_name": {}, "birth_date": {}},
        ).start()
        patch(
            "app.route_dynamic.getAttributesForm2",
            return_value={"portrait": {}, "age_over_18": {}},
        ).start()

        # Mock date functions
        patch("app.route_dynamic.date").start()
        patch("app.route_dynamic.timedelta").start()

        yield
        patch.stopall()

    def test_basic_presentation_data_structure(self):
        """Test basic structure of presentation data"""
        from app.route_dynamic import presentation_formatter

        cleaned_data = {
            "family_name": "Doe",
            "given_name": "John",
        }

        result = presentation_formatter(cleaned_data)

        assert isinstance(result, dict)
        assert "PID (mDL)" in result
        assert isinstance(result["PID (mDL)"], dict)

    def test_credential_attributes_included(self):
        """Test that matching attributes are included in presentation"""
        from app.route_dynamic import presentation_formatter

        cleaned_data = {
            "family_name": "Doe",
            "given_name": "John",
            "birth_date": "1990-01-01",
            "portrait": "base64_portrait_data",
        }

        result = presentation_formatter(cleaned_data)

        credential_data = result["PID (mDL)"]
        assert credential_data["family_name"] == "Doe"
        assert credential_data["given_name"] == "John"
        assert credential_data["birth_date"] == "1990-01-01"
        assert "portrait" in credential_data

    def test_non_matching_attributes_excluded(self):
        """Test that non-matching attributes are excluded"""
        from app.route_dynamic import presentation_formatter

        cleaned_data = {
            "family_name": "Doe",
            "random_field": "should_not_appear",
        }

        result = presentation_formatter(cleaned_data)

        credential_data = result["PID (mDL)"]
        assert "family_name" in credential_data
        assert "random_field" not in credential_data

    @patch("app.route_dynamic.date")
    @patch("app.route_dynamic.timedelta")
    def test_issuance_and_expiry_dates_added(self, mock_timedelta, mock_date):
        """Test that issuance and expiry dates are calculated and added"""
        from app.route_dynamic import presentation_formatter
        from datetime import date, timedelta

        # Mock today's date
        mock_today = date(2024, 1, 1)
        mock_date.today.return_value = mock_today

        # Mock timedelta
        mock_timedelta.return_value = timedelta(days=90)

        cleaned_data = {"family_name": "Doe"}

        result = presentation_formatter(cleaned_data)

        credential_data = result["PID (mDL)"]
        assert "estimated_issuance_date" in credential_data
        assert "estimated_expiry_date" in credential_data

    def test_issuing_country_added(self):
        """Test that issuing_country is added from session"""
        from app.route_dynamic import presentation_formatter

        cleaned_data = {"family_name": "Doe"}

        result = presentation_formatter(cleaned_data)

        credential_data = result["PID (mDL)"]
        assert credential_data["issuing_country"] == "EU"

    def test_issuing_authority_added(self):
        """Test that issuing_authority is added from config"""
        from app.route_dynamic import presentation_formatter

        cleaned_data = {"family_name": "Doe"}

        result = presentation_formatter(cleaned_data)

        credential_data = result["PID (mDL)"]
        assert credential_data["issuing_authority"] == "Test Authority"

    def test_seafarer_credential_logo(self):
        """Test seafarer credential includes issuing authority logo"""
        from app.route_dynamic import presentation_formatter

        # Update mock session to request seafarer credential
        mock_session = MagicMock()
        mock_session.country = "EU"
        mock_session.credentials_requested = ["eu.europa.ec.eudi.seafarer_mdoc"]
        self.mock_get_session.return_value = mock_session

        cleaned_data = {"family_name": "Doe"}

        result = presentation_formatter(cleaned_data)

        credential_data = result["Seafarer Identity Document"]
        assert "issuing_authority_logo" in credential_data

    def test_ehic_credential_authority_structure(self):
        """Test EHIC credential has special issuing_authority structure"""
        from app.route_dynamic import presentation_formatter

        # Update mock session to request EHIC credential
        mock_session = MagicMock()
        mock_session.country = "EU"
        mock_session.credentials_requested = ["eu.europa.ec.eudi.ehic_sd_jwt_vc"]
        self.mock_get_session.return_value = mock_session

        cleaned_data = {"family_name": "Doe"}

        result = presentation_formatter(cleaned_data)

        credential_data = result["European Health Insurance Card"]
        assert isinstance(credential_data["issuing_authority"], dict)
        assert credential_data["issuing_authority"]["id"] == "HA-123"
        assert credential_data["issuing_authority"]["name"] == "Health Authority"

    def test_credential_type_added_when_present(self):
        """Test credential_type is added when present in config"""
        from app.route_dynamic import presentation_formatter

        # Use mDL which has credential_type in config
        mock_session = MagicMock()
        mock_session.country = "EU"
        mock_session.credentials_requested = ["org.iso.18013.5.1.mDL"]
        self.mock_get_session.return_value = mock_session

        cleaned_data = {"family_name": "Doe"}

        result = presentation_formatter(cleaned_data)

        credential_data = result["Mobile Driving License"]
        assert credential_data["credential_type"] == "mDL"

    @patch("app.route_dynamic.calculate_age")
    def test_age_over_18_calculated_when_both_fields_present(self, mock_calculate_age):
        """Test age_over_18 is calculated when birth_date present"""
        from app.route_dynamic import presentation_formatter

        mock_calculate_age.return_value = 25

        cleaned_data = {
            "birth_date": "1999-01-01",
            "age_over_18": None,  # Will be calculated
        }

        result = presentation_formatter(cleaned_data)

        credential_data = result["PID (mDL)"]
        assert credential_data["age_over_18"] is True

    @patch("app.route_dynamic.calculate_age")
    def test_age_over_18_false_for_minor(self, mock_calculate_age):
        """Test age_over_18 is False for minors"""
        from app.route_dynamic import presentation_formatter

        mock_calculate_age.return_value = 16

        cleaned_data = {
            "birth_date": "2008-01-01",
            "age_over_18": None,
        }

        result = presentation_formatter(cleaned_data)

        credential_data = result["PID (mDL)"]
        assert credential_data["age_over_18"] is False

    @patch("app.route_dynamic.calculate_age")
    def test_mdl_age_over_18_calculation(self, mock_calculate_age):
        """Test mDL specific age_over_18 calculation"""
        from app.route_dynamic import presentation_formatter

        mock_calculate_age.return_value = 21

        # Use mDL credential
        mock_session = MagicMock()
        mock_session.country = "EU"
        mock_session.credentials_requested = ["org.iso.18013.5.1.mDL"]
        self.mock_get_session.return_value = mock_session

        cleaned_data = {
            "birth_date": "2003-01-01",
        }

        result = presentation_formatter(cleaned_data)

        credential_data = result["Mobile Driving License"]
        assert credential_data["age_over_18"] is True

    @patch("app.route_dynamic.json")
    def test_driving_privileges_json_parsing(self, mock_json):
        """Test driving_privileges string is parsed as JSON"""
        from app.route_dynamic import presentation_formatter

        # Mock json.loads to return parsed data
        mock_json.loads.return_value = [
            {"vehicle_category_code": "B", "issue_date": "2020-01-01"}
        ]

        # Add driving_privileges to form attributes
        patch(
            "app.route_dynamic.getAttributesForm",
            return_value={"driving_privileges": {}},
        ).start()

        cleaned_data = {
            "driving_privileges": '{"vehicle_category_code": "B"}',
        }

        result = presentation_formatter(cleaned_data)

        credential_data = result["PID (mDL)"]
        assert isinstance(credential_data["driving_privileges"], list)
        mock_json.loads.assert_called_once()

    @patch("app.route_dynamic.base64")
    def test_portrait_field_base64_encoding(self, mock_base64):
        """Test portrait field is re-encoded from urlsafe to standard base64"""
        from app.route_dynamic import presentation_formatter

        mock_base64.urlsafe_b64decode.return_value = b"decoded_data"
        mock_base64.b64encode.return_value = b"encoded_data"

        cleaned_data = {
            "portrait": "urlsafe_base64_data",
        }

        result = presentation_formatter(cleaned_data)

        credential_data = result["PID (mDL)"]
        mock_base64.urlsafe_b64decode.assert_called_with("urlsafe_base64_data")
        mock_base64.b64encode.assert_called_with(b"decoded_data")

    @patch("app.route_dynamic.base64")
    def test_multiple_image_fields_encoded(self, mock_base64):
        """Test multiple image fields are all re-encoded"""
        from app.route_dynamic import presentation_formatter

        mock_base64.urlsafe_b64decode.return_value = b"decoded"
        mock_base64.b64encode.return_value.decode.return_value = "encoded"

        # Mock getAttributesForm2 to include all image fields
        patch(
            "app.route_dynamic.getAttributesForm2",
            return_value={
                "portrait": {},
                "image": {},
                "signature_usual_mark": {},
                "picture": {},
            },
        ).start()

        cleaned_data = {
            "portrait": "portrait_data",
            "image": "image_data",
            "signature_usual_mark": "signature_data",
            "picture": "picture_data",
        }

        result = presentation_formatter(cleaned_data)

        # Should be called 4 times (once for each image field)
        assert mock_base64.urlsafe_b64decode.call_count == 4

    def test_number_categories_fields_removed(self):
        """Test NumberCategories and related date fields are removed"""
        from app.route_dynamic import presentation_formatter

        # Add NumberCategories to form attributes
        patch(
            "app.route_dynamic.getAttributesForm",
            return_value={
                "NumberCategories": {},
                "IssueDate1": {},
                "ExpiryDate1": {},
                "IssueDate2": {},
                "ExpiryDate2": {},
            },
        ).start()

        cleaned_data = {
            "NumberCategories": "2",
            "IssueDate1": "2020-01-01",
            "ExpiryDate1": "2025-01-01",
            "IssueDate2": "2021-01-01",
            "ExpiryDate2": "2026-01-01",
        }

        result = presentation_formatter(cleaned_data)

        credential_data = result["PID (mDL)"]
        assert "NumberCategories" not in credential_data
        assert "IssueDate1" not in credential_data
        assert "ExpiryDate1" not in credential_data
        assert "IssueDate2" not in credential_data
        assert "ExpiryDate2" not in credential_data

    def test_multiple_credentials_requested(self):
        """Test handling multiple credentials requested"""
        from app.route_dynamic import presentation_formatter

        # Request multiple credentials
        mock_session = MagicMock()
        mock_session.country = "EU"
        mock_session.credentials_requested = [
            "eu.europa.ec.eudi.pid_mdoc",
            "org.iso.18013.5.1.mDL",
        ]
        self.mock_get_session.return_value = mock_session

        cleaned_data = {
            "family_name": "Doe",
            "given_name": "John",
        }

        result = presentation_formatter(cleaned_data)

        assert "PID (mDL)" in result
        assert "Mobile Driving License" in result
        assert result["PID (mDL)"]["family_name"] == "Doe"
        assert result["Mobile Driving License"]["family_name"] == "Doe"

    def test_session_manager_called_with_session_id(self):
        """Test session_manager.get_session is called with correct session_id"""
        from app.route_dynamic import presentation_formatter

        cleaned_data = {"family_name": "Doe"}

        presentation_formatter(cleaned_data)

        self.mock_get_session.assert_called()
        # Check that session_id was passed as keyword argument
        call_kwargs = self.mock_get_session.call_args[1]
        assert call_kwargs["session_id"] == "test_session"


# -----------------------
# Test: Redirect Wallet Route
# -----------------------
class TestRedirectWallet:
    """Test class for /redirect_wallet route"""

    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        """Setup common mocks for redirect_wallet tests"""
        # Mock session_manager
        patcher_get_session = patch("app.route_dynamic.session_manager.get_session")
        self.mock_get_session = patcher_get_session.start()

        # Mock session object with a jws_token
        self.mock_session = MagicMock()
        self.mock_session.jws_token = "mocked_jws_token_987"
        self.mock_get_session.return_value = self.mock_session

        # Mock cfgserv to provide the target endpoint
        class MockCfgServ:
            OpenID_first_endpoint = "https://openid.provider.test/auth"
            app_logger = MagicMock()

        patch("app.route_dynamic.cfgserv", new=MockCfgServ).start()

        # Mock url_get to check parameters passed to the utility function
        # Using a side_effect lambda to easily construct the expected redirect URL
        patcher_url_get = patch(
            "app.route_dynamic.url_get",
            side_effect=lambda url, params: f"{url}?token={params['token']}&username={params['username']}",
        )
        self.mock_url_get = patcher_url_get.start()

        yield
        patch.stopall()

    def test_successful_redirection(self, client):
        """Test POST request successfully redirects with token and session_id"""
        test_session_id = "test_sess_456"
        test_user_id = "user_abc_789"

        # Set session_id in Flask session
        with client.session_transaction() as sess:
            sess["session_id"] = test_session_id

        # Send POST request with required user_id
        response = client.post(
            "/dynamic/redirect_wallet", data={"user_id": test_user_id}
        )

        # 1. Check status code (302 for redirect)
        assert response.status_code == 302

        # 2. Check redirect location
        expected_location = "https://openid.provider.test/auth?token=mocked_jws_token_987&username=test_sess_456"
        assert response.location == expected_location

        # 3. Verify session_manager was called correctly
        self.mock_get_session.assert_called_once_with(session_id=test_session_id)

        # 4. Verify url_get was called with correct parameters
        self.mock_url_get.assert_called_once_with(
            "https://openid.provider.test/auth",
            {"token": self.mock_session.jws_token, "username": test_session_id},
        )

    def test_get_method_fails(self, client):
        """Test GET request returns 405 Method Not Allowed"""
        # The route is explicitly POST/GET but the logic expects POST data,
        # but Flask handles 405 if only POST is specified in decorator and GET is used.
        # Since the route is defined as methods=["GET", "POST"], the key errors will result in 500, not 405.

        # However, to avoid a KeyError in the GET path, we must ensure session is set up.
        with client.session_transaction() as sess:
            sess["session_id"] = "test_sess_456"

        # The route logic immediately tries to access request.form["user_id"] which fails on GET,
        # leading to a KeyError caught by Flask as 500.
        response = client.get("/dynamic/redirect_wallet")
        assert response.status_code == 500

    def test_missing_user_id_returns_500(self, client):
        """Test missing 'user_id' in form data causes KeyError (500)"""
        with client.session_transaction() as sess:
            sess["session_id"] = "test_sess_456"

        # 'user_id' is missing from data
        response = client.post("/dynamic/redirect_wallet", data={})

        # Flask catches the KeyError on form_data["user_id"] and returns 500
        assert response.status_code == 500

    def test_missing_session_id_returns_500(self, client):
        """Test missing 'session_id' in Flask session causes KeyError (500)"""
        # Don't set session_id in session_transaction
        response = client.post(
            "/dynamic/redirect_wallet", data={"user_id": "test_user"}
        )

        # Flask catches the KeyError on session["session_id"] and returns 500
        assert response.status_code == 500


# -----------------------
# Test: generate_connector_authorization_url Function
# -----------------------
class TestGenerateConnectorAuthorizationUrl:
    """Test class for generate_connector_authorization_url function"""

    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        """Setup common mocks for authorization url generation tests"""
        # Mock uuid4 to return a predictable state value (fix applied here)
        patcher_uuid = patch(
            "app.route_dynamic.uuid4", return_value="mocked_uuid_state_xyz"
        )
        self.mock_uuid4 = patcher_uuid.start()

        # Mock requests.get to simulate fetching connector metadata
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "authorization_endpoint": "https://connector.auth/authorize"
        }
        patcher_requests_get = patch(
            "app.route_dynamic.requests.get", return_value=mock_response
        )
        self.mock_requests_get = patcher_requests_get.start()

        # Mock Flask session dictionary
        self.mock_session_dict = {}
        patcher_session = patch("app.route_dynamic.session", new=self.mock_session_dict)
        self.mock_session = patcher_session.start()

        # Import the function under test (assuming standard file structure)
        from app.route_dynamic import generate_connector_authorization_url

        self.generate_connector_authorization_url = generate_connector_authorization_url

        yield
        patch.stopall()

    @pytest.fixture
    def mock_oauth_data(self):
        """Fixture for standard OAuth configuration data"""
        return {
            "base_url": "https://connector.test",
            "client_id": "mock-client-id-123",
            "redirect_uri": "https://rp.test/redirect",
        }

    def test_successful_url_generation(self, mock_oauth_data):
        """Test the function generates the correct full authorization URL and parameters."""
        country = "DE"
        credentials = ["eu.europa.ec.eudi.pid_mdoc"]
        expected_state = "mocked_uuid_state_xyz"
        expected_endpoint = "https://connector.auth/authorize"

        result_url = self.generate_connector_authorization_url(
            mock_oauth_data, country, credentials
        )

        # 1. Check if requests.get was called with the correct metadata URL
        expected_metadata_url = (
            "https://connector.test/.well-known/oauth-authorization-server"
        )
        self.mock_requests_get.assert_called_once_with(expected_metadata_url)

        # 2. Check the final URL structure and key parameters (order is not guaranteed)
        assert result_url.startswith(expected_endpoint)
        assert f"client_id={mock_oauth_data['client_id']}" in result_url
        # The assertion below is now robust because the state parameter will be a simple string,
        # making the URL encoding predictable.
        assert (
            f"redirect_uri={mock_oauth_data['redirect_uri']}" in result_url
            or f"redirect_uri=https%3A%2F%2Frp.test%2Fredirect" in result_url
        )
        assert "response_type=code" in result_url
        assert f"scope={credentials[0]}" in result_url
        assert f"state={expected_state}" in result_url
        assert f"entity={country}" in result_url

    def test_session_state_is_set_correctly(self, mock_oauth_data):
        """Test that the generated state is stored in the Flask session."""
        self.generate_connector_authorization_url(mock_oauth_data, "FR", ["scope1"])

        assert "oauth_state" in self.mock_session_dict
        assert self.mock_session_dict["oauth_state"] == "mocked_uuid_state_xyz"

    def test_handles_multiple_scopes_uses_first(self, mock_oauth_data):
        """Test that only the first credential in the list is used as scope."""
        credentials = ["scope_one", "scope_two", "scope_three"]

        result_url = self.generate_connector_authorization_url(
            mock_oauth_data, "PT", credentials
        )

        # Only "scope_one" should be in the URL parameters
        assert "scope=scope_one" in result_url
        assert "scope_two" not in result_url
        assert "scope_three" not in result_url

    def test_missing_authorization_endpoint_raises_keyerror(self, mock_oauth_data):
        """Test that missing 'authorization_endpoint' in metadata raises KeyError."""
        # Setup mock response to return JSON without the required key
        mock_response_missing = MagicMock()
        mock_response_missing.json.return_value = {"another_key": "value"}
        self.mock_requests_get.return_value = mock_response_missing

        with pytest.raises(KeyError):
            self.generate_connector_authorization_url(mock_oauth_data, "ES", ["scope"])

    def test_missing_required_oauth_data_key_raises_error(self, mock_oauth_data):
        """Test that missing required keys in oauth_data dict raise errors."""

        # Missing client_id
        data_missing_client = mock_oauth_data.copy()
        del data_missing_client["client_id"]
        with pytest.raises(KeyError):
            self.generate_connector_authorization_url(
                data_missing_client, "IT", ["scope"]
            )

        # Missing redirect_uri
        data_missing_redirect = mock_oauth_data.copy()
        del data_missing_redirect["redirect_uri"]
        with pytest.raises(KeyError):
            self.generate_connector_authorization_url(
                data_missing_redirect, "IT", ["scope"]
            )
