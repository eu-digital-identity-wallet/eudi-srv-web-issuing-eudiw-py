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

    @patch("app.route_dynamic.render_template")
    @patch("app.route_dynamic.cfgserv")
    def test_cancelled_form(self, mock_cfgserv, mock_render, client):
        """Test form cancellation returns auth_method.html"""
        mock_cfgserv.service_url = "https://service.test"
        mock_render.return_value = b"rendered_template"

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session"

        response = client.post("/dynamic/", data={"Cancelled": "true"})

        assert response.data == b"rendered_template"
        mock_render.assert_called_once()

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

    @patch("app.route_dynamic.render_template")
    @patch("app.route_dynamic.cfgserv", new=MockConfService)
    def test_cancelled_form(self, mock_render, client):
        """Test that cancelling the form renders auth_method.html"""
        mock_render.return_value = b"rendered_template"

        with client.session_transaction() as sess:
            sess["session_id"] = "test_session"

        response = client.post("/dynamic/country_selected", data={"Cancelled": "true"})

        assert response.data == b"rendered_template"
        mock_render.assert_called_once()

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
