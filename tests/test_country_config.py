import pytest
from app.app_config import config_countries


class TestConfCountries:
    def test_has_supported_countries(self):
        """Ensure supported_countries exists and contains expected keys."""
        countries = config_countries.ConfCountries.supported_countries
        assert isinstance(countries, dict)
        assert "EU" in countries
        assert config_countries.ConfCountries.formCountry in countries
        assert "EE" in countries

    @pytest.mark.parametrize("country_code", ["EU", "FC", "PT", "EE", "CZ", "NL", "LU"])
    def test_country_structure_and_required_keys(self, country_code):
        """Each country entry should contain mandatory configuration keys."""
        countries = config_countries.ConfCountries.supported_countries
        country_conf = countries[country_code]

        assert isinstance(country_conf, dict)
        assert "supported_credentials" in country_conf
        assert isinstance(country_conf["supported_credentials"], list)
        assert len(country_conf["supported_credentials"]) > 0

        # Every config must define at least a private key and cert path
        assert "pid_mdoc_privkey" in country_conf
        assert "pid_mdoc_cert" in country_conf
        assert country_conf["pid_mdoc_privkey"].startswith(
            config_countries.cfgserv.privKey_path
        )
        assert country_conf["pid_mdoc_cert"].startswith(
            config_countries.cfgserv.trusted_CAs_path
        )

    def test_urlReturnEE_is_defined(self):
        """Check the EE redirect URL constant."""
        assert config_countries.ConfCountries.urlReturnEE.startswith("https://")
        assert "tara/redirect" in config_countries.ConfCountries.urlReturnEE

    def test_eidas_loa_high_constant(self):
        """Ensure the EIDAS LOA constant is correct."""
        assert config_countries.EIDAS_LOA_HIGH == "http://eidas.europa.eu/LoA/high"

    def test_eu_oauth_structure(self):
        """Check that EU entry defines a valid OAuth configuration."""
        eu_conf = config_countries.ConfCountries.supported_countries["EU"]
        oauth = eu_conf["oauth_auth"]

        assert "base_url" in oauth
        assert oauth["redirect_uri"].startswith(config_countries.cfgserv.service_url)
        assert oauth["response_type"] == "code"
        assert "client_id" in oauth
        assert "client_secret" in oauth

    def test_ee_oidc_structure(self):
        """Ensure the EE configuration contains expected OIDC and redirect data."""
        ee_conf = config_countries.ConfCountries.supported_countries["EE"]
        assert ee_conf["connection_type"] == "openid"

        oidc_auth = ee_conf["oidc_auth"]
        assert oidc_auth["redirect_uri"] == config_countries.ConfCountries.urlReturnEE

        oidc_redirect = ee_conf["oidc_redirect"]
        assert "headers" in oidc_redirect
        assert "redirect_uri" in oidc_redirect
        assert (
            oidc_redirect["redirect_uri"] == config_countries.ConfCountries.urlReturnEE
        )


class TestConfFrontend:
    def test_registered_frontends_exist(self):
        """Ensure registered_frontends dictionary is defined correctly."""
        frontend_conf = config_countries.ConfFrontend.registered_frontends
        assert isinstance(frontend_conf, dict)
        assert len(frontend_conf) > 0

    def test_frontend_entry_contains_url(self):
        """Check that all registered frontend entries have valid URLs."""
        for (
            frontend_id,
            data,
        ) in config_countries.ConfFrontend.registered_frontends.items():
            assert isinstance(frontend_id, str)
            assert "url" in data
            assert data["url"].startswith("https://")
