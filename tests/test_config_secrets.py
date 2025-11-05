import importlib
import re


class TestConfigImport:
    """Test importing and loading of the configuration module."""

    def test_module_imports(self):
        """Ensure the configuration module imports without error."""
        module = importlib.import_module("app.app_config.__config_secrets")
        assert module is not None

    def test_required_attributes_exist(self):
        """Ensure all expected secret attributes exist in the module."""
        module = importlib.import_module("app.app_config.__config_secrets")
        for name in [
            "flask_secret_key",
            "eidasnode_lightToken_secret",
            "revocation_api_key",
        ]:
            assert hasattr(module, name), f"Missing config attribute: {name}"


class TestConfigValues:
    """Test the correctness and validity of configuration values."""

    @classmethod
    def setup_class(cls):
        import app.app_config.__config_secrets as cfg

        cls.cfg = cfg

    def test_secrets_are_nonempty_strings(self):
        """Ensure all secrets are defined and non-empty strings."""
        for name in [
            "flask_secret_key",
            "eidasnode_lightToken_secret",
            "revocation_api_key",
        ]:
            value = getattr(self.cfg, name)
            assert isinstance(value, str), f"{name} must be a string"
            assert value.strip() != "", f"{name} must not be empty"

    def test_secrets_encoding_is_latin1_safe(self):
        """Ensure all secrets are valid Latin-1 encodable strings."""
        for name in [
            "flask_secret_key",
            "eidasnode_lightToken_secret",
            "revocation_api_key",
        ]:
            value = getattr(self.cfg, name)
            value.encode("latin-1")  # Should not raise

    def test_secret_strength_format(self):
        """Ensure secrets meet minimal strength and format expectations."""
        for name in [
            "flask_secret_key",
            "eidasnode_lightToken_secret",
            "revocation_api_key",
        ]:
            value = getattr(self.cfg, name)
            assert len(value) >= 8, f"{name} is too short"
            assert re.match(r"^[A-Za-z0-9_\-]+$", value), f"{name} has invalid chars"
