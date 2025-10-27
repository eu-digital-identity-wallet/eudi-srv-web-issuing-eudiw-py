import pytest
from werkzeug.datastructures import ImmutableMultiDict
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime

# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def valid_rsa_key():
    """Generate a temporary RSA public/private key pair in PEM format"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem


@pytest.fixture
def invalid_pem_key():
    """Provide an invalid PEM key"""
    return b"not a valid pem key"


# ============================================================================
# VALIDATE_MANDATORY_ARGS TESTS
# ============================================================================


class TestValidateMandatoryArgs:
    """Tests for validate_mandatory_args function"""

    def test_all_mandatory_present(self):
        """All mandatory arguments are present"""
        args = ImmutableMultiDict({"arg1": "value1", "arg2": "value2"})
        mandlist = ["arg1", "arg2"]

        from app.validate import validate_mandatory_args

        result, missing = validate_mandatory_args(args, mandlist)
        assert result is True
        assert missing == []

    def test_some_mandatory_missing(self):
        """Some mandatory arguments are missing"""
        args = ImmutableMultiDict({"arg1": "value1"})
        mandlist = ["arg1", "arg2"]

        from app.validate import validate_mandatory_args

        result, missing = validate_mandatory_args(args, mandlist)
        assert result is False
        assert missing == ["arg2"]

    def test_all_mandatory_missing(self):
        """All mandatory arguments are missing"""
        args = ImmutableMultiDict({})
        mandlist = ["arg1", "arg2"]

        from app.validate import validate_mandatory_args

        result, missing = validate_mandatory_args(args, mandlist)
        assert result is False
        assert set(missing) == {"arg1", "arg2"}


# ============================================================================
# IS_VALID_PEM_PUBLIC_KEY TESTS
# ============================================================================


class TestIsValidPemPublicKey:
    """Tests for is_valid_pem_public_key function"""

    def test_valid_pem_public_key(self, valid_rsa_key):
        """Valid PEM key returns True"""
        from app.validate import is_valid_pem_public_key

        assert is_valid_pem_public_key(valid_rsa_key) is True

    def test_invalid_pem_public_key(self, invalid_pem_key):
        """Invalid PEM key returns False"""
        from app.validate import is_valid_pem_public_key

        assert is_valid_pem_public_key(invalid_pem_key) is False

    def test_empty_pem_key(self):
        """Empty PEM returns False"""
        from app.validate import is_valid_pem_public_key

        assert is_valid_pem_public_key(b"") is False


# ============================================================================
# VALIDATE_DATE_FORMAT TESTS
# ============================================================================


class TestValidateDateFormat:
    """Tests for validate_date_format function"""

    def test_valid_date_format(self):
        """Correct format YYYY-MM-DD returns True"""
        from app.validate import validate_date_format

        assert validate_date_format("2025-10-27") is True

    def test_invalid_date_format_wrong_order(self):
        """Wrong order returns False"""
        from app.validate import validate_date_format

        assert validate_date_format("27-10-2025") is False

    def test_invalid_date_format_slashes(self):
        """Wrong separator returns False"""
        from app.validate import validate_date_format

        assert validate_date_format("2025/10/27") is False

    def test_invalid_date_format_non_date(self):
        """Non-date string returns False"""
        from app.validate import validate_date_format

        assert validate_date_format("invalid") is False

    def test_empty_date(self):
        """Empty string returns False"""
        from app.validate import validate_date_format

        assert validate_date_format("") is False
