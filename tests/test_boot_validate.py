import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from datetime import datetime, timedelta

from app.boot_validate import validate_cert_algo  # adjust if needed


def create_self_signed_cert(private_key, algo=hashes.SHA256()):
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=10))
        .sign(private_key, algo)
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def test_valid_ec_certificate():
    private_key = ec.generate_private_key(SECP256R1())
    pem = create_self_signed_cert(private_key)
    lalgo = {"ecdsa-with-SHA256": ["secp256r1", "secp384r1"]}
    result = validate_cert_algo(pem, lalgo)
    assert result == (True, "ecdsa-with-SHA256", "secp256r1")


def test_unsupported_algorithm():
    private_key = ec.generate_private_key(SECP256R1())
    pem = create_self_signed_cert(private_key)
    lalgo = {"sha384": ["secp256r1"]}
    result = validate_cert_algo(pem, lalgo)
    assert result == (False, "ecdsa-with-SHA256", "secp256r1")


def test_unsupported_curve():
    private_key = ec.generate_private_key(SECP256R1())
    pem = create_self_signed_cert(private_key)
    lalgo = {"ecdsa-with-SHA256": ["secp384r1"]}  # wrong curve
    result = validate_cert_algo(pem, lalgo)
    assert result == (False, "ecdsa-with-SHA256", "secp256r1")


def test_invalid_certificate_format():
    pem = b"-----BEGIN CERTIFICATE-----\nINVALIDDATA\n-----END CERTIFICATE-----"
    lalgo = {"ecdsa-with-SHA256": ["secp256r1"]}
    result = validate_cert_algo(pem, lalgo)
    assert result[0] is False
    assert result[2] == "unknown"


def test_rsa_certificate():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = create_self_signed_cert(private_key)
    lalgo = {"sha256WithRSAEncryption": []}
    result = validate_cert_algo(pem, lalgo)

    # RSA certs have no EC curve — function may raise or return unknown
    assert isinstance(result, tuple)
    assert result[1].startswith("sha256")
