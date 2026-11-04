###############################################################################
# Copyright (c) 2026 European Commission
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
"""Helpers building throw-away X.509 certificates and x5c chains for tests."""

import base64
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from app.utils.crypto import certificate_validity

NOW = datetime.datetime.now(datetime.timezone.utc)


def make_name(common_name):
    """Builds an X.509 name with only a common name."""
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def key_usage(*, ca):
    """Returns the usual ``keyUsage``: keyCertSign / cRLSign for a CA, digitalSignature otherwise."""
    return x509.KeyUsage(
        digital_signature=not ca,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=ca,
        crl_sign=ca,
        encipher_only=False,
        decipher_only=False,
    )


def make_cert(
    subject, issuer, public_key, signing_key, *, ca, not_before=None, not_after=None, usage="default", extensions=()
):
    """Creates a certificate for ``subject`` signed by ``signing_key`` as ``issuer``.

    ``usage`` is the ``keyUsage`` extension: ``"default"`` adds :func:`key_usage`,
    ``None`` omits it. ``extensions`` are extra ``(extension, critical)`` pairs.
    """
    builder = (
        x509.CertificateBuilder()
        .subject_name(make_name(subject))
        .issuer_name(make_name(issuer))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or NOW - datetime.timedelta(days=1))
        .not_valid_after(not_after or NOW + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if usage == "default":
        usage = key_usage(ca=ca)
    if usage is not None:
        builder = builder.add_extension(usage, critical=True)
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)
    return builder.sign(signing_key, hashes.SHA256())


def x5c(*certs):
    """Encodes certificates as an ``x5c`` header value (base64 DER, leaf first)."""
    return [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode() for c in certs]


def ca_entry(cert):
    """Builds a trusted CA store entry for ``app.core.state.trusted_CAs``."""
    not_valid_before, not_valid_after = certificate_validity(cert)
    return {
        "certificate": cert,
        "public_key": cert.public_key(),
        "not_valid_before": not_valid_before,
        "not_valid_after": not_valid_after,
    }
