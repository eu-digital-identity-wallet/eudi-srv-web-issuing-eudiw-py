# coding: latin-1
###############################################################################
# Copyright (c) 2025 European Commission
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
"""Base64 / base64url helpers shared across the code base."""

from __future__ import annotations

import base64
import re

_B64URL_CHARS = re.compile(r"[A-Za-z0-9\-_]*")
_B64_CHARS = re.compile(r"[A-Za-z0-9+/]*={0,2}")


def _pad(data: str) -> str:
    """Appends the ``=`` padding required to decode ``data``.

    Args:
        data: Unpadded (or padded) base64 text.

    Returns:
        ``data`` with the correct amount of padding.
    """
    return data + "=" * (-len(data) % 4)


def urlsafe_b64encode_nopad(data: bytes) -> str:
    """Encodes bytes as URL-safe base64 without padding.

    Args:
        data: The data to encode.

    Returns:
        Base64url text without trailing ``=``.
    """
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def b64url_decode(data: str) -> bytes:
    """Decodes base64url data, adding missing padding.

    Args:
        data: Base64url text, with or without padding.

    Returns:
        The decoded bytes.

    Raises:
        binascii.Error: If ``data`` is not valid base64.
    """
    return base64.urlsafe_b64decode(_pad(data))


def b64url_decode_strict(data: str) -> bytes:
    """Decodes base64url data after validating its alphabet.

    Args:
        data: Unpadded base64url text.

    Returns:
        The decoded bytes.

    Raises:
        ValueError: If ``data`` contains characters outside the base64url
            alphabet or cannot be decoded.
    """
    if not _B64URL_CHARS.fullmatch(data):
        raise ValueError("Invalid base64url characters in input")
    try:
        return base64.urlsafe_b64decode(_pad(data))
    except Exception as e:
        raise ValueError(f"Invalid base64 data: {e}") from e


def b64_decode_x5c(data: str) -> bytes:
    """Decodes a standard-base64 ``x5c`` certificate entry after validation.

    Args:
        data: Standard base64 DER certificate.

    Returns:
        The DER bytes.

    Raises:
        ValueError: If ``data`` is not valid standard base64.
    """
    if not _B64_CHARS.fullmatch(data):
        raise ValueError("Invalid base64 characters in x5c certificate")
    try:
        return base64.b64decode(_pad(data))
    except Exception as e:
        raise ValueError(f"Invalid base64 in x5c: {e}") from e


def int_to_bytes(value: int, length: int | None = None) -> bytes:
    """Encodes a non-negative integer as big-endian bytes.

    Args:
        value: Integer to encode.
        length: Fixed output length; defaults to the minimal length.

    Returns:
        Big-endian byte string.
    """
    return value.to_bytes(length or (value.bit_length() + 7) // 8, "big")


def b64url_uint(value: int, length: int | None = None) -> str:
    """Encodes an integer as an unpadded base64url string (JWK style).

    Args:
        value: Integer to encode.
        length: Fixed byte length; defaults to the minimal length.

    Returns:
        Base64url text without padding.
    """
    return urlsafe_b64encode_nopad(int_to_bytes(value, length))
