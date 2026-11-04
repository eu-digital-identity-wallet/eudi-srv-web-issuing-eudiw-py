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
"""QR code helpers."""

from __future__ import annotations

import base64
import io

import segno


def qr_png_base64(content: str, scale: int = 3) -> str:
    """Renders ``content`` as a PNG QR code and base64-encodes it.

    Args:
        content: Text to encode (usually a URL).
        scale: Pixel size of each QR module.

    Returns:
        Standard base64 PNG data (no ``data:`` prefix).
    """
    out = io.BytesIO()
    segno.make(content).save(out, kind="png", scale=scale)
    return base64.b64encode(out.getvalue()).decode("utf-8")


def qr_data_uri(content: str, scale: int = 3) -> str:
    """Renders ``content`` as a PNG QR code embedded in a data URI.

    Args:
        content: Text to encode (usually a URL).
        scale: Pixel size of each QR module.

    Returns:
        ``data:image/png;base64,...`` string.
    """
    return "data:image/png;base64," + qr_png_base64(content, scale)
