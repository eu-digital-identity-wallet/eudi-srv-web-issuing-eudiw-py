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
"""HTTP helpers: URL building and browser POST-redirects.

The auto-submit page posts a ``payload`` (JSON) to a frontend ``/display_*``
route. When the frontend has a ``payload_key`` (``frontends_config.<id>``, a
shared secret of at least :data:`PAYLOAD_KEY_MIN_LENGTH` characters), the
page also posts ``payload_jwt``: an HS256 JWS over
``{"payload", "aud": <frontend id>, "iat", "exp"}`` the frontend verifies to
know the payload comes from the backend.

Attributes:
    DEFAULT_TIMEOUT: Timeout (seconds) applied to outgoing HTTP calls.
    PAYLOAD_JWT_LIFETIME_SECONDS: Lifetime of a ``payload_jwt``.
"""

from __future__ import annotations

import base64
import hashlib
import json as std_json
import logging
import time
import urllib.parse
from typing import Any, Mapping, Optional, Set

import jwt
from flask import json, render_template_string

from app.utils.frontend import frontend_config, frontend_id_for_url, is_frontend_url

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30

PAYLOAD_JWT_LIFETIME_SECONDS = 300
PAYLOAD_JWT_ALGORITHM = "HS256"
#: Shortest accepted ``payload_key`` (HS256 needs a key of at least 256 bits).
PAYLOAD_KEY_MIN_LENGTH = 32
#: Frontends already warned about for having no ``payload_key``.
_unsigned_frontends_warned: Set[str] = set()

#: Inline script of the auto-submit page; allowed by its hash in the CSP.
AUTO_SUBMIT_SCRIPT = "document.getElementById('redirect_form').submit();"
#: CSP ``script-src`` source matching :data:`AUTO_SUBMIT_SCRIPT`.
AUTO_SUBMIT_SCRIPT_HASH = "'sha256-" + base64.b64encode(hashlib.sha256(AUTO_SUBMIT_SCRIPT.encode()).digest()).decode() + "'"

# ``data`` and ``url`` are autoescaped: render_template_string always escapes,
# and the attribute values are double-quoted.
_AUTO_SUBMIT_HTML = (
    """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Redirecting...</title>
        <style>
            body { margin: 0; padding: 0; overflow: hidden; }
            #redirect_form { display: none; }
        </style>
    </head>
    <body>
        <form id="redirect_form" method="POST" action="{{ url }}">
            <input type="hidden" name="payload" value="{{ data }}">
            {% if payload_jwt %}<input type="hidden" name="payload_jwt" value="{{ payload_jwt }}">{% endif %}
            <noscript>
                <div style="font-family: sans-serif; padding: 20px; text-align: center;">
                    <p>JavaScript is required. Please click the button below:</p>
                    <button type="submit" style="padding: 10px 20px; background-color: #007bff; color: white; border: none; border-radius: 6px; cursor: pointer;">
                        Continue
                    </button>
                </div>
            </noscript>
        </form>
        <script>"""
    + AUTO_SUBMIT_SCRIPT
    + """</script>
    </body>
    </html>
    """
)


def url_get(url_path: str, args: Mapping[str, Any]) -> str:
    """Builds the URL of an HTTP GET query.

    Args:
        url_path: URL without query string.
        args: Query parameters.

    Returns:
        ``url_path?<urlencoded args>``.
    """
    return url_path + "?" + urllib.parse.urlencode(args)


def frontend_payload_key(frontend_id: str) -> Optional[str]:
    """Returns the key that signs the display payloads of a frontend.

    Args:
        frontend_id: Frontend identifier.

    Returns:
        ``frontends_config.<frontend_id>.payload_key``, or ``None`` when unset.

    Raises:
        ValueError: If the key is set but not a string of at least
            :data:`PAYLOAD_KEY_MIN_LENGTH` characters.
    """
    key = frontend_config(frontend_id).get("payload_key")
    if key is None or key == "":
        return None
    if not isinstance(key, str) or len(key) < PAYLOAD_KEY_MIN_LENGTH:
        raise ValueError(
            f"frontends_config.{frontend_id}.payload_key must be at least {PAYLOAD_KEY_MIN_LENGTH} characters"
        )
    return key


def sign_display_payload(frontend_id: str, payload_json: str) -> Optional[str]:
    """Signs a display payload for the frontend that will receive it.

    Args:
        frontend_id: Receiving frontend (the ``aud`` claim).
        payload_json: The exact JSON posted in the ``payload`` field.

    Returns:
        The compact HS256 JWS, or ``None`` when the frontend has no
        ``payload_key`` (logged once per frontend).

    Raises:
        ValueError: If the configured key is too short.
    """
    key = frontend_payload_key(frontend_id)
    if key is None:
        if frontend_id not in _unsigned_frontends_warned:
            _unsigned_frontends_warned.add(frontend_id)
            logger.warning(f"Frontend {frontend_id} has no payload_key: display payloads are posted unsigned")
        return None
    now = int(time.time())
    claims = {
        "payload": std_json.loads(payload_json),
        "aud": frontend_id,
        "iat": now,
        "exp": now + PAYLOAD_JWT_LIFETIME_SECONDS,
    }
    return jwt.encode(claims, key.encode("utf-8"), algorithm=PAYLOAD_JWT_ALGORITHM, headers={"typ": "JWT"})


def post_redirect_with_payload(target_url: str, data_payload: Mapping[str, Any]) -> str:
    """Renders an auto-submitting HTML form that POSTs ``data_payload``.

    This simulates an HTTP POST redirect, passing a JSON payload to another
    service without hitting URL length limits. Every frontend display page is
    rendered here, so every one gets a ``payload_jwt`` when the receiving
    frontend (found from ``target_url``) has a ``payload_key``.

    Args:
        target_url: URL the browser should be POSTed to.
        data_payload: Dictionary serialized as JSON into the ``payload`` field.

    Returns:
        The rendered intermediate HTML page.

    Raises:
        ValueError: If ``target_url`` is not on a configured frontend, or that
            frontend's ``payload_key`` is too short.
    """
    if not is_frontend_url(target_url):
        raise ValueError(f"POST-redirect target is not a configured frontend: {target_url}")
    payload_json = json.dumps(data_payload)
    frontend_id = frontend_id_for_url(target_url)
    if frontend_id is None:
        logger.warning(f"POST-redirect target is under no frontend URL, payload not signed: {target_url}")
        payload_jwt = None
    else:
        payload_jwt = sign_display_payload(frontend_id, payload_json)
    return render_template_string(_AUTO_SUBMIT_HTML, url=target_url, data=payload_json, payload_jwt=payload_jwt)
