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
"""Lookup helpers for the frontend configuration section."""

from __future__ import annotations

from typing import Any, List, Optional
from urllib.parse import urlsplit

from app.core.config import CONFIGURATION


def frontend_config(frontend_id: Optional[str] = None) -> dict[str, Any]:
    """Returns the configuration block of a frontend.

    Args:
        frontend_id: Frontend identifier; the default frontend when falsy.

    Returns:
        The ``frontend.frontends_config[<id>]`` mapping.

    Raises:
        KeyError: If the frontend is not configured.
    """
    frontends = CONFIGURATION["frontend"]
    return frontends["frontends_config"][frontend_id or frontends["default"]]


def frontend_url(frontend_id: Optional[str] = None) -> str:
    """Returns the base URL of a frontend.

    Args:
        frontend_id: Frontend identifier; the default frontend when falsy.

    Returns:
        The frontend base URL.

    Raises:
        KeyError: If the frontend is not configured.
    """
    return frontend_config(frontend_id)["url"]


def _origin(url: str) -> Optional[str]:
    """Returns the ``scheme://host[:port]`` origin of a URL.

    Args:
        url: Absolute URL.

    Returns:
        The origin, or ``None`` for relative / malformed URLs.
    """
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else None


def allowed_cors_origins() -> List[str]:
    """Lists the browser origins allowed to call the backend cross-origin.

    The origins of every configured frontend URL, plus any extra origins in
    the optional ``cors_allowed_origins`` configuration list.

    Returns:
        Sorted, de-duplicated origins (empty when nothing is configured).
    """
    frontends = (CONFIGURATION.get("frontend") or {}).get("frontends_config") or {}
    urls = [cfg.get("url", "") for cfg in frontends.values()]
    urls += CONFIGURATION.get("cors_allowed_origins") or []
    return sorted({origin for origin in map(_origin, urls) if origin})


def frontend_origins() -> List[str]:
    """Lists the origins of the configured frontend URLs.

    Returns:
        Sorted, de-duplicated origins.
    """
    frontends = (CONFIGURATION.get("frontend") or {}).get("frontends_config") or {}
    return sorted({origin for origin in (_origin(cfg.get("url", "")) for cfg in frontends.values()) if origin})


def is_frontend_url(url: str) -> bool:
    """Tells whether ``url`` is on the origin of a configured frontend.

    Args:
        url: Absolute URL.

    Returns:
        ``True`` when its scheme and host match a frontend URL.
    """
    return bool(url) and _origin(url) in frontend_origins()


def frontend_id_for_url(url: str) -> Optional[str]:
    """Finds the frontend whose base URL ``url`` lies under.

    Args:
        url: Absolute URL, e.g. ``<frontend url>/display_form``.

    Returns:
        The id of the frontend with the longest matching base URL (ties go to
        the smallest id), or ``None`` when no frontend URL is a prefix of ``url``.
    """
    frontends = (CONFIGURATION.get("frontend") or {}).get("frontends_config") or {}
    matches = [
        (len(base), frontend_id)
        for frontend_id, cfg in frontends.items()
        if (base := str(cfg.get("url") or "").rstrip("/")) and (url == base or url.startswith(base + "/"))
    ]
    if not matches:
        return None
    longest = max(length for length, _ in matches)
    return min(frontend_id for length, frontend_id in matches if length == longest)
