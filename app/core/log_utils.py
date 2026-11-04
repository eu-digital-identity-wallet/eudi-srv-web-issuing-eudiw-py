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
"""Helpers to log request data safely.

* :func:`safe` neutralizes log injection (CR / LF and other control
  characters) and bounds the length of any value taken from a request.
* :func:`summarize_credential_request` describes a credential request by
  its shape (configuration id, proof types and counts, encryption) without
  logging proofs, keys or tokens.

Personal data, tokens, proofs, pre-authorized codes and transaction codes must
never be logged; log identifiers and outcomes instead.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

DEFAULT_LIMIT = 200

#: Control characters left after CR / LF / TAB are escaped.
_OTHER_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def safe(value: Any, limit: int = DEFAULT_LIMIT) -> str:
    """Renders a value for a log line without allowing log injection.

    Args:
        value: Any value (typically request-supplied).
        limit: Maximum number of characters kept.

    Returns:
        A single-line string: CR / LF / TAB are escaped, other control
        characters replaced by ``?``, and long values truncated with the
        number of omitted characters.
    """
    # Line breaks first, with str.replace: no request value can start a new log line.
    text = str(value).replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    text = _OTHER_CONTROL_CHARS.sub("?", text)
    if len(text) > limit:
        return f"{text[:limit]}...(+{len(text) - limit} chars)"
    return text


def summarize_credential_request(credential_request: Any) -> str:
    """Describes a credential request without secrets.

    Args:
        credential_request: Parsed credential request.

    Returns:
        E.g. ``config=eu.europa.ec.eudi.pid_mdoc proofs=jwt:3 encrypted_response=True``.
    """
    if not isinstance(credential_request, Mapping):
        return f"<{type(credential_request).__name__}>"

    config_id = credential_request.get("credential_configuration_id") or credential_request.get(
        "credential_identifier"
    )
    if isinstance(credential_request.get("proofs"), Mapping):
        proofs = ",".join(
            f"{proof_type}:{len(values) if isinstance(values, list) else 1}"
            for proof_type, values in credential_request["proofs"].items()
        )
    elif isinstance(credential_request.get("proof"), Mapping):
        proofs = f"{credential_request['proof'].get('proof_type')}:1"
    else:
        proofs = "none"
    return (
        f"config={safe(config_id, 100)} proofs={safe(proofs, 100)} "
        f"encrypted_response={'credential_response_encryption' in credential_request}"
    )
