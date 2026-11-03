# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
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
"""Runtime configuration loading for the PID Issuer.

The issuer is configured through a YAML file whose location is given by the
``ISSUER_CONFIG_PATH`` environment variable. Key and certificate paths found
in the file are resolved eagerly and their contents stored next to the path
(e.g. ``private_key_path`` -> ``private_key``) so that the rest of the code
base never touches the filesystem for key material.

When ``MOCK_CONFIGURATION`` is set (test / CI runs) a minimal in-memory
configuration is used instead.

Attributes:
    CONFIGURATION: The process-wide configuration dictionary.
    IS_TEST_ENV: ``True`` only when ``EUDIW_TEST_ENV=true`` is set.
"""

from __future__ import annotations

import os
import re
from typing import Any

import yaml
from dotenv import load_dotenv

load_dotenv()

DEFAULT_CONFIG_PATH = "/etc/issuer_config/config_issuer_backend.yaml"

#: ``${name}`` placeholder of a value defined in the ``variables`` section.
_PLACEHOLDER = re.compile(r"\$\{([A-Za-z0-9_]+)\}")
#: Frontend ids are a path segment of the frontend's authorization server issuer.
FRONTEND_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def _substitute(text: str, variables: dict[str, str]) -> str:
    """Replaces the ``${name}`` placeholders of ``text``.

    Args:
        text: String value of the configuration.
        variables: Resolved variables.

    Returns:
        ``text`` with every placeholder replaced by its variable.

    Raises:
        RuntimeError: If a placeholder names an undefined variable.
    """

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in variables:
            raise RuntimeError(f"Undefined config variable: ${{{name}}}")
        return variables[name]

    return _PLACEHOLDER.sub(replace, text)


def _interpolate(value: Any, variables: dict[str, str]) -> Any:
    """Substitutes the variables in every string of ``value``, recursively.

    Dictionaries and lists are rebuilt, so values shared through YAML aliases
    become independent copies.

    Args:
        value: Configuration value.
        variables: Resolved variables.

    Returns:
        The value with its placeholders replaced.
    """
    if isinstance(value, dict):
        return {key: _interpolate(item, variables) for key, item in value.items()}
    if isinstance(value, list):
        return [_interpolate(item, variables) for item in value]
    if isinstance(value, str):
        return _substitute(value, variables)
    return value


def resolve_variables(config: dict[str, Any]) -> dict[str, Any]:
    """Applies the top-level ``variables`` section to the configuration.

    ``variables`` maps names to strings; any string value of the
    configuration may then use ``${name}``, e.g.
    ``"${keys_dir}/PID-DS-0002_PT.pem"``. A variable may use the variables
    defined before it. The section is removed from the result.

    Args:
        config: Parsed YAML configuration.

    Returns:
        A new configuration with the placeholders replaced.

    Raises:
        RuntimeError: If ``variables`` is not a mapping of strings, or a
            placeholder names an undefined variable.
    """
    config = dict(config)
    raw = config.pop("variables", None) or {}
    if not isinstance(raw, dict):
        raise RuntimeError("Config section 'variables' must be a mapping")

    variables: dict[str, str] = {}
    for name, value in raw.items():
        if not isinstance(value, str):
            raise RuntimeError(f"Config variable '{name}' must be a string")
        variables[name] = _substitute(value, variables)

    return _interpolate(config, variables)


def _load_file(path: str) -> bytes:
    """Reads a file as raw bytes.

    Args:
        path: Filesystem path to read.

    Returns:
        The file contents.

    Raises:
        OSError: If the file cannot be read.
    """
    with open(path, "rb") as f:
        return f.read()


def _load_registration_certificate(frontend_id: str, path: str) -> str:
    """Reads the registration certificate (``rc-wrp+jwt``) of a frontend.

    Only the compact JWS form is checked; the signature and validity are
    for the wallet to verify.

    Args:
        frontend_id: Frontend the certificate belongs to (for errors).
        path: Text file holding the JWT.

    Returns:
        The JWT, surrounding whitespace removed.

    Raises:
        OSError: If the file cannot be read.
        RuntimeError: If the file does not hold a compact JWS.
    """
    try:
        token = _load_file(path).decode("ascii").strip()
    except UnicodeDecodeError as e:
        raise RuntimeError(f"Registration certificate of frontend {frontend_id} is not a JWT: {path}") from e
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise RuntimeError(f"Registration certificate of frontend {frontend_id} is not a JWT: {path}")
    return token


def process_config(config: dict[str, Any]) -> dict[str, Any]:
    """Loads all key/certificate files referenced by the configuration.

    For every frontend, the global ``keys`` section and every country key
    entry, the ``*_path`` value is read and the bytes are stored under the
    matching key without the ``_path`` suffix. A frontend's optional
    ``registration_certificate_path`` is stored as a string (the JWT).

    Args:
        config: Parsed YAML configuration. Mutated in place.

    Returns:
        The same ``config`` object, for convenience.

    Raises:
        OSError: If a referenced key or certificate file cannot be read.
        KeyError: If a mandatory section is missing.
        RuntimeError: If a registration certificate is not a JWT, or a
            frontend id is not a plain URL path segment.
    """
    for frontend_id, frontend in config["frontend"]["frontends_config"].items():
        # The id is the last path segment of the frontend's issuer at the
        # authorization server (<authorization_server.base_url>/<id>).
        if not isinstance(frontend_id, str) or not FRONTEND_ID_PATTERN.match(frontend_id):
            raise RuntimeError(f"Frontend id {frontend_id!r} may only contain letters, digits, '_' and '-'")
        frontend["metadata_signing_key"] = _load_file(frontend["metadata_signing_key_path"])
        frontend["metadata_access_certificate"] = _load_file(
            frontend["metadata_access_certificate_path"]
        )
        if frontend.get("registration_certificate_path"):
            frontend["registration_certificate"] = _load_registration_certificate(
                frontend_id, frontend["registration_certificate_path"]
            )

    keys = config["keys"]
    keys["nonce_key"] = _load_file(keys["nonce_path"])
    keys["credential_encryption_key"] = _load_file(keys["credential_request_path"])

    for country in config["countries"].values():
        # Each entry name is either "_default" or a frontend UUID.
        for entry in country["keys"].values():
            entry["private_key"] = _load_file(entry["private_key_path"])
            entry["certificate"] = _load_file(entry["certificate_path"])

    return config


def load_config(path: str | None = None) -> dict[str, Any]:
    """Reads and processes the issuer YAML configuration.

    Args:
        path: Explicit configuration path. Defaults to ``ISSUER_CONFIG_PATH``
            or :data:`DEFAULT_CONFIG_PATH`.

    Returns:
        The processed configuration dictionary.

    Raises:
        RuntimeError: If the file is missing, empty or not valid YAML, or
            uses an undefined variable.
    """
    config_path = path or os.environ.get("ISSUER_CONFIG_PATH", DEFAULT_CONFIG_PATH)
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
    except FileNotFoundError as e:
        raise RuntimeError(f"Config file not found: {config_path}") from e
    except yaml.YAMLError as e:
        raise RuntimeError(f"Invalid YAML in config: {e}") from e

    if not config:
        raise RuntimeError(f"Config file is empty: {config_path}")

    return process_config(resolve_variables(config))


def mock_config() -> dict[str, Any]:
    """Returns the minimal configuration used when ``MOCK_CONFIGURATION`` is set.

    Returns:
        A configuration dictionary sufficient to import the application
        (no database: background services are disabled in tests).
    """
    return {"expiry": {"session": 30}}


#: Environment variable that switches the test-environment defaults on.
TEST_ENV_VARIABLE = "EUDIW_TEST_ENV"


def _detect_test_env() -> bool:
    """Tells whether the process runs as a test environment.

    The test environment relaxes start-up checks (random session key, no
    trusted CAs, no background services), so it needs an explicit opt-in:
    generic variables such as ``CI``, which build and container platforms
    set, or the presence of pytest, do not enable it.

    Returns:
        ``True`` only for ``EUDIW_TEST_ENV=true``.
    """
    return os.getenv(TEST_ENV_VARIABLE) == "true"


CONFIGURATION: dict[str, Any] = mock_config() if os.getenv("MOCK_CONFIGURATION") else load_config()

IS_TEST_ENV: bool = _detect_test_env()


def feature_enabled(name: str) -> bool:
    """Tells whether a test-only feature is switched on.

    Test features (``test_features.<name>`` in the configuration) let a demo
    issuer accept self-asserted data. They are off unless set to ``true``.

    Args:
        name: Feature name, for example ``form_countries``.

    Returns:
        ``True`` only when the configuration sets the feature to ``true``.
    """
    features = CONFIGURATION.get("test_features") if isinstance(CONFIGURATION, dict) else None
    return isinstance(features, dict) and features.get(name) is True
