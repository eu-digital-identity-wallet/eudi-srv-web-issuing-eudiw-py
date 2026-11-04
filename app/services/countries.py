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
"""Connectors to the national identity providers used for user authentication.

A country is either a *form* country (``FC``, ``AV``, ``AV2``: the user
types the attributes) or a connector reached over OAuth 2.0 / OpenID
Connect (``connection_type`` ``oauth`` / ``openid`` in the configuration).

Attributes:
    FORM_COUNTRIES: Countries whose data is entered in the issuer form.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import requests

from app.core.config import CONFIGURATION
from app.core.log_utils import safe
from app.core.state import session_manager
from app.utils.http import DEFAULT_TIMEOUT

logger = logging.getLogger(__name__)

FORM_COUNTRIES = ("FC", "AV", "AV2")
_METADATA_TIMEOUT = 5

#: Default place of birth injected for connector countries that do not provide one.
OAUTH_BIRTH_PLACES = {
    "EU": "Brussels",
    "EE": "Tallinn",
    "CZ": "Prague",
    "NL": "Amsterdam",
    "LU": "Luxembourg",
    "PT": "Lisbon",
}
OPENID_BIRTH_PLACES = {
    "EE": "Tallinn",
    "CZ": "Prague",
    "NL": "Amsterdam",
    "LU": "Luxembourg",
}


class CountryConnectorError(ValueError):
    """Raised when a country identity provider cannot be used."""


def is_form_country(country: str) -> bool:
    """Tells whether the user enters the attributes of ``country`` in a form.

    Args:
        country: Country code.

    Returns:
        ``True`` for ``FC``, ``AV`` and ``AV2``.
    """
    return country in FORM_COUNTRIES


def country_config(country: str) -> Dict[str, Any]:
    """Returns the configuration of a country.

    Args:
        country: Country code.

    Returns:
        ``CONFIGURATION["countries"][country]``.

    Raises:
        KeyError: If the country is not configured.
    """
    return CONFIGURATION["countries"][country]


def issuing_country_code(country: str) -> str:
    """Returns the ISO 3166-1 alpha-2 code written in credentials of ``country``.

    The session country is a configuration key (``FC`` for the FormEU form);
    the ``issuing_country`` claim must instead match the ``countryName`` of
    the document signer certificate (ISO/IEC 18013-5), set per country with
    ``issuing_country`` in the configuration.

    Args:
        country: Country configuration key.

    Returns:
        The configured ``issuing_country``, else ``country`` itself.
    """
    return ((CONFIGURATION.get("countries") or {}).get(country) or {}).get("issuing_country", country)


def fetch_well_known(base_url: str, document: str) -> Dict[str, Any]:
    """GETs ``<base_url>/.well-known/<document>``.

    Args:
        base_url: Identity provider base URL.
        document: Metadata document name.

    Returns:
        The JSON document.

    Raises:
        requests.RequestException: On network errors.
    """
    return requests.get(f"{base_url}/.well-known/{document}", timeout=DEFAULT_TIMEOUT).json()


def get_metadata(base_url: str) -> Dict[str, Any]:
    """Discovers OAuth / OIDC metadata that contains a ``token_endpoint``.

    ``oauth-authorization-server`` is tried before ``openid-configuration``.

    Args:
        base_url: Identity provider base URL.

    Returns:
        The first metadata document that has a ``token_endpoint``.

    Raises:
        ValueError: If no usable metadata is found.
    """
    for document in ("oauth-authorization-server", "openid-configuration"):
        url = f"{base_url}/.well-known/{document}"
        try:
            res = requests.get(url, timeout=_METADATA_TIMEOUT)
            if res.status_code == 200:
                data = res.json()
                if "token_endpoint" in data:
                    logger.debug(f"Discovered IdP metadata at {url}")
                    return data
        except Exception as e:
            logger.exception(f"Metadata fetch failed for {safe(url)}: {safe(e)}")
    raise ValueError("No valid OAuth/OIDC metadata found")


def openid_authorization_url(country: str, state: str) -> str:
    """Builds the OIDC authorization request URL of a country.

    Args:
        country: Country code (``connection_type: openid``).
        state: Random OAuth ``state``, checked on the redirect back.

    Returns:
        The authorization URL.
    """
    auth = country_config(country)["auth"]
    authorization_endpoint = fetch_well_known(auth["base_url"], "openid-configuration")["authorization_endpoint"]
    return (
        f"{authorization_endpoint}?redirect_uri={auth['redirect_uri']}&scope={auth['scope']}"
        f"&state={state}&response_type={auth['response_type']}&client_id={auth['client_id']}"
    )


def generate_connector_authorization_url(
    oauth_data: Dict[str, Any], country: str, credentials_requested: List[str], state: str
) -> str:
    """Builds the OAuth authorization request URL of a connector country.

    Args:
        oauth_data: The country's ``auth`` configuration.
        country: Country code, sent as ``entity``.
        credentials_requested: Requested credentials; the first is sent as scope.
        state: OAuth ``state`` value.

    Returns:
        The authorization URL.
    """
    authorization_endpoint = fetch_well_known(oauth_data.get("base_url"), "oauth-authorization-server")[
        "authorization_endpoint"
    ]
    params = {
        "client_id": oauth_data["client_id"],
        "redirect_uri": oauth_data["redirect_uri"],
        "response_type": "code",
        "scope": credentials_requested[0],
        "state": state,
        "entity": country,
    }
    return f"{authorization_endpoint}?{urlencode(params)}"


def _client_authorization(auth: Dict[str, Any]) -> str:
    """Builds the HTTP Basic client authentication header value.

    Args:
        auth: Country ``auth`` configuration with ``client_id`` and
            ``client_secret`` (which may already be a ``Basic ...`` value).

    Returns:
        The ``Authorization`` header value.

    Raises:
        CountryConnectorError: If the client credentials are missing.
    """
    client_id = auth.get("client_id")
    client_secret = auth.get("client_secret")
    if not client_id or not client_secret:
        raise CountryConnectorError("Missing client_id or client_secret in auth config")
    if client_secret.startswith("Basic "):
        return client_secret
    return "Basic " + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()


def exchange_authorization_code(country: str, code: str) -> str:
    """Exchanges an authorization code for an access token at the country IdP.

    Args:
        country: Country code.
        code: Authorization code.

    Returns:
        The access token.

    Raises:
        CountryConnectorError: If ``auth`` / client credentials are missing
            or the token request fails.
        ValueError: If no metadata can be discovered.
    """
    config = country_config(country)
    if "auth" not in config:
        raise CountryConnectorError("Missing 'auth' configuration for country")
    auth = config["auth"]

    token_endpoint = get_metadata(auth["base_url"])["token_endpoint"]
    headers = {**auth.get("token_endpoint_headers", {}), "Authorization": _client_authorization(auth)}
    params = {"grant_type": "authorization_code", "code": code, "redirect_uri": auth["redirect_uri"]}

    try:
        response = requests.post(token_endpoint, data=params, headers=headers, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        access_token = response.json().get("access_token")
    except requests.exceptions.RequestException as e:
        logger.exception(f"An error occurred: {safe(e)}")
        raise CountryConnectorError("Token request to the country identity provider failed") from e

    if not access_token:
        raise CountryConnectorError("Country identity provider returned no access token")
    return access_token


def _apply_custom_modifiers(country: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Renames IdP attributes according to the country's ``custom_modifiers``.

    Args:
        country: Country code.
        data: IdP user info (mutated: renamed keys are removed).

    Returns:
        ``{issuer_attribute: value}`` for the renamed attributes.
    """
    modifiers = country_config(country).get("custom_modifiers", {}).get("_default", {})
    renamed = {}
    for target, source in modifiers.items():
        if source in data:
            renamed[target] = data.pop(source)
    return renamed


def _add_country_defaults(country: str, data: Dict[str, Any], birth_places: Dict[str, str]) -> None:
    """Adds nationality and default place-of-birth claims.

    Args:
        country: Country code.
        data: User data (mutated).
        birth_places: Default birth place per country.
    """
    data["nationality"] = [country]
    data["nationalities"] = [country]
    if country in birth_places:
        data["birth_place"] = birth_places[country]
        data["place_of_birth"] = [{"locality": birth_places[country]}]


def _collect_oauth(country: str, access_token: str) -> Dict[str, Any]:
    """Fetches and maps the user info of an OAuth connector country.

    Args:
        country: Country code.
        access_token: IdP access token.

    Returns:
        The mapped user data.

    Raises:
        CountryConnectorError: If the user info request fails.
    """
    metadata = fetch_well_known(country_config(country)["auth"]["base_url"], "oauth-authorization-server")
    try:
        response = requests.get(
            metadata["userinfo_endpoint"],
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=DEFAULT_TIMEOUT,
        )
        response.raise_for_status()
        user_data = response.json()
    except requests.exceptions.RequestException as e:
        logger.exception(f"An error occurred while fetching user data: {safe(e)}")
        raise CountryConnectorError("Failed to fetch user data from the country identity provider") from e

    if country != "PT":
        cleaned = _apply_custom_modifiers(country, user_data)
    else:
        # PT returns a list of {name, value, state} attributes.
        modifiers = country_config(country).get("custom_modifiers", {}).get("_default", {})
        cleaned = {
            modifiers[attribute["name"]]: attribute["value"]
            for attribute in user_data
            if attribute["state"] == "Available" and attribute["name"] in modifiers
        }

    logger.debug(f"OAuth user info for {country}: fields {sorted(cleaned)}")
    _add_country_defaults(country, cleaned, OAUTH_BIRTH_PLACES)
    return cleaned


def _collect_openid(country: str, access_token: str) -> Dict[str, Any]:
    """Fetches and maps the user info of an OpenID Connect connector country.

    Args:
        country: Country code.
        access_token: IdP access token.

    Returns:
        The mapped user data.

    Raises:
        CountryConnectorError: If the user info request fails.
    """
    auth = country_config(country)["auth"]
    userinfo_endpoint = get_metadata(auth["base_url"])["userinfo_endpoint"]
    headers = dict(auth.get("authorization_headers", {}))

    if country == "EE":
        url = f"{userinfo_endpoint}?access_token={access_token}"
    else:
        url = userinfo_endpoint
        headers["Authorization"] = f"Bearer {access_token}"

    try:
        data = json.loads(requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT).text)
    except Exception as e:
        raise CountryConnectorError("openid connection failed") from e

    data.update(_apply_custom_modifiers(country, data))
    logger.debug(f"OpenID user info for {country}: fields {safe(sorted(data), 500)}")
    _add_country_defaults(country, data, OPENID_BIRTH_PLACES)
    return data


def collect_user_data(country: str, session_id: str, access_token: Optional[str]) -> Dict[str, Any]:
    """Returns the user attributes for the selected country and stores them.

    Form countries return the data already stored in the session; connector
    countries query their IdP and the result is saved as the session's
    user data.

    Args:
        country: Country code.
        session_id: Issuance session.
        access_token: IdP access token (connector countries).

    Returns:
        The user data, or ``{"error", "error_description"}`` when a form
        country has no data.

    Raises:
        CountryConnectorError: If the connector fails or is unsupported.
    """
    if is_form_country(country):
        data = session_manager.get_session(session_id=session_id).user_data
        if data == "Data not found":
            return {"error": "error", "error_description": "Data not found"}
        return data

    match country_config(country)["connection_type"]:
        case "oauth":
            data = _collect_oauth(country, access_token)
        case "openid":
            data = _collect_openid(country, access_token)
        case _:
            raise CountryConnectorError("Not supported")

    session_manager.update_user_data(session_id=session_id, user_data=data)
    return data
