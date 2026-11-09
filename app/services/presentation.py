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
"""Form data normalization and the consent-page ("presentation") view model.

:func:`form_formatter` turns the flat HTML form submitted by the user into
the nested attribute dict stored as the session's user data.
:func:`presentation_formatter` builds, per requested credential, the data
shown to the user before issuance.
"""

from __future__ import annotations

import base64
import datetime
import json
import re
from typing import Any, Collection, Dict, FrozenSet, Iterable, List, Mapping, Set, Tuple

from app.core.constants import IMAGE_ATTRIBUTES, ConfService as cfgserv
from app.core.state import oidc_metadata
from app.services.attributes import getAttributesForm, getAttributesForm2
from app.services.countries import issuing_country_code
from app.services.sca_card import CARD_FIELD, add_card_to_presentation
from app.utils.dates import calculate_age, format_date, to_rfc3339

_KEY_PARTS = re.compile(r"([^\[\]]+)")
_SKIPPED_FORM_KEYS = ("proceed", "Cancelled", "NumberCategories")
_SAMPLE_IMAGES = {"Port1": cfgserv.portrait1, "Port2": cfgserv.portrait2}
EHIC_CONFIGURATION = "eu.europa.ec.eudi.ehic_sd_jwt_vc"
SEAFARER_CONFIGURATION = "eu.europa.ec.eudi.seafarer_mdoc"
MDL_SCOPE = "org.iso.18013.5.1.mDL"
#: Largest list index accepted in a form key such as ``capacities[3][code]``.
MAX_FORM_INDEX = 99
#: Attribute names that carry the same value; :func:`form_formatter` copies
#: each one into the others, so protecting one name must protect all of them.
ATTRIBUTE_ALIASES: Tuple[FrozenSet[str], ...] = (
    frozenset({"birth_date", "birthdate"}),
    frozenset({"birth_place", "place_of_birth"}),
    frozenset({"nationality", "nationalities"}),
    frozenset({"portrait", "picture"}),
)


class InvalidFormError(ValueError):
    """Raised when a submitted attribute form is malformed."""


def _form_index(part: str) -> int:
    """Converts a bracketed list index of a form key, within bounds.

    Args:
        part: Digits from the key.

    Returns:
        The index.

    Raises:
        InvalidFormError: Above :data:`MAX_FORM_INDEX` (a huge index would
            allocate a huge list).
    """
    idx = int(part)
    if idx > MAX_FORM_INDEX:
        raise InvalidFormError(f"Form list index {idx} exceeds {MAX_FORM_INDEX}")
    return idx


def _set_nested(target: Dict[str, Any], key: str, value: Any) -> None:
    """Stores ``value`` at the path encoded in a bracketed form key.

    E.g. ``capacities[0][codes][1][code]`` becomes
    ``target["capacities"][0]["codes"][1]["code"]``.

    Args:
        target: Root dict (mutated).
        key: Bracketed form key.
        value: Value to store.

    Raises:
        InvalidFormError: If a list index is too large, or the key conflicts
            with another one (``a`` and ``a[0]``, ``a[0]`` and ``a[0][b]``).
    """
    parts = _KEY_PARTS.findall(key)
    if not parts:
        raise InvalidFormError("Form key without an attribute name")
    current: Any = target
    for part, next_part in zip(parts[:-1], parts[1:]):
        if part.isdigit() and isinstance(current, list):
            current = current[_list_slot(current, part, dict)]
        elif isinstance(current, dict):
            current = current.setdefault(part, [] if next_part.isdigit() else {})
        else:
            raise InvalidFormError(f"Form key {key!r} conflicts with another field")

    final_key = parts[-1]
    if final_key.isdigit() and isinstance(current, list):
        current[_list_slot(current, final_key, lambda: None)] = value
    elif isinstance(current, dict):
        current[final_key] = value
    else:
        raise InvalidFormError(f"Form key {key!r} conflicts with another field")


def _list_slot(items: List[Any], part: str, filler: Any) -> int:
    """Grows ``items`` up to a bracketed form key index and returns the index.

    Args:
        items: List being built (mutated).
        part: Digits from the key.
        filler: Factory of the values added to reach the index.

    Returns:
        The index.

    Raises:
        InvalidFormError: If the index is too large.
    """
    idx = _form_index(part)
    while len(items) <= idx:
        items.append(filler())
    return idx


def _merge_places_of_work(cleaned_data: Dict[str, Any]) -> None:
    """Merges the per-row ``places_of_work`` entries produced by the form parser.

    ``[{'no_fixed_place': [a]}, {'no_fixed_place': [b]}]`` becomes
    ``[{'no_fixed_place': [a, b]}]``.

    Args:
        cleaned_data: Parsed form data (mutated).
    """
    places = cleaned_data.get("places_of_work")
    if not isinstance(places, list):
        return
    aggregated: Dict[str, List[Any]] = {}
    for item in places:
        if isinstance(item, dict):
            for key, value_list in item.items():
                aggregated.setdefault(key, [])
                if isinstance(value_list, list):
                    aggregated[key].extend(value_list)
    if aggregated:
        cleaned_data["places_of_work"] = [aggregated]


def _fill_aliases(cleaned_data: Dict[str, Any]) -> None:
    """Fills the :data:`ATTRIBUTE_ALIASES` of the parsed form data.

    Nationalities become a list of country codes and places of birth a
    single object, under both names.

    Args:
        cleaned_data: Parsed form data (mutated).
    """
    for key in ("nationality", "nationalities"):
        values = cleaned_data.get(key)
        if isinstance(values, list) and values and isinstance(values[0], dict):
            country_codes = [item.get("country_code") for item in values if "country_code" in item]
            cleaned_data["nationality"] = country_codes
            cleaned_data["nationalities"] = country_codes
            break

    if isinstance(cleaned_data.get("birth_place"), list):
        cleaned_data["birth_place"] = cleaned_data["birth_place"][0]
        cleaned_data["place_of_birth"] = cleaned_data["birth_place"]
    if isinstance(cleaned_data.get("place_of_birth"), list):
        cleaned_data["place_of_birth"] = cleaned_data["place_of_birth"][0]
        cleaned_data["birth_place"] = cleaned_data["place_of_birth"]

    if "birth_date" in cleaned_data:
        cleaned_data["birthdate"] = cleaned_data["birth_date"]
    if "portrait" in cleaned_data:
        cleaned_data["picture"] = cleaned_data["portrait"]


def _resolve_form_choices(cleaned_data: Dict[str, Any]) -> None:
    """Replaces form choices (sample signature, ``age_over_18`` text) by values.

    Args:
        cleaned_data: Parsed form data (mutated).
    """
    for field in ("signature_usual_mark", "signature_usual_mark_issuing_officer"):
        if cleaned_data.get(field) == "Sig1":
            cleaned_data[field] = cfgserv.signature_usual_mark_issuing_officer

    match cleaned_data.get("age_over_18"):
        case "true":
            cleaned_data["age_over_18"] = True
        case "false":
            cleaned_data["age_over_18"] = False


def form_formatter(form_data: Dict[str, Any], issuing_country: str) -> Dict[str, Any]:
    """Normalizes a submitted attribute form into the session user data.

    Args:
        form_data: Flat form fields (``field[]`` already collected as lists,
            see :func:`app.utils.forms.parse_form`). Mutated.
        issuing_country: Country of the issuance session.

    Returns:
        The nested, normalized user data (with ``issuing_country``).

    Raises:
        InvalidFormError: If a field is malformed (bad date, conflicting keys).
    """
    if "effective_from_date" in form_data:
        try:
            form_data["effective_from_date"] = to_rfc3339(form_data["effective_from_date"])
        except (AttributeError, TypeError, ValueError) as e:
            raise InvalidFormError("effective_from_date is not a YYYY-MM-DD date") from e

    cleaned_data: Dict[str, Any] = {}
    # Sorted so parent structures (capacities[0]) are created before children.
    for key in sorted(form_data):
        value = form_data[key]
        if not value or key in _SKIPPED_FORM_KEYS:
            continue
        if "option" in key and "on" in value:
            continue
        _set_nested(cleaned_data, key, value)

    _merge_places_of_work(cleaned_data)
    _fill_aliases(cleaned_data)
    _resolve_form_choices(cleaned_data)

    # Sample image choices; anything else is the uploaded base64url image.
    final_data = {
        item: _SAMPLE_IMAGES.get(value, value) if item in IMAGE_ATTRIBUTES and isinstance(value, str) else value
        for item, value in cleaned_data.items()
    }
    final_data["issuing_country"] = issuing_country_code(issuing_country)
    return final_data


def form_key_root(key: str) -> str:
    """Returns the top-level attribute a form key writes to.

    Parsed as :func:`_set_nested` does, so ``[family_name]`` and
    ``family_name][x`` both name ``family_name``.

    Args:
        key: Form key, possibly bracketed.

    Returns:
        The attribute name, or ``""`` when the key has none.
    """
    parts = _KEY_PARTS.findall(key)
    return parts[0] if parts else ""


def with_aliases(names: Iterable[str]) -> Set[str]:
    """Extends attribute names with their aliases (see :data:`ATTRIBUTE_ALIASES`).

    Args:
        names: Attribute names.

    Returns:
        ``names`` plus every alias of each of them.
    """
    extended = set(names)
    for group in ATTRIBUTE_ALIASES:
        if extended & group:
            extended |= group
    return extended


def verified_form_formatter(
    form_data: Mapping[str, Any],
    verified: Mapping[str, Any],
    allowed: Collection[str],
    issuing_country: str,
) -> Dict[str, Any]:
    """Builds the user data of a session whose identity comes from a verified PID.

    The verified values of the form's attributes (or of their aliases) are
    the base and are never taken from the form. Only form fields whose
    attribute (see :func:`form_key_root`) is in ``allowed`` and is neither
    verified nor an alias of a verified attribute are added; the others are
    ignored, whatever their type or spelling.

    Args:
        form_data: Flat form fields (see :func:`app.utils.forms.parse_form`).
        verified: Attribute name -> value read from the verified PID.
        allowed: Attribute names of the form shown for the requested
            credentials (``getAttributesForm`` / ``getAttributesForm2``).
        issuing_country: Country of the issuance session.

    Returns:
        The normalized user data (see :func:`form_formatter`).

    Raises:
        InvalidFormError: If a kept form field is malformed.
    """
    protected = with_aliases(verified)
    user_fields = {
        key: value
        for key, value in form_data.items()
        if (root := form_key_root(key)) in allowed and root not in protected
    }
    cleaned_data = form_formatter(user_fields, issuing_country=issuing_country)

    # Every alias is filled, as form_formatter does (birthdate from birth_date...).
    bound = dict(verified)
    for group in ATTRIBUTE_ALIASES:
        source = next((name for name in sorted(group) if name in verified), None)
        if source is not None:
            bound.update({alias: verified[source] for alias in group - verified.keys()})
    # Only the form's attributes: PID metadata such as expiry_date or
    # issuing_authority must not reach the new credential.
    form_attributes = with_aliases(allowed)
    cleaned_data.update({name: value for name, value in bound.items() if name in form_attributes})
    cleaned_data["issuing_country"] = issuing_country_code(issuing_country)
    return cleaned_data


def _to_display_base64(value: str) -> str:
    """Converts base64url image data to standard base64 for display.

    Args:
        value: Base64url data.

    Returns:
        Standard base64 data.
    """
    return base64.b64encode(base64.urlsafe_b64decode(value)).decode("utf-8")


def _add_issuer_fields(
    data: Dict[str, Any], credential_requested: str, doctype_config: Dict[str, Any], country: str
) -> None:
    """Adds the issuer-filled attributes shown on the consent page.

    Args:
        data: Attributes shown for the credential (mutated).
        credential_requested: Credential configuration id.
        doctype_config: ``issuer_config`` of the credential.
        country: Issuing country.
    """
    today = datetime.date.today()
    data["estimated_issuance_date"] = format_date(today)
    data["estimated_expiry_date"] = format_date(today + datetime.timedelta(days=doctype_config["validity"]))
    data["issuing_country"] = issuing_country_code(country)

    if credential_requested == SEAFARER_CONFIGURATION:
        data["issuing_authority_logo"] = cfgserv.issuing_authority_logo

    if credential_requested == EHIC_CONFIGURATION:
        data["issuing_authority"] = {
            "id": doctype_config["issuing_authority_id"],
            "name": doctype_config["issuing_authority"],
        }
    else:
        data["issuing_authority"] = doctype_config["issuing_authority"]

    if "credential_type" in doctype_config:
        data["credential_type"] = doctype_config["credential_type"]


def _to_display_values(data: Dict[str, Any], scope: str) -> None:
    """Converts attribute values to their consent page form.

    Computes ``age_over_18``, decodes ``driving_privileges``, shows images as
    standard base64 and drops the mDL category helper fields.

    Args:
        data: Attributes shown for the credential (mutated).
        scope: Credential scope.
    """
    if "birth_date" in data and ("age_over_18" in data or scope == MDL_SCOPE):
        data["age_over_18"] = calculate_age(data["birth_date"]) >= 18

    if isinstance(data.get("driving_privileges"), str):
        data["driving_privileges"] = json.loads(data["driving_privileges"])

    for field in IMAGE_ATTRIBUTES:
        if field in data:
            data[field] = _to_display_base64(data[field])

    if "NumberCategories" in data:
        for i in range(1, int(data["NumberCategories"]) + 1):
            data.pop(f"IssueDate{i}")
            data.pop(f"ExpiryDate{i}")
        data.pop("NumberCategories")


def presentation_formatter(
    cleaned_data: Dict[str, Any],
    credentials_requested: Iterable[str],
    country: str,
    include_optional: bool = True,
) -> Dict[str, Dict[str, Any]]:
    """Builds the per-credential data shown on the consent page.

    Args:
        cleaned_data: User data (see :func:`form_formatter`).
        credentials_requested: Credential configuration ids.
        country: Issuing country.
        include_optional: Whether optional attributes are shown too.

    Returns:
        ``{credential display name: {attribute: value}}``.
    """
    credentials_supported = oidc_metadata["credential_configurations_supported"]
    presentation_data: Dict[str, Dict[str, Any]] = {}

    for credential_requested in credentials_requested:
        credential_config = credentials_supported[credential_requested]
        name = credential_config["credential_metadata"]["display"][0]["name"]

        shown_attributes = set(getAttributesForm([credential_requested]))
        if include_optional:
            shown_attributes |= set(getAttributesForm2([credential_requested]))
        data = {k: v for k, v in cleaned_data.items() if k in shown_attributes}

        _add_issuer_fields(data, credential_requested, credential_config["issuer_config"], country)
        # GRNET fork: the SCA card the user picked, see app.services.sca_card.
        add_card_to_presentation(data, credential_config["issuer_config"], cleaned_data.get(CARD_FIELD))
        _to_display_values(data, credential_config["scope"])
        presentation_data[name] = data

    return presentation_data
