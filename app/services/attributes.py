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
"""Credential metadata lookups and form-attribute extraction.

Everything in this module is derived from
``oidc_metadata["credential_configurations_supported"]``: which attributes a
user must / may fill in for the requested credentials, which are filled by
the issuer, and translations between configuration ids, ``vct``, doctype and
scope.

Attribute form entries have the shape::

    {"type": <value_type>, "filled_value": None, ["mandatory": True],
     ["cardinality": {...}], ["attributes": <nested>], ...}
"""

from __future__ import annotations

import copy
import logging
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from app.core.state import oidc_metadata

logger = logging.getLogger(__name__)

Claim = Dict[str, Any]
AttributesForm = Dict[str, Any]

MDOC_FORMAT = "mso_mdoc"
SDJWT_FORMAT = "dc+sd-jwt"

# Fixed sub-attribute definitions used for SD-JWT ``nationalities`` / ``place_of_birth``.
_NATIONALITIES_ATTRIBUTES = [
    {"country_code": {"mandatory": True, "type": "string", "source": "user"}}
]
_PLACE_OF_BIRTH_ATTRIBUTES = [
    {"country": {"mandatory": False, "type": "string", "source": "user"}},
    {"region": {"mandatory": False, "type": "string", "source": "user"}},
    {"locality": {"mandatory": False, "type": "string", "source": "user"}},
]


# ---------------------------------------------------------------------------
# Metadata lookups
# ---------------------------------------------------------------------------


def _credentials_supported() -> Dict[str, Dict[str, Any]]:
    """Returns the supported credential configurations.

    Returns:
        ``credential_configuration_id -> configuration``.
    """
    return oidc_metadata["credential_configurations_supported"]


def _find_credential(predicate: Callable[[Dict[str, Any]], bool]) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Finds the first credential configuration matching ``predicate``.

    Args:
        predicate: Test applied to each configuration.

    Returns:
        ``(configuration_id, configuration)`` or ``None``.
    """
    return next(((cid, c) for cid, c in _credentials_supported().items() if predicate(c)), None)


def _by_vct(vct: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Finds the credential configuration with the given ``vct``.

    Args:
        vct: Verifiable credential type.

    Returns:
        ``(configuration_id, configuration)`` or ``None``.
    """
    return _find_credential(lambda c: c.get("vct") == vct)


def vct2id(vct: str) -> Optional[str]:
    """Translates a ``vct`` into its credential configuration id.

    Args:
        vct: Verifiable credential type.

    Returns:
        The configuration id, or ``None``.
    """
    found = _by_vct(vct)
    return found[0] if found else None


def scope2details(scope: Iterable[str]) -> List[Any]:
    """Generates authorization details from a list of scopes.

    Args:
        scope: Requested scopes.

    Returns:
        ``["openid"]`` (when absent from ``scope``) followed by
        ``{"credential_configuration_id": id}`` for each configuration
        whose scope was requested.
    """
    configuration_ids: List[Any] = [] if "openid" in scope else ["openid"]
    credentials = _credentials_supported()
    for item in scope:
        if item == "openid":
            continue
        configuration_ids.extend(
            {"credential_configuration_id": cid}
            for cid, c in credentials.items()
            if c.get("scope") == item
        )
    return configuration_ids


def requested_credential_ids(
    authorization_details: Iterable[Dict[str, Any]],
    resolve_vct: Optional[Callable[[str], Optional[str]]] = None,
) -> List[Any]:
    """Lists the distinct credentials requested in authorization details.

    Args:
        authorization_details: ``openid_credential`` authorization details.
        resolve_vct: Optional translation applied to ``vct`` entries (e.g.
            :func:`vct2id`); ``vct`` values are kept as-is when ``None``.

    Returns:
        Credential configuration ids (or ``vct`` values), in request order.
    """
    requested: List[Any] = []
    for detail in authorization_details:
        if "credential_configuration_id" in detail:
            candidate = detail["credential_configuration_id"]
        elif "vct" in detail:
            candidate = resolve_vct(detail["vct"]) if resolve_vct else detail["vct"]
        else:
            continue
        if candidate not in requested:
            requested.append(candidate)
    return requested


def credential_display_names(
    include: Callable[[str, Dict[str, Any]], bool] = lambda cid, cfg: True,
) -> Dict[str, Dict[str, str]]:
    """Groups the display names of supported credentials by format.

    Args:
        include: Filter receiving ``(configuration_id, configuration)``.

    Returns:
        ``{"sd-jwt vc format": {id: name}, "mdoc format": {id: name}}``.
    """
    groups = {SDJWT_FORMAT: "sd-jwt vc format", MDOC_FORMAT: "mdoc format"}
    credentials: Dict[str, Dict[str, str]] = {label: {} for label in groups.values()}
    for cid, cfg in _credentials_supported().items():
        label = groups.get(cfg["format"])
        if label and include(cid, cfg):
            credentials[label][cid] = cfg["credential_metadata"]["display"][0]["name"]
    return credentials


# ---------------------------------------------------------------------------
# Form attributes
# ---------------------------------------------------------------------------


def _nested_attributes_source(conditions: Dict[str, Any], parent_value_type: Optional[str]) -> Any:
    """Finds the sub-attribute definitions inside ``issuer_conditions``.

    Args:
        conditions: ``issuer_conditions`` of a claim.
        parent_value_type: ``value_type`` of the parent claim.

    Returns:
        The definitions (dict or list), or ``None`` when there are none.
    """
    attr_key = (
        parent_value_type
        if parent_value_type in conditions
        else next((k for k in conditions if k.endswith("_attributes")), None)
    )
    if attr_key:
        return conditions.get(attr_key, {})
    # e.g. 'driving_privileges', which contains the attributes directly.
    if any(isinstance(v, dict) and "value_type" in v for v in conditions.values()):
        return conditions
    return None


def _nested_attribute_entry(value: Dict[str, Any]) -> Dict[str, Any]:
    """Builds the form entry of one nested attribute definition.

    Args:
        value: Attribute definition (with ``value_type``).

    Returns:
        The form entry (a list entry when it has ``issuer_conditions``).
    """
    entry: Dict[str, Any] = {
        "type": value["value_type"],
        "mandatory": value.get("mandatory", False),
        "source": value.get("source"),
        "filled_value": None,
    }
    if "options" in value:
        entry["options"] = value["options"]
    if "issuer_conditions" in value:
        conditions = value["issuer_conditions"]
        entry["type"] = "list"
        entry["cardinality"] = conditions.get("cardinality")
        entry["attributes"] = _process_nested_attributes(conditions, value.get("value_type"))
        if "not_used_if" in conditions:
            entry["not_used_if"] = conditions["not_used_if"]
    return entry


def _process_nested_attributes(conditions: Dict[str, Any], parent_value_type: Optional[str] = None) -> Any:
    """Recursively processes nested attribute definitions.

    The sub-attribute dictionary is looked up by the parent's ``value_type``
    (e.g. ``places``, ``nationalities``) and otherwise by the first key
    ending in ``_attributes``.

    Args:
        conditions: ``issuer_conditions`` of a claim.
        parent_value_type: ``value_type`` of the parent claim.

    Returns:
        A dict of processed attributes, or a list for list-shaped
        definitions (e.g. PDA1 ``places_of_work``).
    """
    attributes_to_process = _nested_attributes_source(conditions, parent_value_type)
    if attributes_to_process is None:
        return {}

    if isinstance(attributes_to_process, list):
        return [
            {
                "attribute": item["attribute"],
                "attributes": _process_nested_attributes(
                    {k: v for k, v in item.items() if k != "attribute"}, item.get("value_type")
                ),
            }
            for item in attributes_to_process
            if "attribute" in item
        ]

    return {
        key: _nested_attribute_entry(value)
        for key, value in attributes_to_process.items()
        if isinstance(value, dict) and "value_type" in value
    }


def getNamespaces(claims: Iterable[Claim]) -> List[str]:
    """Lists the distinct mdoc namespaces used by ``claims``, in order.

    Args:
        claims: Claim definitions.

    Returns:
        Namespaces (first path element).
    """
    return list(dict.fromkeys(claim["path"][0] for claim in claims if "path" in claim))


def _mdoc_attributes(claims: Iterable[Claim], namespace: str, mandatory: bool) -> AttributesForm:
    """Extracts the mandatory or optional user attributes of an mdoc namespace.

    Args:
        claims: Claim definitions.
        namespace: Namespace to extract.
        mandatory: ``True`` for mandatory attributes (issuer-sourced claims
            are skipped), ``False`` for optional ones.

    Returns:
        The attributes form.
    """
    attributes_form: AttributesForm = {}
    for claim in claims:
        if mandatory and claim.get("source") == "issuer":
            continue
        if "overall_issuer_conditions" in claim:
            attributes_form.update(claim["overall_issuer_conditions"])
            continue
        if bool(claim.get("mandatory")) != mandatory or claim.get("path", [None])[0] != namespace:
            continue

        attributes_form[claim["path"][1]] = _mdoc_attribute_entry(claim, mandatory)
    return attributes_form


def _mdoc_attribute_entry(claim: Claim, mandatory: bool) -> Dict[str, Any]:
    """Builds the form entry of one mdoc claim.

    Args:
        claim: Claim definition.
        mandatory: Whether the entry is marked mandatory.

    Returns:
        The form entry (a list entry when it has ``issuer_conditions``).
    """
    entry: Dict[str, Any] = {"type": claim.get("value_type", "string"), "filled_value": None}
    if mandatory:
        entry["mandatory"] = True

    if "issuer_conditions" in claim:
        conditions = claim["issuer_conditions"]
        entry["type"] = "list"
        entry["cardinality"] = conditions.get("cardinality")
        if "at_least_one_of" in conditions:
            entry["at_least_one_of"] = conditions["at_least_one_of"]
        entry["attributes"] = _process_nested_attributes(conditions, claim.get("value_type"))
    return entry


def getMandatoryAttributes(claims: Iterable[Claim], namespace: str) -> AttributesForm:
    """Returns the mandatory user-filled attributes of an mdoc namespace.

    Args:
        claims: Claim definitions.
        namespace: mdoc namespace.

    Returns:
        The attributes form.
    """
    return _mdoc_attributes(claims, namespace, mandatory=True)


def getOptionalAttributes(claims: Iterable[Claim], namespace: str) -> AttributesForm:
    """Returns the optional user-filled attributes of an mdoc namespace.

    Args:
        claims: Claim definitions.
        namespace: mdoc namespace.

    Returns:
        The attributes form.
    """
    return _mdoc_attributes(claims, namespace, mandatory=False)


def _split_sdjwt_claims(
    claims: Iterable[Claim], attributes_form: AttributesForm, mandatory: bool
) -> Tuple[List[Claim], List[Claim], List[Claim]]:
    """Groups SD-JWT claims by path depth.

    ``overall_issuer_conditions`` are merged into ``attributes_form``.
    Top-level claims are kept only when their ``mandatory`` flag equals
    ``mandatory``; nested claims are always kept.

    Args:
        claims: Claim definitions.
        attributes_form: Form being built (mutated).
        mandatory: Which top-level claims to keep.

    Returns:
        ``(depth1, depth2, depth3)`` claim lists.
    """
    levels: Tuple[List[Claim], List[Claim], List[Claim]] = ([], [], [])
    for claim in claims:
        if "overall_issuer_conditions" in claim:
            attributes_form.update(claim["overall_issuer_conditions"])
            continue
        depth = len(claim["path"])
        if depth == 1 and claim["mandatory"] != mandatory:
            continue
        if 1 <= depth <= 3:
            levels[depth - 1].append(claim)
    return levels


def _nested_attribute_details(claim: Claim) -> Dict[str, Any]:
    """Builds the ``{mandatory, type, source}`` entry of a nested SD-JWT claim.

    Args:
        claim: Nested claim definition.

    Returns:
        The attribute details.
    """
    return {"mandatory": claim["mandatory"], "type": claim["value_type"], "source": claim["source"]}


def _copy_conditions(target: Dict[str, Any], claim: Claim, keys: Iterable[str]) -> None:
    """Copies selected ``issuer_conditions`` keys of ``claim`` into ``target``.

    Args:
        target: Destination dict (mutated).
        claim: Claim definition.
        keys: Condition keys to copy when present.
    """
    conditions = claim.get("issuer_conditions", {})
    target.update({k: conditions[k] for k in keys if k in conditions})


def _mandatory_sdjwt_entry(claim: Claim, attributes_form: AttributesForm) -> None:
    """Adds the form entry of a mandatory top-level SD-JWT claim.

    Args:
        claim: Top-level claim definition.
        attributes_form: Form being built (mutated).
    """
    attribute_name = claim["path"][0]
    if attribute_name == "nationalities":
        attributes_form[attribute_name] = {
            "type": claim["value_type"],
            "filled_value": None,
            "mandatory": True,
            "cardinality": {"min": 0, "max": "n"},
            "attributes": copy.deepcopy(_NATIONALITIES_ATTRIBUTES),
        }
        return
    if attribute_name == "place_of_birth":
        attributes_form[attribute_name] = {
            "type": "list",
            "filled_value": None,
            "mandatory": True,
            "cardinality": {"min": 0, "max": 1},
            "attributes": copy.deepcopy(_PLACE_OF_BIRTH_ATTRIBUTES),
        }
        return
    if "value_type" in claim:
        attributes_form[attribute_name] = {"type": claim["value_type"], "filled_value": None, "mandatory": True}
    if "issuer_conditions" in claim:
        _copy_conditions(attributes_form[attribute_name], claim, ["cardinality"])
        if (claim.get("value_type") or "").endswith("_attributes"):
            attributes_form[attribute_name]["type"] = "list"
            attributes_form[attribute_name]["attributes"] = []


def _as_list_entry(entry: Dict[str, Any]) -> List[Any]:
    """Turns a form entry into a list entry and returns its sub-attributes.

    Args:
        entry: Form entry (mutated when it has no ``attributes`` yet).

    Returns:
        The entry's ``attributes`` list.
    """
    if "attributes" not in entry:
        entry["type"] = "list"
        entry["attributes"] = []
    return entry["attributes"]


def _add_mandatory_level3(claim: Claim, attributes_form: AttributesForm) -> None:
    """Adds a depth-3 SD-JWT claim under its depth-2 parent entries.

    Args:
        claim: Claim definition (``path`` of length 3).
        attributes_form: Form being built (mutated).
    """
    attribute_name, level2_name, level3_name = claim["path"]
    for l2_item in attributes_form[attribute_name].get("attributes", []):
        if level2_name in l2_item:
            _as_list_entry(l2_item[level2_name]).append({level3_name: _nested_attribute_details(claim)})


def getMandatoryAttributesSDJWT(claims: Iterable[Claim]) -> AttributesForm:
    """Returns the mandatory user-filled attributes of an SD-JWT VC credential.

    Args:
        claims: Claim definitions.

    Returns:
        The attributes form.
    """
    attributes_form: AttributesForm = {}
    level1_claims, level2_claims, level3_claims = _split_sdjwt_claims(claims, attributes_form, True)

    for claim in level1_claims:
        _mandatory_sdjwt_entry(claim, attributes_form)

    for claim in level2_claims:
        if claim["path"][0] not in attributes_form:
            continue
        details = _nested_attribute_details(claim)
        _copy_conditions(details, claim, ["cardinality", "not_used_if"])
        _as_list_entry(attributes_form[claim["path"][0]]).append({claim["path"][1]: details})

    for claim in level3_claims:
        if claim["path"][0] in attributes_form:
            _add_mandatory_level3(claim, attributes_form)

    return attributes_form


def _optional_sdjwt_entry(claim: Claim, attributes_form: AttributesForm) -> None:
    """Adds the form entry of an optional top-level SD-JWT claim.

    Args:
        claim: Top-level claim definition.
        attributes_form: Form being built (mutated).
    """
    attribute_name = claim["path"][0]
    if attribute_name == "nationalities":
        attributes_form[attribute_name] = {
            "type": claim["value_type"],
            "filled_value": None,
            "cardinality": {"min": 0, "max": "n"},
            "attributes": copy.deepcopy(_NATIONALITIES_ATTRIBUTES),
        }
        return
    if "value_type" in claim:
        attributes_form[attribute_name] = {"type": claim["value_type"], "filled_value": None}
    if "issuer_conditions" in claim:
        _copy_conditions(attributes_form[attribute_name], claim, ["cardinality"])


def _add_optional_level2(claim: Claim, parent: Dict[str, Any]) -> None:
    """Adds a depth-2 optional SD-JWT claim to its parent entry.

    Args:
        claim: Claim definition (``path`` of length 2).
        parent: The parent's form entry (mutated).
    """
    parent["type"] = "list"
    attributes: Dict[str, Any] = {claim["path"][1]: _nested_attribute_details(claim)}
    _copy_conditions(attributes, claim, ["cardinality", "not_used_if"])

    if "attributes" not in parent:
        parent["attributes"] = [attributes]
    elif "cardinality" in parent["attributes"][0]:
        parent["attributes"].append(attributes)
    else:
        parent["attributes"][0].update(attributes)


def getOptionalAttributesSDJWT(claims: Iterable[Claim]) -> AttributesForm:
    """Returns the optional user-filled attributes of an SD-JWT VC credential.

    Args:
        claims: Claim definitions.

    Returns:
        The attributes form.
    """
    attributes_form: AttributesForm = {}
    level1_claims, level2_claims, level3_claims = _split_sdjwt_claims(claims, attributes_form, False)

    for claim in level1_claims:
        _optional_sdjwt_entry(claim, attributes_form)

    for claim in level2_claims:
        if claim["path"][0] in attributes_form:
            _add_optional_level2(claim, attributes_form[claim["path"][0]])

    for claim in level3_claims:
        attribute_name, level2_name, level3_name = claim["path"]
        if attribute_name not in attributes_form:
            continue
        for attribute in attributes_form[attribute_name]["attributes"]:
            if level2_name in attribute:
                attribute[level2_name].setdefault("attributes", []).append(
                    {level3_name: _nested_attribute_details(claim)}
                )

    return attributes_form


def _collect_form_attributes(
    credentials_requested: Iterable[str],
    mdoc_extractor: Callable[[Iterable[Claim], str], AttributesForm],
    sdjwt_extractor: Callable[[Iterable[Claim]], AttributesForm],
    drop_duplicate_nationalities: bool,
) -> AttributesForm:
    """Merges the form attributes of several requested credentials.

    The first credential defining an attribute wins. ``birthdate`` is
    dropped when ``birth_date`` is present (and ``nationalities`` when
    ``nationality`` is, if requested), and the SD-JWT ``picture`` is shown
    as the mdoc ``portrait``.

    Args:
        credentials_requested: Credential configuration ids.
        mdoc_extractor: Per-namespace extractor for mdoc credentials.
        sdjwt_extractor: Extractor for SD-JWT VC credentials.
        drop_duplicate_nationalities: Whether to drop ``nationalities``.

    Returns:
        The merged attributes form.
    """
    credentials = _credentials_supported()
    attributes: AttributesForm = {}

    for request in credentials_requested:
        credential = credentials[request]
        claims = credential["credential_metadata"]["claims"]

        attributes_req: AttributesForm = {}
        match credential["format"]:
            case "mso_mdoc":
                for namespace in getNamespaces(claims):
                    attributes_req.update(mdoc_extractor(claims, namespace))
            case "dc+sd-jwt":
                attributes_req.update(sdjwt_extractor(claims))

        for name, value in attributes_req.items():
            attributes.setdefault(name, value)

        if "birth_date" in attributes and "birthdate" in attributes:
            attributes.pop("birthdate")
        if drop_duplicate_nationalities and "nationality" in attributes and "nationalities" in attributes:
            attributes.pop("nationalities")
        if "picture" in attributes:
            if "portrait" in attributes:
                attributes.pop("picture")
            else:
                attributes = {"portrait" if name == "picture" else name: value for name, value in attributes.items()}

    return attributes


def getAttributesForm(credentials_requested: Iterable[str]) -> AttributesForm:
    """Returns the mandatory attributes the user must fill for the credentials.

    Args:
        credentials_requested: Credential configuration ids.

    Returns:
        The attributes form.
    """
    return _collect_form_attributes(
        credentials_requested, getMandatoryAttributes, getMandatoryAttributesSDJWT, True
    )


def getAttributesForm2(credentials_requested: Iterable[str]) -> AttributesForm:
    """Returns the optional attributes the user may fill for the credentials.

    Args:
        credentials_requested: Credential configuration ids.

    Returns:
        The attributes form.
    """
    return _collect_form_attributes(
        credentials_requested, getOptionalAttributes, getOptionalAttributesSDJWT, False
    )


def optional_only(optional: AttributesForm, mandatory: AttributesForm) -> AttributesForm:
    """Removes from ``optional`` the attributes that are already mandatory.

    Args:
        optional: Optional attributes form.
        mandatory: Mandatory attributes form.

    Returns:
        A new dict with only the attributes not in ``mandatory``.
    """
    return {k: v for k, v in optional.items() if k not in mandatory}


def getIssuerFilledAttributes(claims: Iterable[Claim], namespace: str) -> Dict[str, str]:
    """Returns the issuer-filled attributes of an mdoc namespace.

    Args:
        claims: Claim definitions.
        namespace: mdoc namespace.

    Returns:
        ``{attribute_name: ""}``.
    """
    return {
        claim["path"][1]: ""
        for claim in claims
        if claim.get("source") == "issuer" and claim["path"][0] == namespace
    }


def getIssuerFilledAttributesSDJWT(claims: Iterable[Claim]) -> Dict[str, str]:
    """Returns the issuer-filled top-level attributes of an SD-JWT credential.

    Args:
        claims: Claim definitions.

    Returns:
        ``{attribute_name: ""}``.
    """
    return {claim["path"][0]: "" for claim in claims if claim.get("source") == "issuer"}
