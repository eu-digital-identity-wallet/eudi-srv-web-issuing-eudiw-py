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
import copy
import datetime
import json
import logging
import re
import secrets
import uuid
from flask import session
from misc import (
    KEEP_SINGLE_GROUPS_AS_LISTS,
    calculate_age,
    claim_path,
    doctype2credential,
    doctype2credentialSDJWT,
    getIssuerFilledAttributes,
    getIssuerFilledAttributesSDJWT,
    getMandatoryAttributes,
    getMandatoryAttributesSDJWT,
    getNamespaces,
    getOptionalAttributes,
    getOptionalAttributesSDJWT,
    is_array_group,
)
from redirect_func import json_post
import base64
from flask import session
from misc import calculate_age
from redirect_func import json_post
from app import oidc_metadata
from app import session_manager
from app import CONFIGURATION
from formatter_func import mdocFormatter, sdjwtFormatter

logger = logging.getLogger(__name__)


def dynamic_formatter(format, scope, form_data, device_publickey, session_id):

    current_session = session_manager.get_session(session_id=session_id)

    if (
        scope == "eu.europa.ec.eudi.mdl_mdoc"
        or scope == "eu.europa.ec.eudi.aamva_mdl_mdoc"
    ):
        un_distinguishing_sign = CONFIGURATION["countries"][current_session.country]["un_distinguishing_sign"]
    else:
        un_distinguishing_sign = ""

    data, requested_credential = formatter(
        dict(form_data), un_distinguishing_sign, scope, format
    )

    r = {}

    if format == "mso_mdoc":
        credential = mdocFormatter(
            data=data,
            credential_metadata=requested_credential,
            country=current_session.country,
            device_publickey=device_publickey,
            session_id=session_id,
        )

    elif format == "dc+sd-jwt":
        credential = sdjwtFormatter(
            PID={
                "credential_metadata": requested_credential,
                "data": data,
                "device_publickey": device_publickey
            },
            country=current_session.country,
            scope=scope,
            session_id=session_id,
        )

    return credential


def check_form_data(data, credentials_requested):
    """Why the requested credentials cannot be issued from the form data, or
    None. Runs, on a copy of the data, the formatting the credential endpoint
    runs, so a check that would fail there (a ValueError, e.g. an IBAN's
    check digits) fails while the user is still at the form. Other errors
    are left to the credential endpoint, as before."""
    credentials_supported = oidc_metadata.get("credential_configurations_supported", {})
    for credential_id in credentials_requested or []:
        config = credentials_supported.get(credential_id)
        if not config:
            continue
        try:
            formatter(copy.deepcopy(data), "", credential_id, config["format"])
        except ValueError as e:
            return str(e)
        except Exception:
            logger.warning("Form data not checked for %s", credential_id, exc_info=True)
    return None


def formatter(data, un_distinguishing_sign, scope, format):
    today = datetime.date.today()

    requested_credential, pdata = get_requested_credential(data, scope, format, today)
    doctype_config = requested_credential["issuer_config"]
    expiry = today + datetime.timedelta(days=doctype_config["validity"])

    # Extract claim categories
    if format == "mso_mdoc":
        namescapes = getNamespaces(
            requested_credential["credential_metadata"]["claims"]
        )

        attributes_by_namespace = {}

        attributes_req = {}
        attributes_req2 = {}
        issuer_claims = {}

        for namescape in namescapes:
            attributes_by_namespace[namescape] = {
                "mandatory": getMandatoryAttributes(
                    requested_credential["credential_metadata"]["claims"], namescape
                ),
                "optional": getOptionalAttributes(
                    requested_credential["credential_metadata"]["claims"], namescape
                ),
                "issuer": getIssuerFilledAttributes(
                    requested_credential["credential_metadata"]["claims"], namescape
                ),
            }

        attributes_req = {}
        attributes_req2 = {}
        issuer_claims = {}

        for namescape in namescapes:
            attributes_req.update(attributes_by_namespace[namescape]["mandatory"])
            attributes_req2.update(attributes_by_namespace[namescape]["optional"])
            issuer_claims.update(attributes_by_namespace[namescape]["issuer"])

    else:  # "dc+sd-jwt"
        attributes_req = getMandatoryAttributesSDJWT(
            requested_credential["credential_metadata"]["claims"]
        )
        attributes_req2 = getOptionalAttributesSDJWT(
            requested_credential["credential_metadata"]["claims"]
        )
        issuer_claims = getIssuerFilledAttributesSDJWT(
            requested_credential["credential_metadata"]["claims"]
        )

    # Update special claims
    update_dates_and_special_claims(
        data,
        issuer_claims,
        un_distinguishing_sign,
        today,
        expiry,
        requested_credential,
        doctype_config,
    )

    # Normalize list and type fields
    normalize_list_and_type_fields(data, attributes_req, attributes_req2, requested_credential.get("scope"))

    if format == "dc+sd-jwt":
        shape_claims(
            data,
            requested_credential["credential_metadata"]["claims"],
            single_groups_as_objects=scope not in KEEP_SINGLE_GROUPS_AS_LISTS,
        )
        check_presence_conditions(
            data, requested_credential["credential_metadata"]["claims"]
        )

    # Populate pdata
    populate_pdata(
        data,
        pdata,
        format,
        namescapes if format == "mso_mdoc" else None,
        attributes_req,
        attributes_req2,
        issuer_claims,
        attributes_by_namespace=(
            attributes_by_namespace if format == "mso_mdoc" else None
        ),
    )

    return pdata, requested_credential


def get_requested_credential(data, scope, format, today):
    cred = oidc_metadata["credential_configurations_supported"][scope]

    if format == "mso_mdoc":
        # cred = doctype2credential(doctype, format)
        pdata = {}
    else:  # "dc+sd-jwt"
        # cred = doctype2credentialSDJWT(doctype, format)
        doctype_config = cred["issuer_config"]
        pdata = {
            "evidence": [
                {
                    "type": cred["vct"],
                    "source": {
                        "organization_name": doctype_config["organization_name"],
                        "organization_id": doctype_config["organization_id"],
                        "country_code": data["issuing_country"],
                    },
                }
            ],
            "claims": {},
        }
    return cred, pdata


def update_dates_and_special_claims(
    data,
    issuer_claims,
    un_distinguishing_sign,
    today,
    expiry,
    requested_credential,
    doctype_config,
):
    # Age over 18
    if "age_over_18" in issuer_claims and "birth_date" in data:
        data["age_over_18"] = calculate_age(data["birth_date"]) >= 18

    # Un-distinguishing sign
    if "un_distinguishing_sign" in issuer_claims:
        data["un_distinguishing_sign"] = un_distinguishing_sign

    # Dates
    date_fields = {
        "issuance_date": today,
        "date_of_issuance": today,
        "issue_date": today,
        "expiry_date": expiry,
        "date_of_expiry": expiry,
    }
    for field, value in date_fields.items():
        if field in issuer_claims:
            data[field] = value.strftime("%Y-%m-%d")

    # Issuing authority
    if "issuing_authority" in issuer_claims:
        if requested_credential.get("scope") == "eu.europa.ec.eudi.ehic_sd_jwt_vc":
            data["issuing_authority"] = {
                "id": doctype_config["issuing_authority_id"],
                "name": doctype_config["issuing_authority"],
            }
        else:
            data["issuing_authority"] = doctype_config["issuing_authority"]

    if "issuing_authority_unicode" in issuer_claims:
        data["issuing_authority_unicode"] = doctype_config["issuing_authority"]

    if "credential_type" in issuer_claims:
        data["credential_type"] = doctype_config["credential_type"]

    # WE BUILD rulebooks fix the legal category per attestation type, and not
    # all to the same value, so each credential declares its own.
    if "attestation_legal_category" in issuer_claims:
        data["attestation_legal_category"] = doctype_config["attestation_legal_category"]

    # Identifies this issued credential, not the subject or the card, so it is
    # new on every issuance (rb-sca-card-dpc, section 2.2).
    if "credential_id" in issuer_claims:
        data["credential_id"] = f"urn:uuid:{uuid.uuid4()}"

    # A test issuer stands in for the card issuer, which knows the card, so
    # the holder types neither: one network per credential, as configured, and
    # a fresh opaque card reference that reveals nothing of a PAN
    # (rb-sca-card-dpc, IR-01 and IR-02).
    if "network" in issuer_claims:
        data["network"] = doctype_config["network"]

    if "card_id" in issuer_claims:
        data["card_id"] = str(uuid.uuid4())

    # The SCA subject identifier is a random reference of the issuer, not
    # something the holder types (rb-sca-iban and rb-sca-user, section 3.2).
    if "sub" in issuer_claims:
        data["sub"] = f"urn:uuid:{uuid.uuid4()}"

    # The account provider is the issuing bank itself, so its data comes from
    # the issuer configuration (rb-iban-ov, section 3.2).
    # A copy, as the credential's data is reshaped later and the configuration
    # is shared by every issuance.
    if "account_provider" in issuer_claims and "account_provider" in doctype_config:
        data["account_provider"] = copy.deepcopy(doctype_config["account_provider"])

    # A configured issuing country is the issuer's own, whatever country the
    # holder picked to authenticate.
    if "issuing_country" in issuer_claims and "issuing_country" in doctype_config:
        data["issuing_country"] = doctype_config["issuing_country"]

    # rb-sca-iban IR-01 and IR-02: the masked IBAN and the national bank code
    # are derived from the full IBAN, so they cannot disagree with it.
    if "masked_iban" in issuer_claims:
        iban = checked_iban(data.get("iban"))
        data["iban"] = iban
        data["masked_iban"] = mask_iban(iban)
        if "national_bank_code" in issuer_claims:
            code = national_bank_code(iban)
            if code:
                data["national_bank_code"] = code
            else:
                # Not known where this country's IBAN carries it, so it
                # cannot be checked against the IBAN: left out (optional).
                data.pop("national_bank_code", None)


# Where the national bank code is in the IBAN of a country, as
# (start, end) indexes into the IBAN (SWIFT IBAN Registry, bank identifier).
_IBAN_BANK_CODE = {
    "AT": (4, 9), "BE": (4, 7), "BG": (4, 8), "CH": (4, 9), "CY": (4, 7),
    "CZ": (4, 8), "DE": (4, 12), "DK": (4, 8), "EE": (4, 6), "ES": (4, 8),
    "FI": (4, 7), "FR": (4, 9), "GB": (4, 8), "GR": (4, 7), "HR": (4, 11),
    "HU": (4, 7), "IE": (4, 8), "IT": (5, 10), "LI": (4, 9), "LT": (4, 9),
    "LU": (4, 7), "LV": (4, 8), "MT": (4, 8), "NL": (4, 8), "NO": (4, 8),
    "PT": (4, 8), "RO": (4, 8), "SE": (4, 7), "SK": (4, 8),
}


def checked_iban(value):
    """The IBAN without spaces, in capitals, if it is well-formed and its
    check digits are right (ISO 13616, mod 97); issuance fails otherwise."""
    iban = re.sub(r"\s+", "", value or "").upper()
    if not re.fullmatch(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}", iban):
        raise ValueError("The IBAN is missing or not well-formed")
    digits = "".join(str(int(c, 36)) for c in iban[4:] + iban[:4])
    if int(digits) % 97 != 1:
        raise ValueError("The IBAN check digits are wrong")
    return iban


def mask_iban(iban):
    """rb-sca-iban 3.2: the first 4 and the last 4 characters unmasked. The
    middle is 11 asterisks whatever the IBAN's length, as in both of the
    rulebook's examples (CZ55***********8745), which also hides the length."""
    return iban[:4] + "*" * 11 + iban[-4:]


def national_bank_code(iban):
    """The bank code in the IBAN, or None for a country not in the table."""
    position = _IBAN_BANK_CODE.get(iban[:2])
    return iban[position[0]:position[1]] if position else None


def _made_up_last_four():
    return f"{secrets.randbelow(10000):04d}"


def sca_card_choice(credentials_requested):
    """The form field in which the user picks the card an SCA-Card (DPC) is
    for, shown by its card art with its last four digits and expiry, or None
    if no requested credential has cards configured.

    A test issuer stands in for the card issuer, which would know the user's
    cards, so each card's last four digits are made up here, and travel in
    the option's value, "<alias>|<last four>", to sca_card_display. The
    expiry is the credential's, from its validity; the display meta-data has
    no expiry (rb-sca-card-dpc, section 2.9), so it is shown here only.
    """
    credentials_supported = oidc_metadata.get("credential_configurations_supported", {})
    for credential_id in credentials_requested:
        issuer_config = credentials_supported.get(credential_id, {}).get("issuer_config", {})
        config = issuer_config.get("card_display")
        if config:
            expiry = None
            if "validity" in issuer_config:
                expiry = (
                    datetime.date.today() + datetime.timedelta(days=issuer_config["validity"])
                ).strftime("%m/%y")
            options = []
            for product in config["products"]:
                last_four = _made_up_last_four()
                options.append(
                    {
                        "value": f"{product['alias']}|{last_four}",
                        "label": product["alias"],
                        "image_url": product["card_art"][0]["image_url"],
                        "last_four": last_four,
                        "expiry": expiry,
                    }
                )
            return {"type": "card_choice", "mandatory": True, "options": options}
    return None


def sca_card_display(issuer_config, card=None):
    """The display meta-data of an SCA-Card (DPC) attestation (rb-sca-card-dpc,
    section 2.9), or None if the credential has none configured.

    It is unsigned and goes in the credential response's display array, not
    in the credential (sections 2.9 and 4.1). A test issuer stands in for the
    card issuer, so the card is the one the user picked, "<alias>|<last four>"
    from sca_card_choice, else the first configured product with made-up
    digits, as card_id is. The card issuer is the product's own, else the
    configuration's, as each card may be a different issuer's. The network
    branding is for the credential's own network, as IR-04 requires.
    """
    config = issuer_config.get("card_display")
    if not config:
        return None

    alias, _, last_four = (card or "").rpartition("|")
    if not re.fullmatch(r"[0-9]{4}", last_four):
        last_four = _made_up_last_four()
    product = next(
        (p for p in config["products"] if p["alias"] == alias),
        config["products"][0],
    )
    card = {}
    if "type" in config:
        card["type"] = config["type"]
    card["last_four"] = last_four
    card["card_art"] = product["card_art"]
    card["alias"] = product["alias"]
    issuer = product.get("issuer", config.get("issuer"))
    if issuer:
        card["issuer"] = issuer
    card["network_branding"] = {
        "network": issuer_config["network"],
        "branding": config["network_branding"],
    }
    return {"card": card}


def normalize_list_and_type_fields(data, attributes_req, attributes_req2, scope=None):
    list_fields = [
        "places_of_work",
        "legislation",
        "employment_details",
        "competent_institution",
        "credential_holder",
        "subject",
        "residence_address"
    ]

    if scope == "eu.europa.ec.eudi.pid_vc_sd_jwt":
        list_fields.append("address")

    for field in list_fields:
        if field in attributes_req and field in data:
            if isinstance(data[field], str):
                data[field] = json.loads(data[field])
            if isinstance(data[field], list):
                data[field] = data[field][0]

        if field in attributes_req2 and field in data:
            if isinstance(data[field], str):
                data[field] = json.loads(data[field])
            if isinstance(data[field], list):
                data[field] = data[field][0]

    # Numeric conversions
    if "age_in_years" in data and isinstance(data["age_in_years"], str):
        data["age_in_years"] = int(data["age_in_years"])
    if "age_birth_year" in data and isinstance(data["age_birth_year"], str):
        data["age_birth_year"] = int(data["age_birth_year"])
    if (
        "gender" in data
        and isinstance(data["gender"], str)
        and data["gender"].isdigit()
    ):
        data["gender"] = int(data["gender"])

def _to_int(value):
    return int(value) if isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()) else value


def _to_number(value):
    if not isinstance(value, str):
        return value
    try:
        number = float(value)
    except ValueError:
        return value
    return int(number) if number.is_integer() and "." not in value else number


def _to_date_time(value):
    """Claims carry RFC 3339. The form converts the user's local time to UTC
    before sending it (2026-10-22T07:14:00Z), which is kept as it is. A
    date-time without an offset (YYYY-MM-DDTHH:MM[:SS]) has no time zone to
    go by, so it is taken as UTC."""
    if isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?", value):
        return (value if value.count(":") == 2 else value + ":00") + "Z"
    return value


_VALUE_TYPES = {
    "int": _to_int,
    "number": _to_number,
    "date-time": _to_date_time,
    # Fields left empty (e.g. an unused free value next to a list) are dropped
    "list_string": lambda v: (
        [v] if isinstance(v, str) else [s for s in v if s != ""] if isinstance(v, list) else v
    ),
}


def _apply_at(node, path, transform):
    """Apply transform to the value at path (a misc.claim_path, so names
    only), in every element of the arrays on the way."""
    if isinstance(node, list):
        for element in node:
            _apply_at(element, path, transform)
    elif isinstance(node, dict) and path[0] in node:
        if len(path) == 1:
            node[path[0]] = transform(node[path[0]])
        else:
            _apply_at(node[path[0]], path[1:], transform)


def shape_claims(data, claims, single_groups_as_objects=True):
    """Give the form data the JSON shape the claim metadata describes. The
    form sends every group as a list (name[0][attribute]), but a group that
    occurs at most once is an object (misc.is_array_group). Leaf values get
    their value_type."""
    for claim in claims:
        if "path" not in claim:
            continue
        path = list(claim_path(claim))
        value_type = claim.get("value_type") or ""

        if value_type.endswith("_attributes"):
            if is_array_group(claim, single_groups_as_objects):
                continue
            _apply_at(
                data,
                path,
                lambda v: v[0] if isinstance(v, list) and len(v) == 1 else v,
            )
        elif value_type in _VALUE_TYPES:
            _apply_at(data, path, _VALUE_TYPES[value_type])


def _objects_at(node, path):
    """The objects at path (a misc.claim_path), in every element of the
    arrays on the way."""
    if isinstance(node, list):
        for element in node:
            yield from _objects_at(element, path)
    elif isinstance(node, dict):
        if not path:
            yield node
        elif path[0] in node:
            yield from _objects_at(node[path[0]], path[1:])


def _absent(value):
    return value is None or value in ("", [], {})


def check_presence_conditions(data, claims):
    """Conditional claims, from issuer_conditions:
    - used_if {"attribute", "values"}: the claim is present if and only if
      its sibling attribute has one of the values (rb-iban-ov 3.4: owner_name
      and legal_person_identifiers for an entity, given_name and surname for
      a person). Where the condition does not hold the claim is dropped;
      where it holds and the claim is missing, issuance fails.
    - not_used_if {"attributes"}: the claim and those siblings exclude each
      other (rb-eucc: a legal representative is a natural or a legal
      person). Issuance fails if both are present.
    - other_values {"used_if"} next to options: values besides the options
      are allowed, and at least one is required, if and only if the sibling
      condition holds (rb-eu-poa IR-04: limitation details when substitution
      is limited). Issuance fails otherwise.
    """
    for claim in claims:
        if "path" not in claim:
            continue
        conditions = claim.get("issuer_conditions", {})
        if not any(k in conditions for k in ("used_if", "not_used_if", "other_values")):
            continue
        path = claim_path(claim)
        name = path[-1]

        for parent in _objects_at(data, path[:-1]):
            rule = conditions.get("used_if")
            if rule:
                value = parent.get(rule["attribute"])
                if value not in rule["values"]:
                    parent.pop(name, None)
                elif _absent(parent.get(name)):
                    raise ValueError(
                        f"{'.'.join(path)} is required when "
                        f"{rule['attribute']} is {value}"
                    )

            excluded = conditions.get("not_used_if", {}).get("attributes", [])
            if not _absent(parent.get(name)):
                present = [a for a in excluded if not _absent(parent.get(a))]
                if present:
                    raise ValueError(
                        f"{'.'.join(path)} cannot be combined with "
                        f"{', '.join(present)}"
                    )

            other = conditions.get("other_values")
            if other and isinstance(parent.get(name), list):
                options = conditions.get("options", [])
                others = [v for v in parent[name] if v not in options]
                rule = other["used_if"]
                value = parent.get(rule["attribute"])
                if value in rule["values"] and not others:
                    raise ValueError(
                        f"{'.'.join(path)} needs {other.get('label', 'a value')} "
                        f"besides the listed values when {rule['attribute']} is {value}"
                    )
                if value not in rule["values"] and others:
                    raise ValueError(
                        f"{'.'.join(path)} only takes the listed values unless "
                        f"{rule['attribute']} is {', '.join(rule['values'])}"
                    )


def populate_pdata(
    data,
    pdata,
    format,
    namescapes,
    attributes_req,
    attributes_req2,
    issuer_claims,
    attributes_by_namespace=None,
):
    if format == "mso_mdoc":
        for namescape in namescapes:
            pdata[namescape] = {}
            # Use the namespace-specific attributes
            namespace_attrs = attributes_by_namespace[namescape]
            for attr_group in (
                namespace_attrs["mandatory"],
                namespace_attrs["optional"],
                namespace_attrs["issuer"],
            ):
                for attr in attr_group:
                    if attr in data:
                        pdata[namescape][attr] = data[attr]
    else:  # "dc+sd-jwt"
        for attr_group in (attributes_req, attributes_req2, issuer_claims):
            for attr in attr_group:
                if attr in data:
                    pdata["claims"][attr] = data[attr]
