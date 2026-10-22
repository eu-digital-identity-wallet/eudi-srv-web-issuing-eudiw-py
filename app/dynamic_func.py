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
import datetime
import json
import re
import secrets
import uuid
from flask import session
from misc import (
    calculate_age,
    doctype2credential,
    doctype2credentialSDJWT,
    getIssuerFilledAttributes,
    getIssuerFilledAttributesSDJWT,
    getMandatoryAttributes,
    getMandatoryAttributesSDJWT,
    getNamespaces,
    getOptionalAttributes,
    getOptionalAttributesSDJWT,
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
    if "account_provider" in issuer_claims and "account_provider" in doctype_config:
        data["account_provider"] = doctype_config["account_provider"]

    # A configured issuing country is the issuer's own, whatever country the
    # holder picked to authenticate.
    if "issuing_country" in issuer_claims and "issuing_country" in doctype_config:
        data["issuing_country"] = doctype_config["issuing_country"]


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
    credentials_supported = oidc_metadata["credential_configurations_supported"]
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
    """The form sends a local date-time (YYYY-MM-DDTHH:MM); claims carry
    RFC 3339, taken here as UTC."""
    if isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?", value):
        return (value if value.count(":") == 2 else value + ":00") + "Z"
    return value


_VALUE_TYPES = {
    "int": _to_int,
    "number": _to_number,
    "date-time": _to_date_time,
    "list_string": lambda v: [v] if isinstance(v, str) else v,
}


def _apply_at(node, path, transform):
    """Apply transform to the value at path, in every element of the arrays
    on the way (claim paths have no segment for array elements)."""
    if isinstance(node, list):
        for element in node:
            _apply_at(element, path, transform)
    elif isinstance(node, dict) and path[0] in node:
        if len(path) == 1:
            node[path[0]] = transform(node[path[0]])
        else:
            _apply_at(node[path[0]], path[1:], transform)


# Credentials already live that issue their single-occurrence groups as
# one-element lists (EHIC: authentic_source). Holders and verifiers may rely
# on that shape, so it is kept.
KEEP_SINGLE_GROUPS_AS_LISTS = {"eu.europa.ec.eudi.ehic_sd_jwt_vc"}


def shape_claims(data, claims, single_groups_as_objects=True):
    """Give the form data the JSON shape the claim metadata describes. The
    form sends every group as a list (name[0][attribute]), but a group that
    occurs at most once is an object. Leaf values get their value_type."""
    for claim in claims:
        if "path" not in claim:
            continue
        path = [s for s in claim["path"] if s is not None]
        value_type = claim.get("value_type") or ""
        max_count = claim.get("issuer_conditions", {}).get("cardinality", {}).get("max")

        if value_type.endswith("_attributes"):
            if max_count != 1 or not single_groups_as_objects:
                continue
            _apply_at(
                data,
                path,
                lambda v: v[0] if isinstance(v, list) and len(v) == 1 else v,
            )
        elif value_type in _VALUE_TYPES:
            _apply_at(data, path, _VALUE_TYPES[value_type])


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
