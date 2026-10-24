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
"""
The PID Issuer Web service is a component of the PID Provider backend.
Its main goal is to issue the PID and MDL in cbor/mdoc (ISO 18013-5 mdoc) and SD-JWT format.


This misc.py file includes different miscellaneous functions.
"""
# Standard library imports
import base64
import datetime
import json
import secrets
import uuid
from io import BytesIO
from typing import Any, Dict, Optional, Tuple
import requests
import logging


# Third-party imports
import jwt
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from PIL import Image
from flask import current_app, jsonify, redirect, render_template_string
from flask.helpers import make_response


# Local/project-specific imports
from app import oidc_metadata
from app import trusted_CAs
from app_config.config_service import ConfService as cfgservice
from redirect_func import url_get
from app import CONFIGURATION

logger = logging.getLogger(__name__)

def create_dict(dict, item):
    """Create dictionary with key and value element. The key will be the key of dict and the value will be dict[item]

    Keyword arguments:
    + dict -- dictionary
    + item -- dictionary item

    Return: Return dictionary key: value, where key is the key of dict, and value is dict[item]
    """
    d = {}
    for key in dict:
        try:
            d[key] = dict[key][item]
        except:
            pass
    return d


def _process_nested_attributes(conditions, parent_value_type=None):
    # Recursively processes nested attribute definitions.
    # It now uses the parent's value_type to find the correct sub-attribute dictionary.

    processed_attrs = {}

    # dynamically looks for a key that matches the parent's value_type (e.g., 'places', 'nationalities')
    # or falls back to searching for a key ending in '_attributes'.
    attr_key = (
        parent_value_type
        if parent_value_type in conditions
        else next((k for k in conditions if k.endswith("_attributes")), None)
    )

    if not attr_key:
        # This handles the new 'driving_privileges' structure which contains attributes directly
        if any(isinstance(v, dict) and "value_type" in v for v in conditions.values()):
            attributes_to_process = conditions
        else:
            return {}
    else:
        attributes_to_process = conditions.get(attr_key, {})

    if isinstance(attributes_to_process, list):
        # This handles structures like PDA1's places_of_work
        processed_list = []
        for item in attributes_to_process:
            if "attribute" in item:
                item_attrs = {k: v for k, v in item.items() if k != "attribute"}
                processed_list.append(
                    {
                        "attribute": item["attribute"],
                        "attributes": _process_nested_attributes(
                            item_attrs, item.get("value_type")
                        ),
                    }
                )
        return processed_list

    # This handles structures like pid_mdoc's place_of_birth and mDL's driving_privileges
    for key, value in attributes_to_process.items():
        if isinstance(value, dict) and "value_type" in value:
            processed_attrs[key] = {
                "type": value["value_type"],
                "mandatory": value.get("mandatory", False),
                "source": value.get("source"),
                "filled_value": None,
            }
            # Add options for dropdowns if they exist
            if "options" in value:
                processed_attrs[key]["options"] = value["options"]

            if "issuer_conditions" in value:
                processed_attrs[key]["type"] = "list"
                processed_attrs[key]["cardinality"] = value["issuer_conditions"].get(
                    "cardinality"
                )
                # Recursive step for the next level of nesting
                processed_attrs[key]["attributes"] = _process_nested_attributes(
                    value["issuer_conditions"], value.get("value_type")
                )
                if "not_used_if" in value["issuer_conditions"]:
                    processed_attrs[key]["not_used_if"] = value["issuer_conditions"][
                        "not_used_if"
                    ]
    return processed_attrs


def urlsafe_b64encode_nopad(data: bytes) -> str:
    """
    Encodes bytes using URL-safe base64 and removes padding.

    Args:
        data (bytes): The data to encode.

    Returns:
        str: Base64 URL-safe encoded string without padding.
    """
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def calculate_age(date_of_birth: str):
    """returns the age, based on the date_of_birth

    Keyword arguments:
    + date_of_birth -- date of birth in the format Year-Month-Day

    Return: Age
    """
    birthDate = datetime.datetime.strptime(date_of_birth, "%Y-%m-%d").date()
    today = datetime.date.today()
    age = today.year - birthDate.year
    if today < datetime.date(today.year, birthDate.month, birthDate.day):
        age -= 1
    return age


def convert_png_to_jpeg(png_bytes):
    # Open the PNG image from bytes
    png_image = Image.open(BytesIO(png_bytes))

    # Create a new in-memory file-like object
    jpeg_buffer = BytesIO()

    # Convert the PNG image to JPEG format and save to the buffer
    png_image.convert("RGB").save(jpeg_buffer, format="JPEG")

    # Get the JPEG bytes from the buffer
    jpeg_bytes = jpeg_buffer.getvalue()

    return jpeg_bytes


def getNamespaces(claims):
    namespaces = []
    for claim in claims:
        if "path" in claim:
            if claim["path"][0] not in namespaces:
                namespaces.append(claim["path"][0])

    return namespaces


def getAttributesForm(credentials_requested):
    """
    Function to get attributes needed to populate form depending credentials requested by user

    Keyword arguments:"
    credentials_requested --credentials requested by the user

    """
    credentialsSupported = oidc_metadata["credential_configurations_supported"]

    attributes = {}

    for request in credentials_requested:
        format = credentialsSupported[request]["format"]

        attributes_req = {}
        if format == "mso_mdoc":
            namescapes = getNamespaces(
                credentialsSupported[request]["credential_metadata"]["claims"]
            )
            for namescape in namescapes:
                attributes_req.update(
                    getMandatoryAttributes(
                        credentialsSupported[request]["credential_metadata"]["claims"],
                        namescape,
                    )
                )

        elif format == "dc+sd-jwt":
            attributes_req.update(
                getMandatoryAttributesSDJWT(
                    credentialsSupported[request]["credential_metadata"]["claims"]
                )
            )

        for attribute in attributes_req:
            if attribute not in attributes:
                attributes.update({attribute: attributes_req[attribute]})

        if "birth_date" in attributes and "birthdate" in attributes:
            attributes.pop("birthdate")

        if "nationality" in attributes and "nationalities" in attributes:
            attributes.pop("nationalities")

    return attributes


def getMandatoryAttributes(claims, namespace):
    """
    Function to get mandatory attributes from credential.
    Now passes the claim's value_type to the helper function.
    """
    attributes_form = {}

    for claim in claims:
        if claim.get("source") == "issuer":
            continue

        elif "overall_issuer_conditions" in claim:
            for key, value in claim["overall_issuer_conditions"].items():
                attributes_form.update({key: value})

        elif claim.get("mandatory") and claim.get("path", [None])[0] == namespace:
            attribute_name = claim["path"][1]
            attributes_form[attribute_name] = {
                "type": claim.get("value_type", "string"),
                "filled_value": None,
                "mandatory": True,
            }

            if "issuer_conditions" in claim:
                attributes_form[attribute_name]["type"] = "list"
                attributes_form[attribute_name]["cardinality"] = claim[
                    "issuer_conditions"
                ].get("cardinality")
                if "at_least_one_of" in claim["issuer_conditions"]:
                    attributes_form[attribute_name]["at_least_one_of"] = claim[
                        "issuer_conditions"
                    ]["at_least_one_of"]

                # Pass the value_type to the helper
                attributes_form[attribute_name]["attributes"] = (
                    _process_nested_attributes(
                        claim["issuer_conditions"], claim.get("value_type")
                    )
                )

    return attributes_form


# Credentials already live that issue their single-occurrence groups as
# one-element lists (EHIC: authentic_source). Holders and verifiers may rely
# on that shape, so it is kept.
KEEP_SINGLE_GROUPS_AS_LISTS = {"eu.europa.ec.eudi.ehic_sd_jwt_vc"}


def claim_path(claim):
    """A claim's path without its null (array element) segments. The
    metadata paths are claims path pointers, with a null segment after every
    array; the form and the issued data are walked by name only."""
    return tuple(s for s in claim["path"] if s is not None)


def is_array_group(claim, single_groups_as_objects=True):
    """The form sends every group as a list. It is issued as one unless it
    occurs at most once and is shaped into an object (shape_claims)."""
    if not (claim.get("value_type") or "").endswith("_attributes"):
        return False
    max_count = claim.get("issuer_conditions", {}).get("cardinality", {}).get("max")
    return max_count != 1 or not single_groups_as_objects


def array_claims(claims, single_groups_as_objects=True):
    """The claims (as claim_path gives them) issued as JSON arrays: the groups
    is_array_group says stay lists, and any claim whose metadata path already
    has a null segment after it (lists the issuer fills in itself)."""
    arrays = set()
    for claim in claims:
        if "path" not in claim:
            continue
        if is_array_group(claim, single_groups_as_objects):
            arrays.add(claim_path(claim))
        names = []
        for segment in claim["path"]:
            if segment is None:
                arrays.add(tuple(names))
            else:
                names.append(segment)
    return arrays


def with_array_segments(path, arrays):
    """The claims path pointer for a claim_path: a null segment after every
    array on the way to the claim."""
    pointer = []
    for i, segment in enumerate(path):
        pointer.append(segment)
        if tuple(path[: i + 1]) in arrays and i + 1 < len(path):
            pointer.append(None)
    return pointer


def sd_flags(claims):
    """The explicit selective_disclosure flags of the claims, keyed by
    claim_path, so a flag applies to the claim in every array element."""
    return {
        claim_path(claim): claim["selective_disclosure"]
        for claim in claims
        if "path" in claim
        and "overall_issuer_conditions" not in claim
        and "selective_disclosure" in claim
    }


def is_disclosable(path, flags):
    """Whether the issuer makes the claim at path (a claim_path) selectively
    disclosable. A claim's own selective_disclosure flag decides; without
    one, a top-level claim is disclosable, a second-level claim is if its
    parent is, and a deeper claim is not. The one rule for both the issued
    credential (formatter_func.sdjwtNestedClaims) and its published type
    metadata (type_metadata._claims), so the two cannot disagree."""
    path = tuple(path)
    if path in flags:
        return flags[path]
    if len(path) == 1:
        return True
    if len(path) == 2:
        return is_disclosable(path[:1], flags)
    return False


def _by_name(claims):
    """The claims with claim_path paths, for the form builders below."""
    return [
        dict(claim, path=list(claim_path(claim))) if "path" in claim else claim
        for claim in claims
    ]


def _form_hints(claim):
    """Input hints a claim gives the form: a closed list of values (options),
    free values besides them (other_values: {"label", "used_if"}), an input
    pattern, and a condition on a sibling for the claim to be used
    (used_if: {"attribute": ..., "values": [...]}; the form shows and
    requires the claim only then). They live in issuer_conditions, which is
    not published in the issuer metadata."""
    conditions = claim.get("issuer_conditions", {})
    return {
        k: conditions[k]
        for k in ("options", "other_values", "pattern", "used_if")
        if k in conditions
    }


def getMandatoryAttributesSDJWT(claims):
    """
    Function to get mandatory attributes from credential in sd-jwt vc format
    """
    claims = _by_name(claims)
    attributes_form = {}

    level1_claims = []
    level2_claims = []
    level3_claims = []

    for claim in claims:
        if "overall_issuer_conditions" in claim:
            for key, value in claim["overall_issuer_conditions"].items():
                attributes_form.update({key: value})

        else:

            claim_depth = len(claim["path"])

            if claim_depth == 1:
                if claim["mandatory"] == True:
                    level1_claims.append(claim)
            elif claim_depth == 2:
                level2_claims.append(claim)
            elif claim_depth == 3:
                level3_claims.append(claim)

    for claim in level1_claims:
        attribute_name = claim["path"][0]
        if attribute_name == "nationalities":

            attributes_form.update(
                {
                    attribute_name: {
                        "type": claim["value_type"],
                        "filled_value": None,
                        "mandatory": True,
                    }
                }
            )
            attributes_form[attribute_name]["cardinality"] = {"min": 0, "max": "n"}
            attributes_form[attribute_name]["attributes"] = [
                {
                    "country_code": {
                        "mandatory": True,
                        "type": "string",
                        "source": "user",
                    }
                }
            ]

        if attribute_name == "place_of_birth":
            attributes_form.update(
                {
                    attribute_name: {
                        "type": "list",
                        "filled_value": None,
                        "mandatory": True,
                    }
                }
            )
            attributes_form[attribute_name]["cardinality"] = {"min": 0, "max": 1}
            attributes_form[attribute_name]["attributes"] = [
                {
                    "country": {
                        "mandatory": False,
                        "type": "string",
                        "source": "user",
                    }
                },
                {
                    "region": {
                        "mandatory": False,
                        "type": "string",
                        "source": "user",
                    }
                },
                {
                    "locality": {
                        "mandatory": False,
                        "type": "string",
                        "source": "user",
                    }
                },
            ]

        if "value_type" in claim and attribute_name not in (
            "nationalities",
            "place_of_birth",
        ):
            attributes_form.update(
                {
                    attribute_name: {
                        "type": claim["value_type"],
                        "filled_value": None,
                        "mandatory": True,
                        **_form_hints(claim),
                    }
                }
            )

        if "issuer_conditions" in claim and attribute_name not in (
            "nationalities",
            "place_of_birth",
        ):
            if "cardinality" in claim["issuer_conditions"]:
                attributes_form[attribute_name]["cardinality"] = claim[
                    "issuer_conditions"
                ]["cardinality"]

            if claim.get("value_type") and claim.get("value_type").endswith(
                "_attributes"
            ):
                attributes_form[attribute_name]["type"] = "list"
                attributes_form[attribute_name]["attributes"] = []

    for claim in level2_claims:
        attribute_name = claim["path"][0]

        if attribute_name not in attributes_form:
            continue

        if "attributes" not in attributes_form[attribute_name]:
            attributes_form[attribute_name]["type"] = "list"
            attributes_form[attribute_name]["attributes"] = []

        level2_name = claim["path"][1]
        attribute_details = {
            "mandatory": claim["mandatory"],
            "type": claim["value_type"],
            "source": claim["source"],
            **_form_hints(claim),
        }

        if "issuer_conditions" in claim:
            if "cardinality" in claim["issuer_conditions"]:
                attribute_details["cardinality"] = claim["issuer_conditions"][
                    "cardinality"
                ]
            if "not_used_if" in claim["issuer_conditions"]:
                attribute_details["not_used_if"] = claim["issuer_conditions"][
                    "not_used_if"
                ]

        attributes_form[attribute_name]["attributes"].append(
            {level2_name: attribute_details}
        )

    for claim in level3_claims:
        attribute_name = claim["path"][0]
        if attribute_name not in attributes_form:
            continue

        level2_name = claim["path"][1]
        level3_name = claim["path"][2]

        for l2_item_dict in attributes_form[attribute_name].get("attributes", []):
            if level2_name in l2_item_dict:
                l2_attribute = l2_item_dict[level2_name]
                if "attributes" not in l2_attribute:
                    l2_attribute["type"] = "list"
                    l2_attribute["attributes"] = []

                l2_attribute["attributes"].append(
                    {
                        level3_name: {
                            "mandatory": claim["mandatory"],
                            "type": claim[
                                "value_type"
                            ],  # FIX: Use 'type' for consistency
                            "source": claim["source"],
                            **_form_hints(claim),
                        }
                    }
                )

    return attributes_form


def getOptionalAttributesSDJWT(claims):
    """
    Function to get optional attributes from credential in sd-jwt vc format
    """
    claims = _by_name(claims)
    attributes_form = {}

    level1_claims = []
    level2_claims = []
    level3_claims = []

    for claim in claims:
        if "overall_issuer_conditions" in claim:
            for key, value in claim["overall_issuer_conditions"].items():
                attributes_form.update({key: value})

        else:
            claim_depth = len(claim["path"])

            if claim_depth == 1:
                if claim["mandatory"] == False:
                    level1_claims.append(claim)
            elif claim_depth == 2:
                level2_claims.append(claim)
            elif claim_depth == 3:
                level3_claims.append(claim)

    for claim in level1_claims:
        attribute_name = claim["path"][0]
        if attribute_name == "nationalities":
            attributes_form.update(
                {attribute_name: {"type": claim["value_type"], "filled_value": None}}
            )
            attributes_form[attribute_name]["cardinality"] = {"min": 0, "max": "n"}
            attributes_form[attribute_name]["attributes"] = [
                {
                    "country_code": {
                        "mandatory": True,
                        "type": "string",
                        "source": "user",
                    }
                }
            ]

        if "value_type" in claim and attribute_name != "nationalities":
            attributes_form.update(
                {
                    attribute_name: {
                        "type": claim["value_type"],
                        "filled_value": None,
                        **_form_hints(claim),
                    }
                }
            )

        if "issuer_conditions" in claim and attribute_name != "nationalities":
            if "cardinality" in claim["issuer_conditions"]:
                attributes_form[attribute_name]["cardinality"] = claim[
                    "issuer_conditions"
                ]["cardinality"]

    for claim in level2_claims:
        attribute_name = claim["path"][0]

        if attribute_name not in attributes_form:
            continue

        attributes_form[attribute_name]["type"] = "list"

        level2_name = claim["path"][1]
        attribute_details = {
            "mandatory": claim["mandatory"],
            "type": claim["value_type"],
            "source": claim["source"],
            **_form_hints(claim),
        }

        # Inside the attribute, as in getMandatoryAttributesSDJWT: next to it,
        # the form took them for attributes of their own ("Cardinality").
        if "issuer_conditions" in claim:
            if "cardinality" in claim["issuer_conditions"]:
                attribute_details["cardinality"] = claim["issuer_conditions"]["cardinality"]
            if "not_used_if" in claim["issuer_conditions"]:
                attribute_details["not_used_if"] = claim["issuer_conditions"]["not_used_if"]

        attributes_form[attribute_name].setdefault("attributes", []).append(
            {level2_name: attribute_details}
        )

    for claim in level3_claims:

        attribute_name = claim["path"][0]

        if attribute_name not in attributes_form:
            continue

        level2_name = claim["path"][1]
        level3_name = claim["path"][2]

        for attribute in attributes_form[attribute_name]["attributes"]:
            if level2_name in attribute:
                # A second-level group is a list of its third-level
                # attributes, as in getMandatoryAttributesSDJWT.
                if "attributes" not in attribute[level2_name]:
                    attribute[level2_name]["type"] = "list"
                attribute[level2_name].setdefault("attributes", []).append(
                    {
                        level3_name: {
                            "mandatory": claim["mandatory"],
                            "type": claim["value_type"],
                            "source": claim["source"],
                            **_form_hints(claim),
                        }
                    }
                )

    return attributes_form


def getAttributesForm2(credentials_requested):
    """
    Function to get attributes needed to populate form depending credentials requested by user

    Keyword arguments:"
    credentials_requested --credentials requested by the user

    """
    credentialsSupported = oidc_metadata["credential_configurations_supported"]

    attributes = {}
    for request in credentials_requested:
        format = credentialsSupported[request]["format"]
        attributes_req = {}

        if format == "mso_mdoc":
            namescapes = getNamespaces(
                credentialsSupported[request]["credential_metadata"]["claims"]
            )
            for namescape in namescapes:
                attributes_req.update(
                    getOptionalAttributes(
                        credentialsSupported[request]["credential_metadata"]["claims"],
                        namescape,
                    )
                )

        elif format == "dc+sd-jwt":
            attributes_req.update(
                getOptionalAttributesSDJWT(
                    credentialsSupported[request]["credential_metadata"]["claims"]
                )
            )

        for attribute in attributes_req:
            if attribute not in attributes:
                attributes.update({attribute: attributes_req[attribute]})

        if "birth_date" in attributes and "birthdate" in attributes:
            attributes.pop("birthdate")

    return attributes


def getOptionalAttributes(claims, namespace):
    """
    Function to get optional attributes from credential.
    Now passes the claim's value_type to the helper function.
    """
    attributes_form = {}

    for claim in claims:
        if "overall_issuer_conditions" in claim:
            for key, value in claim["overall_issuer_conditions"].items():
                attributes_form.update({key: value})
        elif not claim.get("mandatory") and claim.get("path", [None])[0] == namespace:
            attribute_name = claim["path"][1]
            attributes_form[attribute_name] = {
                "type": claim.get("value_type", "string"),
                "filled_value": None,
            }

            if "issuer_conditions" in claim:
                attributes_form[attribute_name]["type"] = "list"
                attributes_form[attribute_name]["cardinality"] = claim[
                    "issuer_conditions"
                ].get("cardinality")
                if "at_least_one_of" in claim["issuer_conditions"]:
                    attributes_form[attribute_name]["at_least_one_of"] = claim[
                        "issuer_conditions"
                    ]["at_least_one_of"]

                # Pass the value_type to the helper
                attributes_form[attribute_name]["attributes"] = (
                    _process_nested_attributes(
                        claim["issuer_conditions"], claim.get("value_type")
                    )
                )

    return attributes_form


def getIssuerFilledAttributes(claims, namespace):
    """
    Function to get mandatory attributes from credential
    """

    attributes_form = {}

    for claim in claims:
        if (
            "source" in claim
            and claim["source"] == "issuer"
            and claim["path"][0] == namespace
        ):
            attributes_form.update({claim["path"][1]: ""})

    return attributes_form


def getIssuerFilledAttributesSDJWT(claims):
    """
    Function to get mandatory attributes from credential
    """

    attributes_form = {}

    for claim in claims:
        if "source" in claim and claim["source"] == "issuer":
            attributes_form.update({claim["path"][0]: ""})

    return attributes_form


def generate_unique_id():
    """Function to generate a random uuid"""

    return str(uuid.uuid4())


def validate_image(file):
    """
    Converts input file value into base64url
    """
    try:
        if file.filename == "":
            return False, "No selected file"

        img = Image.open(file)

        width, height = img.size
        if width != 360 or height != 433:
            return False, "Image dimensions are invalid."
    except:
        return False, "Failed to open image."

    return True, None


def getSubClaims(claimLv1, vct):
    subclaims = []
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    for credential_id, credential in credentialsSupported.items():
        if "vct" not in credential or credential["vct"] != vct:
            continue
        else:
            for claim in credential["claims"]:
                if claim["path"][0] != claimLv1:
                    continue
                else:
                    subclaims.append(claim["path"])
    return subclaims


# Searches for credential metadata from doctype and format
def doctype2credential(doctype, format):
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    for credential_id, credential in credentialsSupported.items():
        if credential["format"] != format or credential["doctype"] != doctype:
            continue
        else:
            return credential


# Searches for credential metadata from doctype and format
def doctype2credentialSDJWT(doctype, format):
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    for credential_id, credential in credentialsSupported.items():
        if (
            credential["format"] == format
            and "doctype" in credential.get("issuer_config", {})
            and credential["issuer_config"]["doctype"] == doctype
        ):
            return credential
        else:
            continue


def vct2scope(vct: str):
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    for credential in credentialsSupported:
        if (
            "vct" in credentialsSupported[credential]
            and credentialsSupported[credential]["vct"] == vct
        ):
            return credentialsSupported[credential]["scope"]


def vct2doctype(vct: str):
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    for credential in credentialsSupported:
        if (
            "vct" in credentialsSupported[credential]
            and credentialsSupported[credential]["vct"] == vct
        ):
            issuer_config = credentialsSupported[credential].get("issuer_config")

            if issuer_config and "doctype" in issuer_config:
                return issuer_config["doctype"]
            else:
                return None


""" def vct2doctype(vct: str):
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    for credential in credentialsSupported:
        if (
            "vct" in credentialsSupported[credential]
            and credentialsSupported[credential]["vct"] == vct
        ):
            return credentialsSupported[credential]["issuer_config"]["doctype"] """


def vct2id(vct):
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    for credential in credentialsSupported:
        if (
            "vct" in credentialsSupported[credential]
            and credentialsSupported[credential]["vct"] == vct
        ):
            return credential


def doctype2vct(doctype: str):
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    for credential in credentialsSupported:
        if (
            "vct" in credentialsSupported[credential]
            and credentialsSupported[credential]["scope"] == doctype
        ):
            return credentialsSupported[credential]["vct"]


# Generates authorization details from a scope
# First supported credential found of that doctype
def scope2details(scope):
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    configuration_ids = []
    if "openid" not in scope:
        configuration_ids.append("openid")

    for item in scope:
        if item != "openid":
            for credential in credentialsSupported:
                if "scope" in credentialsSupported[credential]:
                    if credentialsSupported[credential]["scope"] == item:
                        configuration_ids.append(
                            {"credential_configuration_id": credential}
                        )

    return configuration_ids


def credential_error_resp(error, desc):
    return (
        jsonify(
            {
                "error": error,
                "error_description": desc,
                "c_nonce": secrets.token_urlsafe(16),
                "c_nonce_expires_in": 86400,
            }
        ),
        400,
    )


# Error redirection to the wallet during authentication without jws_token
def auth_error_redirect(return_uri, error, error_description=None):

    error_msg = {
        "error": error,
    }

    if error_description is not None:
        error_msg["error_description"] = error_description

    return redirect(
        url_get(return_uri, error_msg),
        code=302,
    )


class CertificateVerificationError(Exception):
    """Raised when certificate verification fails."""

    pass


def b64url_decode(data: str) -> bytes:
    """Decode base64url encoded data with proper padding."""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def verify_certificate_against_trusted_CA(certificate_der: bytes) -> x509.Certificate:
    """
    Verify a certificate against trusted CAs.

    Args:
        certificate_der: DER-encoded certificate bytes

    Returns:
        The verified certificate object

    Raises:
        CertificateVerificationError: If verification fails
    """
    logger.debug("Starting certificate verification")

    certificate = x509.load_der_x509_certificate(certificate_der, default_backend())
    issuer = certificate.issuer
    subject = certificate.subject

    logger.debug(f"Certificate subject: {subject}")
    logger.debug(f"Certificate issuer: {issuer}")

    now = datetime.datetime.now(datetime.timezone.utc)

    # Check if issued by trusted CA
    """ if issuer not in trusted_CAs:
        logger.error(
            f"Certificate not issued by a trusted CA. Issuer: {issuer}"
        )
        raise CertificateVerificationError(
            f"Certificate not issued by a trusted CA. Issuer: {issuer}"
        ) """

    logger.debug(f"Certificate issuer found in trusted CAs")

    """ ca_info = trusted_CAs[issuer]
    public_key_ca = ca_info["public_key"]

    # Verify certificate signature using CA's public key
    try:
        logger.debug("Verifying certificate signature")
        public_key_ca.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm),
        )
        logger.debug("Certificate signature verified successfully")
    except InvalidSignature:
        logger.error(
            "Certificate signature verification failed: Invalid signature"
        )
        raise CertificateVerificationError("Certificate signature invalid")
    except Exception as e:
        logger.error(f"Certificate signature verification failed: {e}")
        raise CertificateVerificationError(f"Signature verification failed: {e}") """

    # Check the CERTIFICATE's validity period (not the CA's)
    """ cert_not_before = certificate.not_valid_before_utc
    cert_not_after = certificate.not_valid_after_utc """

    """ logger.debug(
        f"Certificate validity period: {cert_not_before} to {cert_not_after}"
    )
    logger.debug(f"Current time: {now}")

    if now < cert_not_before:
        logger.error(
            f"Certificate not yet valid. Valid from: {cert_not_before}, current time: {now}"
        )
        raise CertificateVerificationError(
            f"Certificate not yet valid. Valid from: {cert_not_before}"
        )
    if now > cert_not_after:
        logger.error(
            f"Certificate expired. Valid until: {cert_not_after}, current time: {now}"
        )
        raise CertificateVerificationError(
            f"Certificate expired. Valid until: {cert_not_after}"
        ) """

    logger.debug("Certificate validity period check passed")

    # Optional: Also check if the CA certificate itself is still valid
    """ ca_not_valid_before = ca_info["not_valid_before"].replace(
        tzinfo=datetime.timezone.utc
    )
    ca_not_valid_after = ca_info["not_valid_after"].replace(
        tzinfo=datetime.timezone.utc
    )

    logger.debug(
        f"CA validity period: {ca_not_valid_before} to {ca_not_valid_after}"
    )

    if not (ca_not_valid_before <= now <= ca_not_valid_after):
        logger.error(
            f"CA certificate not currently valid. Valid period: {ca_not_valid_before} to {ca_not_valid_after}"
        )
        raise CertificateVerificationError("CA certificate not currently valid") """

    logger.debug("CA certificate validity check passed")
    logger.debug("Certificate verification completed successfully")

    return certificate


def extract_public_key_from_x5c(
    jwt_raw: str, allowed_algorithms: Optional[list[str]] = None
) -> Tuple[CertificatePublicKeyTypes, str]:
    """
    Extract and verify the public key from x5c header in a JWT.

    Args:
        jwt_raw: The raw JWT as a string
        allowed_algorithms: List of allowed signing algorithms (e.g., ['ES256', 'RS256'])
                          If None, any algorithm in the header is accepted (less secure)

    Raises:
        ValueError: If the x5c header is missing or algorithm is not allowed
        CertificateVerificationError: If certificate verification fails

    Returns:
        Tuple of (public_key, algorithm)
    """
    logger.debug("Extracting public key from x5c header")

    unverified_header = jwt.get_unverified_header(jwt_raw)
    logger.debug(f"JWT header (unverified): {unverified_header}")

    # Validate algorithm before using it (prevent algorithm confusion attacks)
    alg = unverified_header.get("alg")
    if not alg:
        logger.error("Algorithm not specified in JWT header")
        raise ValueError("Algorithm not specified in JWT header")

    logger.debug(f"JWT algorithm: {alg}")

    if allowed_algorithms:
        if alg not in allowed_algorithms:
            logger.error(
                f"Algorithm '{alg}' not in allowed list: {allowed_algorithms}"
            )
            raise ValueError(
                f"Algorithm '{alg}' not allowed. Permitted algorithms: {allowed_algorithms}"
            )
        logger.debug(f"Algorithm '{alg}' is allowed")
    else:
        logger.warning(
            "No algorithm whitelist specified - accepting any algorithm (less secure)"
        )

    # Get x5c certificate chain
    x5c_chain = unverified_header.get("x5c")
    if not x5c_chain:
        logger.error("x5c header not found in JWT")
        raise ValueError("x5c header not found in JWT")

    if not isinstance(x5c_chain, list) or len(x5c_chain) == 0:
        logger.error(
            f"x5c header must be a non-empty array, got: {type(x5c_chain)}"
        )
        raise ValueError("x5c header must be a non-empty array")

    logger.debug(f"x5c chain contains {len(x5c_chain)} certificate(s)")

    # Decode and verify the leaf certificate (first in chain)
    try:
        x5c_cert_der = b64url_decode(x5c_chain[0])
        logger.debug(
            f"Decoded certificate from x5c[0], length: {len(x5c_cert_der)} bytes"
        )
    except Exception as e:
        logger.error(f"Failed to decode x5c certificate: {e}")
        raise ValueError(f"Invalid base64 encoding in x5c[0]: {e}")

    # Verify certificate against trusted CA (this loads and validates it)
    verified_certificate = verify_certificate_against_trusted_CA(x5c_cert_der)

    logger.debug(
        "Successfully extracted and verified public key from x5c"
    )

    # Extract public key from the VERIFIED certificate
    return verified_certificate.public_key(), alg


def verify_jwt_with_x5c(
    jwt_raw: str,
    audience: Optional[str] = None,
    issuer: Optional[str] = None,
    allowed_algorithms: Optional[list[str]] = None,
    verify_exp: bool = True,
) -> Dict[str, Any]:
    """
    Verify a JWT using the x5c certificate chain in its header.

    Args:
        jwt_raw: The raw JWT as a string
        audience: Expected audience claim (validated if provided)
        issuer: Expected issuer claim (validated if provided)
        allowed_algorithms: List of allowed signing algorithms
        verify_exp: Whether to verify expiration (default: True)

    Returns:
        Decoded JWT claims if valid

    Raises:
        ValueError: If certificate verification or JWT structure is invalid
        CertificateVerificationError: If certificate verification fails
        jwt.ExpiredSignatureError: If the token has expired
        jwt.InvalidIssuerError: If the issuer claim doesn't match expected
        jwt.InvalidAudienceError: If the audience claim doesn't match expected
        jwt.InvalidTokenError: For other JWT validation failures
    """
    logger.debug("Starting JWT verification with x5c")
    logger.debug(
        f"Expected audience: {audience}, Expected issuer: {issuer}"
    )
    logger.debug(f"Verify expiration: {verify_exp}")

    # Extract and verify the public key from x5c
    public_key, alg = extract_public_key_from_x5c(jwt_raw, allowed_algorithms)

    # Build options for PyJWT
    options = {"verify_exp": verify_exp}

    logger.debug(f"Decoding JWT with algorithm: {alg}")

    # Verify the JWT signature and claims using PyJWT
    claims = jwt.decode(
        jwt_raw,
        key=public_key,
        algorithms=[alg],
        audience=audience,
        issuer=issuer,
        options=options,
    )

    logger.debug("JWT signature and claims verified successfully")
    logger.debug(f"JWT claims: {claims}")

    return claims



def verify_wua_jwt_with_x5c(
    jwt_raw: str,
    audience: Optional[str] = None,
    issuer: Optional[str] = None,
    allowed_algorithms: Optional[list[str]] = None,
    verify_exp: bool = True,
) -> Dict[str, Any]:
    """
    Verify a JWT using the x5c certificate chain in its header.

    Args:
        jwt_raw: The raw JWT as a string
        audience: Expected audience claim (validated if provided)
        issuer: Expected issuer claim (validated if provided)
        allowed_algorithms: List of allowed signing algorithms
        verify_exp: Whether to verify expiration (default: True)

    Returns:
        Decoded JWT claims if valid

    Raises:
        ValueError: If certificate verification or JWT structure is invalid
        CertificateVerificationError: If certificate verification fails
        jwt.ExpiredSignatureError: If the token has expired
        jwt.InvalidIssuerError: If the issuer claim doesn't match expected
        jwt.InvalidAudienceError: If the audience claim doesn't match expected
        jwt.InvalidTokenError: For other JWT validation failures
    """
    logger.debug("Starting JWT verification with x5c")
    logger.debug(
        f"Expected audience: {audience}, Expected issuer: {issuer}"
    )
    logger.debug(f"Verify expiration: {verify_exp}")

    # Extract and verify the public key from x5c
    public_key, alg = extract_public_key_from_x5c_wua(jwt_raw, allowed_algorithms)

    # Build options for PyJWT
    options = {"verify_exp": verify_exp}

    logger.debug(f"Decoding JWT with algorithm: {alg}")

    # Verify the JWT signature and claims using PyJWT
    claims = jwt.decode(
        jwt_raw,
        key=public_key,
        algorithms=[alg],
        audience=audience,
        issuer=issuer,
        options=options,
    )

    logger.debug("JWT signature and claims verified successfully")
    logger.debug(f"JWT claims: {claims}")

    return claims


def extract_public_key_from_x5c_wua(
    jwt_raw: str, allowed_algorithms: Optional[list[str]] = None
) -> Tuple[CertificatePublicKeyTypes, str]:
    """
    Extract and verify the public key from x5c header in a JWT.

    Args:
        jwt_raw: The raw JWT as a string
        allowed_algorithms: List of allowed signing algorithms (e.g., ['ES256', 'RS256'])
                          If None, any algorithm in the header is accepted (less secure)

    Raises:
        ValueError: If the x5c header is missing or algorithm is not allowed
        CertificateVerificationError: If certificate verification fails

    Returns:
        Tuple of (public_key, algorithm)
    """
    logger.debug("Extracting public key from x5c header")

    unverified_header = jwt.get_unverified_header(jwt_raw)
    logger.debug(f"JWT header (unverified): {unverified_header}")

    # Validate algorithm before using it (prevent algorithm confusion attacks)
    alg = unverified_header.get("alg")
    if not alg:
        logger.error("Algorithm not specified in JWT header")
        raise ValueError("Algorithm not specified in JWT header")

    logger.debug(f"JWT algorithm: {alg}")

    if allowed_algorithms:
        if alg not in allowed_algorithms:
            logger.error(
                f"Algorithm '{alg}' not in allowed list: {allowed_algorithms}"
            )
            raise ValueError(
                f"Algorithm '{alg}' not allowed. Permitted algorithms: {allowed_algorithms}"
            )
        logger.debug(f"Algorithm '{alg}' is allowed")
    else:
        logger.warning(
            "No algorithm whitelist specified - accepting any algorithm (less secure)"
        )

    # Get x5c certificate chain
    x5c_chain = unverified_header.get("x5c")
    if not x5c_chain:
        logger.error("x5c header not found in JWT")
        raise ValueError("x5c header not found in JWT")

    if not isinstance(x5c_chain, list) or len(x5c_chain) == 0:
        logger.error(
            f"x5c header must be a non-empty array, got: {type(x5c_chain)}"
        )
        raise ValueError("x5c header must be a non-empty array")

    logger.debug(f"x5c chain contains {len(x5c_chain)} certificate(s)")

    # Decode and verify the leaf certificate (first in chain)
    try:
        x5c_cert_der = b64url_decode(x5c_chain[0])
        logger.debug(
            f"Decoded certificate from x5c[0], length: {len(x5c_cert_der)} bytes"
        )
    except Exception as e:
        logger.error(f"Failed to decode x5c certificate: {e}")
        raise ValueError(f"Invalid base64 encoding in x5c[0]: {e}")

    # Verify certificate against trusted CA (this loads and validates it)
    #verified_certificate = verify_certificate_against_trusted_CA(x5c_cert_der)

    if CONFIGURATION["trust_validator"]["enabled"]:
        verified = call_trust_validator(
                url=CONFIGURATION["trust_validator"]["url"],
                chain=x5c_chain,
                verification_context="WalletUnitAttestation")
    else:
        verified = True

    if not verified:
        logger.error("Certificate verification failed by trust validator")
        raise CertificateVerificationError("Certificate verification failed by trust validator")

    cert_der = base64.b64decode(x5c_chain[0])
    verified_certificate = x509.load_der_x509_certificate(cert_der)

    logger.debug(
        "Successfully extracted and verified public key from x5c"
    )
        
    # Extract public key from the VERIFIED certificate
    return verified_certificate.public_key(), alg



def call_trust_validator(url: str, chain: list[str], verification_context: str, timeout: int = 10):
    """
    Generic function to call the trust validator.

    Args:
        url: Trust validator endpoint
        chain: certificate chain (list of base64 certs)
        verification_context: Validation context (e.g., WalletUnitAttestation, PID)
        timeout: Request timeout in seconds

    Returns:
        dict: Parsed JSON response from the trust validator
    """

    payload = {
        "chain": chain,
        "verificationContext": verification_context
    }

    headers = {
        "accept": "application/json",
        "Content-Type": "application/json"
    }

    response = requests.post(url, json=payload, headers=headers, timeout=timeout)
    response.raise_for_status()

    data = response.json()

    return bool(data.get("trusted", False))