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
"""GRNET fork: the WE BUILD SCA-Card (DPC) attestation (rb-sca-card-dpc).

A test issuer stands in for the card issuer, which would know the user's
cards. The user picks a card by its card art on the attribute form
(:func:`sca_card_choice`); the card's display meta-data goes on the consent
page and in the credential response (:func:`sca_card_display`). A credential
opts in with ``card_display`` and ``network`` in its ``issuer_config``.
"""

from __future__ import annotations

import datetime
import re
import secrets
import uuid
from typing import Any, Dict, Iterable, Optional

from app.core.state import oidc_metadata

#: The form field that carries the chosen card, ``"<alias>|<last four>"``.
CARD_FIELD = "card"


def _made_up_last_four() -> str:
    return f"{secrets.randbelow(10000):04d}"


def add_special_claims(data: Dict[str, Any], issuer_claims: Dict[str, Any], doctype_config: Dict[str, Any]) -> None:
    """Fills the issuer-controlled claims the WE BUILD rulebooks add.

    Args:
        data: Form data (mutated).
        issuer_claims: Issuer-filled attribute names.
        doctype_config: ``issuer_config`` of the credential.
    """
    # The rulebooks fix the legal category per attestation type, and not all
    # to the same value, so each credential declares its own.
    if "attestation_legal_category" in issuer_claims:
        data["attestation_legal_category"] = doctype_config["attestation_legal_category"]

    # Identifies this issued credential, not the subject or the card, so it is
    # new on every issuance (rb-sca-card-dpc, section 2.2).
    if "credential_id" in issuer_claims:
        data["credential_id"] = f"urn:uuid:{uuid.uuid4()}"

    # The holder types neither: one network per credential, as configured, and
    # a fresh opaque card reference that reveals nothing of a PAN
    # (rb-sca-card-dpc, IR-01 and IR-02).
    if "network" in issuer_claims:
        data["network"] = doctype_config["network"]

    if "card_id" in issuer_claims:
        data["card_id"] = str(uuid.uuid4())


def sca_card_choice(credentials_requested: Iterable[str]) -> Optional[Dict[str, Any]]:
    """The form field in which the user picks the card an SCA-Card is for.

    Each card is shown by its card art with its last four digits and expiry.
    The digits are made up here and travel in the option's value,
    ``"<alias>|<last four>"``, to :func:`sca_card_display`. The expiry is the
    credential's, from its validity; the display meta-data has no expiry
    (rb-sca-card-dpc, section 2.9), so it is shown here only.

    Args:
        credentials_requested: Credential configuration ids.

    Returns:
        The field, or ``None`` if no requested credential has cards configured.
    """
    credentials_supported = oidc_metadata.get("credential_configurations_supported", {})
    for credential_id in credentials_requested:
        issuer_config = credentials_supported.get(credential_id, {}).get("issuer_config", {})
        config = issuer_config.get("card_display")
        if not config:
            continue
        expiry = None
        if "validity" in issuer_config:
            expiry = (datetime.date.today() + datetime.timedelta(days=issuer_config["validity"])).strftime("%m/%y")
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


def sca_card_display(issuer_config: Dict[str, Any], card: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """The display meta-data of an SCA-Card attestation (rb-sca-card-dpc, section 2.9).

    It is unsigned and goes in the credential response's ``display`` array,
    not in the credential (sections 2.9 and 4.1). The card is the one the user
    picked, else the first configured product with made-up digits, as
    ``card_id`` is. The card issuer is the product's own, else the
    configuration's, as each card may be a different issuer's. The network
    branding is for the credential's own network, as IR-04 requires.

    Args:
        issuer_config: ``issuer_config`` of the credential.
        card: The form's ``card`` value, ``"<alias>|<last four>"``.

    Returns:
        ``{"card": {...}}``, or ``None`` if the credential has none configured.
    """
    config = issuer_config.get("card_display")
    if not config:
        return None

    alias, _, last_four = (card if isinstance(card, str) else "").rpartition("|")
    if not re.fullmatch(r"[0-9]{4}", last_four):
        last_four = _made_up_last_four()
    product = next((p for p in config["products"] if p["alias"] == alias), config["products"][0])
    display: Dict[str, Any] = {}
    if "type" in config:
        display["type"] = config["type"]
    display["last_four"] = last_four
    display["card_art"] = product["card_art"]
    display["alias"] = product["alias"]
    issuer = product.get("issuer", config.get("issuer"))
    if issuer:
        display["issuer"] = issuer
    display["network_branding"] = {
        "network": issuer_config["network"],
        "branding": config["network_branding"],
    }
    return {"card": display}


def add_card_to_presentation(data: Dict[str, Any], doctype_config: Dict[str, Any], card: Optional[str]) -> None:
    """Shows the picked card on the consent page, as on the form, so that the
    user recognises it before issuance (rb-sca-card-dpc, sections 2.9 and 4.1).

    A card's issuing authority is its issuer, the bank whose card the user
    picked; the country of the form it was asked for on means nothing for it.

    Args:
        data: Attributes shown for the credential (mutated).
        doctype_config: ``issuer_config`` of the credential.
        card: The form's ``card`` value.
    """
    card_display = sca_card_display(doctype_config, card=card)
    if not card_display:
        return
    expiry = datetime.date.today() + datetime.timedelta(days=doctype_config["validity"])
    data["card_display"] = dict(card_display["card"], expiry=expiry.strftime("%m/%y"))
    card_issuer = card_display["card"].get("issuer", {}).get("branding", {}).get("name")
    if card_issuer:
        data["issuing_authority"] = card_issuer
    data.pop("issuing_country", None)
