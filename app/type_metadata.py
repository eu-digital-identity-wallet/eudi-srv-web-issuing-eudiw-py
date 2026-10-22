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
SD-JWT VC Type Metadata (draft-ietf-oauth-sd-jwt-vc, section 6) for the
credentials this issuer issues, built from their configuration. The WE BUILD
rulebooks require it: the SCA rulebooks for the issuer-specific vct, which is a
URL of this issuer and extends the WE BUILD base type, and the eReceipt
rulebook for its Claim Selective Disclosure Metadata.

- /credentials/<path>: the document of an SD-JWT VC type whose vct is a URL
  ending in /credentials/<path>, so it is retrievable from the vct itself.
- /type-metadata/<vct>: the document of any SD-JWT VC type, by vct.
"""
import logging

from flask import Blueprint, abort, jsonify
from flask_cors import CORS

from app import oidc_metadata
from misc import (
    KEEP_SINGLE_GROUPS_AS_LISTS,
    array_claims,
    claim_path,
    is_disclosable,
    sd_flags,
    with_array_segments,
)

logger = logging.getLogger(__name__)

# The types already warned about for lacking extends#integrity
_warned_without_integrity = set()

type_metadata = Blueprint("type_metadata", __name__, url_prefix="/")
CORS(type_metadata)


def _sd_jwt_configs():
    for config in oidc_metadata["credential_configurations_supported"].values():
        if config.get("format") == "dc+sd-jwt" and "vct" in config:
            yield config


def _display(entry):
    display = {k: entry[k] for k in ("locale", "name", "description") if k in entry}
    simple = {k: entry[k] for k in ("logo", "background_color", "text_color") if k in entry}
    if simple:
        display["rendering"] = {"simple": simple}
    return display


def _claims(config):
    """Claim metadata with the issuer's actual selective disclosure: the
    rule app/formatter_func.py sdjwtNestedClaims issues by
    (misc.is_disclosable). Paths get a null segment after every array the
    issuer actually issues, whether or not the configured path has it
    (misc.array_claims)."""
    claims = config["credential_metadata"]["claims"]
    by_path = {claim_path(c): c for c in claims if "path" in c}
    flags = sd_flags(claims)
    arrays = array_claims(
        claims,
        single_groups_as_objects=config.get("scope") not in KEEP_SINGLE_GROUPS_AS_LISTS,
    )

    out = []
    for path, c in by_path.items():
        entry = {
            "path": with_array_segments(path, arrays),
            "sd": "always" if is_disclosable(path, flags) else "never",
        }
        if "display" in c:
            entry["display"] = [
                {"locale": d.get("locale", "en"), "label": d["name"]}
                for d in c["display"]
                if "name" in d
            ]
        out.append(entry)
    return out


def _document(config):
    displays = config.get("credential_metadata", {}).get("display", [])
    document = {"vct": config["vct"]}
    if displays:
        document["name"] = displays[0].get("name")
        if "description" in displays[0]:
            document["description"] = displays[0]["description"]
    # The SCA rulebooks require both: the base type, and the hash of the base
    # type document this issuer was built against (an SRI string,
    # "sha256-<base64>"). The hash is configured, not computed from the base
    # document as it is now, as that would defeat its purpose.
    type_config = config.get("issuer_config", {}).get("type_metadata", {})
    if type_config.get("extends"):
        document["extends"] = type_config["extends"]
        if type_config.get("extends#integrity"):
            document["extends#integrity"] = type_config["extends#integrity"]
        elif config["vct"] not in _warned_without_integrity:
            # Once per type, not on every request
            _warned_without_integrity.add(config["vct"])
            logger.warning(
                "Type %s extends %s without extends#integrity; wallets "
                "following the SCA rulebooks reject it",
                config["vct"],
                type_config["extends"],
            )
    document["display"] = [_display(d) for d in displays]
    document["claims"] = _claims(config)
    return document


@type_metadata.route("/credentials/<path:subpath>")
def vct_document(subpath):
    for config in _sd_jwt_configs():
        if config["vct"].endswith(f"/credentials/{subpath}"):
            return jsonify(_document(config))
    abort(404)


@type_metadata.route("/type-metadata/<path:vct>")
def type_metadata_by_vct(vct):
    for config in _sd_jwt_configs():
        if config["vct"] == vct:
            return jsonify(_document(config))
    abort(404)
