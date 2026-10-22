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
from flask import Blueprint, abort, jsonify
from flask_cors import CORS

from app import oidc_metadata

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
    """Claim metadata with the issuer's actual selective disclosure, as
    app/formatter_func.py sdjwtNestedClaims applies it. Array levels get a
    null path segment, as the metadata paths leave them out."""
    claims = config["credential_metadata"]["claims"]
    by_path = {tuple(c["path"]): c for c in claims if "path" in c}
    arrays = {
        path
        for path, c in by_path.items()
        if c.get("issuer_conditions", {}).get("cardinality", {}).get("max") == "n"
        and (c.get("value_type") or "").endswith("_attributes")
    }

    def sd(path):
        flag = by_path.get(path, {}).get("selective_disclosure")
        if flag is not None:
            return flag
        if len(path) == 1:
            return True
        if len(path) == 2:
            return sd(path[:1])
        return False

    out = []
    for path, c in by_path.items():
        typed_path = []
        for i, segment in enumerate(path):
            typed_path.append(segment)
            if path[: i + 1] in arrays and i + 1 < len(path):
                typed_path.append(None)
        entry = {"path": typed_path, "sd": "always" if sd(path) else "never"}
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
    extends = config.get("issuer_config", {}).get("type_metadata", {}).get("extends")
    if extends:
        document["extends"] = extends
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
