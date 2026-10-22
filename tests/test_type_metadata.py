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
from app import type_metadata

CONFIG = {
    "format": "dc+sd-jwt",
    "vct": "https://issuer.test/credentials/sca/iban/1.0",
    "credential_metadata": {
        "display": [{"name": "SCA IBAN", "locale": "en", "description": "d",
                     "logo": {"uri": "https://issuer.test/logo.png"}}],
        "claims": [
            {"path": ["sub"], "selective_disclosure": False,
             "display": [{"name": "Subject", "locale": "en"}]},
            {"path": ["masked_iban"], "display": [{"name": "Masked IBAN", "locale": "en"}]},
            {"path": ["products"], "value_type": "products_attributes",
             "issuer_conditions": {"cardinality": {"min": 1, "max": "n"}}},
            {"path": ["products", "name"]},
            {"path": ["products", "vats", "rate"]},
        ],
    },
    "issuer_config": {"type_metadata": {"extends": "https://base.test/sca-iban/1.0"}},
}


def test_document():
    document = type_metadata._document(CONFIG)

    assert document["vct"] == CONFIG["vct"]
    assert document["name"] == "SCA IBAN"
    assert document["extends"] == "https://base.test/sca-iban/1.0"
    assert document["display"] == [{
        "locale": "en", "name": "SCA IBAN", "description": "d",
        "rendering": {"simple": {"logo": {"uri": "https://issuer.test/logo.png"}}},
    }]
    claims = {tuple(c["path"]): c for c in document["claims"]}
    assert claims[("sub",)]["sd"] == "never"
    assert claims[("sub",)]["display"] == [{"locale": "en", "label": "Subject"}]
    assert claims[("masked_iban",)]["sd"] == "always"
    # Array levels get a null segment; SD as sdjwtNestedClaims applies it.
    assert claims[("products", None, "name")]["sd"] == "always"
    assert claims[("products", None, "vats", "rate")]["sd"] == "never"


def test_routes(monkeypatch):
    from flask import Flask

    receipt = dict(CONFIG, vct="eu.we-build.ereceipt.1", issuer_config={})
    monkeypatch.setitem(
        type_metadata.oidc_metadata,
        "credential_configurations_supported",
        {"x": CONFIG, "y": receipt},
    )
    app = Flask(__name__)
    app.register_blueprint(type_metadata.type_metadata)
    client = app.test_client()

    assert client.get("/credentials/sca/iban/1.0").json["vct"] == CONFIG["vct"]
    response = client.get("/type-metadata/eu.we-build.ereceipt.1")
    assert response.json["vct"] == "eu.we-build.ereceipt.1"
    assert "extends" not in response.json
    assert client.get("/credentials/sca/other/1.0").status_code == 404
    assert client.get("/type-metadata/unknown").status_code == 404


def test_array_segments():
    config = {
        "scope": "s",
        "credential_metadata": {"claims": [
            {"path": ["group"], "value_type": "group_attributes",
             "issuer_conditions": {"cardinality": {"min": 1, "max": 1}}},
            {"path": ["group", "id"]},
            # A list the issuer fills in itself: the null in the path says so.
            {"path": ["provider", "ids", None, "value"]},
        ]},
    }
    paths = [c["path"] for c in type_metadata._claims(config)]
    assert ["group", "id"] in paths
    assert ["provider", "ids", None, "value"] in paths

    # EHIC keeps its single-occurrence groups as one-element lists.
    ehic = dict(config, scope="eu.europa.ec.eudi.ehic_sd_jwt_vc")
    assert ["group", None, "id"] in [c["path"] for c in type_metadata._claims(ehic)]


# --- The WE BUILD credentials as configured ----------------------------------

import json
import os

CONFIGS = os.path.join(
    os.path.dirname(__file__), "..", "app", "metadata_config", "credentials_supported"
)


def _config(file_name):
    with open(os.path.join(CONFIGS, file_name), encoding="utf-8") as f:
        (config,) = json.load(f).values()
    return config


WE_BUILD_SD_JWT = [
    "e_receipt_jwt_vc.json",
    "eu_cc_jwt_vc.json",
    "eu_poa_jwt_vc.json",
    "iban_ov_jwt_vc.json",
    "sca_iban_jwt_vc.json",
]


def test_configured_paths_are_the_issued_shape():
    """The issuer metadata publishes the configured paths; they must point
    into the credential as it is issued, arrays included."""
    for file_name in WE_BUILD_SD_JWT:
        config = _config(file_name)
        configured = [
            c["path"] for c in config["credential_metadata"]["claims"] if "path" in c
        ]
        published = [c["path"] for c in type_metadata._claims(config)]
        assert published == configured, file_name


def test_e_receipt_selective_disclosure():
    """rb-e-receipt section 5.1: the Disclosable column."""
    sd = {
        tuple(s for s in c["path"] if s is not None): c["sd"]
        for c in type_metadata._claims(_config("e_receipt_jwt_vc.json"))
    }
    must = [
        ("type",), ("receipt_number",), ("receipt_timestamp",), ("currency_iso_code",),
        ("total_price_exc_vat",), ("total_vat_amount",), ("total_price_inc_vat",),
        ("merchant", "name"), ("merchant", "company_id"),
        ("merchant", "branch", "id"), ("merchant", "branch", "pos_id"),
        ("merchant", "branch", "name"),
        ("merchant", "address", "street_address"), ("merchant", "address", "city"),
        ("merchant", "address", "zip_code"), ("merchant", "address", "country"),
        ("products",), ("products", "name"), ("products", "quantity"),
        ("products", "quantity_code"), ("products", "unit_price_inc_vat"),
        ("products", "total_amount_exc_vat"), ("products", "total_amount_inc_vat"),
        ("products", "vats"), ("products", "vats", "vat_rate"),
        ("products", "vats", "vat_amount"), ("products", "vats", "total_amount_exc_vat"),
        ("products", "vats", "total_amount_inc_vat"),
        ("vats",), ("vats", "vat_rate"), ("vats", "total_vat_amount"),
        ("vats", "total_amount_exc_vat"), ("vats", "total_amount_inc_vat"),
        ("payments",), ("payments", "type"), ("payments", "amount"),
    ]
    must_not = [("attestation_legal_category",)] + [
        path for path in sd if path[0] == "verifications"
    ]
    assert [p for p in must if sd[p] != "always"] == []
    assert [p for p in must_not if sd[p] != "never"] == []


def test_extends_integrity(caplog, monkeypatch):
    """rb-sca-iban / rb-sca-card-dpc 4.5: extends and extends#integrity."""
    monkeypatch.setattr(type_metadata, "_warned_without_integrity", set())
    pinned = dict(CONFIG, issuer_config={"type_metadata": {
        "extends": "https://base.test/sca-iban/1.0",
        "extends#integrity": "sha256-AAAA",
    }})
    document = type_metadata._document(pinned)
    assert document["extends#integrity"] == "sha256-AAAA"

    with caplog.at_level("WARNING"):
        document = type_metadata._document(CONFIG)
    assert "extends#integrity" not in document
    assert "without extends#integrity" in caplog.text

    # Once per type, not on every request
    caplog.clear()
    with caplog.at_level("WARNING"):
        type_metadata._document(CONFIG)
    assert "without extends#integrity" not in caplog.text


def _sample_data(entries):
    """Data with every claim of the type metadata entries, one element in
    every array. Children first, so a group is the container they made."""
    data = {}
    for entry in sorted(entries, key=lambda e: -len(e["path"])):
        node, path = data, entry["path"]
        for i, segment in enumerate(path):
            if segment is None:
                continue
            if i == len(path) - 1:
                node.setdefault(segment, "x")
            elif path[i + 1] is None:
                node = node.setdefault(segment, [{}])[0]
            else:
                node = node.setdefault(segment, {})
    return data


def _issued_disclosures(value, path=()):
    """Whether each claim of an issued (nested) claim set is disclosable."""
    from sd_jwt.common import SDObj

    found = {}
    if isinstance(value, dict):
        for key, child in value.items():
            name = key.value if isinstance(key, SDObj) else key
            found[path + (name,)] = isinstance(key, SDObj)
            found.update(_issued_disclosures(child, path + (name,)))
    elif isinstance(value, list):
        for element in value:
            found.update(_issued_disclosures(element, path))
    return found


def test_published_disclosure_is_the_issued_one():
    """The type metadata says of every claim what the issued credential does
    (rb-e-receipt 5.1: the Type Metadata SHALL match the issued SD-JWT VC)."""
    from app.formatter_func import sdjwtNestedClaims

    for file_name in WE_BUILD_SD_JWT + ["sca_card_dpc.json"]:
        config = _config(file_name)
        entries = type_metadata._claims(config)
        issued = _issued_disclosures(sdjwtNestedClaims(_sample_data(entries), config))

        published = {
            tuple(s for s in e["path"] if s is not None): e["sd"] == "always"
            for e in entries
        }
        assert set(published) == set(issued), file_name
        assert [p for p in published if published[p] != issued[p]] == [], file_name
