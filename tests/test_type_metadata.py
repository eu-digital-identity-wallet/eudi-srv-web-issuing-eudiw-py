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
