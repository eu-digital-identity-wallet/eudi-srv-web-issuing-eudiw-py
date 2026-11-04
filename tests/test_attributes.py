###############################################################################
# Copyright (c) 2026 European Commission
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
"""Tests for form-attribute extraction and credential metadata lookups."""

from unittest.mock import patch

import pytest

from app.services import attributes as attrs

NS = "eu.europa.ec.eudi.pid.1"


def _claim(path, mandatory=True, value_type="string", source="user", **extra):
    return {"path": path, "mandatory": mandatory, "value_type": value_type, "source": source, **extra}


@pytest.fixture
def credentials():
    configs = {
        "pid_mdoc": {
            "format": "mso_mdoc",
            "scope": "pid_mdoc",
            "credential_metadata": {
                "display": [{"name": "PID (mdoc)"}],
                "claims": [
                    _claim([NS, "family_name"]),
                    _claim([NS, "birth_date"], value_type="full-date"),
                    _claim([NS, "nickname"], mandatory=False),
                    _claim([NS, "issuing_country"], source="issuer"),
                ],
            },
        },
        "pid_sdjwt": {
            "format": "dc+sd-jwt",
            "scope": "pid_sdjwt",
            "vct": "urn:pid",
            "credential_metadata": {
                "display": [{"name": "PID (SD-JWT)"}],
                "claims": [
                    _claim(["family_name"]),
                    _claim(["birthdate"], value_type="full-date"),
                    _claim(["nationality"]),
                    _claim(["nationalities"], value_type="nationalities"),
                ],
            },
        },
        "other": {"format": "jwt_vc_json", "scope": "other", "credential_metadata": {"display": [{"name": "x"}], "claims": []}},
    }
    with patch.dict("app.core.state.oidc_metadata", {"credential_configurations_supported": configs}, clear=True):
        yield configs


class TestLookups:
    def test_requested_credential_ids(self):
        details = [
            {"credential_configuration_id": "a"},
            {"vct": "urn:b"},
            {"credential_configuration_id": "a"},
            {"type": "openid_credential"},
        ]
        assert attrs.requested_credential_ids(details) == ["a", "urn:b"]
        assert attrs.requested_credential_ids(details, resolve_vct=lambda v: v.upper()) == ["a", "URN:B"]

    def test_credential_display_names(self, credentials):
        assert attrs.credential_display_names() == {
            "sd-jwt vc format": {"pid_sdjwt": "PID (SD-JWT)"},
            "mdoc format": {"pid_mdoc": "PID (mdoc)"},
        }
        only_mdoc = attrs.credential_display_names(lambda cid, cfg: cfg["format"] == "mso_mdoc")
        assert only_mdoc["sd-jwt vc format"] == {}

    def test_scope2details(self, credentials):
        assert attrs.scope2details(["pid_mdoc", "unknown"]) == ["openid", {"credential_configuration_id": "pid_mdoc"}]
        assert attrs.scope2details(["openid", "pid_sdjwt"]) == [{"credential_configuration_id": "pid_sdjwt"}]

    def test_vct2id(self, credentials):
        assert attrs.vct2id("urn:pid") == "pid_sdjwt"
        assert attrs.vct2id("urn:nope") is None

    def test_optional_only(self):
        assert attrs.optional_only({"a": 1, "b": 2}, {"a": 0}) == {"b": 2}


class TestNestedAttributes:
    def test_value_type_key_with_options_and_nested_conditions(self):
        conditions = {
            "places": {
                "country": {"value_type": "string", "mandatory": True, "source": "user", "options": ["PT", "FR"]},
                "region": {
                    "value_type": "region_attributes",
                    "issuer_conditions": {
                        "cardinality": {"min": 0, "max": 1},
                        "not_used_if": {"attribute": "country"},
                        "region_attributes": {"name": {"value_type": "string"}},
                    },
                },
                "ignored": "not a definition",
            }
        }
        result = attrs._process_nested_attributes(conditions, "places")

        assert result["country"] == {"type": "string", "mandatory": True, "source": "user", "filled_value": None, "options": ["PT", "FR"]}
        region = result["region"]
        assert region["type"] == "list" and region["cardinality"] == {"min": 0, "max": 1}
        assert region["not_used_if"] == {"attribute": "country"}
        assert region["attributes"] == {"name": {"type": "string", "mandatory": False, "source": None, "filled_value": None}}
        assert "ignored" not in result

    def test_list_definitions(self):
        conditions = {
            "places_attributes": [
                {"attribute": "no_fixed_place", "value_type": "x", "x": {"code": {"value_type": "string"}}},
                {"value_type": "skipped-without-attribute"},
            ]
        }
        assert attrs._process_nested_attributes(conditions) == [
            {
                "attribute": "no_fixed_place",
                "attributes": {"code": {"type": "string", "mandatory": False, "source": None, "filled_value": None}},
            }
        ]

    def test_attributes_given_directly(self):
        assert list(attrs._process_nested_attributes({"vehicle": {"value_type": "string"}})) == ["vehicle"]

    def test_nothing_to_process(self):
        assert attrs._process_nested_attributes({"cardinality": {"min": 1}}) == {}


class TestMdocAttributes:
    def test_mandatory_and_optional_with_conditions(self):
        claims = [
            {"overall_issuer_conditions": {"at_least_one_of": ["a", "b"]}},
            _claim(
                [NS, "privileges"],
                value_type="privileges",
                issuer_conditions={"cardinality": {"min": 1}, "at_least_one_of": ["x"], "privileges": {"code": {"value_type": "string"}}},
            ),
            _claim([NS, "nickname"], mandatory=False, issuer_conditions={"cardinality": {"max": 2}}),
            _claim([NS, "issued"], source="issuer"),
            _claim(["other.ns", "x"]),
        ]

        mandatory = attrs.getMandatoryAttributes(claims, NS)
        assert mandatory["at_least_one_of"] == ["a", "b"]
        assert mandatory["privileges"]["type"] == "list" and mandatory["privileges"]["mandatory"] is True
        assert mandatory["privileges"]["at_least_one_of"] == ["x"]
        assert "code" in mandatory["privileges"]["attributes"]
        assert "issued" not in mandatory and "x" not in mandatory

        optional = attrs.getOptionalAttributes(claims, NS)
        assert optional["nickname"] == {"type": "list", "filled_value": None, "cardinality": {"max": 2}, "attributes": {}}

    def test_issuer_filled(self):
        claims = [_claim([NS, "issuing_country"], source="issuer"), _claim(["other", "x"], source="issuer"), _claim([NS, "a"])]
        assert attrs.getIssuerFilledAttributes(claims, NS) == {"issuing_country": ""}
        assert attrs.getIssuerFilledAttributesSDJWT([_claim(["iss_claim"], source="issuer"), _claim(["a"])]) == {"iss_claim": ""}


class TestSdJwtAttributes:
    CLAIMS = [
        {"overall_issuer_conditions": {"at_least_one_of": ["address"]}},
        _claim(["nationalities"], value_type="nationalities"),
        _claim(["place_of_birth"], value_type="place_of_birth"),
        _claim(["address"], value_type="address_attributes", issuer_conditions={"cardinality": {"min": 0, "max": 1}}),
        _claim(["address", "street"], issuer_conditions={"cardinality": {"min": 1}, "not_used_if": {"x": 1}}),
        _claim(["address", "geo"], value_type="object"),
        _claim(["address", "geo", "lat"], value_type="number"),
        _claim(["unknown_parent", "child"]),
        _claim(["unknown_parent", "child", "leaf"]),
        _claim(["nickname"], mandatory=False, issuer_conditions={"cardinality": {"max": 3}}),
        _claim(["nickname", "short"], mandatory=False),
        _claim(["nickname", "long"], mandatory=False, issuer_conditions={"cardinality": {"max": 1}}),
        _claim(["nickname", "short", "first"], mandatory=False),
        _claim(["tags"], mandatory=False, value_type="nationalities"),
        _claim(["a", "b", "c", "d"]),
    ]

    def test_mandatory(self):
        form = attrs.getMandatoryAttributesSDJWT(self.CLAIMS)

        assert form["at_least_one_of"] == ["address"]
        assert form["nationalities"]["attributes"] == [{"country_code": {"mandatory": True, "type": "string", "source": "user"}}]
        assert form["place_of_birth"]["cardinality"] == {"min": 0, "max": 1}
        assert [list(a)[0] for a in form["place_of_birth"]["attributes"]] == ["country", "region", "locality"]

        address = form["address"]
        assert address["type"] == "list" and address["cardinality"] == {"min": 0, "max": 1}
        street, geo = address["attributes"]
        assert street["street"] == {"mandatory": True, "type": "string", "source": "user", "cardinality": {"min": 1}, "not_used_if": {"x": 1}}
        assert geo["geo"]["type"] == "list" and geo["geo"]["attributes"] == [{"lat": {"mandatory": True, "type": "number", "source": "user"}}]
        assert "unknown_parent" not in form and "nickname" not in form

    def test_templates_are_not_shared(self):
        first = attrs.getMandatoryAttributesSDJWT(self.CLAIMS)
        first["nationalities"]["attributes"][0]["country_code"]["mandatory"] = False
        second = attrs.getMandatoryAttributesSDJWT(self.CLAIMS)
        assert second["nationalities"]["attributes"][0]["country_code"]["mandatory"] is True

    def test_optional(self):
        form = attrs.getOptionalAttributesSDJWT(self.CLAIMS)

        # Special handling is by claim name, not value type.
        assert form["tags"] == {"type": "nationalities", "filled_value": None}
        nickname = form["nickname"]
        assert nickname["type"] == "list" and nickname["cardinality"] == {"max": 3}
        # 'short' starts the first entry; 'long' carries its own cardinality, so it is merged into the first entry
        assert nickname["attributes"][0]["short"]["attributes"] == [{"first": {"mandatory": False, "type": "string", "source": "user"}}]
        assert nickname["attributes"][0]["cardinality"] == {"max": 1}
        assert "family_name" not in form and "address" not in form

    def test_optional_nationalities(self):
        form = attrs.getOptionalAttributesSDJWT([_claim(["nationalities"], mandatory=False, value_type="array")])
        assert form["nationalities"]["cardinality"] == {"min": 0, "max": "n"}
        assert form["nationalities"]["attributes"] == [{"country_code": {"mandatory": True, "type": "string", "source": "user"}}]

    def test_optional_appends_after_cardinality_entry(self):
        claims = [
            _claim(["n"], mandatory=False),
            _claim(["n", "a"], mandatory=False, issuer_conditions={"cardinality": {"max": 1}}),
            _claim(["n", "b"], mandatory=False),
        ]
        assert [sorted(entry) for entry in attrs.getOptionalAttributesSDJWT(claims)["n"]["attributes"]] == [["a", "cardinality"], ["b"]]


class TestAttributesForm:
    def test_mandatory_merge_and_deduplication(self, credentials):
        credentials["pid_sdjwt"]["credential_metadata"]["claims"].append(_claim(["birth_date"]))
        form = attrs.getAttributesForm(["pid_mdoc", "pid_sdjwt", "other"])

        assert {"family_name", "birth_date", "nationality"} <= set(form)
        assert "birthdate" not in form and "nationalities" not in form
        assert form["family_name"]["type"] == "string"  # first credential wins

    def test_optional_form(self, credentials):
        form = attrs.getAttributesForm2(["pid_mdoc", "pid_sdjwt"])
        assert form == {"nickname": {"type": "string", "filled_value": None}}

    @pytest.mark.parametrize("requested", [["pid_mdoc"], ["pid_sdjwt"], ["pid_mdoc", "pid_sdjwt"], ["pid_sdjwt", "pid_mdoc"]])
    def test_picture_shown_as_portrait(self, credentials, requested):
        credentials["pid_mdoc"]["credential_metadata"]["claims"].append(_claim([NS, "portrait"], mandatory=False, value_type="jpeg"))
        credentials["pid_sdjwt"]["credential_metadata"]["claims"].append(_claim(["picture"], mandatory=False, value_type="jpeg"))
        form = attrs.getAttributesForm2(requested)

        assert "picture" not in form
        assert form["portrait"] == {"type": "jpeg", "filled_value": None}
