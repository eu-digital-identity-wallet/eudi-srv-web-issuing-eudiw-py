"""GRNET fork: the WE BUILD SCA-Card (DPC) attestation, see app.services.sca_card."""

import datetime
import uuid
from unittest.mock import patch

import pytest

from app.services import sca_card
from app.services.dynamic_formatter import credentialCreation, update_dates_and_special_claims
from app.services.sca_card import add_card_to_presentation, sca_card_choice, sca_card_display

MOCK_TODAY = datetime.date(2026, 11, 9)

CARD_DISPLAY = {
    "type": {"code": "CREDIT", "label": "Credit card"},
    "network_branding": {"name": "Mastercard", "logo": [{"theme": "DEFAULT", "image_url": "https://x/mc.png"}]},
    "products": [
        {
            "alias": "Partner Bank Mastercard",
            "card_art": [{"theme": "DEFAULT", "image_url": "https://x/partner.png"}],
            "issuer": {"branding": {"name": "Partner Bank"}},
        },
        {
            "alias": "Gold Mastercard",
            "card_art": [{"theme": "DEFAULT", "image_url": "https://x/gold.png"}],
            "issuer": {"branding": {"name": "Mastercard"}},
        },
    ],
}
CARD_CONFIG = {
    "issuing_authority": "Test SCA issuer",
    "validity": 730,
    "network": "mastercard",
    "card_display": CARD_DISPLAY,
}
METADATA = {
    "credential_configurations_supported": {
        "card": {"scope": "card", "format": "dc+sd-jwt", "issuer_config": CARD_CONFIG},
        "pid": {"scope": "pid", "format": "dc+sd-jwt", "issuer_config": {"validity": 90}},
    }
}


@pytest.fixture
def metadata():
    with patch.object(sca_card, "oidc_metadata", METADATA):
        yield


def _special_claims(issuer_claims, issuer_config):
    data = {}
    update_dates_and_special_claims(
        data, issuer_claims, "", MOCK_TODAY, MOCK_TODAY, {"scope": "s", "issuer_config": issuer_config}, issuer_config
    )
    return data


class TestSpecialClaims:
    def test_attestation_legal_category_from_issuer_config(self):
        """The legal category is the credential's own, from its issuer_config."""
        data = _special_claims({"attestation_legal_category"}, {"attestation_legal_category": "non-qualified-EAA"})
        assert data["attestation_legal_category"] == "non-qualified-EAA"

    def test_credential_id_is_a_new_urn_uuid_each_time(self):
        """credential_id identifies the issued credential, so it never repeats."""
        ids = [_special_claims({"credential_id"}, {})["credential_id"] for _ in range(2)]
        for credential_id in ids:
            assert credential_id.startswith("urn:uuid:")
            uuid.UUID(credential_id.removeprefix("urn:uuid:"))
        assert ids[0] != ids[1]

    def test_card_network_and_card_id_from_the_issuer(self):
        """A test card: network as configured, card_id a fresh opaque UUID."""
        cards = []
        for _ in range(2):
            data = _special_claims({"network", "card_id"}, {"network": "mastercard"})
            assert data["network"] == "mastercard"
            uuid.UUID(data["card_id"])
            cards.append(data["card_id"])
        assert cards[0] != cards[1]

    def test_rulebook_claims_only_when_issuer_filled(self):
        """No rulebook claim is added to a credential that does not declare it."""
        data = _special_claims({"issuing_authority"}, {"issuing_authority": "IA", "network": "mastercard"})
        assert not {"attestation_legal_category", "credential_id", "network", "card_id"} & data.keys()


class TestCardChoice:
    def test_one_option_per_product(self, metadata):
        field = sca_card_choice(["pid", "card"])
        assert field["type"] == "card_choice" and field["mandatory"]
        assert [o["label"] for o in field["options"]] == ["Partner Bank Mastercard", "Gold Mastercard"]
        for option in field["options"]:
            assert option["value"] == f"{option['label']}|{option['last_four']}"
            assert len(option["last_four"]) == 4 and option["last_four"].isdigit()
            assert option["expiry"] == (datetime.date.today() + datetime.timedelta(days=730)).strftime("%m/%y")

    def test_none_without_cards(self, metadata):
        assert sca_card_choice(["pid"]) is None
        assert sca_card_choice(["unknown"]) is None


class TestCardDisplay:
    def test_the_picked_card(self):
        card = sca_card_display(CARD_CONFIG, card="Gold Mastercard|1234")["card"]
        assert card["alias"] == "Gold Mastercard"
        assert card["last_four"] == "1234"
        assert card["issuer"] == {"branding": {"name": "Mastercard"}}
        assert card["type"] == CARD_DISPLAY["type"]
        assert card["network_branding"] == {"network": "mastercard", "branding": CARD_DISPLAY["network_branding"]}

    @pytest.mark.parametrize("value", [None, "", "Unknown|12", "Gold Mastercard|abcd", 5])
    def test_falls_back_to_the_first_product_with_made_up_digits(self, value):
        card = sca_card_display(CARD_CONFIG, card=value)["card"]
        if value != "Gold Mastercard|abcd":
            assert card["alias"] == "Partner Bank Mastercard"
        assert len(card["last_four"]) == 4 and card["last_four"].isdigit()

    def test_none_without_card_display(self):
        assert sca_card_display({"validity": 90}) is None


class TestPresentation:
    def test_shows_the_card_and_its_issuer(self):
        data = {"issuing_authority": "Test SCA issuer", "issuing_country": "FC"}
        add_card_to_presentation(data, CARD_CONFIG, "Partner Bank Mastercard|4321")
        assert data["card_display"]["last_four"] == "4321"
        assert data["card_display"]["expiry"] == (datetime.date.today() + datetime.timedelta(days=730)).strftime(
            "%m/%y"
        )
        assert data["issuing_authority"] == "Partner Bank"
        assert "issuing_country" not in data

    def test_leaves_other_credentials_alone(self):
        data = {"issuing_authority": "IA", "issuing_country": "FC"}
        add_card_to_presentation(data, {"validity": 90}, None)
        assert data == {"issuing_authority": "IA", "issuing_country": "FC"}


class TestCredentialResponse:
    @pytest.fixture
    def creation(self):
        with patch("app.services.dynamic_formatter.oidc_metadata", METADATA), patch(
            "app.services.dynamic_formatter._supports_country", return_value=True
        ), patch("app.services.dynamic_formatter.issuing_country_code", return_value="FC"), patch(
            "app.services.dynamic_formatter.dynamic_formatter", return_value="CREDENTIAL"
        ):
            yield

    def _request(self, scope, proofs=2):
        return {"credential_configuration_id": scope, "proofs": [{"jwt": f"k{i}"} for i in range(proofs)]}

    def test_one_display_for_the_batch(self, creation):
        response = credentialCreation(self._request("card"), {"card": "Gold Mastercard|9876"}, "FC", "sid")
        assert response["credentials"] == [{"credential": "CREDENTIAL"}] * 2
        assert len(response["display"]) == 1
        assert response["display"][0]["card"]["alias"] == "Gold Mastercard"
        assert response["display"][0]["card"]["last_four"] == "9876"

    def test_display_with_a_credential_identifier(self, creation):
        """The configuration is found by its id, not by its scope."""
        metadata = {"credential_configurations_supported": {"card_config": dict(
            METADATA["credential_configurations_supported"]["card"], scope="card.scope"
        )}}
        request = {"credential_identifier": "card_config", "proofs": [{"jwt": "k"}]}
        with patch("app.services.dynamic_formatter.oidc_metadata", metadata):
            response = credentialCreation(request, {"card": "Gold Mastercard|9876"}, "FC", "sid")
        assert response["display"][0]["card"]["alias"] == "Gold Mastercard"

    def test_no_display_for_other_credentials(self, creation):
        response = credentialCreation(self._request("pid"), {}, "FC", "sid")
        assert "display" not in response
