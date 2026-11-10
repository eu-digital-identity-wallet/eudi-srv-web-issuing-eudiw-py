"""GRNET fork: every credential configuration parses in the EUDI wallet.

The wallet's OpenID4VCI library reads the whole issuer metadata at once, so one
configuration of the wrong shape makes every credential of the issuer
unavailable ("Failed to parse literal "ES256" as an int value", 2026-11-10,
from eu.webuildconsortium.sca.iban_mdoc).
"""

import glob
import json
import os

import pytest

CREDENTIALS_DIR = os.path.join(os.path.dirname(__file__), "..", "app", "metadata_config", "credentials_supported")


def _configurations():
    for path in sorted(glob.glob(os.path.join(CREDENTIALS_DIR, "*.json"))):
        with open(path, encoding="utf-8") as f:
            for configuration_id, configuration in json.load(f).items():
                yield pytest.param(configuration, id=f"{os.path.basename(path)}:{configuration_id}")


@pytest.mark.parametrize("configuration", list(_configurations()))
def test_signing_algorithms_have_the_type_of_their_format(configuration):
    """OpenID4VCI 1.0 appendix A: COSE algorithm identifiers (integers) for
    mso_mdoc, JOSE algorithm names (strings) for dc+sd-jwt."""
    algorithms = configuration.get("credential_signing_alg_values_supported") or []
    if configuration["format"] == "mso_mdoc":
        assert all(isinstance(a, int) and not isinstance(a, bool) for a in algorithms), algorithms
    elif configuration["format"] == "dc+sd-jwt":
        assert all(isinstance(a, str) for a in algorithms), algorithms
