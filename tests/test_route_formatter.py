# tests/test_route_formatter.py
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
import pytest
from unittest.mock import patch
from flask import Flask, json
from app.route_formatter import formatter
from app.app_config.config_service import ConfService as cfgservice


@pytest.fixture
def app():
    app = Flask(__name__)
    app.register_blueprint(formatter)
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


# -------------------------
# Tests for /formatter/cbor
# -------------------------
@patch("app.route_formatter.validate_mandatory_args")
@patch("app.route_formatter.mdocFormatter")
def test_cborformatter_success(mock_mdocFormatter, mock_validate, client):
    mock_validate.return_value = (True, [])
    mock_mdocFormatter.return_value = "base64mdoc"

    payload = {
        "credential_metadata": {"doctype": "org.iso.18013.5.1.mDL"},
        "country": "FC",  # use actual example country
        "device_publickey": "pubkey",
        "data": {
            "org.iso.18013.5.1": {
                "expiry_date": "2025-12-31",
                "issue_date": "2023-01-01",
            }
        },
    }

    with patch("app.route_formatter.validate_date_format", return_value=True):
        response = client.post("/formatter/cbor", json=payload)

    data = json.loads(response.data)
    assert response.status_code == 200
    assert data["error_code"] == 0
    assert data["mdoc"] == "base64mdoc"


@patch("app.route_formatter.validate_mandatory_args")
def test_cborformatter_invalid_expiry_date(mock_validate, client):
    mock_validate.return_value = (True, [])
    payload = {
        "credential_metadata": {"doctype": "org.iso.18013.5.1.mDL"},
        "country": "FC",
        "device_publickey": "pub",
        "data": {
            "org.iso.18013.5.1": {"expiry_date": "invalid", "issue_date": "2023-01-01"}
        },
    }
    with patch("app.route_formatter.validate_date_format", return_value=False):
        response = client.post("/formatter/cbor", json=payload)
    data = json.loads(response.data)
    assert data["error_code"] == 306


@patch("app.route_formatter.validate_mandatory_args")
def test_cborformatter_invalid_issue_date(mock_validate, client):
    mock_validate.return_value = (True, [])
    payload = {
        "credential_metadata": {"doctype": "org.iso.18013.5.1.mDL"},
        "country": "FC",
        "device_publickey": "pub",
        "data": {
            "org.iso.18013.5.1": {"expiry_date": "2025-12-31", "issue_date": "invalid"}
        },
    }
    with patch("app.route_formatter.validate_date_format", side_effect=[True, False]):
        response = client.post("/formatter/cbor", json=payload)
    data = json.loads(response.data)
    assert data["error_code"] == 306


# ---------------------------
# Tests for /formatter/sd-jwt
# ---------------------------
@patch("app.route_formatter.sdjwtFormatter")
def test_sd_jwtformatter_success(mock_sdjwtFormatter, client):
    mock_sdjwtFormatter.return_value = "signed_sdjwt"
    payload = {"country": "FC", "data": {}, "credential_metadata": {}}
    response = client.post("/formatter/sd-jwt", json=payload)
    data = json.loads(response.data)
    assert response.status_code == 200
    assert data["error_code"] == 0
    assert data["sd-jwt"] == "signed_sdjwt"


@patch("app.route_formatter.validate_mandatory_args")
def test_cborformatter_missing_mandatory_args(mock_validate, client):
    # Simulate missing mandatory args
    mock_validate.return_value = (False, ["country", "device_publickey"])

    payload = {
        # intentionally missing 'country' and 'device_publickey'
        "credential_metadata": {"doctype": "org.iso.18013.5.1.mDL"},
        "data": {
            "org.iso.18013.5.1": {
                "expiry_date": "2025-12-31",
                "issue_date": "2023-01-01",
            }
        },
    }

    response = client.post("/formatter/cbor", json=payload)
    data = json.loads(response.data)

    assert response.status_code == 200
    assert data["error_code"] == 401
    assert data["error_message"] == cfgservice.error_list["401"]
    assert data["mdoc"] == ""


@patch("app.route_formatter.validate_mandatory_args")
def test_cborformatter_unsupported_country(mock_validate, client):
    # Simulate mandatory args validation passing
    mock_validate.return_value = (True, [])

    payload = {
        "credential_metadata": {"doctype": "org.iso.18013.5.1.mDL"},
        "country": "XX",  # Unsupported country code
        "device_publickey": "pubkey",
        "data": {
            "org.iso.18013.5.1": {
                "expiry_date": "2025-12-31",
                "issue_date": "2023-01-01",
            }
        },
    }

    response = client.post("/formatter/cbor", json=payload)
    data = json.loads(response.data)

    assert response.status_code == 200
    assert data["error_code"] == 102
    assert data["error_message"] == cfgservice.error_list["102"]
    assert data["mdoc"] == ""
