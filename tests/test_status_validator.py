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
"""Tests for the status-list validator client (single and batch mode)."""

from unittest.mock import MagicMock, patch

import pytest
import requests
from flask import Flask

from app.services import auth_server, nightly_sweep
from app.services.auth_server import StatusCheckError, check_status_list_revocation
from config_helpers import patch_configuration

URL = "https://status-validator.test/status"
STATUS_URI = "https://issuer.test/token_status_list/FC/urn:eudi:pid:1/list"


def _response(status=200, body=None, text=""):
    response = MagicMock()
    response.status_code = status
    response.text = text
    if body is None:
        response.json.side_effect = ValueError("no json")
    else:
        response.json.return_value = body
    if status >= 400:
        response.raise_for_status.side_effect = requests.HTTPError(str(status))
    return response


@pytest.fixture
def status_config():
    with patch_configuration({"status_validator": {"enabled": True, "url": URL}}) as cfg:
        yield cfg


class TestCheckStatusListRevocation:
    """Single-check mode: POST /status {idx, uri, validation_context}."""

    def test_valid_entry(self, status_config):
        with patch("app.services.auth_server.requests.post", return_value=_response(body={"valid": True, "status": 0})) as post:
            assert check_status_list_revocation(URL, 7, STATUS_URI) is False
        assert post.call_args.kwargs["json"] == {
            "idx": 7,
            "uri": STATUS_URI,
            "validation_context": "WalletOrKeyStorageStatus",
        }

    def test_revoked_entry(self, status_config):
        with patch("app.services.auth_server.requests.post", return_value=_response(body={"valid": False, "status": 1})):
            assert check_status_list_revocation(URL, 7, STATUS_URI) is True

    def test_context_from_configuration(self):
        cfg = {"status_validator": {"enabled": True, "url": URL, "validation_context": "Custom"}}
        with patch_configuration(cfg), patch(
            "app.services.auth_server.requests.post", return_value=_response(body={"valid": True})
        ) as post:
            check_status_list_revocation(URL, 1, STATUS_URI)
        assert post.call_args.kwargs["json"]["validation_context"] == "Custom"

    def test_explicit_context(self, status_config):
        with patch("app.services.auth_server.requests.post", return_value=_response(body={"valid": True})) as post:
            check_status_list_revocation(URL, 1, STATUS_URI, validation_context="PIDStatus")
        assert post.call_args.kwargs["json"]["validation_context"] == "PIDStatus"

    @pytest.mark.parametrize(
        "status, error",
        [
            (400, "Index 999999 is out of range for this Status List"),
            (403, "Certificate chain in Status List Token was rejected by the trust validator"),
            (502, "HTTP error fetching status list"),
        ],
    )
    def test_error_statuses_raise_with_message(self, status_config, status, error):
        with patch("app.services.auth_server.requests.post", return_value=_response(status, {"error": error})):
            with pytest.raises(StatusCheckError, match=f"HTTP {status}: {error}"):
                check_status_list_revocation(URL, 1, STATUS_URI)

    def test_network_error(self, status_config):
        with patch("app.services.auth_server.requests.post", side_effect=requests.ConnectionError("down")):
            with pytest.raises(StatusCheckError, match="unreachable"):
                check_status_list_revocation(URL, 1, STATUS_URI)

    def test_missing_valid_flag(self, status_config):
        with patch("app.services.auth_server.requests.post", return_value=_response(body={"status": 0})):
            with pytest.raises(StatusCheckError, match="no 'valid' flag"):
                check_status_list_revocation(URL, 1, STATUS_URI)

    def test_non_json_error_body(self, status_config):
        with patch("app.services.auth_server.requests.post", return_value=_response(500, None, text="boom")):
            with pytest.raises(StatusCheckError, match="HTTP 500: boom"):
                check_status_list_revocation(URL, 1, STATUS_URI)


class TestIssuanceFailsClosed:
    """WIA / key attestation status errors reject the request instead of crashing."""

    CLIENT_STATUS = {"status": {"status_list": {"idx": 3, "uri": STATUS_URI}}, "exp": 9999999999}

    @pytest.fixture
    def app(self):
        return Flask(__name__)

    def _introspection(self):
        response = MagicMock()
        response.json.return_value = {"active": True, "username": "session-1"}
        return response

    def _verify(self, app, revoked=None, error=None, client_status=CLIENT_STATUS, check=None):
        from app.routes import oidc

        check = check or MagicMock(return_value=revoked, side_effect=error)
        with app.app_context(), patch.object(oidc, "introspect", return_value=self._introspection()), patch.object(
            oidc, "decode_authorization_server_jwt", return_value={"client_status": client_status}
        ), patch.object(oidc, "check_status_list_revocation", check):
            return oidc.verify_introspection("header.payload.signature")

    @pytest.mark.parametrize(
        "client_status",
        [{"exp": 1}, {"status": None}, {"status": {"status_list": {"idx": 3}}}, "not-a-dict"],
    )
    def test_malformed_client_status_fails_closed(self, app, status_config, client_status):
        check = MagicMock()
        response, status = self._verify(app, client_status=client_status, check=check)
        assert status == 401
        assert response.get_json()["error_description"] == "Malformed client_status"
        check.assert_not_called()

    def test_wia_valid(self, app, status_config):
        assert self._verify(app, revoked=False) == ("session-1", self.CLIENT_STATUS)

    def test_wia_revoked(self, app, status_config):
        response, status = self._verify(app, revoked=True)
        assert status == 401
        assert response.get_json() == {"error": "invalid_token"}

    def test_wia_status_unverifiable(self, app, status_config):
        response, status = self._verify(app, error=StatusCheckError("HTTP 403: rejected"))
        assert status == 401
        assert response.get_json()["error_description"] == "Wallet status could not be verified"

    def _attestation_claims(self):
        return {
            "attested_keys": [],
            "key_storage_status": {"exp": 4102444800, "status": {"status_list": {"idx": 1, "uri": STATUS_URI}}},
        }

    def test_key_attestation_status_unverifiable(self, status_config):
        from app.services import credential_issuance

        with patch.object(credential_issuance, "verify_jwt_with_x5c", return_value=self._attestation_claims()), patch.object(
            credential_issuance, "check_status_list_revocation", side_effect=StatusCheckError("HTTP 502: down")
        ):
            with pytest.raises(credential_issuance.KeyAttestationStatusError, match="could not be verified"):
                credential_issuance.decode_verify_attestation("ka.jwt")

            with pytest.raises(credential_issuance.InvalidProofError, match="could not be verified"):
                credential_issuance._verified_attestation("ka.jwt", "session-1", "test", require_nonce=True)

    def test_key_attestation_revoked(self, status_config):
        from app.services import credential_issuance

        with patch.object(credential_issuance, "verify_jwt_with_x5c", return_value=self._attestation_claims()), patch.object(
            credential_issuance, "check_status_list_revocation", return_value=True
        ):
            with pytest.raises(credential_issuance.KARevokedError):
                credential_issuance.decode_verify_attestation("ka.jwt")


def _entry(idx, uri=STATUS_URI):
    return {"status_list": {"idx": idx, "uri": uri}}


class TestNightlyBatch:
    """Batch mode: POST /status {checks: [...]} with results correlated by index."""

    def test_results_correlated_by_index(self, status_config):
        body = {
            "results": [
                {"index": 1, "valid": False, "status": 1, "status_code": 200},
                {"index": 0, "valid": True, "status": 0, "status_code": 200},
            ]
        }
        with patch("app.services.nightly_sweep.requests.post", return_value=_response(body=body)) as post:
            results = nightly_sweep.check_statuses_batch([_entry(10), _entry(11)])

        assert [r["valid"] for r in results] == [True, False]
        assert post.call_args.kwargs["json"] == {
            "checks": [
                {"idx": 10, "uri": STATUS_URI, "validation_context": "WalletOrKeyStorageStatus"},
                {"idx": 11, "uri": STATUS_URI, "validation_context": "WalletOrKeyStorageStatus"},
            ]
        }

    def test_malformed_entries_not_sent(self, status_config):
        body = {"results": [{"index": 0, "valid": False, "status": 1, "status_code": 200}]}
        with patch("app.services.nightly_sweep.requests.post", return_value=_response(body=body)) as post:
            results = nightly_sweep.check_statuses_batch([{"status_list": {"idx": 1}}, _entry(5)])

        assert post.call_args.kwargs["json"]["checks"] == [
            {"idx": 5, "uri": STATUS_URI, "validation_context": "WalletOrKeyStorageStatus"}
        ]
        assert results[0] == {"error": "malformed_status_entry"}
        assert results[1]["valid"] is False
        assert [nightly_sweep.is_revoked(r) for r in results] == [False, True]

    def test_only_malformed_entries_makes_no_request(self, status_config):
        with patch("app.services.nightly_sweep.requests.post") as post:
            results = nightly_sweep.check_statuses_batch([{}, {"status_list": {"uri": "x"}}])
        post.assert_not_called()
        assert results == [{"error": "malformed_status_entry"}] * 2

    def test_per_item_error_is_not_revoked(self, status_config):
        body = {"results": [{"index": 0, "error": "rejected by the trust validator", "status_code": 403}]}
        with patch("app.services.nightly_sweep.requests.post", return_value=_response(body=body)):
            results = nightly_sweep.check_statuses_batch([_entry(1)])
        assert nightly_sweep.is_revoked(results[0]) is False

    def test_request_failure_marks_chunk(self, status_config):
        with patch("app.services.nightly_sweep.requests.post", return_value=_response(400, {"error": "bad"})):
            results = nightly_sweep.check_statuses_batch([_entry(1), {}])
        assert results == [{"error": "request_failed"}, {"error": "malformed_status_entry"}]

    def test_chunks_of_100(self, status_config):
        def reply(url, json, **kwargs):
            return _response(body={"results": [{"index": i, "valid": True} for i in range(len(json["checks"]))]})

        with patch("app.services.nightly_sweep.requests.post", side_effect=reply) as post:
            results = nightly_sweep.check_statuses_batch([_entry(i) for i in range(205)])

        assert [len(c.kwargs["json"]["checks"]) for c in post.call_args_list] == [100, 100, 5]
        assert len(results) == 205 and all(r["valid"] for r in results)

    def test_empty(self, status_config):
        assert nightly_sweep.check_statuses_batch([]) == []


def test_default_context_constant():
    assert auth_server.WALLET_STATUS_CONTEXT == "WalletOrKeyStorageStatus"
