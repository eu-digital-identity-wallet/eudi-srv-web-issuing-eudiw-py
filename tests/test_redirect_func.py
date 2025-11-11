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
from unittest.mock import patch, MagicMock
from flask import Flask, json
from app import redirect_func as rf


@pytest.fixture
def app():
    """Creates a Flask app for testing redirects."""
    app = Flask(__name__)
    app.secret_key = "test_secret"
    return app


class TestRedirectFunc:
    @patch("app.redirect_func.cfgserv")
    def test_url_get_simple(self, mock_cfgserv):
        url = "http://example.com"
        args = {"a": "1", "b": "2"}
        result = rf.url_get(url, args)
        assert result.startswith(url)
        assert "a=1" in result and "b=2" in result

    @patch("app.redirect_func.requests.post")
    def test_json_post_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        url = "http://example.com"
        payload = {"key": "value"}
        resp = rf.json_post(url, payload)
        mock_post.assert_called_once_with(
            url, json=payload, headers={"Content-Type": "application/json"}
        )
        assert resp.status_code == 200

    @patch("app.redirect_func.requests.post", side_effect=Exception("fail"))
    def test_json_post_exception(self, mock_post):
        url = "http://example.com"
        payload = {"key": "value"}
        with pytest.raises(Exception) as excinfo:
            rf.json_post(url, payload)
        assert "fail" in str(excinfo.value)

    @patch("app.redirect_func.render_template_string")
    def test_post_redirect_with_payload(self, mock_render):
        target_url = "https://wallet.com/callback"
        payload = {"key": "value"}

        # Call the function
        rf.post_redirect_with_payload(target_url, payload)

        # Ensure render_template_string was called
        assert mock_render.called

        # Grab kwargs
        args, kwargs = mock_render.call_args
        data_passed = kwargs.get("data")

        # Decode the payload passed to the template
        decoded_payload = json.loads(data_passed)

        # Check that the payload matches
        assert decoded_payload["key"] == "value"

        # Check that the URL was passed correctly (key is 'url', not 'target_url')
        assert kwargs.get("url") == target_url

    # ---------------------------
    # Test post_redirect_with_payload edge cases
    # ---------------------------
    @patch("app.redirect_func.render_template_string")
    def test_post_redirect_empty_payload(self, mock_render):
        target_url = "https://wallet.com/callback"
        payload = {}
        rf.post_redirect_with_payload(target_url, payload)
        args, kwargs = mock_render.call_args
        data_passed = kwargs.get("data")
        decoded_payload = json.loads(data_passed)
        assert decoded_payload == {}
        assert kwargs.get("url") == target_url

    # -----------------------------
    # post_redirect_with_payload empty string payload
    # -----------------------------
    @patch("app.redirect_func.render_template_string")
    def test_post_redirect_with_payload_empty_string(self, mock_render):
        target_url = "https://example.com"
        payload = {"key": ""}
        rf.post_redirect_with_payload(target_url, payload)
        args, kwargs = mock_render.call_args
        decoded_payload = json.loads(kwargs["data"])
        assert decoded_payload["key"] == ""
