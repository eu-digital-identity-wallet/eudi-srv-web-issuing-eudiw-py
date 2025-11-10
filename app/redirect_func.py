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
The PID Issuer Web service is a component of the PID Provider backend.
Its main goal is to issue the PID and MDL in cbor/mdoc (ISO 18013-5 mdoc) and SD-JWT format.


This redirect_func.py file manages the redirection of the flow.
"""
import requests
import urllib.parse
from flask import json, redirect, render_template_string, session

from app_config.config_service import ConfService as cfgserv


def url_get(url_path: str, args: dict):
    """Returns the URL for a HTTP GET query

    Keyword arguments:
    + url_path -- URL without the GET parameters
    + args -- dictionary of parameters (key: value)

    Return: URL for a HTTP GET query
    """
    return url_path + "?" + urllib.parse.urlencode(args)


def json_post(url_path: str, json: dict):
    """Executes the HTTP POST to url_path with json payload

    Keyword arguments:
    + url_path -- URL to POST
    + json -- json payload dictionary (key: value)

    Return: Returns the answer to the HTTP POST
    """
    return requests.post(
        url_path, json=json, headers={"Content-Type": "application/json"}
    )


def post_redirect_with_payload(target_url: str, data_payload: dict):
    """
    Renders an intermediate HTML page containing an auto-submitting POST form.

    This is used to simulate an HTTP POST redirect, passing a JSON payload
    to an external service without hitting URL length limits.

    Args:
        target_url (str): The final URL the user's browser should be POSTed to.
        data_payload (dict): The Python dictionary to be serialized as JSON
                             and included in the POST request body under the
                             field name 'payload'.

    Returns:
        A Flask response object that renders the intermediate HTML.
    """
    # 1. Serialize the dictionary into a JSON string
    json_data_string = json.dumps(data_payload)

    # 2. Define the intermediate HTML template
    # Submit immediately without waiting for page load or rendering
    AUTO_SUBMIT_HTML = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Redirecting...</title>
        <style>
            body { margin: 0; padding: 0; overflow: hidden; }
            #redirect_form { display: none; }
        </style>
    </head>
    <body>
        <form id="redirect_form" method="POST" action="{{ url }}">
            <input type="hidden" name="payload" value='{{ data | safe }}'>
            <noscript>
                <div style="font-family: sans-serif; padding: 20px; text-align: center;">
                    <p>JavaScript is required. Please click the button below:</p>
                    <button type="submit" style="padding: 10px 20px; background-color: #007bff; color: white; border: none; border-radius: 6px; cursor: pointer;">
                        Continue
                    </button>
                </div>
            </noscript>
        </form>
        <script>
            // Submit immediately without waiting for full page load
            document.getElementById('redirect_form').submit();
        </script>
    </body>
    </html>
    """

    # 3. Render the HTML with the specific URL and data
    return render_template_string(
        AUTO_SUBMIT_HTML, url=target_url, data=json_data_string
    )
