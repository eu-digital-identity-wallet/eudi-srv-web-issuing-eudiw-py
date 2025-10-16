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
This route simulates a pre-authorization flow.
Currently the libraries used do not support pre-authorization.
This route generates a client registration capable of using a pre-authorization code for testing purposes.
"""

import base64
import io
import json
import random
from flask import (
    Blueprint,
    render_template,
    request,
    session,
)
from flask_cors import CORS
import requests
import urllib.parse
from datetime import datetime, timedelta, timezone

import segno

from app.route_dynamic import form_formatter, presentation_formatter
from .app_config.config_service import ConfService as cfgservice
from app.misc import (
    generate_unique_id,
    getAttributesForm,
    getAttributesForm2,
)

from . import session_manager


preauth = Blueprint("preauth", __name__, url_prefix="/")
CORS(preauth)  # enable CORS on the blue print


@preauth.route("/preauth", methods=["GET"])
def preauthRed():

    credentials_id = request.args.get("credentials_id")
    credential_list = json.loads(credentials_id)

    scope = " ".join(credential_list)
    print("\ncredential_list: ", scope)

    session_id = request_preauth_token(scope=scope)

    session["session_id"] = session_id
    print("\nsession_id")

    authorization_details = []

    for credential in credential_list:
        authorization_details.append(
            {"type": "openid_credential", "credential_configuration_id": credential}
        )

    print("\nauthorization_details: ", authorization_details)

    session_manager.update_authorization_details(
        session_id=session_id, authorization_details=authorization_details
    )

    # session["authorization_details"] = authorization_details

    credentials_requested = []
    for cred in authorization_details:
        if "credential_configuration_id" in cred:
            if cred["credential_configuration_id"] not in credentials_requested:
                credentials_requested.append(cred["credential_configuration_id"])
        elif "vct" in cred:
            if cred["vct"] not in credentials_requested:
                credentials_requested.append(cred["vct"])

    session_manager.update_credentials_requested(
        session_id=session_id, credentials_requested=credentials_requested
    )

    print("\ncredentials_requested", credentials_requested)

    # session["credentials_requested"] = credentials_requested

    mandatory_attributes = getAttributesForm(credentials_requested)

    optional_attributes_raw = getAttributesForm2(credentials_requested)

    optional_attributes_filtered = {
        key: value
        for key, value in optional_attributes_raw.items()
        if key not in mandatory_attributes
    }

    return render_template(
        "dynamic/dynamic-form.html",
        mandatory_attributes=mandatory_attributes,
        optional_attributes=optional_attributes_filtered,
        redirect_url=cfgservice.service_url + "preauth_form",
    )


@preauth.route("/preauth_form", methods=["GET", "POST"])
def preauth_form():
    # session["country"] = "FC"

    form_data = request.form.to_dict()

    if "effective_from_date" in form_data:
        dt = datetime.strptime(form_data["effective_from_date"], "%Y-%m-%d").replace(
            tzinfo=timezone.utc
        )
        rfc3339_string = dt.isoformat().replace("+00:00", "Z")
        form_data.update({"effective_from_date": rfc3339_string})

    session_id = session["session_id"]

    form_data.pop("proceed")

    cleaned_data = form_formatter(form_data)

    print("\nCleaned Data: ", cleaned_data)

    """ form_dynamic_data[user_id] = cleaned_data.copy()
    form_dynamic_data[user_id].update(
        {"expires": datetime.now() + timedelta(minutes=cfgservice.form_expiry)}
    )
    print("\nform_dynamic_data: ", form_dynamic_data[user_id]) """

    session_manager.update_user_data(session_id=session_id, user_data=cleaned_data)

    presentation_data = presentation_formatter(cleaned_data=cleaned_data)

    print("\nPresentation Data: ", presentation_data)

    return render_template(
        "dynamic/form_authorize.html",
        presentation_data=presentation_data,
        user_id=session_id,
        redirect_url=cfgservice.service_url + "/form_authorize_generate",
    )


@preauth.route("/form_authorize_generate", methods=["GET", "POST"])
def form_authorize_generate():

    form_data = request.form.to_dict()

    user_id = form_data["user_id"]
    # data = form_dynamic_data[user_id]

    current_session = session_manager.get_session(user_id)
    data = current_session.user_data

    return generate_offer(data)


def generate_offer(data):

    session_id = session["session_id"]

    current_session = session_manager.get_session(session_id=session_id)

    """ pre_auth_code = generate_preauth_token(
        data=data, authorization_details=session["authorization_details"]
    )

    tx_code = random.randint(10000, 99999) """

    pre_auth_code = current_session.pre_authorized_code

    tx_code = current_session.tx_code

    transaction_id = generate_unique_id()

    print("\npre_auth_code: ", pre_auth_code)

    credential_offer = {
        "credential_issuer": cfgservice.service_url[:-1],
        "credential_configuration_ids": current_session.credentials_requested,
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": pre_auth_code,
                "tx_code": {
                    "length": 5,
                    "input_mode": "numeric",
                    "description": "Please provide the one-time code.",
                },
            }
        },
    }

    # create URI
    json_string = json.dumps(credential_offer)

    credential_offer_URI = session["credential_offer_URI"]

    uri = (
        f"{credential_offer_URI}credential_offer?credential_offer="
        + urllib.parse.quote(json_string, safe=":/")
    )

    qrcode = segno.make(uri)
    out = io.BytesIO()
    qrcode.save(out, kind="png", scale=2)

    qr_img_base64 = "data:image/png;base64," + base64.b64encode(out.getvalue()).decode(
        "utf-8"
    )

    wallet_url = cfgservice.wallet_test_url + "redirect_preauth"

    return render_template(
        "openid/credential_offer_qr_code.html",
        wallet_dev=wallet_url
        + "?code="
        + transaction_id
        + "&tx_code="
        + str(tx_code)
        + "&credential_offer="
        + json.dumps(credential_offer),
        url_data=uri,
        tx_code=tx_code,
        qrcode=qr_img_base64,
    )


@preauth.route("/credentialOfferReq2", methods=["POST"])
def credentialOfferReq2():

    json_token = request.form.get("request")

    header, payload, signature = json_token.split(".")

    payload += "=" * (-len(payload) % 4)
    decoded_payload = base64.urlsafe_b64decode(payload).decode("utf-8")

    json_payload = json.loads(decoded_payload)

    authorization_details = []
    credential_ids = []

    for credential in json_payload["credentials"]:
        authorization_details.append(
            {
                "type": "openid_credential",
                "credential_configuration_id": credential[
                    "credential_configuration_id"
                ],
            }
        )
        if credential["credential_configuration_id"] not in credential_ids:
            credential_ids.append(credential["credential_configuration_id"])

    data = json_payload["credentials"][0]["data"]

    scope = " ".join(credential_ids)
    print("\ncredential_list: ", scope)

    session_id = request_preauth_token(scope=scope)

    print("\nsession_id", session_id)

    session_manager.update_authorization_details(
        session_id=session_id, authorization_details=authorization_details
    )

    session_manager.update_user_data(session_id=session_id, user_data=data)

    current_session = session_manager.get_session(session_id=session_id)

    pre_auth_code = current_session.pre_authorized_code

    tx_code = current_session.tx_code

    credential_offer = {
        "credential_issuer": cfgservice.service_url[:-1],
        "credential_configuration_ids": credential_ids,
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": pre_auth_code,
                "tx_code": {
                    "length": 5,
                    "input_mode": "numeric",
                    "description": "Please provide the one-time code.",
                    "value": tx_code,
                },
            }
        },
    }

    json_string = json.dumps(credential_offer)

    uri = (
        f"openid-credential-offer://credential_offer?credential_offer="
        + urllib.parse.quote(json_string, safe=":/")
    )

    # return {"credential_offer": credential_offer, "uri": uri}
    return credential_offer  # {"credential_offer": credential_offer,"uri": uri}


def request_preauth_token(scope):
    url = "http://127.0.0.1:6005/preauth_generate"

    payload = f"scope={scope}"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = requests.request("POST", url, headers=headers, data=payload)

    _response = response.json()

    preauth_code = _response.get("preauth_code")

    session_id = _response.get("session_id")

    tx_code = _response.get("tx_code")

    session_manager.add_session(
        session_id=session_id,
        pre_authorized_code=preauth_code,
        tx_code=tx_code,
        country="FC",
    )

    return session_id
