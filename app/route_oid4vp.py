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
The oid4vp route implements the communication with an openid4vp backend service.

It has support for both same device and cross device oid4vp
"""

import base64
from datetime import date, timedelta, datetime
import io
import json
from uuid import uuid4
from flask import Blueprint, Flask, jsonify, render_template, request, session
from flask_cors import CORS
import requests
import segno
from misc import generate_unique_id, authentication_error_redirect
from formatter_func import cbor2elems

from app.validate_vp_token import validate_vp_token
from .app_config.config_service import ConfService as cfgservice

oid4vp = Blueprint("oid4vp", __name__, url_prefix="/")
CORS(oid4vp)  # enable CORS on the blue print

# secrets
from app.data_management import oid4vp_requests, form_dynamic_data

from app_config.config_service import ConfService as log


@oid4vp.route("/oid4vp", methods=["GET"])
def openid4vp():

    if "session_id" in session:
        log.logger_info.info(", Session ID: " + session["session_id"] + ", " + "Authorization selection, Type: " + "oid4vp")

    url = "https://dev.verifier-backend.eudiw.dev/ui/presentations"
    payload_cross_device = json.dumps(
        {
            "type": "vp_token",
            "nonce": "hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc=",
            "presentation_definition": {
                "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "input_descriptors": [
                {
                    "id": "eu.europa.ec.eudi.pid.1",
                    "format": {
                    "mso_mdoc": {
                        "alg": [
                        "ES256",
                        "ES384",
                        "ES512",
                        "EdDSA"
                        ]
                    }
                    },
                    "name": "EUDI PID",
                    "purpose": "We need to verify your identity",
                    "constraints": {
                    "fields": [
                        {
                        "path": [
                            "$['eu.europa.ec.eudi.pid.1']['family_name']"
                        ],
                        "intent_to_retain": False
                        },
                        {
                        "path": [
                            "$['eu.europa.ec.eudi.pid.1']['given_name']"
                        ],
                        "intent_to_retain": False
                        },
                        {
                        "path": [
                            "$['eu.europa.ec.eudi.pid.1']['birth_date']"
                        ],
                        "intent_to_retain": False
                        },
                        {
                        "path": [
                            "$['eu.europa.ec.eudi.pid.1']['age_over_18']"
                        ],
                        "intent_to_retain": False
                        },
                        {
                        "path": [
                            "$['eu.europa.ec.eudi.pid.1']['issuing_authority']"
                        ],
                        "intent_to_retain": False
                        },
                        {
                        "path": [
                            "$['eu.europa.ec.eudi.pid.1']['issuing_country']"
                        ],
                        "intent_to_retain": False
                        }
                    ]
                    }
                }
                ]
            }
        }
    )

    payload_same_device = json.dumps(
        {
            "type": "vp_token",
            "nonce": "hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc=",
            "presentation_definition": {
                "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "input_descriptors": [
                {
                    "id": "eu.europa.ec.eudi.pid.1",
                    "format": {
                    "mso_mdoc": {
                        "alg": [
                        "ES256",
                        "ES384",
                        "ES512",
                        "EdDSA"
                        ]
                    }
                    },
                    "name": "EUDI PID",
                    "purpose": "We need to verify your identity",
                    "constraints": {
                    "fields": [
                        {
                        "path": [
                            "$['eu.europa.ec.eudi.pid.1']['family_name']"
                        ],
                        "intent_to_retain": False
                        },
                        {
                        "path": [
                            "$['eu.europa.ec.eudi.pid.1']['given_name']"
                        ],
                        "intent_to_retain": False
                        },
                        {
                        "path": [
                            "$['eu.europa.ec.eudi.pid.1']['birth_date']"
                        ],
                        "intent_to_retain": False
                        },
                        {
                        "path": [
                            "$['eu.europa.ec.eudi.pid.1']['age_over_18']"
                        ],
                        "intent_to_retain": False
                        },
                        {
                        "path": [
                            "$['eu.europa.ec.eudi.pid.1']['issuing_authority']"
                        ],
                        "intent_to_retain": False
                        },
                        {
                        "path": [
                            "$['eu.europa.ec.eudi.pid.1']['issuing_country']"
                        ],
                        "intent_to_retain": False
                        }
                    ]
                    }
                }
                ]
            },
            "wallet_response_redirect_uri_template":cfgservice.service_url + "getpidoid4vp?response_code={RESPONSE_CODE}&session_id=" + session["session_id"]
        }
    )

    headers = {
        "Content-Type": "application/json",
    }

    response_cross = requests.request("POST", url, headers=headers, data=payload_cross_device).json()

    response_same = requests.request("POST", url, headers=headers, data=payload_same_device).json()

    
    oid4vp_requests.update({session["session_id"]:{"response": response_same, "expires":datetime.now() + timedelta(minutes=cfgservice.deffered_expiry)}})

    deeplink_url = (
        "eudi-openid4vp://dev.verifier-backend.eudiw.dev?client_id="
        + response_same["client_id"]
        + "&request_uri="
        + response_same["request_uri"]
    )

    qr_code_url = (
        "eudi-openid4vp://dev.verifier-backend.eudiw.dev?client_id="
        + response_cross["client_id"]
        + "&request_uri="
        + response_cross["request_uri"]
    )

    # Generate QR code
    # img = qrcode.make("uri")
    # QRCode.print_ascii()

    qrcode = segno.make(qr_code_url)
    out = io.BytesIO()
    qrcode.save(out, kind='png', scale=3)

    """ qrcode.to_artistic(
        background=cfgtest.qr_png,
        target=out,
        kind="png",
        scale=4,
    ) """
    # qrcode.terminal()
    # qr_img_base64 = qrcode.png_data_uri(scale=4)

    qr_img_base64 = "data:image/png;base64," + base64.b64encode(out.getvalue()).decode(
        "utf-8"
    )

    return render_template(
        "openid/pid_login_qr_code.html",
        url_data=deeplink_url,
        qrcode=qr_img_base64,
        presentation_id=response_cross["presentation_id"],
        redirect_url= cfgservice.service_url
    )


@oid4vp.route("/getpidoid4vp", methods=["GET"])
def getpidoid4vp():

    if "response_code" in request.args and "session_id" in request.args:
        log.logger_info.info(", Session ID: " + session["session_id"] + ", " + "oid4vp flow: same_device")
        response_code = request.args.get("response_code")
        presentation_id = oid4vp_requests[request.args.get("session_id")]["response"]["presentation_id"]
        url = (
            "https://dev.verifier-backend.eudiw.dev/ui/presentations/"
            + presentation_id
            + "?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="
            + "&response_code=" + response_code
        )

    elif "presentation_id" in request.args:
        log.logger_info.info(", Session ID: " + session["session_id"] + ", " + "oid4vp flow: cross_device")
        presentation_id = request.args.get("presentation_id")

        url = (
            "https://dev.verifier-backend.eudiw.dev/ui/presentations/"
            + presentation_id
            + "?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="
        )

    headers = {
        "Content-Type": "application/json",
    }

    response = requests.request("GET", url, headers=headers)
    if response.status_code != 200:
        error_msg = str(response.status_code)
        return jsonify({"error": error_msg}), 400

    error, error_msg = validate_vp_token(response.json())

    if error == True:
        return authentication_error_redirect(
            jws_token=session["authorization_params"]["token"],
            error="invalid_request",
            error_description=error_msg,
        )

    mdoc_json = cbor2elems(response.json()["vp_token"] + "==")
    attributesForm = {}

    if (
        "authorization_params" in session
        and "authorization_details" in session["authorization_params"]
    ):
        cred_request_json = json.loads(
            session["authorization_params"]["authorization_details"]
        )

        for cred_request in cred_request_json:
            if "credential_configuration_id" in cred_request:
                if (
                    cred_request["credential_configuration_id"]
                    == "eu.europa.ec.eudi.pseudonym_over18_mdoc"
                    or cred_request["credential_configuration_id"]
                    == "eu.europa.ec.eudi.pseudonym_over18_mdoc_deferred_endpoint"
                ):
                    attributesForm.update({"user_pseudonym": str(uuid4())})
            elif "vct" in cred_request:
                if cred_request["vct"] == "eu.europa.ec.eudi.pseudonym_jwt_vc_json":
                    attributesForm.update({"user_pseudonym": str(uuid4())})

    elif (
        "authorization_params" in session and "scope" in session["authorization_params"]
    ):
        cred_scopes = session["authorization_params"]["scope"]
        if (
            "eu.europa.ec.eudi.pseudonym.age_over_18.1" in cred_scopes
            or "eu.europa.ec.eudi.pseudonym.age_over_18.deferred_endpoint"
            in cred_scopes
        ):
            attributesForm.update({"user_pseudonym": str(uuid4())})

    for doctype in mdoc_json:
        for attribute, value in mdoc_json[doctype]:
            if attribute == "age_over_18":
                attributesForm.update({attribute: value})
    
    doctype_config = cfgservice.config_doctype["eu.europa.ec.eudi.pseudonym.age_over_18.1"]

    attributesForm.update({"issuing_country": "FC"})
    attributesForm.update({"issuing_authority": doctype_config["issuing_authority"]})

    user_id = generate_unique_id()
    form_dynamic_data[user_id] = attributesForm
    
    presentation_data = attributesForm.copy()

    today = date.today()
    expiry = today + timedelta(days=doctype_config["validity"])
    

    presentation_data.update({"estimated_issuance_date": today.strftime("%Y-%m-%d")})
    presentation_data.update({"estimated_expiry_date": expiry.strftime("%Y-%m-%d")})
    presentation_data.update({})
    presentation_data.update({})

    if "jws_token" not in session and "authorization_params" in session:
            session["jws_token"] = session["authorization_params"]["token"]

    return render_template(
        "dynamic/form_authorize_oid4vp.html",
        attributes=presentation_data,
        user_id="FC." + user_id,
        redirect_url=cfgservice.service_url + "dynamic/redirect_wallet",
    )