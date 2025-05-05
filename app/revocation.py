# coding: latin-1
###############################################################################
# Copyright (c) 2025 European Commission
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

import base64
import io
import json
from urllib.parse import urlparse
import uuid
import cbor2
from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for
import urllib

import requests
import segno
from .app_config.config_service import ConfService as cfgservice
from app.misc import auth_error_redirect, authentication_error_redirect, scope2details, vct2id
from app.validate_vp_token import validate_vp_token
from . import oidc_metadata, openid_metadata, oauth_metadata, oidc_metadata_clean
from datetime import datetime, timedelta
from app.data_management import (
    getSessionId_accessToken,
    parRequests,
    transaction_codes,
    deferredRequests,
    session_ids,
    getSessionId_requestUri,
    getSessionId_authCode,
    credential_offer_references,
    oid4vp_requests
)

revocation = Blueprint("revocation", __name__, url_prefix="/revocation")
    
@revocation.route("revocation_choice", methods=["GET"])
def revocation_choice():
    """Page for selecting credentials

    Loads credentials supported by EUDIW Issuer
    """
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    
    credentials = {"sd-jwt vc format": {}, "mdoc format": {}}

    for cred in credentialsSupported:
        credential = credentialsSupported[cred]

        if credential["format"] == "dc+sd-jwt":
            # if credential["scope"] == "eu.europa.ec.eudiw.pid.1":
            if (
                cred in cfgservice.auth_method_supported_credencials["PID_login"]
                or cred
                in cfgservice.auth_method_supported_credencials["country_selection"]
            ):
                credentials["sd-jwt vc format"].update(
                    # {"Personal Identification Data": cred}
                    {cred: credential["display"][0]["name"]}
                )

        if credential["format"] == "mso_mdoc":
            if (
                cred in cfgservice.auth_method_supported_credencials["PID_login"]
                or cred
                in cfgservice.auth_method_supported_credencials["country_selection"]
            ):
                credentials["mdoc format"].update(
                    {cred: credential["display"][0]["name"]}
                )

    return render_template(
        "openid/revocation_choice.html",
        cred=credentials,
        redirect_url=cfgservice.service_url + "revocation/oid4vp_call",
    )

@revocation.route("oid4vp_call", methods=["GET", "POST"])
def oid4vp_call():
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    form_keys = request.form.keys()
    form = list(form_keys)
    form.remove("proceed")
    session_id = str(uuid.uuid4())

    authorization_details = []
    authorization_details.extend(scope2details(form))

    credentials_requested = []
    for cred in authorization_details:
        if "credential_configuration_id" in cred:
            if cred["credential_configuration_id"] not in credentials_requested:
                credentials_requested.append(cred["credential_configuration_id"])

    input_descriptors = []

    for id in credentials_requested:
        credential = credentialsSupported[id]
        fields = []

        if credential["format"] == "mso_mdoc":
            id2 = credential["doctype"]
            format = {
                "mso_mdoc": {
                    "alg": [
                        "ES256",
                        "ES384",
                        "ES512",
                        "EdDSA"
                    ]
                }
            }


            for claim in credential["claims"]:
                if claim["mandatory"] == True:
                    fields.append(
                        {
                        "path": [
                            "$['" + claim["path"][0] + "']['" + claim["path"][1] + "']"
                        ],
                        "intent_to_retain": False
                        }
                    )
                    
        elif credential["format"] == "dc+sd-jwt":
            format = {
          "vc+sd-jwt": {
            "sd-jwt_alg_values": [
              "ES256",
              "ES384",
              "ES512"
            ],
            "kb-jwt_alg_values": [
              "RS256",
              "RS384",
              "RS512",
              "ES256",
              "ES384",
              "ES512"
            ]
          }
        }
        
        input_descriptors.append(
            {
                "id": id2,
                "format": format,
                "name": "EUDI PID",
                "purpose": "We need to verify your identity",
                "constraints": {
                "fields": fields
                }
            }
        )

        

    url = cfgservice.dynamic_presentation_url
    payload_cross_device = json.dumps(
        {
            "type": "vp_token",
            "nonce": "hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc=",
            "presentation_definition": {
                "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "input_descriptors": input_descriptors
            }
        }
    )

    payload_same_device = json.dumps(
        {
            "type": "vp_token",
            "nonce": "hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc=",
            "presentation_definition": {
                "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "input_descriptors": input_descriptors
            },
            "wallet_response_redirect_uri_template":cfgservice.service_url + "getpidoid4vp?response_code={RESPONSE_CODE}&session_id=" + session_id
        }
    )

    headers = {
        "Content-Type": "application/json",
    }

    print("\npayload: ", payload_cross_device)
    response_cross = requests.request("POST", url[:-1], headers=headers, data=payload_cross_device).json()

    response_same = requests.request("POST", url[:-1], headers=headers, data=payload_same_device).json()
    
    oid4vp_requests.update({session_id:{"response": response_same, "expires":datetime.now() + timedelta(minutes=cfgservice.deffered_expiry)}})

    domain = urlparse(url).netloc

    deeplink_url = (
        "eudi-openid4vp://" + domain + "?client_id="
        + response_same["client_id"]
        + "&request_uri="
        + response_same["request_uri"]
    )

    qr_code_url = (
        "eudi-openid4vp://" + domain + "?client_id="
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
        "openid/revocation_qr_code.html",
        url_data=deeplink_url,
        qrcode=qr_img_base64,
        presentation_id=response_cross["transaction_id"],
        redirect_url= cfgservice.service_url
    )


@revocation.route("getoid4vp", methods=["GET", "POST"])
def oid4vp_get():

    if "response_code" in request.args and "session_id" in request.args:
        cfgservice.app_logger.info(", Session ID: " + session["session_id"] + ", " + "oid4vp flow: same_device")

        response_code = request.args.get("response_code")
        presentation_id = oid4vp_requests[request.args.get("session_id")]["response"]["transaction_id"]
        url = (
            cfgservice.dynamic_presentation_url
            + presentation_id
            + "?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="
            + "&response_code=" + response_code
        )

    elif "presentation_id" in request.args:
        cfgservice.app_logger.info(", Session ID: " + session["session_id"] + ", " + "oid4vp flow: cross_device")
        presentation_id = request.args.get("presentation_id")

        url = (
            cfgservice.dynamic_presentation_url
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

    response_json = response.json()

    mdoc = response_json["vp_token"][0]
    mdoc_ver = None

    try:
        mdoc_ver = base64.urlsafe_b64decode(mdoc)

    except:
        mdoc_ver = base64.urlsafe_b64decode(mdoc + "==")

    mdoc_cbor = cbor2.decoder.loads(mdoc_ver)

    status = cbor2.loads(mdoc_cbor["documents"][0]["issuerSigned"]["issuerAuth"][2])

    status2 = cbor2.loads(status.value)["status"]

    return status2