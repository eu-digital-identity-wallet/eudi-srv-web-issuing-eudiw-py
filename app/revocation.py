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
from formatter_func import cbor2elems
import requests
import segno
from .app_config.config_service import ConfService as cfgservice
from app.misc import auth_error_redirect, authentication_error_redirect, scope2details, vct2doctype, vct2id
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

#TODO finish revocation pages.
""" @revocation.route("revocation_choice", methods=["GET"])
def revocation_choice():
    Page for selecting credentials

    Loads credentials supported by EUDIW Issuer
   
    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    
    credentials = {"sd-jwt vc format": {}, "mdoc format": {}}

    for cred in credentialsSupported:
        credential = credentialsSupported[cred]

        if credential["format"] == "dc+sd-jwt":
            # if credential["scope"] == "eu.europa.ec.eudiw.pid.1":
            credentials["sd-jwt vc format"].update(
                # {"Personal Identification Data": cred}
                {cred: credential["display"][0]["name"]}
            )

        if credential["format"] == "mso_mdoc":
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

    print("\nform: ", form)

    input_descriptors = []

    #print("\nrequested: ", credentials_requested)

    for id in form:
        credential = credentialsSupported[id]
        fields = []

        if credential["format"] == "mso_mdoc":
            doctype = credential["doctype"]
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
                            "$" + "".join(f"['{p}']" for p in claim["path"])
                        ],
                        "intent_to_retain": False
                        }
                    )

            
            input_descriptors.append(
                {
                    "id": doctype,
                    "format": format,
                    "name": "EUDI PID",
                    "purpose": "We need to verify your identity",
                    "constraints": {
                    "fields": fields
                    }
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
        

            fields.append(
                {
                    "path": [
                        "$.vct"
                    ],
                    "filter": {
                        "type": "string",
                        "const": credentialsSupported[id]["vct"]
                    }
                },
            )

            for claim in credential["claims"]:
                    if claim["mandatory"] == True:
                        fields.append(
                            {
                                "path": [
                                    "$." + ".".join(claim["path"])
                                ],
                                "intent_to_retain": False
                            }
                        )
            print("\nfields: ", fields)

            input_descriptors.append(
                {
                    "id": str(uuid.uuid4()),
                    "format": format,
                    "name": "EUDI PID",
                    "purpose": "We need to verify your identity",
                    "constraints": {
                    "fields": fields
                    }
                }
            )

            print("\ninput_descriptors: ", input_descriptors)

        

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

def b64url_decode(data):
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def decode_sd_jwt(sd_jwt: str):
    # Split SD-JWT into its parts
    parts = sd_jwt.split('~')
    jwt = parts[0]
    disclosures = parts[1:]

    # JWT parts: header, payload, signature
    header_b64, payload_b64, signature_b64 = jwt.split('.')
    
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))
    # signature = b64url_decode(signature_b64)  # only if verifying

    print("\nheader: ", header)
    print("\npayload: ", payload)
    print("\ndisclosures: ", disclosures)
    # Decode disclosures

    decoded_disclosures = []

    for disclosure in disclosures:
        decoded_disclosure = base64.urlsafe_b64decode(disclosure + "==")
        print("\ndecoded_disclosure", decoded_disclosure)
        if "." in disclosure:
            continue

        decoded_disclosures.append(json.loads(decoded_disclosure))


    return {
        "header": header,
        "payload": payload,
        "disclosures": decoded_disclosures
    }

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

    print("\nresponse: ", response_json)

    credentials = {"dc+sd-jwt":[],
                   "mso_mdoc": []}
    resp = {"dc+sd-jwt":[],
            "mso_mdoc": []}
    
    for desc in response_json['presentation_submission']['descriptor_map']:
        format = desc['format']
        path = desc['path']
        index_str = path[path.find('[') + 1:path.find(']')]
        index = int(index_str)

        print("\nformat", format)
        print("\nindex", index)
        print("\ncredential", response_json["vp_token"][index])

        if format == "mso_mdoc":
            credentials["mso_mdoc"].append(response_json["vp_token"][index])
        elif format == "vc+sd-jwt":
            credentials["dc+sd-jwt"].append(response_json["vp_token"][index])


    for credential in credentials["mso_mdoc"]:
        mdoc_ver = None

        try:
            mdoc_ver = base64.urlsafe_b64decode(credential)

        except:
            mdoc_ver = base64.urlsafe_b64decode(credential + "==")

        mdoc_cbor = cbor2.decoder.loads(mdoc_ver)

        #print("\nDocuments: ", cbor2.loads(mdoc_cbor["documents"]))

        status = cbor2.loads(mdoc_cbor["documents"][0]["issuerSigned"]["issuerAuth"][2])

        status2 = cbor2.loads(status.value)["status"]

        print("\nstatus2: ", status2)
        #cbor_elements = cbor2elems(credential)

        resp["mso_mdoc"].append(credential)

    for credential in credentials["dc+sd-jwt"]:
        resp["dc+sd-jwt"].append(decode_sd_jwt(credential)["disclosures"])
    
    print("\nresp: ", resp)

    return resp
 """