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
from flask import Blueprint, current_app, make_response, redirect, render_template, request, session
from flask_cors import CORS
import requests
import urllib.parse
from datetime import datetime, timedelta

import segno

from app.route_oidc import service_endpoint
from .app_config.config_service import ConfService as cfgservice
from app.misc import authentication_error_redirect, getAttributesForm, getAttributesForm2

from app.data_management import parRequests, transaction_codes, getSessionId_requestUri

from app_config.config_service import ConfService as log




preauth = Blueprint("preauth", __name__, url_prefix="/")
CORS(preauth)  # enable CORS on the blue print


@preauth.route("/preauth", methods=["GET"])
def preauthRed():
    
    url = cfgservice.service_url + "pushed_authorizationv2"
    credentials_id=request.args.get("credentials_id")
    credential_list=json.loads(credentials_id)

    authorization_details=[]

    for credential in credential_list:
        authorization_details.append({
            "type": "openid_credential",
            "credential_configuration_id":credential
        })
    authorization_details=urllib.parse.quote_plus(json.dumps(authorization_details))
    
    redirect_url = urllib.parse.quote(cfgservice.service_url) + "preauth-code"

    payload = 'response_type=code&state=af0ifjsldkj&client_id=ID&redirect_uri=' + redirect_url + '&code_challenge=-ciaVij0VMswVfqm3_GK758-_dAI0E9i97hu1SAOiFQ&code_challenge_method=S256&authorization_details='+ authorization_details
    headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
    }

    #print("\n------ PAR payload -----\n", payload)

    response = requests.request("POST", url, headers=headers, data=payload)

    if response.status_code != 200:
        #print("\n",str(response.json()),"\n")
        return make_response("invalid_request", 400)
    
    par_response = response.json()

    return redirect(cfgservice.service_url +"authorization-preauth?client_id=ID&request_uri=" + par_response["request_uri"])

@preauth.route("/authorization-preauth", methods=["GET"])
def authorizationpre():

    try:
        request_uri = request.args.get("request_uri")
    except:
        cfgservice.logger_error.error("Pre authorization request_uri not found")
        return make_response("Authorization error", 400)

    if not request_uri in parRequests:  # unknow request_uri => return error
        # needs to be changed to an appropriate error message, and need to be logged
        return service_endpoint(current_app.server.get_endpoint("authorization"))
    
    session_id = getSessionId_requestUri(request_uri)

    if session_id == None:
        log.logger_error.error("Authorization request_uri not found.")
        return make_response("Request_uri not found", 400)
    
    session["session_id"] = session_id

    par_args = parRequests[request_uri]["req_args"]

    if "scope" not in par_args:
        par_args["scope"] = "openid"

    url = (
        cfgservice.service_url + "authorization?redirect_uri="
        + par_args["redirect_uri"]
        + "&response_type="
        + par_args["response_type"]
        + "&scope="
        + par_args["scope"]
        + "&client_id="
        + par_args["client_id"]
        + "&request_uri="
        + request_uri
    )

    payload = {}
    headers = {}
    response = requests.request(
        "GET", url, headers=headers, data=payload
    )

    if response.status_code != 200:
        print("\n",str(response.json()),"\n")
        return make_response("invalid_request", 400)

    response = response.json()
    args = {}
    if "authorization_details" in response:
        args.update({"authorization_details": response["authorization_details"]})
    if "scope" in response:
        args.update({"scope": response["scope"]})
    if not args:
        return authentication_error_redirect(
            jws_token=response["token"],
            error=response["error"],
            error_description=response["error_description"],
        )

    params = {"token": response["token"]}

    params.update(args)

    session["authorization_params"] = params

    #return redirect(url_get(response["url"], params))
    return redirect(cfgservice.service_url + "preauth-form")
    # return response.content


@preauth.route("/preauth-form", methods=["GET"])
def preauthForm():
    """ Form used for pre-authorization
    Form page where the user information is parsed.
    """

    authorization_params = session["authorization_params"]
    
    authorization_details = []
    if "authorization_details" in authorization_params:
        authorization_details.extend(
            json.loads(authorization_params["authorization_details"])
        )

    if not authorization_details:
        return authentication_error_redirect(
            jws_token=authorization_params["token"],
            error="invalid authentication",
            error_description="No authorization details or scope found in dynamic route.",
        )

    session["authorization_details"] = authorization_details

    credentials_requested = []
    for cred in authorization_details:
        if "credential_configuration_id" in cred:
            if cred["credential_configuration_id"] not in credentials_requested:
                credentials_requested.append(cred["credential_configuration_id"])
        elif "vct" in cred:
            if cred["vct"] not in credentials_requested:
                credentials_requested.append(cred["vct"])



    session["credentials_requested"] = credentials_requested

    attributesForm=getAttributesForm(session["credentials_requested"])

    print("\n-----Mandatory-----\n", attributesForm)
    attributesForm2 = getAttributesForm2(session["credentials_requested"])
    print("\n-----Optional-----\n", attributesForm2)
    

    return render_template(
            "dynamic/dynamic-form.html",
            mandatory_attributes=attributesForm,
            optional_attributes=attributesForm2,
            redirect_url=cfgservice.service_url + "dynamic/form",
        )


@preauth.route("/preauth-code", methods=["GET"])
def preauthCode():
    code = request.args.get("code")
    print(session)
    credential_offer = {
        "credential_issuer": cfgservice.service_url[:-1],
        "credential_configuration_ids": session["credentials_id"],
        "grants" : {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code" : {
                 "pre-authorized_code": code,
                 "tx_code": {
                    "length": 5,
                    "input_mode": "numeric",
                    "description": "Please provide the one-time code."
                }
            }
        }
    }

    tx_code=random.randint(10000,99999)

    transaction_codes.update({code:{"tx_code":str(tx_code),"expires":datetime.now() + timedelta(minutes=cfgservice.tx_code_expiry)}})

    print("\n----- Updating transaction codes-----\n", transaction_codes)

    # create URI
    json_string = json.dumps(credential_offer)
    
    credential_offer_URI = session["credential_offer_URI"]

    uri = f"{credential_offer_URI}credential_offer?credential_offer=" + urllib.parse.quote(
                    json_string, safe=":/"
                )

    # Generate QR code
    # img = qrcode.make("uri")
    # QRCode.print_ascii()

    qrcode = segno.make(uri)
    out = io.BytesIO()
    qrcode.save(out, kind='png', scale=2)
    

    #print(qrcode.terminal(compact=True))

    """ qrcode.to_artistic(
        background=cfgtest.qr_png,
        target=out,
        kind="png",
        scale=2,
    ) """

    # qrcode.terminal()
    #qr_img_base64 = qrcode.png_data_uri(scale=4)

    qr_img_base64 = "data:image/png;base64," + base64.b64encode(
        out.getvalue()
    ).decode("utf-8")

    wallet_url = cfgservice.wallet_test_url + "redirect_preauth"

    return render_template(
        "openid/credential_offer_qr_code.html",
        wallet_dev= wallet_url + "?code=" + code + "&tx_code=" + str(tx_code) + "&credential_offer=" + json.dumps(credential_offer),
        url_data=uri,
        tx_code=tx_code,
        qrcode=qr_img_base64,
    )