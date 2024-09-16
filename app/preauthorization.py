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
from redirect_func import url_get

import segno

from app.route_oidc import service_endpoint
from .app_config.config_service import ConfService as cfgservice
from app.misc import authentication_error_redirect, generate_unique_id, getAttributesForm, getAttributesForm2

from app.data_management import parRequests, transaction_codes, getSessionId_requestUri, session_ids

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

    print(credential_offer)

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


from app.data_management import form_dynamic_data

@preauth.route("/credentialOfferReq", methods=["POST"])
def credentialOfferReq():

    json_token = request.form.get('request')

    print("\n-----JWT in credential offer---\n", json_token)

    header, payload, signature = json_token.split('.')

    payload += '=' * (-len(payload) % 4)
    decoded_payload = base64.urlsafe_b64decode(payload).decode('utf-8')

    json_payload = json.loads(decoded_payload)

    authorization_details=[]
    credential_ids = []

    for credential in json_payload["credentials"]:
        authorization_details.append({
            "type": "openid_credential",
            "credential_configuration_id":credential["credential_configuration_id"]
        })
        if credential["credential_configuration_id"] not in credential_ids:
            credential_ids.append(credential["credential_configuration_id"])

    session["credentials_id"] = credential_ids

    user_id = generate_unique_id()
 
    data = json_payload["credentials"][0]["data"]

    data.update({"issuing_country": "FC"})

    form_dynamic_data[user_id] = data

    user_id="FC." + user_id


    url = cfgservice.service_url + "pushed_authorizationv2"
 
    authorization_details=urllib.parse.quote_plus(json.dumps(authorization_details))
    
    redirect_url = urllib.parse.quote(cfgservice.service_url) + "preauth-codeReq"

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

    return redirect(cfgservice.service_url +"authorization-preauthReq?client_id=ID&request_uri=" + par_response["request_uri"] + "&user_id=" + user_id)

@preauth.route("/authorization-preauthReq", methods=["GET"])
def authorizationpreReq():

    try:
        request_uri = request.args.get("request_uri")
        user_id = request.args.get("user_id")
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
    #return redirect(cfgservice.service_url + "preauth-form")
    # return response.content
    return redirect(
            url_get(
                cfgservice.OpenID_first_endpoint,
                {
                    "jws_token": session["authorization_params"]["token"],
                    "username": user_id,
                },
            )
        )


@preauth.route("/preauth-codeReq", methods=["GET"])
def preauthCodeReq():
    code = request.args.get("code")
    #print(session)

    tx_code=random.randint(10000,99999)

    transaction_codes.update({code:{"tx_code":str(tx_code),"expires":datetime.now() + timedelta(minutes=cfgservice.tx_code_expiry)}})

    #print("\n----- Updating transaction codes-----\n", transaction_codes)

    #print(session)
    credential_offer = {
        "credential_issuer": cfgservice.service_url[:-1],
        "credential_configuration_ids": session["credentials_id"],
        "grants" : {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code" : {
                 "pre-authorized_code": code,
                 "tx_code": {
                    "length": 5,
                    "input_mode": "numeric",
                    "description": "Please provide the one-time code.",
                    "value": tx_code
                }
            }
        }
    }


    json_string = json.dumps(credential_offer)

    """ uri = f"openid-credential-offer://credential_offer?credential_offer=" + urllib.parse.quote(
                    json_string, safe=":/"
                ) """
   

    return credential_offer #{"credential_offer": credential_offer,"uri": uri}


@preauth.route("/credentialOfferReq2", methods=["POST"])
def credentialOfferReq2():

    json_token = request.form.get('request')

    print("\n-----JWT in credential offer---\n", json_token)

    header, payload, signature = json_token.split('.')

    payload += '=' * (-len(payload) % 4)
    decoded_payload = base64.urlsafe_b64decode(payload).decode('utf-8')

    json_payload = json.loads(decoded_payload)

    authorization_details=[]
    credential_ids = []

    for credential in json_payload["credentials"]:
        authorization_details.append({
            "type": "openid_credential",
            "credential_configuration_id":credential["credential_configuration_id"]
        })
        if credential["credential_configuration_id"] not in credential_ids:
            credential_ids.append(credential["credential_configuration_id"])

    #session["credentials_id"] = credential_ids

    user_id = generate_unique_id()
 
    data = json_payload["credentials"][0]["data"]

    data.update({"issuing_country": "FC"})

    form_dynamic_data[user_id] = data

    user_id="FC." + user_id


    url = cfgservice.service_url + "pushed_authorizationv2"
 
    authorization_details=urllib.parse.quote_plus(json.dumps(authorization_details))
    
    redirect_url = urllib.parse.quote(cfgservice.service_url) + "preauth-codeReq"

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


    request_uri = par_response["request_uri"]

    if not request_uri in parRequests:  # unknow request_uri => return error
        # needs to be changed to an appropriate error message, and need to be logged
        return service_endpoint(current_app.server.get_endpoint("authorization"))
    
    session_id = getSessionId_requestUri(request_uri)

    if session_id == None:
        log.logger_error.error("Authorization request_uri not found.")
        return make_response("Request_uri not found", 400)
    

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

    code = verify(session_id,user_id, params["token"])

    #code = request.args.get("code")
    #print(session)

    tx_code=random.randint(10000,99999)

    transaction_codes.update({code:{"tx_code":str(tx_code),"expires":datetime.now() + timedelta(minutes=cfgservice.tx_code_expiry)}})

    #print("\n----- Updating transaction codes-----\n", transaction_codes)

    #print(session)
    credential_offer = {
        "credential_issuer": cfgservice.service_url[:-1],
        "credential_configuration_ids": credential_ids,
        "grants" : {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code" : {
                 "pre-authorized_code": code,
                 "tx_code": {
                    "length": 5,
                    "input_mode": "numeric",
                    "description": "Please provide the one-time code.",
                    "value": tx_code
                }
            }
        }
    }


    json_string = json.dumps(credential_offer)

    uri = f"openid-credential-offer://credential_offer?credential_offer=" + urllib.parse.quote(
                    json_string, safe=":/"
                )
   

    return credential_offer #{"credential_offer": credential_offer,"uri": uri}

  


from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oauth2 import ResponseMessage

def verify(session_id2, username, jws_token):
    """
    Authentication verification

    :param url_endpoint: Which endpoint to use
    :param kwargs: response arguments
    :return: HTTP redirect
    """
    # kwargs = dict([(k, v) for k, v in request.form.items()])

    try:
        authn_method = current_app.server.get_context().authn_broker.get_method_by_id(
        "user"
    )
        username = authn_method.verify(username=username)

        auth_args = authn_method.unpack_token(jws_token)
    except:
        log.logger_error.error("Authorization verification: username or jws_token not found")
        return render_template("misc/500.html", error="Authentication verification Error")

    authz_request = AuthorizationRequest().from_urlencoded(auth_args["query"])

    endpoint = current_app.server.get_endpoint("authorization")

    _session_id = endpoint.create_session(
        authz_request,
        username,
        auth_args["authn_class_ref"],
        auth_args["iat"],
        authn_method,
    )

    args = endpoint.authz_part2(request=authz_request, session_id=_session_id)

    if isinstance(args, ResponseMessage) and "error" in args:
        return make_response(args.to_json(), 400)

    session_ids[session_id2]["auth_code"] = args["response_args"]["code"]

    logText = ", Session ID: " + session_id2 + ", " + "Authorization Response, Code: " + args["response_args"]["code"]

    if "state" in args["response_args"]:

        logText = logText + ", State: " + args["response_args"]["state"]


    log.logger_info.info(logText)
    return args["response_args"]["code"]
    #return do_response(endpoint, request, **args)