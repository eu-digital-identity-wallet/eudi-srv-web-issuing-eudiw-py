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
from PIL import Image
from flask import Blueprint, current_app, make_response, redirect, render_template, request, session
from flask_cors import CORS
import requests
import urllib.parse
from datetime import date, datetime, timedelta
from redirect_func import url_get

import segno

from app.route_oidc import service_endpoint
from .app_config.config_service import ConfService as cfgservice
from app.misc import authentication_error_redirect, calculate_age, generate_unique_id, getAttributesForm, getAttributesForm2, validate_image

from app.data_management import parRequests, transaction_codes, getSessionId_requestUri, session_ids
from app.data_management import form_dynamic_data
from . import oidc_metadata

from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oauth2 import ResponseMessage



preauth = Blueprint("preauth", __name__, url_prefix="/")
CORS(preauth)  # enable CORS on the blue print

@preauth.route("/preauth", methods=["GET"])
def preauthRed():
    
    credentials_id=request.args.get("credentials_id")
    credential_list=json.loads(credentials_id)

    authorization_details=[]

    for credential in credential_list:
        authorization_details.append({
            "type": "openid_credential",
            "credential_configuration_id":credential
        })

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

    attributesForm2 = getAttributesForm2(session["credentials_requested"])    

    return render_template(
            "dynamic/dynamic-form.html",
            mandatory_attributes=attributesForm,
            optional_attributes=attributesForm2,
            redirect_url=cfgservice.service_url + "preauth_form",
        )


@preauth.route("/preauth_form", methods=["GET", "POST"])
def preauth_form():
    form_data = request.form.to_dict()

    user_id = generate_unique_id()

    form_data.pop("proceed")
    cleaned_data = {}

    grouped = {}
    for key, value in form_data.items():
        if not value:
            continue
        if "option" in key and "on" in value:
            continue
        if '[' not in key and ']' not in key:
            grouped.update({key:value})
        else:
            parts = key.replace('][', '/').replace('[', '/').replace(']', '').split('/')
            
            sub_key = ""
            if '-' in key:
                hyphen_parts = key.split('-')
                base_key = hyphen_parts[0]
                #sub_key = hyphen_parts[1]
                if len(parts) == 3:
                    sub_key = parts[2]
                    index = parts[1]
                else:
                    sub_key = parts[1]
                    index = 0

            else:

                base_key = parts[0]
                index = int(parts[1])
                sub_key = parts[2]
            
            if base_key not in grouped:
                grouped.update({base_key:[{sub_key:value}]})
            
            else:
                if index in grouped[base_key]:
                    grouped[base_key][index].update({sub_key:value})
                else:
                    grouped[base_key].append({sub_key:value})

    for item in grouped:

        if item == "nationality":
            cleaned_data[item] = [item['country_code'] for item in grouped[item]]
            
        elif item == "portrait":
            if grouped[item] == "Port1":
                cleaned_data["portrait"] = cfgservice.portrait1
            elif grouped[item] == "Port2":
                cleaned_data["portrait"] = cfgservice.portrait2
            elif grouped[item] == "Port3":
                portrait= request.files["Image"]

                img = Image.open(portrait)
                #imgbytes = img.tobytes()
                bio = io.BytesIO()
                img.save(bio, format="JPEG")
                del img

                response,error_msg = validate_image(portrait)

                if response==False:
                    return authentication_error_redirect(
                        jws_token=session["jws_token"],
                        error="Invalid Image",
                        error_description=error_msg,
                    )
                else :
                    imgurlbase64=base64.urlsafe_b64encode(bio.getvalue()).decode('utf-8')
                    cleaned_data["portrait"]=imgurlbase64

        elif item == "Category1":
            DrivingPrivileges = []
            i = 1
            for i in range(int(grouped["NumberCategories"])):
                f = str(i + 1)
                drivP = {
                    "vehicle_category_code": grouped["Category" + f],
                    "issue_date": grouped["IssueDate" + f],
                    "expiry_date": grouped["ExpiryDate" + f],
                }
                DrivingPrivileges.append(drivP)

            cleaned_data["driving_privileges"] = json.dumps(DrivingPrivileges)
        
        elif grouped[item] == "true":
            cleaned_data[item] = True

        elif grouped[item] == "false":
            cleaned_data[item] = False


        else:
            if grouped[item] != "" and grouped[item] != "unset":
             cleaned_data[item] = grouped[item]

    cleaned_data.update(
        {
            "version": cfgservice.current_version,
            "issuing_country": "FC",
        }
    )

    form_dynamic_data[user_id] = cleaned_data.copy()
    form_dynamic_data[user_id].update({"expires":datetime.now() + timedelta(minutes=cfgservice.form_expiry)})

    credentialsSupported = oidc_metadata["credential_configurations_supported"]

    presentation_data=dict()

    for credential_requested in session["credentials_requested"]:
        
        scope= credentialsSupported[credential_requested]["scope"]

        """ if scope in cfgservice.common_name:
            credential=cfgservice.common_name[scope]

        else:
            credential = scope """
        
        credential = credentialsSupported[credential_requested]["display"][0]["name"]

        presentation_data.update({credential:{}})

        credential_atributes_form=list()
        credential_atributes_form.append(credential_requested)
        attributesForm = getAttributesForm(credential_atributes_form).keys()
        attributesForm2 = getAttributesForm2(credential_atributes_form).keys()

        for attribute in cleaned_data.keys():

            if attribute in attributesForm:
                presentation_data[credential][attribute]= cleaned_data[attribute]
            
            if attribute in attributesForm2:
                presentation_data[credential][attribute]= cleaned_data[attribute]

        doctype_config=credentialsSupported[credential_requested]["issuer_config"]

        today = date.today()
        expiry = today + timedelta(days=doctype_config["validity"])
    
        presentation_data[credential].update({"estimated_issuance_date":today.strftime("%Y-%m-%d")})
        presentation_data[credential].update({"estimated_expiry_date":expiry.strftime("%Y-%m-%d")})
        presentation_data[credential].update({"issuing_country": "FC"}),
        presentation_data[credential].update({"issuing_authority": doctype_config["issuing_authority"]})
        
        if "credential_type" in doctype_config:
                presentation_data[credential].update({"credential_type":doctype_config["credential_type"] })
        
        if "birth_date" in presentation_data[credential] and "age_over_18" in presentation_data[credential]:
            presentation_data[credential].update({"age_over_18": True if calculate_age(presentation_data[credential]["birth_date"]) >= 18 else False})

        if scope == "eu.europa.ec.eudi.pid.1" or scope == "org.iso.18013.5.1.mDL":
            if "birth_date" in presentation_data[credential]:
                presentation_data[credential].update({"age_over_18": True if calculate_age(presentation_data[credential]["birth_date"]) >= 18 else False})

        if "driving_privileges" in presentation_data[credential]:
            json_priv = json.loads(presentation_data[credential]["driving_privileges"])
            presentation_data[credential].update({"driving_privileges":json_priv})
        
        if "portrait" in presentation_data[credential]:
            presentation_data[credential].update({"portrait":base64.b64encode(base64.urlsafe_b64decode(presentation_data[credential]["portrait"])).decode("utf-8")})
        
        if "NumberCategories" in presentation_data[credential]:
            for i in range(int(presentation_data[credential]["NumberCategories"])):
                    f = str(i + 1)
                    presentation_data[credential].pop("IssueDate" + f)
                    presentation_data[credential].pop("ExpiryDate" + f)
            presentation_data[credential].pop("NumberCategories")

    return render_template("dynamic/form_authorize.html", presentation_data=presentation_data, user_id=user_id, redirect_url=cfgservice.service_url + "/form_authorize_generate" )


@preauth.route("/form_authorize_generate", methods=["GET", "POST"])
def form_authorize_generate():

    form_data = request.form.to_dict()

    user_id= form_data["user_id"]
    data = form_dynamic_data[user_id]

    return generate_offer(data)



def generate_offer(data):

    pre_auth_code = generate_preauth_token(data=data, authorization_details=session["authorization_details"])

    tx_code=random.randint(10000,99999)
    transaction_id = generate_unique_id()

    transaction_codes.update({transaction_id:{"pre_auth_code":pre_auth_code,"tx_code":str(tx_code),"expires":datetime.now() + timedelta(minutes=cfgservice.tx_code_expiry)}})

    credential_offer = {
        "credential_issuer": cfgservice.service_url[:-1],
        "credential_configuration_ids": session["credentials_id"],
        "grants" : {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code" : {
                 "pre-authorized_code": transaction_id,
                 "tx_code": {
                    "length": 5,
                    "input_mode": "numeric",
                    "description": "Please provide the one-time code."
                }
            }
        }
    }

    
    # create URI
    json_string = json.dumps(credential_offer)
    
    credential_offer_URI = session["credential_offer_URI"]

    uri = f"{credential_offer_URI}credential_offer?credential_offer=" + urllib.parse.quote(
                    json_string, safe=":/"
                )

    qrcode = segno.make(uri)
    out = io.BytesIO()
    qrcode.save(out, kind='png', scale=2)
    

    qr_img_base64 = "data:image/png;base64," + base64.b64encode(
        out.getvalue()
    ).decode("utf-8")

    wallet_url = cfgservice.wallet_test_url + "redirect_preauth"

    return render_template(
        "openid/credential_offer_qr_code.html",
        wallet_dev= wallet_url + "?code=" + transaction_id + "&tx_code=" + str(tx_code) + "&credential_offer=" + json.dumps(credential_offer),
        url_data=uri,
        tx_code=tx_code,
        qrcode=qr_img_base64,
    )



@preauth.route("/credentialOfferReq2", methods=["POST"])
def credentialOfferReq2():

    json_token = request.form.get('request')

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
 
    data = json_payload["credentials"][0]["data"]

    pre_auth_code = generate_preauth_token(data=data,authorization_details=authorization_details)

    tx_code=random.randint(10000,99999)

    transaction_id = generate_unique_id()

    transaction_codes.update({transaction_id:{"pre_auth_code":pre_auth_code,"tx_code":str(tx_code),"expires":datetime.now() + timedelta(minutes=cfgservice.tx_code_expiry)}})

    credential_offer = {
        "credential_issuer": cfgservice.service_url[:-1],
        "credential_configuration_ids": credential_ids,
        "grants" : {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code" : {
                 "pre-authorized_code": transaction_id,
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





def generate_preauth_token(data, authorization_details):
    user_id = generate_unique_id()
 
    data.update({"issuing_country": "FC"})

    form_dynamic_data[user_id] = data.copy()

    form_dynamic_data[user_id].update({"expires":datetime.now() + timedelta(minutes=cfgservice.form_expiry)})

    user_id="FC." + user_id


    url = cfgservice.service_url + "pushed_authorizationv2"
 
    authorization_details=urllib.parse.quote_plus(json.dumps(authorization_details))
    
    redirect_url = "preauth" #urllib.parse.quote(cfgservice.service_url) + "preauth-codeReq"

    payload = 'response_type=code&state=af0ifjsldkj&client_id=ID&redirect_uri=' + redirect_url + '&code_challenge=-ciaVij0VMswVfqm3_GK758-_dAI0E9i97hu1SAOiFQ&code_challenge_method=S256&authorization_details='+ authorization_details
    headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    if response.status_code != 201:
        return make_response("invalid_request", 400)
    
    par_response = response.json()


    request_uri = par_response["request_uri"]

    if not request_uri in parRequests:  # unknow request_uri => return error
        # needs to be changed to an appropriate error message, and need to be logged
        return service_endpoint(current_app.server.get_endpoint("authorization"))
    
    session_id = getSessionId_requestUri(request_uri)

    if session_id == None:
        cfgservice.app_logger.error("Authorization request_uri not found.")
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

    try:
        authn_method = current_app.server.get_context().authn_broker.get_method_by_id(
        "user"
    )
        username = authn_method.verify(username=user_id)

        auth_args = authn_method.unpack_token(params["token"])
    except:
        cfgservice.app_logger.error("Authorization verification: username or jws_token not found")
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

    session_ids[session_id]["auth_code"] = args["response_args"]["code"]

    logText = ", Session ID: " + session_id + ", " + "Authorization Response, Code: " + args["response_args"]["code"]

    if "state" in args["response_args"]:

        logText = logText + ", State: " + args["response_args"]["state"]


    cfgservice.app_logger.info(logText)
    return args["response_args"]["code"]
