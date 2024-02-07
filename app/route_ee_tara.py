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


This route_ee_tara.py file is the blueprint for the route /tara (EE - Estonia) of the PID Issuer Web service.
"""
import base64
import logging
import requests
import json
from app_config.config_service import ConfService

from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
    jsonify,
)

from cryptography.hazmat.primitives import serialization

from validate import validate_mandatory_args
from redirect_func import redirect_getpid_or_mdl, url_get
from pid_func import process_pid_form
from app_config.config_devtest import ConfTest as cfgdev
from app_config.config_service import ConfService as cfgserv

# /tara blueprint
tara = Blueprint("tara", __name__, url_prefix="/tara")

# Log
from app_config.config_service import ConfService as log


# --------------------------------------------------------------------------------------------------------------------------------------
# route to /tara
# @tara.route('', methods=['GET','POST'])
# # route to /tara/
# @tara.route('/', methods=['GET','POST'])
# def tara():
#     """Initial eIDAS-node page.
#     Loads country config information and renders pid_index.html so that the user can select the PID issuer country."""


#     if 'country' in request.form.keys():
#         print(cfgcountries.supported_countries[request.form.get('country')]['pid_url'])
#     return render_template('route_pid/pid-countries.html', countries = create_dict(cfgcountries.supported_countries, 'name'))
#     return "to be implemented", status.HTTP_200_OK


# --------------------------------------------------------------------------------------------------------------------------------------
# route to /tara/redirect
@tara.route("/redirect", methods=["GET"])
def red():
    """Receives token from EE Tara IDP - communication originated in route /pid/getpid for country EE

    GET parameters:
    + code (mandatory) - Token code to retrieve the shared attributes consented by the user.
    + scope (mandatory) - scope of the request.
    + state (mandatory) - state of the request.

    Return: Redirect answer to returnURL.
    """
    session["route"] = "/tara/redirect"
    
    log.logger_info.info(" - INFO - " + session["route"] + " - " + " -  entered the route")

    # (v, l) = validate_mandatory_args(request.args, ["code", "scope", "state"])
    # if not v:  # if not all arguments are available
    #    return redirect_getpid_or_mdl(session["version"], session["returnURL"], 501, [])

    # log.logger_info.info(" - INFO - " + session["route"] + " - " + session['device_publickey'] + " -  entered the route")
    # Retrieve the shared attributes consented by the user
    url = "https://tara-test.ria.ee/oidc/token"
    headers = {
        "Host": "tara-test.ria.ee",
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Basic ZXVfZXVyb3BhX2VjX2V1ZGl3X3BpZF9wcm92aWRlcl8xX3BwcjpINUVpVjdPaGZMTUs1TFBvcXB0NG5WT1FJeEdicEZ3MQ==",
    }
    data = (
        "grant_type=authorization_code&code="
        + request.args.get("code")
        + "&redirect_uri=https://pprpid.provider.eudiw.projj.eu/tara/redirect"
    )
    r = requests.post(url, headers=headers, data=data)
    json_response = json.loads(r.text)
    session["access_token"] = json_response["access_token"]

    session["returnURL"] = cfgserv.OpenID_first_endpoint

    return redirect(
        url_get(
            session["returnURL"],
            {
                "jws_token": request.args.get("state"),
                "username": "EE." + session["access_token"],
            },
        )
    )


@tara.route("/R2", methods=["GET"])
def red2():
  
    """ Route acessed by OpenID to get PID attributes from country EE

    Get query parameters:
    + user_id - token to obtain PID attributes
    
    Return:PID in sd-jwt and mdoc formats
    """

    session['route'] = "/tara/R2"


 
    user_id = request.args.get("user_id")
    session["device_publickey"] = request.args.get("device_publickey")

    log.logger_info.info(" - INFO - " + session["route"] + " - " + session['device_publickey'] + " -  entered the route")


    url = "https://tara-test.ria.ee/oidc/profile?access_token=" + user_id
    headers = {"Host": "tara-test.ria.ee"}
    r = requests.get(url, headers=headers)
    json_response = json.loads(r.text)

    session["country"] = "EE"
    session["version"] = "0.4"

    form = {
        "CurrentGivenName": json_response["given_name"],
        "CurrentFamilyName": json_response["family_name"],
        "DateOfBirth": json_response["date_of_birth"],
        "version": session["version"],
        "country": session["country"],
        "certificate": "",
        "returnURL": "",
    }

    (error_code, mdoc, nonce, authTag, pub64, sd_jwt) = process_pid_form(
        form, cipher=False
    )

    if not error_code == 0:
        return redirect_getpid_or_mdl(
            session["version"], cfgserv.service_url + "pid/getpid", error_code, []
        )

    """     privkey = serialization.load_pem_private_key(base64.b64decode(session['privkey']), password=None, backend=default_backend())
        mdoc = decrypt_ECC(base64.urlsafe_b64decode(ciphertext.encode('utf-8')), 
                            base64.urlsafe_b64decode(nonce.encode('utf-8')),
                            base64.urlsafe_b64decode(authTag.encode('utf-8')), 
                            pubkeyPoint(serialization.load_der_public_key(base64.urlsafe_b64decode(pub64.encode("utf-8")))),
                            privkey.private_numbers().private_value)
     

    """

    return {"mdoc": mdoc, "sd-jwt": sd_jwt}
