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


This route_pt_cmd.py file is the blueprint for the route /cmd (PT - Portugal) of the PID Issuer Web service.
"""
import logging
import time
import requests
import datetime
import base64

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

from validate import validate_mandatory_args
from redirect_func import redirect_getpid_or_mdl, url_get
from pid_func import process_pid_form
from mdl_func import process_mdl_form
from app_config.config_devtest import ConfTest as cfgdev
from app_config.config_service import ConfService as cfgserv
from misc import convert_png_to_jpeg


# /cmd blueprint
cmd = Blueprint("cmd", __name__, url_prefix="/cmd")

# Log
from app_config.config_service import ConfService as log


# --------------------------------------------------------------------------------------------------------------------------------------
# route to /cmd
# @cmd.route('', methods=['GET','POST'])
# # route to /cmd/
# @cmd.route('/', methods=['GET','POST'])
# def cmd():
#     """Initial eIDAS-node page.
#     Loads country config information and renders pid_index.html so that the user can select the PID issuer country."""


#     if 'country' in request.form.keys():
#         print(cfgcountries.supported_countries[request.form.get('country')]['pid_url'])
#     return render_template('route_pid/pid-countries.html', countries = create_dict(cfgcountries.supported_countries, 'name'))
#     return "to be implemented", status.HTTP_200_OK


# --------------------------------------------------------------------------------------------------------------------------------------
# route to /cmd/redirect
@cmd.route("/redirect", methods=["GET"])
def red():
    """Receives token from PT IDP - communication originated in route /pid/getpid for country PT

    GET parameters:
    + code (mandatory) - Token code to retrieve the shared attributes consented by the user.
    + scope (mandatory) - scope of the request.
    + state (mandatory) - state of the request.

    Return: Redirect result to returnURL.
    """
    session["route"] = "/cmd/redirect"

    if not request.args:  # if args is empty
        return render_template("/route_pid/pid-pt_url.html")
    """
    (v, l) = validate_mandatory_args(request.args, ["access_token"])
    if not v:  # if not all arguments are available
        return redirect_getpid_or_mdl(session["version"], session["returnURL"], 501, [])

    log.logger_info.info(
        " - INFO - "
        + session["route"]
        + " -  entered the route"
    ) """


    # Retrieve the shared attributes consented by the user
    token = request.args.get("access_token")
    r1 = requests.post(
        "https://preprod.autenticacao.gov.pt/oauthresourceserver/api/AttributeManager",
        json={"token": token},
    )

    session["returnURL"] = cfgserv.OpenID_first_endpoint

    return redirect(
        url_get(
            session["returnURL"],
            {
                "jws_token": session["jws_token"],
                "username": "PT."
                + token
                + "&authenticationContextId="
                + r1.json()["authenticationContextId"],
            },
        )
    )

@cmd.route("/R2", methods=["GET"])
def red2():
    """Receives token from oid4vci
    
    GET parameters:
    + user_id: concatenation of token plus authenticationContextId to get the PID attributes from country PT 

    Return: PID in sd-jwt and mdoc formats
    """

    user_id = request.args.get("user_id")

    # info = user_id.split(".")

    # token = info[0]
    authenticationContextId = request.args.get("authenticationContextId")

    r2 = requests.get(
        "https://preprod.autenticacao.gov.pt/oauthresourceserver/api/AttributeManager?token="
        + user_id
        + "&authenticationContextId="
        + authenticationContextId
    )
    json_data = r2.json()
    birthdate = datetime.datetime.strptime(json_data[2]["value"], "%d-%m-%Y").strftime(
        "%Y-%m-%d"
    )

    session["country"] = "PT"
    session["version"] = "0.4"

    session["device_publickey"] = request.args.get("device_publickey")
    session['route'] = "/cmd/R2"
    log.logger_info.info(" - INFO - " + session["route"] + " - " + session['device_publickey'] + " -  entered the route")


    form = {
        "CurrentGivenName": json_data[1]["value"],
        "CurrentFamilyName": json_data[0]["value"],
        "DateOfBirth": birthdate,
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
            session["version"], session["returnURL"], error_code, []
        )

    json = {"mdoc": mdoc, "sd-jwt": sd_jwt}

    return json


# route to /cmd/redirect
@cmd.route("/redirectmdl", methods=["GET"])
def redmdl():
    """Receives token from PT IDP - communication originated in route /mdl/getmdl for country PT

    GET parameters:
    + code (mandatory) - Token code to retrieve the shared attributes consented by the user.
    + scope (mandatory) - scope of the request.
    + state (mandatory) - state of the request.

    Return: Redirect result to returnURL.
    """
    session["route"] = "/cmd/redirectmdl"
    log.logger_info.info(
        " - INFO - "
        + session["route"]
        + " -  entered the route"
    )

    if not request.args:  # if args is empty
        return render_template("/route_mdl/mdl-pt_url.html")

    (v, l) = validate_mandatory_args(request.args, ["access_token"])
    if not v:  # if not all arguments are available
        return redirect_getpid_or_mdl(session["version"], session["returnURL"], 501, [])

    # Retrieve the shared attributes consented by the user
    token = request.args.get("access_token")
    r1 = requests.post(
        "https://preprod.autenticacao.gov.pt/oauthresourceserver/api/AttributeManager",
        json={"token": token},
    )

    session["returnURL"] = cfgserv.OpenID_first_endpoint

    return redirect(
        url_get(
            session["returnURL"],
            {
                "jws_token": session["jws_token"],
                "username": "PT."
                + token
                + "&authenticationContextId="
                + r1.json()["authenticationContextId"],
            },
        )
    )

@cmd.route("/mdl_R2", methods=["GET"])
def mdl_red2():
    """Receives token from oid4vci
    
    GET parameters:
    + user_id: concatenation of token plus authenticationContextId to get the mDL attributes from country PT 

    Return: mDL in sd-jwt and mdoc formats
    """

    user_id = request.args.get("user_id")

    # info = user_id.split(".")

    # token = info[0]
    authenticationContextId = request.args.get("authenticationContextId")

    time.sleep(30)
    r2 = requests.get(
        "https://preprod.autenticacao.gov.pt/oauthresourceserver/api/AttributeManager?token="
        + user_id
        + "&authenticationContextId="
        + authenticationContextId
    )
    json_data = r2.json()
    birthdate = datetime.datetime.strptime(json_data[0]["value"], "%d-%m-%Y").strftime(
        "%Y-%m-%d"
    )

    session["country"] = "PT"
    session["version"] = "0.4"

    session["device_publickey"] = request.args.get("device_publickey")
    session['route'] = "/cmd/mdl_R2"
    log.logger_info.info(" - INFO - " + session["route"] + " - " + session['device_publickey'] + " -  entered the route")

    Portrait= base64.urlsafe_b64encode(convert_png_to_jpeg(base64.b64decode(json_data[6]["value"]))).decode("utf-8")


    form = {
        "CurrentGivenName": json_data[3]["value"],
            "CurrentFamilyName": json_data[2]["value"],
            "DateOfBirth": birthdate,
            "IssuingAuthority": json_data[4]["value"],
            "DocumentNumber": json_data[5]["value"],
            "Portrait": Portrait,
            "DrivingPrivileges": json_data[7]["value"],
            "BirthPlace": json_data[8]["value"],
            "version": session["version"],
            "country": session["country"],
            "certificate": "",
            "returnURL": ""
    }

    (error_code, mdoc, nonce, authTag, pub64, sd_jwt) = process_mdl_form(
        form, cipher=False
    )

    if not error_code == 0:
        return redirect_getpid_or_mdl(
            session["version"], session["returnURL"], error_code, []
        )

    json = {"mdoc": mdoc, "sd-jwt": sd_jwt}

    return json