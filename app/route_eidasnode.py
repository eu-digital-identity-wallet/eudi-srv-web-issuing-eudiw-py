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


This route_eidasnode.py file is the blueprint for the route /eidasnode of the PID Issuer Web service.
"""
import base64
import json
import logging

from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_cors import CORS

from validate import validate_mandatory_args
from app_config.config_countries import ConfCountries as cfgcountries
from app_config.config_service import ConfService as cfgservice
from redirect_func import redirect_getpid_or_mdl, json_post, url_get
from lighttoken import create_request, handle_response
from pid_func import format_pid_data, format_sd_jwt_pid_data

# /eidasnode blueprint
eidasnode = Blueprint("eidasnode", __name__, url_prefix="/eidasnode")
CORS(eidasnode)  # enable CORS on the eidasnode blue print



# --------------------------------------------------------------------------------------------------------------------------------------
# route to /eidasnode
# @eidasnode.route('', methods=['GET','POST'])
# # route to /pid/
# @eidasnode.route('/', methods=['GET','POST'])
# def eidasnode_root():
#     """Initial eIDAS-node page.
#     Loads country config information and renders pid_index.html so that the user can select the PID issuer country."""


#     if 'country' in request.form.keys():
#         print(cfgcountries.supported_countries[request.form.get('country')]['pid_url'])
#     return render_template('route_pid/pid-countries.html', countries = create_dict(cfgcountries.supported_countries, 'name'))
#     return "to be implemented", status.HTTP_200_OK


# --------------------------------------------------------------------------------------------------------------------------------------
# route to /eidasnode/lightrequest
@eidasnode.route("/lightrequest", methods=["GET"])
def getlightrequest_openid():
    """Connects to eIDAS-Node

    Get query parameters:
    + country (mandatory) - Two-letter country code according to ISO 3166-1 alpha-2.

    Return: Error to returnURL if country parameter is missing. Otherwise, create eIDAS node lightRequest and connects to the country's eIDAS node (must be defined in the local eIDAS node how to connect to the country's eIDAS node).
    """
    session["route"] = "/eidasnode/lightrequest"

    (b, l) = validate_mandatory_args(request.args, ["country"])
    if not b:
        return redirect_getpid_or_mdl(
            request.args.get("version"), request.args.get("returnURL"), 301, []
        )

    """ log.logger_info.info(
        " - INFO - "
        + session["route"]
        + " - "
        + session["device_publickey"]
        + " -  entered the route"
    ) """

    country = request.args.get("country")
    country_data = cfgcountries.supported_countries.get(country)
    if country_data is None or "loa" not in country_data:
        return cfgservice.error_list[str(301)]

    # session['country'] = request.args.get('country')
    return create_request(
        request.args.get("country"),
        cfgcountries.supported_countries[request.args.get("country")]["loa"],
    )


# --------------------------------------------------------------------------------------------------------------------------------------
# route to /eidasnode_openid/lightresponse (specific.connector.response.receiver as defined in the eidas.xml file of the local eIDAS node).
# Contains the response to /eidasnode_openid/lightrequest sent by the eIDAS node
@eidasnode.route("/lightresponse", methods=["POST"])
def getlightresponse():
    """Handles the response to /eidasnode_V04/lightrequest sent by the eIDAS node

    Get query parameters:
    + token (mandatory) - token sent by eIDAS node.

    Return: Redirect mdoc to session['returnURL'] if no error. Otherwise redirect error to session['returnURL'],
    """

    session["route"] = "/eidasnode/lightresponse"
    cfgservice.app_logger.info(
        " - INFO - " + session["route"] + " - " + " -  entered the route"
    )

    form_keys = request.form.keys()
    # if token does not exist
    if not "token" in form_keys:
        return redirect_getpid_or_mdl(session["version"], session["returnURL"], 302, [])

    user_id = request.form.get("token")

    (b, e) = handle_response(user_id)
    if not b:  # if error in getting the attributes

        session["tries"] -= 1

        if session["tries"] == 0:
            return redirect(
                url_get(
                    cfgservice.eidasnode_openid_error_endpoint,
                    {
                        "jws_token": session["jws_token"],
                        "error": "login failed",
                        "error_description": "login failed too many times",
                    },
                )
            )

        return render_template(
            "misc/eidas_fail.html",
            Info="Login Failed.  Retries left:" + str(session["tries"]),
            link=cfgcountries.supported_countries["EU"]["pid_url_oidc"],
        )

    return redirect(
        url_get(
            session["returnURL"],
            {
                "jws_token": session["jws_token"],
                "username": "EU." + user_id,
            },
        )
    )


@eidasnode.route("/eidasR2", methods=["GET"])
def eidasnodeR2():
    """Route acessed by OpenID to get PID attributes from country EE

    Get query parameters:
    + user_id - token to obtain PID attributes

    Return:PID in sd-jwt and mdoc formats
    """

    session["country"] = "EU"
    session["version"] = "0.4"
    session["device_publickey"] = request.args["device_publickey"]
    user_id = request.args["user_id"]
    session["returnURL"] = cfgservice.service_url + "V04/getpid"

    session["route"] = "/eidasnode/eidasR2"
    cfgservice.app_logger.info(
        " - INFO - "
        + session["route"]
        + " - "
        + session["device_publickey"]
        + " -  entered the route"
    )

    (b, e) = handle_response(user_id)
    if not b:  # if error in getting the attributes
        return redirect_getpid_or_mdl(
            session["version"], session["returnURL"], 303, [("error_str", e)]
        )
    (v, l) = validate_mandatory_args(e, cfgservice.eidasnode_pid_attributes)
    if not v:  # if not all PID attributes are available
        return redirect_getpid_or_mdl(session["version"], session["returnURL"], 304, [])

    pdata = format_pid_data(e, session["country"])

    pdata1 = format_sd_jwt_pid_data(e, session["country"])

    r = json_post(
        cfgservice.service_url + "formatter/cbor",
        {
            "version": session["version"],
            "country": session["country"],
            "doctype": cfgservice.pid_doctype,
            "device_publickey": session["device_publickey"],
            "data": {cfgservice.pid_namespace: pdata},
        },
    ).json()
    if not r["error_code"] == 0:
        return redirect_getpid_or_mdl(
            session["version"], session["returnURL"], r["error_code"], []
        )

    r1 = json_post(
        cfgservice.service_url + "formatter/sd-jwt",
        {
            "version": session["version"],
            "country": session["country"],
            "doctype": cfgservice.pid_doctype,
            "device_publickey": session["device_publickey"],
            "data": pdata1,
        },
    ).json()
    if not r1["error_code"] == 0:
        return redirect_getpid_or_mdl(
            session["version"], session["returnURL"], r1["error_code"], []
        )

    # mdoc from urlsafe_b64encode to b64encode
    mdoc = bytes(r["mdoc"], "utf-8")

    sd_jwt = r1["sd-jwt"]

    return {"mdoc": mdoc.decode("utf-8"), "sd-jwt": sd_jwt}


@eidasnode.route("/dynamic_R2", methods=["GET"])
def dynamic_eidasnodeR2():
    """Route acessed by OpenID to get PID attributes from country EE

    Get query parameters:
    + user_id - token to obtain PID attributes

    Return:PID in sd-jwt and mdoc formats
    """

    session["country"] = "EU"
    session["version"] = "0.4"

    credential_request_json = json.loads(request.args.get("credential_requests"))

    credential_request = credential_request_json["credential_requests"]
    user_id = credential_request_json["user_id"]

    session["returnURL"] = cfgservice.service_url + "V04/getpid"

    session["route"] = "/eidasnode/eidasR2"
    cfgservice.app_logger.info(
        " - INFO - "
        + session["route"]
        + " - "
        + session["device_publickey"]
        + " -  entered the route"
    )

    (b, e) = handle_response(user_id)
    if not b:  # if error in getting the attributes
        return redirect_getpid_or_mdl(
            session["version"], session["returnURL"], 303, [("error_str", e)]
        )

    credential_response = {}
    document_mappings = cfgservice.document_mappings

    for credential in credential_request:
        format = credential["format"]
        doctype = credential["doctype"]
        device_publickey = credential["device_publickey"]

        formatting_functions = document_mappings[doctype]["formatting_functions"]

        formatting_function_data = formatting_functions.get(format)

        if formatting_function_data:
            formatting_function = formatting_function_data["formatting_function"]
            f = globals().get(formatting_function)
            pdata = f(e, device_publickey)
            credential_response.update({f"{doctype}_{format}": pdata})

    return credential_response
