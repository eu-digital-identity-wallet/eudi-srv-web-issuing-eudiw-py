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


This route_oidc.py file is the blueprint for the route /oidc of the PID Issuer Web service.
"""
import base64
import hashlib
import io
import random
import re
import sys
import time
import uuid
import threading
import urllib.parse
import segno

from flask import (
    Blueprint,
    jsonify,
    Response,
    request,
    session,
    current_app,
    redirect,
    render_template,
    url_for,
)
from flask.helpers import make_response, send_from_directory
import os

from flask_cors import CORS
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oauth2 import ResponseMessage
import json
import sys
import traceback
from typing import Union
from urllib.parse import urlparse

from cryptojwt import as_unicode
from idpyoidc.message.oidc import AccessTokenRequest
import werkzeug

from idpyoidc.server.exception import FailedAuthentication, ClientAuthenticationError
from idpyoidc.server.oidc.token import Token
from app.misc import (
    auth_error_redirect,
    authentication_error_redirect,
    scope2details,
    vct2id,
)

from datetime import datetime, timedelta

#!/usr/bin/env python3
import requests

from .app_config.config_service import ConfService as cfgservice
from .app_config.config_oidc_endpoints import ConfService as cfgoidc

from . import oidc_metadata, openid_metadata, oauth_metadata, oidc_metadata_clean

oidc = Blueprint("oidc", __name__, url_prefix="/")
CORS(oidc)  # enable CORS on the blue print

# variable for PAR requests
from app.data_management import (
    getSessionId_accessToken,
    parRequests,
    transaction_codes,
    deferredRequests,
    session_ids,
    getSessionId_requestUri,
    getSessionId_authCode,
    credential_offer_references,
)


def _add_cookie(resp: Response, cookie_spec: Union[dict, list]):
    kwargs = {k: v for k, v in cookie_spec.items() if k not in ("name",)}
    kwargs["path"] = "/"
    kwargs["samesite"] = "Lax"
    resp.set_cookie(cookie_spec["name"], **kwargs)


def add_cookie(resp: Response, cookie_spec: Union[dict, list]):
    if isinstance(cookie_spec, list):
        for _spec in cookie_spec:
            _add_cookie(resp, _spec)
    elif isinstance(cookie_spec, dict):
        _add_cookie(resp, cookie_spec)


""" @oidc.route("/static/<path:path>")
def send_js(path):
    return send_from_directory("static", path) """


""" @oidc.route("/static/jwks.json")
def keys():
    fname = os.path.join("static", jwks)
    return open(fname).read()
    return send_from_directory('static', 'jwks.json') """


def do_response(endpoint, req_args, error="", **args) -> Response:
    info = endpoint.do_response(request=req_args, error=error, **args)
    # _log = current_app.logger
    cfgservice.app_logger.info("do_response: {}".format(info))

    try:
        _response_placement = info["response_placement"]
    except KeyError:
        _response_placement = endpoint.response_placement

    cfgservice.app_logger.debug("response_placement: {}".format(_response_placement))

    if error:
        if _response_placement == "body":
            cfgservice.app_logger.info("Error Response: {}".format(info["response"]))
            _http_response_code = info.get("response_code", 400)
            resp = make_response(info["response"], _http_response_code)
        else:  # _response_placement == 'url':
            cfgservice.app_logger.info("Redirect to: {}".format(info["response"]))
            resp = redirect(info["response"])
    else:
        if _response_placement == "body":
            cfgservice.app_logger.info("Response: {}".format(info["response"]))
            _http_response_code = info.get("response_code", 200)
            resp = make_response(info["response"], _http_response_code)
        else:  # _response_placement == 'url':
            cfgservice.app_logger.info("Redirect to: {}".format(info["response"]))
            resp = redirect(info["response"])

    for key, value in info["http_headers"]:
        resp.headers[key] = value

    if "cookie" in info:
        add_cookie(resp, info["cookie"])

    return resp


def verify(authn_method):
    """
    Authentication verification

    :param url_endpoint: Which endpoint to use
    :param kwargs: response arguments
    :return: HTTP redirect
    """
    # kwargs = dict([(k, v) for k, v in request.form.items()])

    try:
        username = authn_method.verify(username=request.args.get("username"))

        auth_args = authn_method.unpack_token(request.args.get("jws_token"))
    except:
        cfgservice.app_logger.error(
            "Authorization verification: username or jws_token not found"
        )
        if "jws_token" in request.args:
            return authentication_error_redirect(
                jws_token=request.args.get("jws_token"),
                error="invalid_request",
                error_description="Authentication verification Error",
            )
        else:
            return render_template(
                "misc/500.html", error="Authentication verification Error"
            )

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

    session_ids[session["session_id"]]["auth_code"] = args["response_args"]["code"]

    logText = (
        ", Session ID: "
        + session["session_id"]
        + ", "
        + "Authorization Response, Code: "
        + args["response_args"]["code"]
    )

    if "state" in args["response_args"]:

        logText = logText + ", State: " + args["response_args"]["state"]

    cfgservice.app_logger.info(logText)

    return do_response(endpoint, request, **args)


@oidc.route("/verify/user", methods=["GET"])
def verify_user():
    authn_method = current_app.server.get_context().authn_broker.get_method_by_id(
        "user"
    )
    try:
        return verify(authn_method)
    except FailedAuthentication as exc:
        cfgservice.app_logger.error("Authorization verification failed")
        return render_template("misc/500.html", error=str(exc))


@oidc.route("/.well-known/oauth-authorization-server/oidc")
def well_known2():
    info = {
        "response": openid_metadata,
        "http_headers": [
            ("Content-type", "application/json; charset=utf-8"),
            ("Pragma", "no-cache"),
            ("Cache-Control", "no-store"),
        ],
    }

    _http_response_code = info.get("response_code", 200)
    resp = make_response(info["response"], _http_response_code)

    for key, value in info["http_headers"]:
        resp.headers[key] = value

    return resp


@oidc.route("/.well-known/<service>")
def well_known(service):
    if service == "openid-credential-issuer":
        info = {
            "response": oidc_metadata_clean,
            "http_headers": [
                ("Content-type", "application/json; charset=utf-8"),
                ("Pragma", "no-cache"),
                ("Cache-Control", "no-store"),
            ],
        }

        _http_response_code = info.get("response_code", 200)
        resp = make_response(info["response"], _http_response_code)

        for key, value in info["http_headers"]:
            resp.headers[key] = value

        return resp
    elif service == "oauth-authorization-server":
        info = {
            "response": openid_metadata,
            "http_headers": [
                ("Content-type", "application/json; charset=utf-8"),
                ("Pragma", "no-cache"),
                ("Cache-Control", "no-store"),
            ],
        }

        _http_response_code = info.get("response_code", 200)
        resp = make_response(info["response"], _http_response_code)

        for key, value in info["http_headers"]:
            resp.headers[key] = value

        return resp

    elif service == "openid-configuration":
        # _endpoint = current_app.server.get_endpoint("provider_config")
        info = {
            "response": openid_metadata,
            "http_headers": [
                ("Content-type", "application/json; charset=utf-8"),
                ("Pragma", "no-cache"),
                ("Cache-Control", "no-store"),
            ],
        }

        _http_response_code = info.get("response_code", 200)
        resp = make_response(info["response"], _http_response_code)

        for key, value in info["http_headers"]:
            resp.headers[key] = value

        return resp

    elif service == "webfinger":
        _endpoint = current_app.server.get_endpoint("discovery")
    else:
        return make_response("Not supported", 400)

    return service_endpoint(_endpoint)


@oidc.route("/registration", methods=["GET", "POST"])
def registration():
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
    code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)
    code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
    code_challenge = code_challenge.replace("=", "")

    response = service_endpoint(current_app.server.get_endpoint("registration"))

    return response


@oidc.route("/registration_api", methods=["GET", "DELETE"])
def registration_api():
    if request.method == "DELETE":
        return service_endpoint(current_app.server.get_endpoint("registration_delete"))
    else:
        return service_endpoint(current_app.server.get_endpoint("registration_read"))


@oidc.route("/authorization", methods=["GET"])
def authorization():
    return service_endpoint(current_app.server.get_endpoint("authorization"))


# @oidc.route("/authorizationV2", methods=["GET"])
def authorizationv2(
    client_id,
    redirect_uri,
    response_type,
    scope=None,
    code_challenge_method=None,
    code_challenge=None,
    authorization_details=None,
    state=None,
):

    client_secret = str(uuid.uuid4())

    current_app.server.get_endpoint("registration").process_request_authorization(
        client_id=client_id, client_secret=client_secret, redirect_uri=redirect_uri
    )

    # return service_endpoint(current_app.server.get_endpoint("authorization"))
    url = (
        cfgservice.service_url
        + "authorization?redirect_uri="
        + redirect_uri
        + "&response_type="
        + response_type
        + "&client_id="
        + client_id
    )

    if scope:
        url = url + "&scope=" + scope

    if authorization_details:
        url = url + "&authorization_details=" + authorization_details

    if code_challenge and code_challenge_method:
        url = f"{url}&code_challenge={code_challenge}&code_challenge_method={code_challenge_method}"

    if state:
        url = f"{url}&state={state}"

    payload = {}
    headers = {}
    response = requests.request("GET", url, headers=headers, data=payload)

    if response.status_code != 200:
        cfgservice.app_logger.error("Authorization endpoint invalid request")
        return auth_error_redirect(redirect_uri, "invalid_request")

    response = response.json()

    args = {}
    if "authorization_details" in response:
        args.update({"authorization_details": response["authorization_details"]})
    if "scope" in response:
        args.update({"scope": response["scope"]})
    if not args:
        cfgservice.app_logger.error("Authorization args not found")
        return authentication_error_redirect(
            jws_token=response["token"],
            error=response["error"],
            error_description=response["error_description"],
        )

    params = {"token": response["token"]}

    params.update(args)

    session["authorization_params"] = params

    session_id = str(uuid.uuid4())
    session_ids.update(
        {session_id: {"expires": datetime.now() + timedelta(minutes=60)}}
    )
    session["session_id"] = session_id
    cfgservice.app_logger.info(
        ", Session ID: "
        + session_id
        + ", "
        + "Authorization Request, Payload: "
        + str(
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": response_type,
                "scope": scope,
                "code_challenge_method": code_challenge_method,
                "code_challenge": code_challenge,
                "authorization_details": authorization_details,
            }
        )
    )

    return redirect(response["url"])


@oidc.route("/authorizationV3", methods=["GET"])
def authorizationV3():

    if "request_uri" not in request.args:
        try:
            client_id = request.args.get("client_id")
            redirect_uri = request.args.get("redirect_uri")
            response_type = request.args.get("response_type")
            scope = request.args.get("scope")
            code_challenge_method = request.args.get("code_challenge_method")
            code_challenge = request.args.get("code_challenge")
            authorization_details = request.args.get("authorization_details")
            state = request.args.get("state")
        except:
            return make_response("Authorization v2 error", 400)
        return authorizationv2(
            client_id,
            redirect_uri,
            response_type,
            scope,
            code_challenge_method,
            code_challenge,
            authorization_details,
            state,
        )

    try:
        request_uri = request.args.get("request_uri")
    except:
        cfgservice.app_logger.error("Authorization request_uri not found")
        return make_response("Authorization error", 400)

    if not request_uri in parRequests:  # unknow request_uri => return error
        # needs to be changed to an appropriate error message, and need to be logged
        # return service_endpoint(current_app.server.get_endpoint("authorization"))
        cfgservice.app_logger.error(
            "Authorization request_uri not found in parRequests"
        )
        return make_response("Request_uri not found", 400)

    session_id = getSessionId_requestUri(request_uri)

    if session_id == None:
        cfgservice.app_logger.error("Authorization request_uri not found.")
        return make_response("Request_uri not found", 400)

    cfgservice.app_logger.info(
        ", Session ID: "
        + session_id
        + ", "
        + "Authorization Request, Payload: "
        + str(dict(request.args))
    )

    session["session_id"] = session_id

    par_args = parRequests[request_uri]["req_args"]

    if "scope" not in par_args:
        par_args["scope"] = "openid"

    url = (
        cfgservice.service_url
        + "authorization?redirect_uri="
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
    response = requests.request("GET", url, headers=headers, data=payload)

    if response.status_code != 200:
        cfgservice.app_logger.error("Authorization endpoint invalid request")
        return auth_error_redirect(par_args["redirect_uri"], "invalid_request")

    response = response.json()

    args = {}
    if "authorization_details" in response:
        args.update({"authorization_details": response["authorization_details"]})
    if "scope" in response:
        args.update({"scope": response["scope"]})
    if not args:
        cfgservice.app_logger.error("Authorization args not found")
        return authentication_error_redirect(
            jws_token=response["token"],
            error=response["error"],
            error_description=response["error_description"],
        )

    params = {"token": response["token"]}

    params.update(args)

    session["authorization_params"] = params

    return redirect(response["url"])


@oidc.route("/pid_authorization")
def pid_authorization_get():

    presentation_id = request.args.get("presentation_id")

    if not presentation_id:
        raise ValueError("Presentation id is required")

    if not re.match(r"^[A-Za-z0-9_-]+$", presentation_id):
        raise ValueError("Invalid Presentation id format")

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
        return jsonify({"error": error_msg}), 500
    else:
        data = {"message": "Sucess"}
        return jsonify({"message": data}), 200


@oidc.route("/auth_choice", methods=["GET"])
def auth_choice():
    print("\nAuth_choice")

    token = request.args.get("token")
    session_id = request.args.get("session_id")
    scope = request.args.get("scope")
    authorization_details_str = request.args.get("authorization_details")

    session["session_id"] = session_id

    supported_credencials = cfgservice.auth_method_supported_credencials
    pid_auth = True
    country_selection = True



    authorization_details = None
    authorization_details_request = None
    if authorization_details_str:
        try:
            decoded_string = urllib.parse.unquote(authorization_details_str)
            authorization_details = json.loads(decoded_string)
            authorization_details_request = authorization_details
        except json.JSONDecodeError as e:
            print(f"Error parsing authorization_details JSON: {e}")
            return jsonify({"error": "Invalid authorization_details parameter"}), 400

    # authorization_params = session["authorization_params"]
    authorization_details = []
    if authorization_details:  # "authorization_details" in authorization_params:
        authorization_details.extend(
            json.loads(
                authorization_details
            )  # authorization_params["authorization_details"]
        )

    if scope:  # "scope" in authorization_params:
        scope_elements = scope.split()
        authorization_details.extend(
            scope2details(scope_elements)
        )  # authorization_params["scope"]

    if not authorization_details:
        return authentication_error_redirect(
            jws_token=token,  # authorization_params["token"],
            error="invalid authentication",
            error_description="No authorization details or scope found in dynamic route.",
        )
    
    credentials_requested = []
    for cred in authorization_details:
        if "credential_configuration_id" in cred:
            if cred["credential_configuration_id"] not in credentials_requested:
                credentials_requested.append(cred["credential_configuration_id"])
        elif "vct" in cred:
            if cred["vct"] not in credentials_requested:
                credentials_requested.append(vct2id(cred["vct"]))
    
    credential_configuration_id = scope.replace("openid", "").strip()

    session_manager.add_session(
        session_id=session_id,
        jws_token=token,
        scope=credential_configuration_id,
        authorization_details=authorization_details,
        credentials_requested=credentials_requested
    )

    for cred in credentials_requested:
        if (
            cred in supported_credencials["PID_login"]
            and cred not in supported_credencials["country_selection"]
        ):
            country_selection = False

        elif (
            cred not in supported_credencials["PID_login"]
            and cred in supported_credencials["country_selection"]
        ):
            pid_auth = False

        elif (
            cred not in supported_credencials["PID_login"]
            and cred not in supported_credencials["country_selection"]
        ):
            country_selection = False
            pid_auth = False

    if country_selection == False and pid_auth == True:
        return redirect(cfgservice.service_url + "oid4vp")
    elif country_selection == True and pid_auth == False:
        return redirect(cfgservice.service_url + "dynamic/")

    error = ""
    if pid_auth == False and country_selection == False:
        error = "Combination of requested credentials is not valid!"

    return render_template(
        "misc/auth_method.html",
        pid_auth=pid_auth,
        country_selection=country_selection,
        error=error,
        redirect_url=cfgservice.service_url,
    )

    # return render_template("misc/auth_method.html")


@oidc.route("/token_service", methods=["POST"])
def token_service():

    # session_id = request.cookies.get("session")

    response = service_endpoint(current_app.server.get_endpoint("token"))

    return response


@oidc.route("/token", methods=["POST"])
def token():
    req_args = dict([(k, v) for k, v in request.form.items()])

    response = None

    if req_args["grant_type"] == "authorization_code":

        session_id = getSessionId_authCode(req_args["code"])

        cfgservice.app_logger.info(
            f", Session ID: {session_id}, Token Request, Payload: {request.form.to_dict()}"
        )

        response = service_endpoint(current_app.server.get_endpoint("token"))

        cfgservice.app_logger.info(
            f", Session ID: {session_id}, Token Response, Payload: {json.loads(response.get_data())}"
        )

        response_json = json.loads(response.get_data())

        if "access_token" in response_json:
            session_ids[session_id]["access_token"] = response_json["access_token"]

        if "refresh_token" in response_json:
            session_ids[session_id]["refresh_token"] = response_json["refresh_token"]

    elif (
        req_args["grant_type"] == "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    ):

        if "pre-authorized_code" not in req_args:
            return make_response("invalid_request", 400)

        if "tx_code" not in req_args:
            if "0" != transaction_codes[code]["tx_code"]:
                error_message = {
                    "error": "invalid_request",
                    "description": "invalid tx_code",
                }
            response = make_response(jsonify(error_message), 400)
            return response

        code = req_args["pre-authorized_code"]

        if code not in transaction_codes:
            error_message = {
                "error": "invalid_request",
                "description": "invalid or expired tx_code",
            }
            response = make_response(jsonify(error_message), 400)
            return response

        preauth_code = transaction_codes[code]["pre_auth_code"]

        session_id = getSessionId_authCode(preauth_code)

        """ cfgservice.app_logger.info(
            ", Session ID: "
            + session_id
            + ", "
            + "Pre-Authorized Token Request, Payload: "
            + str(request.form.to_dict())
        ) """

        if req_args["tx_code"] != transaction_codes[code]["tx_code"]:
            error_message = {
                "error": "invalid_request",
                "description": "invalid tx_code",
            }
            response = make_response(jsonify(error_message), 400)
            return response

        url = cfgservice.service_url + "token_service"
        redirect_url = "preauth"

        payload = (
            "grant_type=authorization_code&code="
            + preauth_code
            + "&redirect_uri="
            + redirect_url
            + "&client_id=ID&state=vFs5DfvJqoyHj7_dZs2JbdklePg6pMLsUHHmVIfobRw&code_verifier=FnWCRIhpJtl6IYwVVYB8gZkQsmvBVLfU4HQiABPopYQ6gvIZBwMrXg"
        )
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        response = requests.request("POST", url, headers=headers, data=payload)
        if response.status_code != 200:
            return make_response("invalid_request", 400)

        # response = response.json()
        cfgservice.app_logger.info("Token response: " + str(response.json()))

        transaction_codes.pop(code)

        cfgservice.app_logger.info(
            f", Session ID: {session_id}, Pre-Authorized Token Response, Payload: {response.json()}"
        )

        response_json = response.json()

        if "access_token" in response_json:
            session_ids[session_id]["access_token"] = response_json["access_token"]

        if "refresh_token" in response_json:
            session_ids[session_id]["refresh_token"] = response_json["refresh_token"]

        return response_json

    elif req_args["grant_type"] == "refresh_token":

        response = service_endpoint(current_app.server.get_endpoint("token"))

        response_json = json.loads(response.get_data())

        if "access_token" in response_json:
            session_id = str(uuid.uuid4())
            session_ids.update(
                {session_id: {"expires": datetime.now() + timedelta(minutes=60)}}
            )

            session_ids[session_id]["access_token"] = response_json["access_token"]

    else:

        cfgservice.app_logger.info(
            "Token response: " + str(json.loads(response.get_data()))
        )

    return response


@oidc.route("/introspection", methods=["POST"])
def introspection_endpoint():
    return service_endpoint(current_app.server.get_endpoint("introspection"))


@oidc.route("/userinfo", methods=["GET", "POST"])
def userinfo():
    return service_endpoint(current_app.server.get_endpoint("userinfo"))


@oidc.route("/session", methods=["GET"])
def session_endpoint():
    return service_endpoint(current_app.server.get_endpoint("session"))


@oidc.route("/pushed_authorization", methods=["POST"])
def par_endpoint():
    return service_endpoint(current_app.server.get_endpoint("pushed_authorization"))


@oidc.route("/pushed_authorizationv2", methods=["POST"])
def par_endpointv2():

    session_id = str(uuid.uuid4())

    cfgservice.app_logger.info(
        ", Session ID: "
        + session_id
        + ", "
        + "Pushed Authorization Request, Payload: "
        + str(request.form.to_dict())
    )

    redirect_uri = None
    try:
        redirect_uri = request.form["redirect_uri"]

        client_id = request.form["client_id"]
    except:
        cfgservice.app_logger.error("PAR: client_id or redirect_uri not found")
        if redirect_uri:
            return auth_error_redirect(
                redirect_uri, "invalid_request", "invalid parameters"
            )
        else:
            return make_response("PARv2 error", 400)

    client_secret = str(uuid.uuid4())
    session["redirect_uri"] = redirect_uri
    current_app.server.get_endpoint("registration").process_request_authorization(
        client_id=client_id, client_secret=client_secret, redirect_uri=redirect_uri
    )

    response = service_endpoint(current_app.server.get_endpoint("pushed_authorization"))

    cfgservice.app_logger.info(
        ", Session ID: "
        + session_id
        + ", "
        + "Pushed Authorization Response, Payload: "
        + str(json.loads(response.get_data()))
    )

    session_ids.update(
        {
            session_id: {
                "expires": datetime.now() + timedelta(minutes=60),
                "request_uri": json.loads(response.get_data())["request_uri"],
            }
        }
    )

    return response


def verify_introspection(bearer_token):
    introspection_url = "http://127.0.0.1:6005/introspection"

    payload = f"token={bearer_token}"

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        response = requests.request(
            "POST", introspection_url, headers=headers, data=payload
        )
        response.raise_for_status()  # Raises an HTTPError for 4xx/5xx status codes

        introspection_data = response.json()

    except requests.exceptions.RequestException as e:
        # Error 4: Network or HTTP-level error during introspection call
        print(f"An error occurred during introspection request: {e}")
        return (
            jsonify({"error": "Failed to validate token with the issuer."}),
            502,
        )  # 502 Bad Gateway is appropriate here
    except json.JSONDecodeError:
        # Error 5: Malformed JSON from the introspection endpoint
        print("Failed to decode JSON from introspection response.")
        return (
            jsonify({"error": "Invalid response from the introspection endpoint."}),
            502,
        )

    # --- 3. Verify Introspection Data ---
    is_active = introspection_data.get("active", False)
    username = introspection_data.get("username")

    if not is_active:
        # Error 6: Inactive token
        print("Token is inactive.")
        return jsonify({"error": "Provided token is inactive."}), 401

    if not username:
        # Error 7: Missing username in introspection response
        print("Token is active but missing username.")
        return (
            jsonify(
                {"error": "Token is active but does not contain a username claim."}
            ),
            401,
        )

    return username


from . import session_manager


def verify_credential_request(credential_request):

    if "credential_indentifier" in credential_request:
        return jsonify({"error": "credential_identifier currently not supported."}), 401

    if (
        "credential_identifier" not in credential_request
        and "credential_configuration_id" not in credential_request
    ):
        return (
            jsonify(
                {
                    "error": "Missing credential_identifier or credential_configuration_id"
                }
            ),
            401,
        )

    if "proof" not in credential_request and "proofs" not in credential_request:
        return jsonify({"error": "Credential Issuer requires key proof."}), 401

    elif "proof" in credential_request:
        if "proof_type" not in credential_request["proof"]:
            return jsonify({"error": "Credential Issuer requires key proof."}), 401

        if (
            credential_request["proof"]["proof_type"] == "jwt"
            and "jwt" not in credential_request["proof"]
        ):
            return jsonify({"error": "Missing jwt field."}), 401

    return credential_request


import jwt
from jwt.algorithms import get_default_algorithms

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


# gets the public key from a JWK
def pKfromJWK(jwt_encoded):
    jwt_decoded = jwt.get_unverified_header(jwt_encoded)
    jwk = jwt_decoded["jwk"]

    if "crv" not in jwk or jwk["crv"] != "P-256":
        _resp = {
            "error": "invalid_proof",
            "error_description": "Credential Issuer only supports P-256 curves",
        }
        return _resp  # {"response_args": _resp, "client_id": client_id}

    x = jwk["x"]
    y = jwk["y"]

    # Convert string coordinates to bytes
    x_bytes = base64.urlsafe_b64decode(x + "=" * (4 - len(x) % 4))
    y_bytes = base64.urlsafe_b64decode(y + "=" * (4 - len(y) % 4))

    # Create a public key from the bytes
    public_numbers = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(x_bytes, "big"),
        y=int.from_bytes(y_bytes, "big"),
        curve=ec.SECP256R1(),
    )

    public_key = public_numbers.public_key()

    # Serialize the public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Encode the public key in base64url format

    device_key = base64.urlsafe_b64encode(public_key_pem).decode("utf-8")

    return device_key


from authlib.jose import JsonWebEncryption
from authlib.jose import JsonWebKey


def generate_credentials(credential_request, session_id):
    formatter_request = {}

    formatter_request.update(
        {
            "credential_configuration_id": credential_request[
                "credential_configuration_id"
            ]
        }
    )

    if (
        "proof" in credential_request
        and credential_request["proof"]["proof_type"] == "jwt"
    ):
        try:
            jwt_encoded = credential_request["proof"]["jwt"]
            device_key = pKfromJWK(jwt_encoded)
            formatter_request.update({"proofs": [{"jwt": device_key}]})

        except Exception as e:
            return ""

    pubKeys = []
    if "proofs" in credential_request:
        for alg, key_list in credential_request["proofs"].items():
            if alg != "jwt":
                return {"error": "proof currently not supported"}
            else:
                for jwt_ in key_list:
                    try:
                        device_key = pKfromJWK(jwt_)
                        pubKeys.append({alg: device_key})
                    except Exception as e:
                        _resp = {
                            "error": "invalid_proof",
                            "error_description": str(e),
                        }
                        return _resp

        formatter_request.update({"proofs": pubKeys})

    redirect_uri = cfgservice.service_url + "dynamic/dynamic_R2"

    data = {
        "credential_requests": formatter_request,
        "user_id": session_id,
    }

    json_data = json.dumps(data)
    headers = {"Content-Type": "application/json"}
    _msg = requests.post(redirect_uri, data=json_data, headers=headers).json()

    return _msg


def encrypt_response(credential_request, credential_response):
    encryption_config = credential_request.get("credential_response_encryption", {})

    if not all(k in encryption_config for k in ["jwk", "alg", "enc"]):
        return (
            jsonify(
                {
                    "error": "invalid_credential_response_encryption",
                    "error_description": "Missing required fields in credential_response_encryption.",
                }
            ),
            400,
        )

    protected_header = {
        "alg": encryption_config["alg"],
        "enc": encryption_config["enc"],
    }

    try:
        public_key = JsonWebKey.import_key(encryption_config["jwk"])
        jwe = JsonWebEncryption()
        jwe_token = jwe.serialize_compact(
            protected_header, json.dumps(credential_response), public_key
        )
    except:
        return (
            jsonify(
                {
                    "error": "invalid_credential_response_encryption",
                    "error_description": "Failed to encrypt with the provided key.",
                }
            ),
            400,
        )

    _response = make_response(jwe_token)

    _response.headers["Content-Type"] = "application/jwt"

    return _response


@oidc.route("/credential", methods=["POST"])
def credential():

    credential_request = request.get_json()

    cfgservice.app_logger.info(
        f", Started Credential Request, Payload: {credential_request}"
    )

    # Get the Authorization header from the request
    auth_header = request.headers.get("Authorization")

    bearer_token = None

    if not auth_header:
        return jsonify({"error": "Authorization header is missing"}), 401

    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization header must be a Bearer token"}), 401

    try:
        bearer_token = auth_header.split(" ")[1]
    except IndexError:
        return jsonify({"error": "Invalid Authorization header format"}), 401

    verification_result_introspection = verify_introspection(bearer_token=bearer_token)

    # Check if the result is an error response (a tuple)
    if isinstance(verification_result_introspection, tuple):
        # If it's a tuple, it's a Flask error response. Return it immediately.
        return verification_result_introspection

    # If the result is not a tuple, it's the username string
    session_id = verification_result_introspection

    cfgservice.app_logger.info(
        f", Session ID: {session_id}, Credential Request, Payload: {credential_request}"
    )

    verification_result_request = verify_credential_request(credential_request)

    if isinstance(verification_result_request, tuple):
        # If it's a tuple, it's an error response. Return it immediately.
        return verification_result_request

    # If the check passes, the result is the validated request dictionary.
    validated_credential_request = verification_result_request

    current_session = session_manager.get_session(session_id=session_id)

    _response = generate_credentials(
        credential_request=validated_credential_request, session_id=session_id
    )

    cfgservice.app_logger.info(
        f", Session ID: {session_id}, Credential response, Payload: {_response}"
    )

    if "credential_response_encryption" in validated_credential_request:
        _response = encrypt_response(
            credential_request=validated_credential_request,
            credential_response=_response,
        )

        cfgservice.app_logger.info(
            f", Session ID: {session_id}, Credential encrypted response, Payload: {_response.data.decode('utf-8')}"
        )
        return _response


    return _response


""" @oidc.route("/credential", methods=["POST"])
def credential():

    headers = dict(request.headers)
    payload = json.loads(request.data)

    if "Authorization" not in headers:
        return make_response("Authorization error", 400)

    access_token = headers["Authorization"][7:]
    session_id = getSessionId_accessToken(access_token)

    cfgservice.app_logger.info(
        f", Session ID: {session_id}, Credential Request, Payload: {payload}"
    )

    _response = service_endpoint(current_app.server.get_endpoint("credential"))

    if isinstance(_response, Response):
        if _response.content_type == "application/jwt":
            response_str = str(_response.get_data())

        else:
            response_str = str(json.loads(_response.get_data()))

        cfgservice.app_logger.info(
            f", Session ID: {session_id}, Credential response, Payload: {response_str}"
        )
        return _response

     if (
        "transaction_id" in _response
        and _response["transaction_id"] not in deferredRequests
    ):

        request_data = request.data
        request_headers = dict(request.headers)
        deferredRequests.update(
            {
                _response["transaction_id"]: {
                    "data": request_data,
                    "headers": request_headers,
                    "expires": datetime.now()
                    + timedelta(minutes=cfgservice.deffered_expiry),
                }
            }
        )

        cfgservice.app_logger.info(
            ", Session ID: "
            + session_id
            + ", "
            + "Credential response, Payload: "
            + str(_response)
        )

        return make_response(jsonify(_response), 202) 

    cfgservice.app_logger.info(
        f", Session ID: {session_id}, Credential response, Payload: {_response}"
    )
    return _response """


@oidc.route("/notification", methods=["POST"])
def notification():

    headers = dict(request.headers)
    payload = json.loads(request.data)

    if "Authorization" not in headers:
        return make_response("Authorization error", 400)

    access_token = headers["Authorization"][7:]
    session_id = getSessionId_accessToken(access_token)

    cfgservice.app_logger.info(
        f", Session ID: {session_id}, Notification Request, Payload: {payload}"
    )

    _resp = service_endpoint(current_app.server.get_endpoint("notification"))

    if isinstance(_resp, Response):
        cfgservice.app_logger.info(
            f", Session ID: {session_id}, Notification response, Payload: {_resp}"
        )
        return _resp

    cfgservice.app_logger.info(
        f", Session ID: {session_id}, Notification response, Payload: {_resp}"
    )

    return _resp


@oidc.route("/nonce", methods=["POST"])
def nonce():

    _resp = service_endpoint(current_app.server.get_endpoint("nonce"))

    if isinstance(_resp, Response):
        cfgservice.app_logger.info("Nonce response, Payload: " + str(_resp))
        return _resp

    cfgservice.app_logger.info("Nonce response, Payload: " + str(_resp))

    return _resp


@oidc.route("/deferred_credential", methods=["POST"])
def deferred_credential():

    headers = dict(request.headers)
    payload = json.loads(request.data)
    if "Authorization" not in headers:
        return make_response("Authorization error", 400)

    access_token = headers["Authorization"][7:]
    session_id = getSessionId_accessToken(access_token)

    cfgservice.app_logger.info(
        f", Session ID: {session_id}, Deferred Credential Request, Payload:, Payload: {payload}"
    )

    current_app.server.get_endpoint("credential").process_deferred()

    _resp = service_endpoint(current_app.server.get_endpoint("deferred_credential"))

    if isinstance(_resp, Response):
        if _resp.content_type == "application/jwt":
            response_str = str(_resp.get_data())
        else:
            response_str = str(json.loads(_resp.get_data()))

        cfgservice.app_logger.info(
            f", Session ID: {session_id}, Credential response, Payload: {response_str}"
        )
        return _resp

    cfgservice.app_logger.info(
        f", Session ID: {session_id}, Deferred response, Payload: {_resp}"
    )

    return _resp


@oidc.route("credential_offer_choice", methods=["GET"])
def credential_offer():
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
        "openid/credential_offer.html",
        cred=credentials,
        redirect_url=cfgservice.service_url,
        credential_offer_URI="openid-credential-offer://",
    )


""" @oidc.route("/test_dump", methods=["GET", "POST"])
def dump_test():
    _store = current_app.server.context.dump()
    
    print("\n------Store-----\n", _store)
    print("\n------Store type-----\n", type(_store))
    
    json_string = json.dumps(_store, indent=4)
    
    with open("data.json", "w") as json_file:
        json_file.write(json_string)
    return "dump"

@oidc.route("/test_load", methods=["GET", "POST"])
def load_test():
    print("load_test\n")
    with open("data.json", "r") as json_file:
    # Load the JSON data from the file
        data = json.loads(json_file.read())
        print("\n-----Data-----\n",data)
        current_app.server.context.load(data)

    return "load" """


@oidc.route("/credential_offer", methods=["GET", "POST"])
def credentialOffer():

    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    auth_choice = request.form.get("Authorization Code Grant")
    form_keys = request.form.keys()
    credential_offer_URI = request.form.get("credential_offer_URI")

    if "proceed" in form_keys:
        form = list(form_keys)
        form.remove("proceed")
        form.remove("credential_offer_URI")
        form.remove("Authorization Code Grant")
        all_exist = all(credential in credentialsSupported for credential in form)

        if all_exist:
            credentials_id = form
            session["credentials_id"] = credentials_id
            credentials_id_list = json.dumps(form)
            if auth_choice == "pre_auth_code":
                session["credential_offer_URI"] = credential_offer_URI
                return redirect(
                    url_for("preauth.preauthRed", credentials_id=credentials_id_list)
                )

            else:

                credential_offer = {
                    "credential_issuer": cfgservice.service_url[:-1],
                    "credential_configuration_ids": credentials_id,
                    "grants": {"authorization_code": {}},
                }

                reference_id = str(uuid.uuid4())
                credential_offer_references.update(
                    {
                        reference_id: {
                            "credential_offer": credential_offer,
                            "expires": datetime.now()
                            + timedelta(minutes=cfgservice.form_expiry),
                        }
                    }
                )

                # create URI
                json_string = json.dumps(credential_offer)

                uri = (
                    f"{credential_offer_URI}credential_offer?credential_offer="
                    + urllib.parse.quote(json_string, safe=":/")
                )

                # Generate QR code
                # img = qrcode.make("uri")
                # QRCode.print_ascii()

                qrcode = segno.make(uri)
                out = io.BytesIO()
                qrcode.save(out, kind="png", scale=3)

                """ qrcode.to_artistic(
                    background=cfgtest.qr_png,
                    target=out,
                    kind="png",
                    scale=4,
                ) """
                # qrcode.terminal()
                # qr_img_base64 = qrcode.png_data_uri(scale=4)

                qr_img_base64 = "data:image/png;base64," + base64.b64encode(
                    out.getvalue()
                ).decode("utf-8")

                wallet_url = cfgservice.wallet_test_url + "credential_offer"

                return render_template(
                    "openid/credential_offer_qr_code.html",
                    wallet_dev=wallet_url
                    + "?credential_offer="
                    + json.dumps(credential_offer),
                    url_data=uri,
                    qrcode=qr_img_base64,
                )

    else:
        return redirect(cfgservice.service_url + "credential_offer_choice")


@oidc.route("/credential-offer-reference/<string:reference_id>", methods=["GET"])
def offer_reference(reference_id):
    return credential_offer_references[reference_id]["credential_offer"]


""" @oidc.route("/testgetauth", methods=["GET"])
def testget():
    if "error" in request.args:
        response = (
            request.args.get("error") + "\n" + request.args.get("error_description")
        )
        return response
    else:
        return request.args.get("code") """


IGNORE = ["cookie", "user-agent"]


def service_endpoint(endpoint):
    # _log = current_app.logger
    cfgservice.app_logger.info('At the "{}" endpoint'.format(endpoint.name))

    http_info = {
        "headers": {
            k: v for k, v in request.headers.items(lower=True) if k not in IGNORE
        },
        "method": request.method,
        "url": request.url,
        # name is not unique
        "cookie": [{"name": k, "value": v} for k, v in request.cookies.items()],
    }
    cfgservice.app_logger.info(f"http_info: {http_info}")

    if endpoint.name == "credential":
        try:
            accessToken = http_info["headers"]["authorization"][7:]
            req_args = request.json
            req_args["access_token"] = accessToken
            req_args["oidc_config"] = cfgoidc
            req_args["aud"] = cfgservice.service_url[:-1]
            args = endpoint.process_request(req_args)

            if "response_args" in args:
                if "error" in args["response_args"]:
                    return (
                        jsonify(args["response_args"]),
                        400,
                        {"Content-Type": "application/json"},
                    )
                response = args["response_args"]
            if "encrypted_response" in args:
                response = make_response(args["encrypted_response"])
                response.headers["Content-Type"] = "application/jwt"
                return response
            else:
                if isinstance(args, ResponseMessage) and "error" in args:
                    cfgservice.app_logger.error("Error response: {}".format(args))
                    response = make_response(args.to_json(), 400)
                else:
                    response = do_response(endpoint, args, **args)
            return response
        except Exception as err:
            message = traceback.format_exception(*sys.exc_info())
            cfgservice.app_logger.error(message)
            err_msg = ResponseMessage(
                error="invalid_request", error_description=str(err)
            )
            return make_response(err_msg.to_json(), 400)

    if endpoint.name == "notification":
        try:
            accessToken = http_info["headers"]["authorization"][7:]
            req_args = request.json
            req_args["access_token"] = accessToken
            req_args["oidc_config"] = cfgoidc
            _resp = endpoint.process_request(req_args)

            if isinstance(_resp, ResponseMessage) and "error" in _resp:
                cfgservice.app_logger.error("Error response: {}".format(_resp))
                _resp = make_response(_resp.to_json(), 400)

        except Exception as err:
            cfgservice.app_logger.error(err)
            return make_response(
                json.dumps({"error": "invalid_request", "error_description": str(err)}),
                400,
            )

        return _resp

    if endpoint.name == "nonce":
        try:
            req_args = {}
            req_args["key_path"] = cfgservice.nonce_key
            req_args["iss"] = cfgservice.service_url[:-1]
            req_args["source_endpoint"] = cfgservice.service_url + "nonce"
            req_args["aud"] = [cfgservice.service_url + "credential"]
            _resp = endpoint.process_request(req_args)

            if isinstance(_resp, ResponseMessage) and "error" in _resp:
                cfgservice.app_logger.error("Error response: {}".format(_resp))
                _resp = make_response(_resp.to_json(), 400)

        except Exception as err:
            cfgservice.app_logger.error(err)
            return make_response(
                json.dumps({"error": "invalid_request", "error_description": str(err)}),
                400,
            )

        return _resp

    if endpoint.name == "deferred_credential":
        try:
            accessToken = http_info["headers"]["authorization"][7:]
            req_args = request.json
            req_args["access_token"] = accessToken
            req_args["oidc_config"] = cfgoidc
            args = endpoint.process_request(req_args)
            if "response_args" in args:
                if "error" in args["response_args"]:
                    return (
                        jsonify(args["response_args"]),
                        400,
                        {"Content-Type": "application/json"},
                    )
                response = args["response_args"]

            elif "encrypted_response" in args:
                response = make_response(args["encrypted_response"])
                response.headers["Content-Type"] = "application/jwt"
                return response

            else:
                if isinstance(args, ResponseMessage) and "error" in args:
                    cfgservice.app_logger.error("Error response: {}".format(args))
                    response = make_response(args.to_json(), 400)
                else:
                    response = do_response(endpoint, args, **args)
            return response

        except Exception as err:
            cfgservice.app_logger.error(err)
            return make_response(
                json.dumps({"error": "invalid_request", "error_description": str(err)}),
                400,
            )

    if request.method == "GET":
        try:
            args = request.args.to_dict()
            if "client_id" in args:
                args["client_id"] = args["client_id"].split(".")[0]
            req_args = endpoint.parse_request(args, http_info=http_info)
        except ClientAuthenticationError as err:
            cfgservice.app_logger.error(err)
            return make_response(
                json.dumps(
                    {"error": "unauthorized_client", "error_description": str(err)}
                ),
                401,
            )
        except Exception as err:
            cfgservice.app_logger.error(err)
            return make_response(
                json.dumps({"error": "invalid_request", "error_description": str(err)}),
                400,
            )
    else:
        if request.data:
            if isinstance(request.data, str):
                req_args = request.data
            else:
                req_args = request.data.decode()
        else:
            req_args = dict([(k, v) for k, v in request.form.items()])
        try:
            req_args = endpoint.parse_request(req_args, http_info=http_info)
        except Exception as err:
            cfgservice.app_logger.error(err)
            err_msg = ResponseMessage(
                error="invalid_request", error_description=str(err)
            )
            return make_response(err_msg.to_json(), 400)

    if isinstance(req_args, ResponseMessage) and "error" in req_args:
        cfgservice.app_logger.error("Error response: {}".format(req_args))
        _resp = make_response(req_args.to_json(), 400)
        if request.method == "POST":
            _resp.headers["Content-type"] = "application/json"
        return _resp
    try:
        cfgservice.app_logger.error("request: {}".format(req_args))
        if isinstance(endpoint, Token):
            args = endpoint.process_request(
                AccessTokenRequest(**req_args), http_info=http_info, issue_refresh=True
            )
        else:
            args = endpoint.process_request(
                request=req_args, http_info=http_info, oidc_config=cfgoidc
            )
    except Exception as err:
        message = traceback.format_exception(*sys.exc_info())
        cfgservice.app_logger.error(message)
        err_msg = ResponseMessage(error="invalid_request", error_description=str(err))
        return make_response(err_msg.to_json(), 400)

    # _log.info("Response args: {}".format(args))

    # "pushed_authorization"
    if (
        endpoint.name == "pushed_authorization"
        and "http_response" in args
        and "request_uri" in args["http_response"]
        and "expires_in" in args["http_response"]
    ):
        parRequests[args["http_response"]["request_uri"]] = {
            "req_args": req_args.to_dict(),
            "expires": args["http_response"]["expires_in"]
            + int(datetime.timestamp(datetime.now())),
        }

        return make_response(args["http_response"], 201)

    if "redirect_location" in args:
        return redirect(args["redirect_location"])
    if "http_response" in args:
        return make_response(args["http_response"], 200)

    response = do_response(endpoint, req_args, **args)
    return response


@oidc.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return "bad request!", 400
