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
from app.misc import auth_error_redirect, authentication_error_redirect, scope2details

from datetime import datetime, timedelta

#!/usr/bin/env python3
import requests

from .app_config.config_service import ConfService as cfgservice
from .app_config.config_oidc_endpoints import ConfService as cfgoidc

from . import oidc_metadata, openid_metadata

# Log
from app_config.config_service import ConfService as log

oidc = Blueprint("oidc", __name__, url_prefix="/")
CORS(oidc)  # enable CORS on the blue print

# variable for PAR requests
parRequests = {}
deferredRequests = {}


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
    _log = current_app.logger
    _log.debug("do_response: {}".format(info))

    try:
        _response_placement = info["response_placement"]
    except KeyError:
        _response_placement = endpoint.response_placement

    _log.debug("response_placement: {}".format(_response_placement))

    if error:
        if _response_placement == "body":
            _log.info("Error Response: {}".format(info["response"]))
            _http_response_code = info.get("response_code", 400)
            resp = make_response(info["response"], _http_response_code)
        else:  # _response_placement == 'url':
            _log.info("Redirect to: {}".format(info["response"]))
            resp = redirect(info["response"])
    else:
        if _response_placement == "body":
            _log.info("Response: {}".format(info["response"]))
            _http_response_code = info.get("response_code", 200)
            resp = make_response(info["response"], _http_response_code)
        else:  # _response_placement == 'url':
            _log.info("Redirect to: {}".format(info["response"]))
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
        log.logger_error.error(
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

    return do_response(endpoint, request, **args)


@oidc.route("/verify/user", methods=["GET"])
def verify_user():
    authn_method = current_app.server.get_context().authn_broker.get_method_by_id(
        "user"
    )
    try:
        return verify(authn_method)
    except FailedAuthentication as exc:
        log.logger_error.error("Authorization verification failed")
        return render_template("misc/500.html", error=str(exc))


@oidc.route("/.well-known/<service>")
def well_known(service):
    if service == "openid-credential-issuer":
        info = {
            "response": oidc_metadata,
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
        url = url + "&code_challenge="
        +code_challenge
        +"&code_challenge_method="
        +code_challenge_method

    payload = {}
    headers = {}
    response = requests.request("GET", url, headers=headers, data=payload)

    if response.status_code != 200:
        log.logger_error.error("Authorization endpoint invalid request")
        return auth_error_redirect(redirect_uri, "invalid_request")

    response = response.json()

    args = {}
    if "authorization_details" in response:
        args.update({"authorization_details": response["authorization_details"]})
    if "scope" in response:
        args.update({"scope": response["scope"]})
    if not args:
        log.logger_error.error("Authorization args not found")
        return authentication_error_redirect(
            jws_token=response["token"],
            error=response["error"],
            error_description=response["error_description"],
        )

    params = {"token": response["token"]}

    params.update(args)

    session["authorization_params"] = params

    return redirect(response["url"])


@oidc.route("/authorizationV3", methods=["GET"])
def authorizationV3():

    log.logger_info.info(
        "Authorization request Data: "
        + str(request.args)
        + " | Headers: "
        + str(dict(request.headers))
    )

    if "request_uri" not in request.args:
        try:
            client_id = request.args.get("client_id")
            redirect_uri = request.args.get("redirect_uri")
            response_type = request.args.get("response_type")
            scope = request.args.get("scope")
            code_challenge_method = request.args.get("code_challenge_method")
            code_challenge = request.args.get("code_challenge")
            authorization_details = request.args.get("authorization_details")
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
        )

    try:
        request_uri = request.args.get("request_uri")
    except:
        log.logger_error.error("Authorization request_uri not found")
        return make_response("Authorization error", 400)

    if not request_uri in parRequests:  # unknow request_uri => return error
        # needs to be changed to an appropriate error message, and need to be logged
        # return service_endpoint(current_app.server.get_endpoint("authorization"))
        log.logger_error.error("Authorization request_uri not found in parRequests")
        return make_response("Request_uri not found", 400)

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
        log.logger_error.error("Authorization endpoint invalid request")
        return auth_error_redirect(par_args["redirect_uri"], "invalid_request")

    response = response.json()

    args = {}
    if "authorization_details" in response:
        args.update({"authorization_details": response["authorization_details"]})
    if "scope" in response:
        args.update({"scope": response["scope"]})
    if not args:
        log.logger_error.error("Authorization args not found")
        return authentication_error_redirect(
            jws_token=response["token"],
            error=response["error"],
            error_description=response["error_description"],
        )

    params = {"token": response["token"]}

    params.update(args)

    session["authorization_params"] = params

    return redirect(response["url"])


@oidc.route("/authorization-preauth", methods=["GET"])
def authorizationpre():

    try:
        request_uri = request.args.get("request_uri")
    except:
        log.logger_error.error("Pre authorization request_uri not found")
        return make_response("Authorization error", 400)

    if not request_uri in parRequests:  # unknow request_uri => return error
        # needs to be changed to an appropriate error message, and need to be logged
        return service_endpoint(current_app.server.get_endpoint("authorization"))

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
    response = requests.request("GET", url, headers=headers, data=payload).json()

    print("\n-----before params\n")

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

    print("\n-----Set auth params\n", session)

    # return redirect(url_get(response["url"], params))
    return redirect(cfgservice.service_url + "dynamic/preauth-form")
    # return response.content


@oidc.route("/oid4vp", methods=["GET"])
def oid4vp():

    url = "https://dev.verifier-backend.eudiw.dev/ui/presentations"
    payload = json.dumps(
        {
            "type": "vp_token",
            "nonce": "hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc=",
            "presentation_definition": {
                "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "input_descriptors": [
                    {
                        "id": "eu.europa.ec.eudi.pid.1",
                        "format": {
                            "mso_mdoc": {"alg": ["ES256", "ES384", "ES512", "EdDSA"]}
                        },
                        "name": "EUDI PID",
                        "purpose": "We need to verify your identity",
                        "constraints": {
                            "fields": [
                                {
                                    "path": [
                                        "$['eu.europa.ec.eudi.pid.1']['family_name']"
                                    ],
                                    "intent_to_retain": False,
                                },
                                {
                                    "path": [
                                        "$['eu.europa.ec.eudi.pid.1']['given_name']"
                                    ],
                                    "intent_to_retain": False,
                                },
                                {
                                    "path": [
                                        "$['eu.europa.ec.eudi.pid.1']['birth_date']"
                                    ],
                                    "intent_to_retain": False,
                                },
                                {
                                    "path": [
                                        "$['eu.europa.ec.eudi.pid.1']['age_over_18']"
                                    ],
                                    "intent_to_retain": False,
                                },
                                {
                                    "path": [
                                        "$['eu.europa.ec.eudi.pid.1']['issuing_authority']"
                                    ],
                                    "intent_to_retain": False,
                                },
                                {
                                    "path": [
                                        "$['eu.europa.ec.eudi.pid.1']['issuing_country']"
                                    ],
                                    "intent_to_retain": False,
                                },
                            ]
                        },
                    }
                ],
            },
        }
    )

    headers = {
        "Content-Type": "application/json",
    }

    response = requests.request("POST", url, headers=headers, data=payload).json()

    deeplink_url = (
        "eudi-openid4vp://dev.verifier-backend.eudiw.dev?client_id="
        + response["client_id"]
        + "&request_uri="
        + response["request_uri"]
    )

    # Generate QR code
    # img = qrcode.make("uri")
    # QRCode.print_ascii()

    qrcode = segno.make(deeplink_url)
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

    qr_img_base64 = "data:image/png;base64," + base64.b64encode(out.getvalue()).decode(
        "utf-8"
    )

    return render_template(
        "openid/pid_login_qr_code.html",
        url_data=deeplink_url,
        qrcode=qr_img_base64,
        presentation_id=response["presentation_id"],
        redirect_url=cfgservice.service_url,
    )


@oidc.route("/pid_authorization")
def pid_authorization_get():

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
        return jsonify({"error": error_msg}), 500
    else:
        data = {"message": "Sucess"}
        return jsonify({"message": data}), 200


@oidc.route("/auth_choice", methods=["GET"])
def auth_choice():
    token = request.args.get("token")

    supported_credencials = cfgservice.auth_method_supported_credencials
    pid_auth = True
    country_selection = True

    if "authorization_params" not in session:
        log.logger_info.info(
            "Authorization Params didn't exist in Authentication Choice"
        )
        return render_template(
            "misc/500.html",
            error="Invalid Authentication. No authorization details or scope found.",
        )

    authorization_params = session["authorization_params"]

    authorization_details = []
    if "authorization_details" in authorization_params:
        authorization_details.extend(
            json.loads(authorization_params["authorization_details"])
        )
    if "scope" in authorization_params:
        authorization_details.extend(scope2details(authorization_params["scope"]))

    credentials_requested = []
    for cred in authorization_details:
        if "credential_configuration_id" in cred:
            if cred["credential_configuration_id"] not in credentials_requested:
                credentials_requested.append(cred["credential_configuration_id"])
        elif "vct" in cred:
            if cred["vct"] not in credentials_requested:
                credentials_requested.append(cred["vct"])

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

    error = ""
    if pid_auth == False and country_selection == False:
        error = "Combination of requested credentials is not valid!"

    return render_template(
        "misc/auth_method.html",
        pid_auth=pid_auth,
        country_selection=country_selection,
        error=error,
        redirect_url=log.service_url,
    )

    # return render_template("misc/auth_method.html")


@oidc.route("/token_service", methods=["POST"])
def token_service():

    # session_id = request.cookies.get("session")

    response = service_endpoint(current_app.server.get_endpoint("token"))

    return response


@oidc.route("/token", methods=["POST"])
def token():

    log.logger_info.info(
        "Token request data: "
        + str(request.form.to_dict())
        + " | Headers: "
        + str(dict(request.headers))
    )

    req_args = dict([(k, v) for k, v in request.form.items()])

    response = None

    if req_args["grant_type"] == "authorization_code":

        response = service_endpoint(current_app.server.get_endpoint("token"))

    elif (
        req_args["grant_type"] == "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    ):

        if "pre-authorized_code" not in req_args:
            return make_response("invalid_request", 400)

        code = req_args["pre-authorized_code"]

        url = cfgservice.service_url + "token_service"
        redirect_url = urllib.parse.quote(cfgservice.service_url) + "preauth-code"

        payload = (
            "grant_type=authorization_code&code="
            + code
            + "&redirect_uri="
            + redirect_url
            + "&client_id=ID&state=vFs5DfvJqoyHj7_dZs2JbdklePg6pMLsUHHmVIfobRw&code_verifier=FnWCRIhpJtl6IYwVVYB8gZkQsmvBVLfU4HQiABPopYQ6gvIZBwMrXg"
        )
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        response = requests.request("POST", url, headers=headers, data=payload)

        if response.status_code != 200:
            return make_response("invalid_request", 400)

        # response = response.json()
        log.logger_info.info("Token response: " + str(response.json()))
        return response.json()

    else:
        return make_response("invalid_request", 400)

    log.logger_info.info("Token response: " + str(json.loads(response.get_data())))

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

    log.logger_info.info(
        "Recieved Pushed Authorization request. Data: "
        + str(request.form.to_dict())
        + " | Headers: "
        + str(dict(request.headers))
    )

    redirect_uri = None
    try:
        redirect_uri = request.form["redirect_uri"]

        client_id = request.form["client_id"]
    except:
        log.logger_error.error("PAR: client_id or redirect_uri not found")
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

    log.logger_info.info(
        "PAR response for client_id "
        + client_id
        + " : "
        + str(json.loads(response.get_data()))
    )

    return response


@oidc.route("/credential", methods=["POST"])
def credential():

    if request.data:
        log.logger_info.info(
            "Credential request data: "
            + str(json.loads(request.data))
            + " | Headers: "
            + str(dict(request.headers))
        )

    _response = service_endpoint(current_app.server.get_endpoint("credential"))

    if isinstance(_response, Response):
        log.logger_info.info(
            "Credential response " + str(json.loads(_response.get_data()))
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

        log.logger_info.info("Credential response " + str(_response))

        return make_response(jsonify(_response), 202)

    log.logger_info.info("Credential response " + str(_response))
    return _response


@oidc.route("/batch_credential", methods=["POST"])
def batchCredential():
    log.logger_info.info(
        "Batch credential request data: "
        + str(json.loads(request.data))
        + " | Headers: "
        + str(dict(request.headers))
    )

    _response = service_endpoint(current_app.server.get_endpoint("credential"))

    if isinstance(_response, Response):
        log.logger_info.info(
            "Batch Credential response " + str(json.loads(_response.get_data()))
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

        log.logger_info.info("Batch credential response " + str(_response))
        return make_response(jsonify(_response), 202)

    log.logger_info.info("Batch credential response " + str(_response))

    return _response


@oidc.route("/notification", methods=["POST"])
def notification():
    log.logger_info.info(
        "Notification request data: "
        + str(json.loads(request.data))
        + " | Headers: "
        + str(dict(request.headers))
    )
    _resp = service_endpoint(current_app.server.get_endpoint("notification"))

    if isinstance(_resp, Response):
        log.logger_info.info("Notification response " + str(_resp))
        return _resp

    log.logger_info.info("Notification response " + str(_resp))

    return _resp


@oidc.route("/deferred_credential", methods=["POST"])
def deferred_credential():

    log.logger_info.info(
        "Deferred request data: "
        + str(json.loads(request.data))
        + " | Headers: "
        + str(dict(request.headers))
    )

    _resp = service_endpoint(current_app.server.get_endpoint("deferred_credential"))

    if isinstance(_resp, Response):
        log.logger_info.info("Deferred response " + str(json.loads(_resp.get_data())))
        return _resp

    log.logger_info.info("Deferred response " + str(_resp))

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

        if credential["format"] == "vc+sd-jwt":
            # if credential["scope"] == "eu.europa.ec.eudiw.pid.1":
            credentials["sd-jwt vc format"].update(
                # {"Personal Identification Data": cred}
                {cred: cred}
            )

            """ elif credential["scope"] == "org.iso.18013.5.1.mDL":
                credentials["sd-jwt vc format"].update(
                    {"Mobile Driver's Licence": cred}
                ) """

        if credential["format"] == "mso_mdoc":
            # if credential["scope"] == "eu.europa.ec.eudiw.pid.1":
            credentials["mdoc format"].update(
                {cred: cred}
                # {"Personal Identification Data": cred}
            )

            """ elif credential["scope"] == "org.iso.18013.5.1.mDL":
                credentials["mdoc format"].update({"Mobile Driver's Licence": cred}) """

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
    form_keys = request.form.keys()
    credential_offer_URI = request.form.get("credential_offer_URI")

    if "proceed" in form_keys:
        form = list(form_keys)
        form.remove("proceed")
        form.remove("credential_offer_URI")
        all_exist = all(credential in credentialsSupported for credential in form)

        if all_exist:
            credentials_id = form

            credential_offer = {
                "credential_issuer": cfgservice.service_url[:-1],
                "credential_configuration_ids": credentials_id,
                "grants": {"authorization_code": {}},
            }

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

            return render_template(
                "openid/credential_offer_qr_code.html",
                wallet_dev="https://tester.issuer.eudiw.dev/credential_offer"
                + "?credential_offer="
                + json.dumps(credential_offer),
                url_data=uri,
                qrcode=qr_img_base64,
            )

    else:
        return redirect(cfgservice.service_url + "credential_offer_choice")


@oidc.route("/preauth-code", methods=["GET"])
def preauthCode():
    code = request.args.get("code")

    credential_offer = {
        "credential_issuer": cfgservice.service_url,
        "credential_configuration_ids": ["eu.europa.ec.eudi.loyalty_mdoc"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": code
            }
        },
    }

    # create URI
    json_string = json.dumps(credential_offer)

    uri = "openid-credential-offer://?credential_offer=" + urllib.parse.quote(
        json_string, safe=":/"
    )

    # Generate QR code
    # img = qrcode.make("uri")
    # QRCode.print_ascii()

    qrcode = segno.make(uri)
    out = io.BytesIO()
    qrcode.save(out, kind="png", scale=2)

    # print(qrcode.terminal(compact=True))

    """ qrcode.to_artistic(
        background=cfgtest.qr_png,
        target=out,
        kind="png",
        scale=2,
    ) """

    # qrcode.terminal()
    # qr_img_base64 = qrcode.png_data_uri(scale=4)

    qr_img_base64 = "data:image/png;base64," + base64.b64encode(out.getvalue()).decode(
        "utf-8"
    )

    return render_template(
        "openid/credential_offer_qr_code.html",
        wallet_dev="https://tester.issuer.eudiw.dev/redirect_preauth" + "?code=" + code,
        url_data=uri,
        qrcode=qr_img_base64,
    )


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
    _log = current_app.logger
    _log.info('At the "{}" endpoint'.format(endpoint.name))

    http_info = {
        "headers": {
            k: v for k, v in request.headers.items(lower=True) if k not in IGNORE
        },
        "method": request.method,
        "url": request.url,
        # name is not unique
        "cookie": [{"name": k, "value": v} for k, v in request.cookies.items()],
    }
    _log.info(f"http_info: {http_info}")

    if endpoint.name == "credential":
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
            else:
                if isinstance(args, ResponseMessage) and "error" in args:
                    _log.info("Error response: {}".format(args))
                    response = make_response(args.to_json(), 400)
                else:
                    response = do_response(endpoint, args, **args)
            return response
        except Exception as err:
            message = traceback.format_exception(*sys.exc_info())
            _log.error(message)
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
                _log.info("Error response: {}".format(_resp))
                _resp = make_response(_resp.to_json(), 400)

        except Exception as err:
            _log.error(err)
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
            else:
                if isinstance(args, ResponseMessage) and "error" in args:
                    _log.info("Error response: {}".format(args))
                    response = make_response(args.to_json(), 400)
                else:
                    response = do_response(endpoint, args, **args)
            return response

        except Exception as err:
            _log.error(err)
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
            _log.error(err)
            return make_response(
                json.dumps(
                    {"error": "unauthorized_client", "error_description": str(err)}
                ),
                401,
            )
        except Exception as err:
            _log.error(err)
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
            _log.error(err)
            err_msg = ResponseMessage(
                error="invalid_request", error_description=str(err)
            )
            return make_response(err_msg.to_json(), 400)

    if isinstance(req_args, ResponseMessage) and "error" in req_args:
        _log.info("Error response: {}".format(req_args))
        _resp = make_response(req_args.to_json(), 400)
        if request.method == "POST":
            _resp.headers["Content-type"] = "application/json"
        return _resp
    try:
        _log.info("request: {}".format(req_args))
        if isinstance(endpoint, Token):
            args = endpoint.process_request(
                AccessTokenRequest(**req_args), http_info=http_info
            )
        else:
            args = endpoint.process_request(
                request=req_args, http_info=http_info, oidc_config=cfgoidc
            )
    except Exception as err:
        message = traceback.format_exception(*sys.exc_info())
        _log.error(message)
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

    if "redirect_location" in args:
        return redirect(args["redirect_location"])
    if "http_response" in args:
        return make_response(args["http_response"], 200)

    response = do_response(endpoint, req_args, **args)
    return response


@oidc.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return "bad request!", 400


################################################
## To be moved to a file with scheduled jobs

scheduler_call = 30  # scheduled periodic job will be called every scheduler_call seconds (should be 300; 30 for debug)


def clear_par():
    """Function to clear parRequests"""
    now = int(datetime.timestamp(datetime.now()))
    print("Job scheduled: clear_par() at " + str(now))

    for uri in parRequests.copy():
        expire_time = parRequests[uri]["expires"]
        if now > expire_time:
            parRequests.pop(uri)
            print(
                "Job scheduled: clear_par: "
                + uri
                + " eliminado. "
                + str(now)
                + " > "
                + str(expire_time)
            )
        else:
            print(
                "Job scheduled: clear_par: "
                + uri
                + " não eliminado. "
                + str(now)
                + " < "
                + str(expire_time)
            )

    for req in deferredRequests.copy():

        if datetime.now() > deferredRequests[req]["expires"]:
            print("\n-------Deferred expired-----\n")
            deferredRequests.pop(req)
        else:
            request_data = json.loads(deferredRequests[req]["data"])
            request_data.update({"transaction_id": req})
            request_data = json.dumps(request_data)
            request_headers = deferredRequests[req]["headers"]

            response = requests.post(
                cfgservice.service_url + "credential",
                data=request_data,
                headers=request_headers,
            )
            response_data = response.json()

            if response.status_code == 200:
                if (
                    "credential" in response_data
                    or "credential_responses" in response_data
                ):
                    deferredRequests.pop(req)


def run_scheduler():
    print("Run scheduler.")
    threading.Timer(scheduler_call, run_scheduler).start()
    clear_par()


run_scheduler()
