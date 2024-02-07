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
import re
import sys

from flask import Blueprint, jsonify
from flask.helpers import make_response
from flask import Response
from flask import current_app
from flask import redirect
import os
from typing import Union


from flask import Response
from flask import request
from flask import session
from flask_cors import CORS
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oauth2 import ResponseMessage
import json
import os
import sys
import traceback
from typing import Union
from urllib.parse import urlparse

from cryptojwt import as_unicode
from flask import render_template
from flask.helpers import send_from_directory
from idpyoidc.message.oidc import AccessTokenRequest
import werkzeug

from idpyoidc.server.exception import FailedAuthentication
from idpyoidc.server.exception import ClientAuthenticationError
from idpyoidc.server.oidc.token import Token


from datetime import datetime

#!/usr/bin/env python3
import json
import os
import requests
from redirect_func import url_get



from .app_config.config_service import ConfService as log
from .app_config.config_oidc_endpoints import ConfService as cfgoidc

from . import oidc_metadata, openid_metadata



oidc = Blueprint("oidc", __name__, url_prefix="/oidc")
CORS(oidc)  # enable CORS on the blue print

# variable for PAR requests
parRequests = {}


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


@oidc.route("/static/<path:path>")
def send_js(path):
    return send_from_directory("static", path)


@oidc.route("/keys/<jwks>")
def keys(jwks):
    fname = os.path.join("static", jwks)
    return open(fname).read()


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
        return make_response("Authentication verification", 400)

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


@oidc.route("/verify/user", methods=["GET", "POST"])
def verify_user():
    authn_method = current_app.server.get_context().authn_broker.get_method_by_id(
        "user"
    )
    try:
        return verify(authn_method)
    except FailedAuthentication as exc:
        return render_template("route_pid/500.html", error=str(exc))


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
    return service_endpoint(current_app.server.get_endpoint("registration"))


@oidc.route("/registration_api", methods=["GET", "DELETE"])
def registration_api():
    if request.method == "DELETE":
        return service_endpoint(current_app.server.get_endpoint("registration_delete"))
    else:
        return service_endpoint(current_app.server.get_endpoint("registration_read"))


@oidc.route("/authorization", methods=["GET"])
def authorization():
    return service_endpoint(current_app.server.get_endpoint("authorization"))


@oidc.route("/authorizationV3", methods=["GET"])
def authorizationV3():
    # client_id = request.args.get("client_id")

    try:
        request_uri = request.args.get("request_uri")
    except:
        return make_response("Authorization error", 400)

    if not request_uri in parRequests:  # unknow request_uri => return error
        # needs to be changed to an appropriate error message, and need to be logged
        return service_endpoint(current_app.server.get_endpoint("authorization"))

    par_args = parRequests[request_uri]["req_args"]
    # print("parRequests: " + str(par_args))
    # for e in par_args:
    #    print(e + ": " + par_args[e])

    # redirect_uri = "https%3A%2F%2Fpreprod.issuer.eudiw.dev%2Foidc%2Ftestgetauth"
    # redirect_uri = session["redirect_uri"]
    # client_id = request.args.get("client_id")
    # request_uri = request.args.get("request_uri")

    url = (
        "https://preprod.issuer.eudiw.dev/oidc/authorization?redirect_uri="
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

    params = {"token": response.json()["token"]}
    return redirect(url_get(response.json()["url"], params))
    # return response.content


@oidc.route("/authorizationV2", methods=["GET"])
def authorizationv2():
    try:
        clientAndSecret = request.args.get("client_id").split(".")
        redirect_uri = request.args.get("redirect_uri")
    except:
        return make_response("Authorization v2 error", 400)

    client_id = clientAndSecret[0]
    client_secret = clientAndSecret[1]

    current_app.server.get_endpoint("registration").process_request_authorization(
        client_id=client_id, client_secret=client_secret, redirect_uri=redirect_uri
    )

    return service_endpoint(current_app.server.get_endpoint("authorization"))


@oidc.route("/token", methods=["GET", "POST"])
def token():
    return service_endpoint(current_app.server.get_endpoint("token"))


@oidc.route("/introspection", methods=["POST"])
def introspection_endpoint():
    return service_endpoint(current_app.server.get_endpoint("introspection"))


@oidc.route("/userinfo", methods=["GET", "POST"])
def userinfo():
    return service_endpoint(current_app.server.get_endpoint("userinfo"))


@oidc.route("/session", methods=["GET"])
def session_endpoint():
    return service_endpoint(current_app.server.get_endpoint("session"))


@oidc.route("/pushed_authorization", methods=["GET", "POST"])
def par_endpoint():
    return service_endpoint(current_app.server.get_endpoint("pushed_authorization"))


@oidc.route("/pushed_authorizationv2", methods=["GET", "POST"])
def par_endpointv2():
    try:
        client_id = request.form["client_id"]
        redirect_uri = request.form["redirect_uri"]
    except:
        return make_response("PARv2 error", 400)

    client_secret = "Secret"
    session["redirect_uri"] = redirect_uri
    current_app.server.get_endpoint("registration").process_request_authorization(
        client_id=client_id, client_secret=client_secret, redirect_uri=redirect_uri
    )
    return service_endpoint(current_app.server.get_endpoint("pushed_authorization"))


@oidc.route("/credential", methods=["GET", "POST"])
def credential():
    return service_endpoint(current_app.server.get_endpoint("credential"))


@oidc.route("/error_redirect", methods=["GET", "POST"])
def custom_error_redirect():
    authn_method = current_app.server.get_context().authn_broker.get_method_by_id(
        "user"
    )
    try:
        auth_args = authn_method.unpack_token(request.args.get("jws_token"))
    except:
        pass

    return redirect(
        url_get(
            auth_args["return_uri"],
            {
                "error": "login failed",
                "error_description": "login failed too many times",
            },
        ),
        code=302,
    )


@oidc.route("/testgetauth", methods=["GET"])
def testget():
    if "error" in request.args:
        response = (
            request.args.get("error") + "\n" + request.args.get("error_description")
        )
        return response
    else:
        return request.args.get("code")


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
                response = do_response(endpoint, args, **args)
            return response
        except Exception as err:
            message = traceback.format_exception(*sys.exc_info())
            _log.error(message)
            err_msg = ResponseMessage(
                error="invalid_request", error_description=str(err)
            )
            return make_response(err_msg.to_json(), 400)

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

    _log.info("Response args: {}".format(args))

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


@oidc.route("/check_session_iframe", methods=["GET", "POST"])
def check_session_iframe():
    if request.method == "GET":
        req_args = request.args.to_dict()
    else:
        if request.data:
            req_args = json.loads(as_unicode(request.data))
        else:
            req_args = dict([(k, v) for k, v in request.form.items()])

    if req_args:
        _context = current_app.server.get_context()
        # will contain client_id and origin
        if req_args["origin"] != _context.issuer:
            return "error"
        if req_args["client_id"] != _context.cdb:
            return "error"
        return "OK"

    current_app.logger.debug("check_session_iframe: {}".format(req_args))
    doc = open("templates/check_session_iframe.html").read()
    current_app.logger.debug(f"check_session_iframe response: {doc}")
    return doc


@oidc.route("/verify_logout", methods=["GET", "POST"])
def verify_logout():
    part = urlparse(current_app.server.get_context().issuer)
    page = render_template(
        "route_oidc/logout.html",
        op=part.hostname,
        do_logout="rp_logout",
        sjwt=request.args["sjwt"],
    )
    return page


@oidc.route("/rp_logout", methods=["GET", "POST"])
def rp_logout():
    _endp = current_app.server.get_endpoint("session")
    _info = _endp.unpack_signed_jwt(request.form["sjwt"])
    try:
        request.form["logout"]
    except KeyError:
        alla = False
    else:
        alla = True

    _iframes = _endp.do_verified_logout(alla=alla, **_info)

    if _iframes:
        res = render_template(
            "route_oidc/frontchannel_logout.html",
            frames=" ".join(_iframes),
            size=len(_iframes),
            timeout=5000,
            postLogoutRedirectUri=_info["redirect_uri"],
        )
    else:
        res = redirect(_info["redirect_uri"])

        # rohe are you sure that _kakor is the right word? :)
        _kakor = _endp.kill_cookies()
        for cookie in _kakor:
            _add_cookie(res, cookie)

    return res


@oidc.route("/post_logout", methods=["GET"])
def post_logout():
    page = render_template("route_oidc/post_logout.html")
    return page


################################################
## To be moved to a file with scheduled jobs

import threading

scheduler_call = 300  # scheduled periodic job will be called every scheduler_call seconds (should be 300; 30 for debug)


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


def run_scheduler():
    print("Run scheduler.")
    threading.Timer(scheduler_call, run_scheduler).start()
    clear_par()


run_scheduler()
